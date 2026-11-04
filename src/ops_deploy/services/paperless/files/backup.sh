# paperless_backup on the host: required paths, disk check, Paperless
# version, document_exporter, pg_dump with a private passfile, directories,
# config, units, Traefik and SSH files, metadata, checksum manifest and the
# archive (written to a private temp file and renamed into place). The
# restore's safety snapshot runs this too (no exporter, no archive). The caller
# prepends the settings (see backup_restore.py); secrets arrive on stdin
# (line 1: exporter passphrase, line 2: PostgreSQL password; either may be empty).
IFS= read -r PASSPHRASE || true
IFS= read -r PG_PASSWORD || true

in_site() {
    # The role's become_user shell: cd, source the .env, run manage.py; the
    # passphrase ($1, may be empty) reaches the switched shell on its stdin only.
    local phrase=$1
    shift
    printf '%s' "$phrase" | runuser -u "$APP_USER" -- bash -c "$SITE_SHELL" paperless-backup \
        "$MANAGE_DIR" "$ENV_FILE" "$PYTHON" "$@"
}
SITE_SHELL='set -euo pipefail
IFS= read -r -d "" phrase || true
if [ -n "$phrase" ]; then export PAPERLESS_PASSPHRASE="$phrase"; fi
cd "$1"
set -a
. "$2"
set +a
python=$3
shift 3
exec "$python" manage.py "$@"'

if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$ROOT"; fi
if [ "$RECORD" = 1 ]; then require_new_snapshot "$ROOT" "${DIR##*/}"; fi
for spec in "${REQUIRED[@]}"; do
    IFS=: read -r path description <<<"$spec"
    if [ ! -e "$path" ]; then
        echo "paperless_backup: $description not found: $path" >&2
        exit 1
    fi
done

parent=$(dirname "$ROOT")
if [ "$parent" != / ] && [ ! -d "$parent" ]; then ensure_dir root root 0755 "$parent"; fi
# The role's file task on the parent: mode 0755, owner unchanged.
if [ "$parent" != / ] && [ "$(stat -c '%a' "$parent")" != 755 ]; then chmod 0755 "$parent"; fi
ensure_dir "$OWNER" "$GROUP" "$ROOT_MODE" "$ROOT"
restrict_archives "$ROOT" "$ARCHIVE_MODE"
# While root writes here the snapshot stays root's (0711: the exporter and the
# dump account only traverse it into their own subdirectories); the role's
# owners and modes are applied once root has written everything (HANDOVER).
ensure_dir root root 0711 "$DIR"
for sub in database media data consume export config systemd traefik ssh logs; do
    if [ "$sub" = database ]; then
        ensure_dir "$DB_DIR_OWNER" "$DB_DIR_GROUP" "$DIR_MODE" "$DIR/$sub"
    else
        ensure_dir root root 0700 "$DIR/$sub"
    fi
done

if [ "$DISK_CHECK" = 1 ]; then
    usage=()
    for spec in "${DIRS[@]}"; do
        IFS=: read -r include src dest <<<"$spec"
        if [ "$include" = 1 ] && [ -e "$src" ]; then usage+=("$src"); fi
    done
    if [ "${#usage[@]}" -gt 0 ]; then
        available=$(df -B1 --output=avail "$ROOT" | tail -1 | tr -d ' ')
        required=$(du -sb "${usage[@]}" | awk '{sum += $1} END {print sum}')
        needed=$(awk -v r="$required" -v o="$OVERHEAD" 'BEGIN { v = r * o; n = int(v); if (n < v) n++; print n }')
        if [ "$available" -lt "$needed" ]; then
            echo "Insufficient disk space under $ROOT (available=$available bytes, required~=$needed bytes including overhead)." >&2
            exit 1
        fi
    fi
fi

version=$(in_site "" --version)
version=$(printf '%s' "$version" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

if [ "$EXPORTER" = 1 ]; then
    if [ "$EXPORTER_CLEAN" = 1 ]; then rm -rf -- "$EXPORTER_TARGET"; fi
    ensure_dir "$APP_USER" "$APP_GROUP" 0755 "$EXPORTER_TARGET"
    in_site "$PASSPHRASE" document_exporter "${EXPORTER_FLAGS[@]}" "$EXPORTER_TARGET"
fi

# pg_dump as the PostgreSQL account, with a passfile in a private directory
# when a password is set (peer authentication otherwise); the directory always goes.
dump_args=()
[ -z "$PG_HOST" ] || dump_args+=("--host=$PG_HOST" "--port=$PG_PORT")
dump_args+=("--username=$PG_USER" "${PG_DUMP_OPTIONS[@]}" "$PG_DB")
passdir=""
remove_passdir() { if [ -n "$passdir" ]; then rm -rf -- "$passdir"; fi; }
trap remove_passdir EXIT
pg_env=()
if [ -n "$PG_PASSWORD" ]; then
    # Root creates the directory and hands it over; the PostgreSQL account
    # writes the passfile itself (the role's tempfile and template as become_user).
    passdir=$(mktemp -d /tmp/paperless_backup-pgpass-XXXXXXXXXX)
    chown "$PG_BECOME" "$passdir"
    # The role's passfile escaping (backslash, then colon); no literal double
    # backslash here: root's fish login shell would halve it on the wire.
    bs=$(printf '\x5c')
    escaped=${PG_PASSWORD//"$bs"/"$bs$bs"}
    escaped=${escaped//:/"$bs:"}
    printf '*:*:*:*:%s\n' "$escaped" | runuser -u "$PG_BECOME" -- bash -c 'umask 077; cat >"$1"' passfile "$passdir/pgpass"
    pg_env=("PGPASSFILE=$passdir/pgpass")
fi
dump="$DIR/database/$PG_DB.sql"
# The role's redirect runs in the PostgreSQL account's shell: the file is its.
runuser -u "$PG_BECOME" -- env "${pg_env[@]}" DUMP_TARGET="$dump" \
    bash -c 'set -o pipefail; exec "$@" >"$DUMP_TARGET"' paperless-dump "$PG_DUMP" "${dump_args[@]}"
remove_passdir
trap - EXIT

delete=()
[ "$RSYNC_DELETE" = 1 ] && delete=(--delete)
copied=" "
for spec in "${DIRS[@]}"; do
    IFS=: read -r include src dest <<<"$spec"
    if [ "$include" = 1 ] && [ -e "$src" ]; then
        "$RSYNC" -a "${delete[@]}" "$src/" "$DIR/$dest/"
        copied+="$dest "
    fi
done
for spec in "${COPIES[@]}"; do
    IFS=: read -r src dest <<<"$spec"
    if [ -e "$src" ]; then copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$src" "$DIR/$dest"; fi
done
for spec in "${EXTRA_FILES[@]}"; do
    IFS=: read -r src dest <<<"$spec"
    [ -n "$src" ] || continue
    sub=$(dirname "$dest")
    if [ "$sub" != . ]; then ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$DIR/$sub"; fi
    copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$src" "$DIR/$dest"
done

# Written in a private temp file first: never through a name in $DIR.
metadata=$(mktemp)
(umask 077 && printf '%s' "${METADATA/@VERSION@/"$version"}" >"$metadata")
copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$metadata" "$DIR/metadata.yml"
rm -f -- "$metadata"

if [ "$CHECKSUMS" = 1 ]; then
    (cd "$DIR" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum >manifest.sha256)
fi
if [ "$HANDOVER" = 1 ]; then
    # The role's owners and modes, now that root writes nothing more below $DIR.
    for sub in media data consume export config systemd traefik ssh logs; do
        # rsync -a gave a copied directory its source's owner and mode, as in the role.
        case $copied in *" $sub "*) continue ;; esac
        chown -h "$DIR_OWNER:$DIR_GROUP" "$DIR/$sub"
        chmod "$DIR_MODE" "$DIR/$sub"
    done
    chown -h "$DIR_OWNER:$DIR_GROUP" "$DIR"
    chmod "$DIR_MODE" "$DIR"
fi
if [ "$ARCHIVE" = 1 ]; then
    name=${DIR##*/}
    archive="$name.$FORMAT"
    (
        cd "$ROOT"
        umask 077
        partial=$(mktemp ".$archive.XXXXXXXX")
        trap 'rm -f -- "$partial"' EXIT
        if [ "$FORMAT" = tar.zst ]; then
            tar -C "$ROOT" --zstd -cf "$partial" "$name"
        else
            tar -C "$ROOT" -czf "$partial" "$name"
        fi
        mv -f -- "$partial" "$archive"
    )
    set_attrs "$OWNER" "$GROUP" "$ARCHIVE_MODE" "$ROOT/$archive"
fi
