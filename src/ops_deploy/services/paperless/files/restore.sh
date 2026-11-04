# paperless_restore on the host, in the role's phases: validate (archive,
# metadata, checksums, storage plan, dump, importer artefact), prepare (disk
# check, the safety snapshot through backup.sh), restore (stop services,
# recreate the database, importer or SQL dump plus files, config, system
# files), verify (start services, PostgreSQL and HTTP checks). A failed
# verification rolls back from the safety snapshot (a raw restore of it
# without importer or checks) and fails. Cleanup removes the staging directory
# after a success or dry run and the safety snapshot after a success. The
# caller prepends the settings (see backup_restore.py); secrets arrive on
# stdin (line 1: importer passphrase, 2: PostgreSQL password, 3: PostgreSQL
# admin password; any may be empty).
IFS= read -r PASSPHRASE || true
IFS= read -r PG_PASSWORD || true
IFS= read -r PG_ADMIN_PASSWORD || true

# The mount check comes before anything is created or removed.
if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$STAGING"; fi

staging_path=""
safety_path=""
success=0
rolled_back=0
cleanup() {
    # Every passfile lives below the run's passroot (created before any subshell).
    if [ -n "$passroot" ]; then rm -rf -- "$passroot"; fi
    if [ -n "$staging_path" ] && { [ "$success" = 1 ] || [ "$DRY_RUN" = 1 ] || [ "$rolled_back" = 1 ]; }; then
        rm -rf -- "$staging_path"
    fi
    if [ -n "$safety_path" ] && [ "$SAFETY_CLEANUP" = 1 ] && [ "$success" = 1 ] && [ "$rolled_back" = 0 ]; then
        rm -rf -- "$safety_path"
    fi
    if [ -n "$safety_path" ] && [ "$rolled_back" = 1 ] && [ "$CLEANUP_AFTER_ROLLBACK" = 1 ]; then rm -rf -- "$safety_path"; fi
    if [ "$DRY_RUN" = 1 ]; then
        echo "Paperless restore dry-run validation. Archive: ${archive:-unknown}."
    else
        echo "Paperless restore $([ "$success" = 1 ] && echo 'completed successfully' || echo failed)." \
            "Archive: ${archive:-unknown}. Safety snapshot: ${safety_path:-n/a}."
    fi
}
trap cleanup EXIT

# -- helpers ------------------------------------------------------------------------
SITE_SHELL='set -euo pipefail
IFS= read -r -d "" phrase || true
if [ -n "$phrase" ]; then export PAPERLESS_PASSPHRASE="$phrase"; fi
cd "$1"
set -a
. "$2"
set +a
python=$3
limit=$4
shift 4
if [ "$limit" -gt 0 ]; then exec timeout "$limit" "$python" manage.py "$@"; fi
exec "$python" manage.py "$@"'
# manage.py as the site owner, the role's become_user shell; $1 is the
# passphrase, $2 a timeout in seconds (0: none).
in_site() {
    local phrase=$1 limit=$2
    shift 2
    printf '%s' "$phrase" | runuser -u "$SITE_OWNER" -- bash -c "$SITE_SHELL" paperless-restore \
        "$MANAGE_DIR" "$ENV_FILE" "$PYTHON" "$limit" "$@"
}

# A passfile written by the PostgreSQL account itself (the role's tempfile and
# template as become_user) in a directory below the run's private root, which
# the EXIT trap removes whichever subshell created it. Sets $passfile.
passroot=""
new_passfile() {
    local dir escaped bs
    if [ -z "$passroot" ]; then
        passroot=$(mktemp -d /tmp/paperless_restore-pgpass-XXXXXXXXXX)
        chmod 0711 "$passroot"
    fi
    dir=$(mktemp -d "$passroot/p.XXXXXXXX")
    chown "$PG_BECOME" "$dir"
    # The role's passfile escaping (backslash, then colon); no literal double
    # backslash here: root's fish login shell would halve it on the wire.
    bs=$(printf '\x5c')
    escaped=${1//"$bs"/"$bs$bs"}
    escaped=${escaped//:/"$bs:"}
    printf '*:*:*:*:%s\n' "$escaped" | runuser -u "$PG_BECOME" -- bash -c 'umask 077; cat >"$1"' passfile "$dir/pgpass"
    passfile="$dir/pgpass"
}

# psql as the PostgreSQL account with the admin connection (stdin: SQL).
admin_psql() {
    local args=() env=()
    [ -z "$PG_ADMIN_HOST" ] || args+=("--host=$PG_ADMIN_HOST")
    [ -z "$PG_ADMIN_PORT" ] || args+=("--port=$PG_ADMIN_PORT")
    if [ -n "$PG_ADMIN_PASSWORD" ]; then
        new_passfile "$PG_ADMIN_PASSWORD"
        env=("PGPASSFILE=$passfile")
    fi
    runuser -u "$PG_BECOME" -- env "${env[@]}" "$PSQL" "${args[@]}" "--username=$PG_ADMIN_USER" \
        --set ON_ERROR_STOP=1 "$@"
}

# The account that reads the snapshot's dump: the owner of its directory, who
# alone could have planted a link there. When that account cannot even enter
# the directory (the staging tree is root:postgres), it cannot have changed it
# either, and root reads it, as the role does.
dump_reader() {
    local owner
    owner=$(stat -c '%U' -- "$(dirname -- "$1/$DB_DUMP")")
    if [ "$owner" != root ] && runuser -u "$owner" -- test -x "$(dirname -- "$1/$DB_DUMP")"; then
        printf '%s' "$owner"
    else
        printf root
    fi
}

meta_top() { awk -F: '/^[A-Za-z_][A-Za-z0-9_]*:/ { print $1 }' "$1"; }
meta_value() {
    local value
    value=$(sed -n "s/^$2:[[:space:]]*//p" "$1" | head -n 1)
    value=${value%\"}
    printf '%s' "${value#\"}"
}
# meta_storage FILE KEY: the role's storage.<KEY> (True/False as written).
meta_storage() {
    awk -v key="$2" '
        /^[^[:space:]]/ { block = $0; sub(/:.*/, "", block); next }
        block == "storage" && $1 == key ":" { print $2; exit }
    ' "$1"
}

# -- validate -----------------------------------------------------------------------
# validate SNAPSHOT USE_IMPORTER: the role's checks on an unpacked snapshot;
# sets plan (name:dest), importer_available.
validate() {
    local snapshot=$1 use_importer=$2 metadata version field host spec name dest required flag value
    metadata="$snapshot/metadata.yml"
    if [ ! -f "$metadata" ]; then
        echo "metadata file metadata.yml not found inside snapshot." >&2
        return 1
    fi
    version=$(in_site "" 0 --version 2>/dev/null) || version=""
    version=$(printf '%s' "$version" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    if [ -n "$version" ] && grep -q '^paperless_version:' "$metadata" &&
        [ "$(meta_value "$metadata" paperless_version)" != "$version" ]; then
        echo "WARNING: Backup was taken with Paperless $(meta_value "$metadata" paperless_version), but the" \
            "target host reports $version. Ensure versions match before running document_importer or deploying migrations."
    fi
    if [ "$VALIDATE_METADATA" = 1 ]; then
        for field in "${REQUIRED_FIELDS[@]}"; do
            if ! meta_top "$metadata" | grep -qx -- "$field"; then
                echo "Metadata field '$field' missing from snapshot metadata." >&2
                return 1
            fi
        done
    fi
    if [ "$ENFORCE_HOST" = 1 ] && grep -q '^host:' "$metadata"; then
        host=$(meta_value "$metadata" host)
        if [ "$host" != "$HOST_NAME" ]; then
            echo "Snapshot host $host does not match $HOST_NAME." >&2
            return 1
        fi
    fi
    if [ "$VALIDATE_CHECKSUMS" = 1 ]; then
        if [ ! -f "$snapshot/manifest.sha256" ]; then
            echo "Checksum manifest manifest.sha256 missing from snapshot." >&2
            return 1
        fi
        (cd "$snapshot" && grep -v '  \./manifest\.sha256$' manifest.sha256 | sha256sum --quiet -c -)
    fi
    plan=()
    external=0
    for spec in "${STORAGE[@]}"; do
        IFS=: read -r name dest required flag <<<"$spec"
        value=False
        [ -z "$flag" ] || value=$(meta_storage "$metadata" "$flag")
        if [ "$required" = 1 ] || [ -z "$flag" ] || [ "$value" = True ] || [ "$value" = true ]; then
            if [ ! -e "$snapshot/$name" ]; then
                echo "Required snapshot directory '$name' missing from $snapshot" >&2
                return 1
            fi
            plan+=("$name:$dest")
            case $dest in "$EXTERNAL_ROOT"*) external=1 ;; esac
        fi
    done
    if [ "$external" = 1 ] && [ ! -e "$EXTERNAL_ROOT" ]; then
        echo "External storage $EXTERNAL_ROOT is not mounted or accessible, refusing to restore media/data directories." >&2
        return 1
    fi
    if [ ! -e "$snapshot/$DB_DUMP" ]; then
        echo "Database dump $snapshot/$DB_DUMP missing from snapshot." >&2
        return 1
    fi
    # Checked now, before anything stops or the database is dropped.
    if [ ! -f "$snapshot/$DB_DUMP" ] || [ -L "$snapshot/$DB_DUMP" ]; then
        echo "Database dump $snapshot/$DB_DUMP is not a regular file." >&2
        return 1
    fi
    reader=$(dump_reader "$snapshot")
    if [ "$reader" != root ] && ! runuser -u "$reader" -- test -r "$snapshot/$DB_DUMP"; then
        echo "Database dump $snapshot/$DB_DUMP is not readable by its directory's owner $reader." >&2
        return 1
    fi
    importer_source=${IMPORTER_SOURCE:-$snapshot/$EXPORTER_DIR}
    importer_available=0
    if [ "$use_importer" = 1 ] && [ -d "$importer_source" ]; then importer_available=1; fi
    if [ "$use_importer" = 1 ] && [ "$IMPORTER_REQUIRE" = 1 ] && [ "$importer_available" = 0 ]; then
        echo "paperless_restore_use_importer=true but no exporter artefact was found at $importer_source." \
            "Either disable importer mode or ensure the backup includes the exporter directory." >&2
        return 1
    fi
    echo "Paperless snapshot ready: $snapshot."
}

disk_check() {
    local target=$DISK_PATH total free required
    [ -e "$target" ] || target=$(dirname "$target")
    total=$(find "$1" -type f -printf '%s\n' | awk '{ sum += $1 } END { print sum + 0 }')
    free=$(df -B1 --output=avail "$target" | tail -1 | tr -d ' ')
    required=$(awk -v t="$total" -v m="$MULTIPLIER" 'BEGIN { v = t * m; n = int(v); if (n < v) n++; print n }')
    if [ "$free" -lt "$required" ]; then
        echo "INSUFFICIENT_DISK:$required:$free" >&2
        return 1
    fi
    echo "OK:$required:$free"
}

# -- restore ------------------------------------------------------------------------
# restore_files SNAPSHOT USE_IMPORTER: stop, database, data, config, system files.
restore_files() {
    local snapshot=$1 attempt_importer=$2 unit spec name dest src owner group mode required used=0 env=()
    for unit in "${STOP_SERVICES[@]}"; do systemctl stop "$unit"; done
    if [ "$DROP_DATABASE" = 1 ]; then
        printf 'DROP DATABASE IF EXISTS %s;\n' "$PG_DB_IDENT" | admin_psql --dbname=postgres
    fi
    if [ "$CREATE_DATABASE" = 1 ]; then
        printf "SELECT 'CREATE DATABASE %s OWNER %s' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '%s')%sgexec\n" \
            "$PG_DB_IDENT" "$PG_OWNER_IDENT" "$PG_DB" "$(printf '\x5c')" | admin_psql --dbname=postgres
        # The role's postgresql_db state=present owner=...: an existing database gets the owner too.
        printf 'ALTER DATABASE %s OWNER TO %s;\n' "$PG_DB_IDENT" "$PG_OWNER_IDENT" | admin_psql --dbname=postgres
    fi
    for spec in "${plan[@]}"; do ensure_dir "$SITE_OWNER" "$SITE_GROUP" 0750 "${spec#*:}"; done
    # The dump is read as the owner of its directory (whoever wrote it), so
    # root never follows a link planted there; root writes the staged copy in
    # its own staging directory and hands it to the PostgreSQL account.
    rm -f -- "$staging_root_dump"
    reader=$(dump_reader "$snapshot")
    if [ "$reader" = root ]; then
        (umask 077 && cat -- "$snapshot/$DB_DUMP" >"$staging_root_dump")
    else
        (umask 077 && runuser -u "$reader" -- cat -- "$snapshot/$DB_DUMP" >"$staging_root_dump")
    fi
    chown -h "$PG_BECOME:$PG_BECOME" "$staging_root_dump"
    chmod 0600 "$staging_root_dump"
    if [ "$attempt_importer" = 1 ]; then
        # The role's rescue: a failed importer falls back to the raw snapshot.
        set +e
        (set -e; in_site "$PASSPHRASE" "$IMPORTER_TIMEOUT" document_importer "${IMPORTER_FLAGS[@]}" "$importer_source")
        status=$?
        set -e
        if [ "$status" = 0 ]; then
            used=1
        else
            echo "document_importer failed; falling back to raw snapshot restore."
        fi
    fi
    if [ "$used" = 0 ]; then
        admin_psql "--dbname=$PG_DB" --file "$staging_root_dump"
        admin_psql "--dbname=$PG_DB" <<<"$RECONCILE_SQL"
        local delete=()
        [ "$RSYNC_DELETE" = 1 ] && delete=(--delete)
        for spec in "${plan[@]}"; do
            name=${spec%%:*}
            "$RSYNC" -a "${delete[@]}" "$snapshot/$name/" "${spec#*:}/"
        done
    fi
    # The role checks every required config file before it copies any.
    for spec in "${CONFIGS[@]}"; do
        IFS=: read -r src dest owner group mode required <<<"$spec"
        if [ ! -e "$snapshot/$src" ] && [ "$required" = 1 ]; then
            echo "Config file $src missing from snapshot" >&2
            return 1
        fi
    done
    for spec in "${CONFIGS[@]}"; do
        IFS=: read -r src dest owner group mode required <<<"$spec"
        if [ -e "$snapshot/$src" ]; then copy_file "$owner" "$group" "$mode" "$snapshot/$src" "$dest"; fi
    done
    if [ "$SYSTEM_FILES" = 1 ]; then
        for spec in "${UNITS[@]}"; do
            src=${spec%%:*}
            if [ -e "$snapshot/$src" ]; then copy_file root root 0644 "$snapshot/$src" "${spec#*:}"; fi
        done
        src=${TRAEFIK_FILE%%:*}
        if [ -e "$snapshot/$src" ]; then
            if cmp -s "$snapshot/$src" "${TRAEFIK_FILE#*:}" || "${ROUTE_GUARD[@]}"; then
                copy_file root root 0644 "$snapshot/$src" "${TRAEFIK_FILE#*:}"
            else
                # A transaction took the lock after the check before the stop:
                # leave the route, finish the restore and fail at the end.
                echo "A Traefik transaction holds its lock; the route ${TRAEFIK_FILE#*:} was not restored." >&2
                route_skipped=1
            fi
        fi
        src=${SSH_FILE%%:*}
        if [ -e "$snapshot/$src" ]; then copy_file root root 0644 "$snapshot/$src" "${SSH_FILE#*:}"; fi
        if [ "$RELOAD_AFTER_SYSTEM_FILES" = 1 ]; then systemctl daemon-reload; fi
    fi
    if [ "$FIX_PERMISSIONS" = 1 ]; then chown_tree "$SITE_OWNER" "$SITE_GROUP" "${FIX_PATHS[@]}"; fi
}

# -- verify -------------------------------------------------------------------------
# verify CHECK_PG VERIFY_HTTP
verify() {
    local check_pg=$1 check_http=$2 unit attempt state code env=()
    for unit in "${START_SERVICES[@]}"; do
        systemctl start "$unit"
        sleep "$START_PAUSE"
    done
    for unit in "${START_SERVICES[@]}"; do
        for ((attempt = 0; ; attempt++)); do
            state=$(systemctl is-active "$unit" || true)
            [ "$state" = active ] && break
            if [ "$attempt" -ge "$START_RETRIES" ]; then
                echo "$unit is $state, not active" >&2
                return 1
            fi
            sleep "$START_DELAY"
        done
    done
    if [ "$check_pg" = 1 ]; then
        if [ -n "$PG_PASSWORD" ]; then
            new_passfile "$PG_PASSWORD"
            env=("PGPASSFILE=$passfile")
        fi
        for ((attempt = 0; ; attempt++)); do
            if printf '%s\n' "$PG_TEST_QUERY" | runuser -u "$PG_BECOME" -- env "${env[@]}" "$PSQL" "--host=$PG_HOST" \
                "--port=$PG_PORT" "--username=$PG_USER" "--dbname=$PG_DB" --set ON_ERROR_STOP=1 >/dev/null; then
                break
            fi
            if [ "$attempt" -ge "$PG_RETRIES" ]; then return 1; fi
            sleep "$PG_DELAY"
        done
    fi
    if [ "$check_http" = 1 ]; then
        for ((attempt = 0; ; attempt++)); do
            code=$(curl -s --max-time "$HTTP_TIMEOUT" -o /dev/null -w '%{http_code}' "$HEALTH_URL" || true)
            [ "$code" = "$HEALTH_STATUS" ] && break
            if [ "$attempt" -ge "$HEALTH_RETRIES" ]; then
                echo "$HEALTH_URL answered $code, expected $HEALTH_STATUS" >&2
                return 1
            fi
            sleep "$HEALTH_DELAY"
        done
    fi
}

# -- main ---------------------------------------------------------------------------
if [ -n "$PG_PASSWORD$PG_ADMIN_PASSWORD" ]; then
    passroot=$(mktemp -d /tmp/paperless_restore-pgpass-XXXXXXXXXX)
    chmod 0711 "$passroot"
fi
if [ "$ARCHIVE" = latest ]; then
    archive=$({ find "$SEARCH_ROOT/" -mindepth 1 -maxdepth 1 -type f -name '*.tar.*' ! -name '.*' -printf '%T@ %p\n' 2>/dev/null ||
        true; } | LC_ALL=C sort -rn | awk 'NR == 1 { sub(/^[^ ]* /, ""); print }')
    if [ -z "$archive" ]; then
        echo "No Paperless backup archives found under $SEARCH_ROOT. Upload an archive (just restore paperless does)." >&2
        exit 1
    fi
else
    archive="$SEARCH_ROOT/$ARCHIVE"
fi
if [ ! -f "$archive" ] || [ -L "$archive" ]; then
    echo "Backup artifact $archive does not exist on the host." >&2
    exit 1
fi
# Never adopt a staging root another account created or a link to elsewhere.
if [ -L "$STAGING" ] || { [ -e "$STAGING" ] && [ "$(stat -c '%u' "$STAGING")" != 0 ]; }; then
    echo "$STAGING exists and is not root's directory; refusing to stage there." >&2
    exit 1
fi
ensure_dir "$STAGING_OWNER" "$STAGING_GROUP" "$STAGING_MODE" "$STAGING"
# A fresh directory: mkdir fails when the name exists already.
mkdir -m "$STAGING_MODE" -- "$STAGING/$(basename "$archive")-$STAMP"
staging_path="$STAGING/$(basename "$archive")-$STAMP"
chown "$STAGING_OWNER:$STAGING_GROUP" "$staging_path"
case $archive in
    *.tar.zst) tar --extract --zstd --file "$archive" --directory "$staging_path" ;;
    *) tar --extract --file "$archive" --directory "$staging_path" ;;
esac
mapfile -t candidates < <(find "$staging_path" -mindepth 1 -maxdepth 1 -type d)
if [ "${#candidates[@]}" != 1 ]; then
    echo "Expected exactly one directory inside $staging_path but found ${#candidates[@]}." >&2
    exit 1
fi
snapshot=${candidates[0]}
set_attrs "$STAGING_OWNER" "$STAGING_GROUP" "$STAGING_MODE" "$snapshot"
staging_root_dump="$staging_path/paperless.sql"
validate "$snapshot" "$USE_IMPORTER"
if [ "$CHECK_DISK" = 1 ]; then disk_check "$snapshot"; fi
if [ "$DRY_RUN" = 1 ]; then
    echo "paperless_restore_dry_run=true - skipping service stop, data restore, service start and health checks"
    exit 0
fi
# A route that differs is written only without a held Traefik transaction
# lock: refuse before anything stops when one is held now.
route_skipped=0
src=${TRAEFIK_FILE%%:*}
if [ "$SYSTEM_FILES" = 1 ] && [ -e "$snapshot/$src" ] && ! cmp -s "$snapshot/$src" "${TRAEFIK_FILE#*:}" &&
    ! "${ROUTE_GUARD[@]}"; then
    echo "A Traefik transaction holds its lock; the restore changes nothing. Retry when it is done." >&2
    exit 1
fi
if [ "$CREATE_SAFETY" = 1 ]; then
    # backup.sh with the role's safety overrides (no exporter, no archive, peer auth).
    (
        eval "$SAFETY_SETTINGS"
        eval "$BACKUP_BODY"
    ) < <(printf '\n\n')
    safety_path=$SAFETY_DIR
    echo "Safety snapshot captured at $safety_path"
fi
restore_files "$snapshot" "$importer_available"

set +e
(set -e; verify "$PG_CHECK" "$VERIFY_HTTP")
status=$?
set -e
if [ "$status" = 0 ] && [ "$route_skipped" = 1 ]; then
    echo "Paperless restored without its Traefik route; restore ${TRAEFIK_FILE#*:} from $archive when the transaction is done." >&2
    exit 1
fi
if [ "$status" = 0 ]; then
    success=1
    exit 0
fi
if [ "$ROLLBACK" = 1 ] && [ -n "$safety_path" ]; then
    set +e
    (
        set -e
        [ -d "$safety_path" ] || {
            echo "Safety snapshot $safety_path does not exist on the host." >&2
            exit 1
        }
        for unit in "${STOP_SERVICES[@]}"; do systemctl stop "$unit" || true; done
        route_skipped=0
        # The role's rollback: a raw restore of the safety snapshot, no importer, no checks.
        validate "$safety_path" 0
        if [ "$CHECK_DISK" = 1 ]; then disk_check "$safety_path"; fi
        staging_root_dump="$staging_path/paperless-rollback.sql"
        restore_files "$safety_path" 0
        verify 0 0
        # A route the rollback could not put back leaves it incomplete.
        [ "$route_skipped" = 0 ]
    )
    rollback=$?
    set -e
    # Like the role: only a completed rollback counts (and its own cleanup
    # removed the staging directory); a failed one keeps everything.
    if [ "$rollback" = 0 ]; then
        rolled_back=1
    else
        echo "Automatic rollback attempt failed; manual intervention required." >&2
    fi
fi
echo "Paperless restore verification failed; review the errors above." >&2
exit 1
