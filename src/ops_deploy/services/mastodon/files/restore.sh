# mastodon_restore on the host, in the role's order and with its safety
# contract:
# - the archive is unpacked into the staging directory and the database dump
#   is validated (`pg_restore --list` with TABLE DATA, then a full read into
#   /dev/null) before any service is stopped;
# - the media paths the backup excluded (the manifest's media_rsync_excludes)
#   are excluded from the media restore too, so the live paths they match are
#   kept;
# - an archive whose media/ holds no files outside those excludes is refused
#   at that point while the live media holds files outside them, unless
#   EMPTY_MEDIA_CONFIRMED (the role's mastodon_restore_empty_media_confirmed);
# - the services must stop, otherwise nothing is dropped;
# - after the stop a safety `pg_dump -Fc` of the live database, a snapshot of
#   the media directory and copies of the env, unit, Traefik and nginx files
#   are taken before the first overwrite;
# - the dump is restored with `--single-transaction`;
# - any failure while restoring puts the safety copies back, leaves the
#   services stopped and reports both safety paths;
# - the staging directory (it holds the unpacked dump) always goes.
# The role's block/rescue/always structure is the EXIT trap below, driven by
# `phase` (prepare, safety, restore, done) and `step` (the task that runs).
# The caller prepends the settings (see backup_restore.py) and sends the
# database password on stdin (postgres.sh, sent in front of this script,
# reads it); it never reaches a command line.

# ensure_owned OWNER MODE PATH: Ansible's file state=directory with an owner
# and a mode only (the group stays).
ensure_owned() {
    [ -d "$3" ] || mkdir -p -- "$3"
    [ "$(stat -c %U -- "$3")" = "$1" ] || chown -- "$1" "$3"
    set_mode "$2" "$3"
}

# set_mode MODE PATH: chmod only where the mode differs.
set_mode() {
    [ "$(stat -c %a -- "$2")" = "$(printf '%o' "$((8#$1))")" ] || chmod -- "$1" "$2"
}

stopped_state() {
    case $1 in inactive | failed) return 0 ;; *) return 1 ;; esac
}

phase=prepare
step=""
db_exists=0
media_enabled=0
db_rollback=1
files_rollback=1
files_rollback_error=""
route_written=0
route_rollback=""

# The rescue of the "Restore Mastodon with rollback" block.
roll_back() {
    local service state running=0
    for service in "${SERVICES[@]}"; do systemctl stop "$service" || true; done
    for service in "${SERVICES[@]}"; do
        # Only a positively confirmed stop makes the rollback safe; a failed
        # query (empty output) counts as "maybe running".
        state=$(systemctl is-active "$service" 2>/dev/null) || true
        stopped_state "$(printf '%s' "$state" | tr -d '[:space:]')" || running=1
    done
    if [ "$running" = 0 ] && [ "$db_exists" = 1 ]; then
        db_rollback=0
        with_pgpass "$PG_BECOME" bash -c '
            set -euo pipefail
            dropdb=$1 createdb=$2 pg_restore=$3 db=$4 owner=$5 dump=$6
            shift 6
            admin=() conn=()
            while [ "$#" -gt 0 ] && [ "$1" != -- ]; do admin+=("$1"); shift; done
            shift
            conn=("$@")
            "$dropdb" "${admin[@]}" --if-exists "$db"
            "$createdb" "${admin[@]}" --owner="$owner" "$db"
            "$pg_restore" "${conn[@]}" --dbname="$db" --single-transaction --no-owner "$dump"
        ' mastodon-db-rollback "$PG_DROPDB" "$PG_CREATEDB" "$PG_RESTORE" "$PG_DATABASE" "$PG_USER" "$SAFETY_DUMP" \
            "${ADMIN_ARGS[@]}" -- "${CONN_ARGS[@]}" || db_rollback=$?
    fi
    if [ "$running" = 0 ]; then
        files_rollback=0
        # A separate bash, so its set -e holds inside this rescue.
        files_rollback_error=$(bash -c '
            set -euo pipefail
            media_enabled=$1 media_safety=$2 media=$3 safety_dir=$4 route=$5
            if [ "$media_enabled" = 1 ] && [ -d "$media_safety" ]; then
                rsync -a --delete --checksum "$media_safety/" "$media/"
            fi
            files="$safety_dir/files"
            while IFS= read -r path; do
                [ -n "$path" ] || continue
                # The route is rolled back by the caller, behind the guard.
                [ "$path" != "$route" ] || continue
                if [ -e "$files$path" ] || [ -L "$files$path" ]; then
                    rm -f "$path"
                    cp -a "$files$path" "$path"
                else
                    rm -f "$path"
                fi
            done <"$safety_dir/files.manifest"
            systemctl daemon-reload
        ' mastodon-files-rollback "$media_enabled" "$MEDIA_SAFETY" "$MEDIA" "$SAFETY_DIR" "$TRAEFIK" 2>&1 >/dev/null) ||
            files_rollback=$?
        # Only a route this restore wrote goes back, and only while no Traefik
        # transaction holds its lock.
        if [ "$route_written" = 1 ]; then
            if "${ROUTE_GUARD[@]}"; then
                if [ -e "$SAFETY_DIR/files$TRAEFIK" ] || [ -L "$SAFETY_DIR/files$TRAEFIK" ]; then
                    rm -f "$TRAEFIK" && cp -a "$SAFETY_DIR/files$TRAEFIK" "$TRAEFIK" || route_rollback=FAILED
                else
                    rm -f "$TRAEFIK" || route_rollback=FAILED
                fi
                [ -n "$route_rollback" ] || route_rollback=done
            else
                route_rollback="not rolled back: a Traefik transaction holds its lock; restore $TRAEFIK from $SAFETY_DIR/files by hand"
            fi
        fi
    fi
    local db_text files_text
    if [ "$db_exists" != 1 ]; then
        db_text="not needed (no live database before the restore)"
    elif [ "$running" = 1 ]; then
        db_text=skipped
    elif [ "$db_rollback" = 0 ]; then
        db_text=done
    else
        db_text=FAILED
    fi
    if [ "$running" = 1 ]; then
        files_text=skipped
    elif [ "$files_rollback" = 0 ]; then
        files_text=done
    else
        files_text="FAILED: $files_rollback_error"
    fi
    {
        echo "Mastodon restore failed ($step)."
        if [ "$running" = 1 ]; then
            echo "A service could not be stopped, so NOTHING was rolled back; stop it and roll back by hand from the paths below."
        fi
        echo "Database rollback: $db_text."
        echo "Media and config rollback: $files_text."
        if [ -n "$route_rollback" ]; then echo "Traefik route rollback: $route_rollback."; fi
        echo "Safety dump: $([ "$db_exists" = 1 ] && printf '%s' "$SAFETY_DUMP" || printf none)."
        echo "Media snapshot: $([ "$media_enabled" = 1 ] && printf '%s' "$MEDIA_SAFETY" || printf none)."
        echo "Config copies: $SAFETY_DIR/files."
        echo "Services are left stopped (unless reported above); check the data, then start them with" \
            "\`systemctl start ${SERVICES[*]}\`."
    } >&2
}

on_exit() {
    local rc=$?
    set +e
    drop_pgpass
    if [ "$rc" != 0 ]; then
        case $phase in
            safety)
                echo "Mastodon restore aborted before anything was dropped or overwritten ($step): a service" \
                    "did not stop or a safety copy under $SAFETY_DIR / $MEDIA_SAFETY could not be taken." \
                    "The live database and media are untouched. Services may be stopped; start them with" \
                    "\`systemctl start ${SERVICES[*]}\`." >&2
                ;;
            restore) roll_back ;;
        esac
    fi
    if [ "$CLEANUP" = 1 ]; then rm -rf "$STAGING"; fi
    exit "$rc"
}
trap on_exit EXIT

# -- locate, unpack and validate --------------------------------------------------
step="Select restore archive"
if [ "$ARCHIVE" = latest ]; then
    archive=""
    newest=""
    if [ -d "$RESTORE_ROOT" ]; then
        while IFS= read -r -d '' path; do
            mtime=$(stat -c %Y -- "$path")
            if [ -z "$archive" ] || [ "$mtime" -gt "$newest" ]; then
                archive=$path
                newest=$mtime
            fi
        done < <(find "$RESTORE_ROOT" -mindepth 1 -maxdepth 1 -type f ! -name '.*' -name '*.tar.gz' -print0)
    fi
    if [ -z "$archive" ]; then
        echo "No Mastodon backup archives found in $RESTORE_ROOT" >&2
        exit 1
    fi
else
    archive="$RESTORE_ROOT/$ARCHIVE"
fi
if [ ! -f "$archive" ] || [ -L "$archive" ]; then
    echo "Mastodon restore archive not found: $archive" >&2
    exit 1
fi
echo "Restore archive: $archive"

step="Unpack restore archive"
rm -rf "$STAGING"
ensure_dir root root 0700 "$STAGING"
tar -xzf "$archive" -C "$STAGING"
base=${archive##*/}
payload="$STAGING/${base%.tar.gz}"
if [ ! -d "$payload" ] || [ -L "$payload" ]; then
    payload=$(find "$STAGING" -mindepth 1 -maxdepth 1 -type d ! -name '.*' | LC_ALL=C sort | head -n 1)
fi
if [ -z "$payload" ]; then
    echo "Unable to locate payload directory inside restore archive" >&2
    exit 1
fi
has() { [ -e "$payload/$1" ] || [ -L "$payload/$1" ]; }
dump="$payload/database/$PG_DATABASE.dump"
if ! has "database/$PG_DATABASE.dump"; then
    echo "Database dump missing inside archive" >&2
    exit 1
fi
if has media && [ "$STORAGE" = local ]; then media_enabled=1; fi
has_env=0 has_systemd=0 has_traefik=0 has_nginx=0
if has config/mastodon.env; then has_env=1; fi
if has systemd; then has_systemd=1; fi
if has "traefik/${TRAEFIK##*/}"; then has_traefik=1; fi
if has "nginx/${NGINX##*/}"; then has_nginx=1; fi

for path in "$STAGING" "$payload" "$payload/database"; do
    [ "$(stat -c %U -- "$path")" = "$PG_BECOME" ] || chown -- "$PG_BECOME" "$path"
    set_mode 0700 "$path"
done
[ "$(stat -c %U -- "$dump")" = "$PG_BECOME" ] || chown -- "$PG_BECOME" "$dump"
set_mode 0600 "$dump"

step="Validate the database dump table of contents"
as_user "$PG_BECOME" bash -c '
    set -euo pipefail
    toc="$("$1" --list "$2")"
    if ! grep -Eq "^[0-9]+; [0-9]+ [0-9]+ TABLE DATA " <<<"$toc"; then
        echo "dump has no TABLE DATA entries" >&2
        exit 1
    fi
    "$1" --file=/dev/null "$2"
' mastodon-dump-check "$PG_RESTORE" "$dump"

unit_files=()
if [ "$has_systemd" = 1 ]; then
    while IFS= read -r -d '' path; do unit_files+=("$path"); done < <(
        find "$payload/systemd" -mindepth 1 -maxdepth 1 -type f ! -name '.*' -print0 | LC_ALL=C sort -z
    )
fi
yes_no() { if [ "$1" = 1 ]; then printf yes; else printf no; fi; }
media_text=$(yes_no "$media_enabled")

# stop_unchanged REASON: stop before anything was stopped or changed.
stop_unchanged() {
    echo "Mastodon restore stopped before anything was stopped or changed: $1." >&2
    exit 1
}

# The paths the backup left out of media/ (its media_rsync_excludes, by
# default the remote-media cache /cache/***) are excluded from the media
# restore as well: rsync --delete keeps them in the live media instead of
# deleting them, and the empty-media guard counts only files outside them.
# They come from the manifest's one `media_rsync_excludes: [...]` line, a JSON
# list of strings as both backups write it, without quotes or backslashes in
# a pattern (the backup config refuses those). An archive without a
# manifest.yml or without that line has none, so the restore behaves as
# before the excludes (every live media file the archive lacks is deleted);
# anything else in that line stops the restore here.
media_excludes=()
exclude_args=()
read_media_excludes() {
    local manifest="$payload/manifest.yml" value rest rc=0
    local item='^[[:space:]]*"([^"]+)"[[:space:]]*(,(.*))?$' backslash
    # printf's octal escape: a backslash pair in the script would reach sh
    # halved through root's fish login shell.
    backslash=$(printf '\134')
    if ! has manifest.yml; then
        excludes_text="none (the archive has no manifest.yml)"
        return 0
    fi
    if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then stop_unchanged "the archive's manifest.yml is not a file"; fi
    value=$(grep -e '^media_rsync_excludes:' -- "$manifest") || rc=$?
    if [ "$rc" = 1 ]; then
        excludes_text="none (the archive's manifest.yml lists none)"
        return 0
    fi
    [ "$rc" = 0 ] || stop_unchanged "cannot read the archive's manifest.yml"
    case $value in *$'\n'*) stop_unchanged "the archive's manifest.yml has more than one media_rsync_excludes line" ;; esac
    # A JSON escape could hide a quote; the backup config allows none.
    case $value in *"$backslash"*) stop_unchanged "media_rsync_excludes in the archive's manifest.yml holds a backslash" ;; esac
    if [[ ! ${value#media_rsync_excludes:} =~ ^[[:space:]]*\[(.*)\][[:space:]]*$ ]]; then
        stop_unchanged "cannot read media_rsync_excludes in the archive's manifest.yml (expected a JSON list of strings)"
    fi
    rest=${BASH_REMATCH[1]}
    if [[ ! $rest =~ ^[[:space:]]*$ ]]; then
        while :; do
            [[ $rest =~ $item ]] ||
                stop_unchanged "cannot read media_rsync_excludes in the archive's manifest.yml (expected a JSON list of strings)"
            media_excludes+=("${BASH_REMATCH[1]}")
            [ -n "${BASH_REMATCH[2]}" ] || break
            rest=${BASH_REMATCH[3]}
        done
    fi
    local pattern
    for pattern in "${media_excludes[@]}"; do exclude_args+=("--exclude=$pattern"); done
    if [ "${#media_excludes[@]}" = 0 ]; then
        excludes_text="none (the archive's manifest.yml lists none)"
    else
        excludes_text=$(printf '%s, ' "${media_excludes[@]}")
        excludes_text="${excludes_text%, } (from the archive's manifest.yml)"
    fi
}

# count_media_files DIR: the non-directories (files, links, ...) below DIR
# outside the media excludes, as the media restore's rsync sees them. A
# failing rsync fails the count (pipefail).
count_media_files() {
    rsync -a --list-only "${exclude_args[@]}" "$1/" | awk 'substr($0, 1, 1) != "d" { n++ } END { print n + 0 }'
}

# A backup taken without media still has an empty media/; its rsync --delete
# would delete the live media. Only files outside the excludes count: an
# archive that holds none (only directories, excluded paths or nothing) is
# EMPTY, and it is refused while the live media holds files outside the
# excludes. A failing count stops the restore here.
media_empty=0
live_files=0
excludes_text=""
if [ "$media_enabled" = 1 ]; then
    step="Read the media excludes from the archive's manifest"
    read_media_excludes
    step="Look for media files in the archive"
    archive_files=$(count_media_files "$payload/media") || stop_unchanged "cannot read the archive's media/"
    if [ "$archive_files" = 0 ]; then
        media_empty=1
        media_text="EMPTY"
        step="Look for live media files outside the excludes"
        if [ -e "$MEDIA" ] || [ -L "$MEDIA" ]; then
            live_files=$(count_media_files "$MEDIA") || stop_unchanged "cannot read the live media $MEDIA"
        fi
    fi
fi
echo "Components: database=yes, media=$media_text, env=$(yes_no "$has_env")," \
    "systemd=${#unit_files[@]} unit(s), traefik=$(yes_no "$has_traefik"), nginx=$(yes_no "$has_nginx")"
if [ "$media_enabled" = 1 ]; then
    if [ "${#media_excludes[@]}" = 0 ]; then
        echo "Media excludes: $excludes_text; the restore deletes every live media file the archive lacks."
    else
        echo "Media excludes: $excludes_text; the restore keeps the live media paths they match."
    fi
fi
if [ "$media_empty" = 1 ] && [ "$live_files" = 0 ]; then
    echo "The archive's media/ holds no files outside the excludes, and neither does the live media $MEDIA:" \
        "the media restore deletes no file."
elif [ "$media_empty" = 1 ]; then
    empty_text="The archive's media/ holds no files outside the excludes: restoring it deletes the $live_files file(s)"
    empty_text+=" outside them in the live media $MEDIA"
    if [ "$EMPTY_MEDIA_CONFIRMED" = 1 ]; then
        echo "$empty_text (confirmed with empty_media_confirmed; the pre-restore media snapshot keeps them)."
    elif [ "$DRY_RUN" = 1 ]; then
        echo "$empty_text. A restore refuses this archive unless empty_media_confirmed" \
            "(ops-control: MASTODON_RESTORE_EMPTY_MEDIA_CONFIRMED=true)."
    else
        echo "Mastodon restore refused before anything was stopped or changed. $empty_text." \
            "Restore an archive taken with media, or confirm with empty_media_confirmed" \
            "(ops-control: MASTODON_RESTORE_EMPTY_MEDIA_CONFIRMED=true)." >&2
        exit 1
    fi
fi
if [ "$DRY_RUN" = 1 ]; then
    echo "Dry run: the archive and its dump are valid; nothing was stopped or changed."
    exit 0
fi

# A changed route is written only while no Traefik transaction holds its lock;
# check that before anything stops.
traefik_changed=0
if [ "$has_traefik" = 1 ] && ! cmp -s "$payload/traefik/${TRAEFIK##*/}" "$TRAEFIK"; then
    traefik_changed=1
    if ! "${ROUTE_GUARD[@]}"; then
        echo "A Traefik transaction holds its lock; the restore changes nothing. Retry when it is done." >&2
        exit 1
    fi
fi

step="Ensure media directory exists"
ensure_dir "$USER_NAME" "$GROUP_NAME" 0750 "$MEDIA"
step="Ensure site directory exists"
ensure_dir "$USER_NAME" "$GROUP_NAME" 0750 "$SITE"

# Same endpoint and role as the restore itself, so the safety dump below
# always covers the database that is about to be replaced.
step="Check whether the live database exists"
probe_err="$STAGING/.db-exists.err"
probe_rc=0
probe=$(with_pgpass "$PG_BECOME" "$PG_PSQL" "${CONN_ARGS[@]}" "--dbname=$PG_DATABASE" --no-psqlrc \
    --tuples-only --no-align --command="SELECT 1" 2>"$probe_err") || probe_rc=$?
if [ "$probe_rc" != 0 ] && ! grep -qF "database \"$PG_DATABASE\" does not exist" "$probe_err"; then
    cat "$probe_err" >&2
    exit 1
fi
rm -f "$probe_err"
if [ "$probe_rc" = 0 ] && [ "$(printf '%s' "$probe" | tr -d '[:space:]')" = 1 ]; then db_exists=1; fi

installed=()
for service in "${SERVICES[@]}"; do
    # Fail closed: a unit whose state cannot be read counts as installed, so
    # it has to stop and be confirmed stopped like the others.
    # A unit whose file is gone but that still runs is installed too.
    unit="${service%.service}.service"
    load=$(systemctl show --property=LoadState --value "$unit" 2>/dev/null) || load=""
    if [ "$load" = not-found ]; then
        state=$(systemctl is-active "$unit" 2>/dev/null) || true
        stopped_state "$(printf '%s' "$state" | tr -d '[:space:]')" || load=running
    fi
    if [ "$load" != not-found ]; then installed+=("$service"); fi
done

# -- stop (fail closed) and take the safety copies --------------------------------
phase=safety
if [ "$STOP" = 1 ]; then
    for service in "${installed[@]}"; do
        step="Stop $service before restore"
        systemctl stop "$service"
    done
fi
for service in "${installed[@]}"; do
    step="Confirm $service is stopped"
    state=$(systemctl is-active "$service") || true
    stopped_state "$(printf '%s' "$state" | tr -d '[:space:]')"
done

step="Create safety directories"
ensure_owned root 0711 "$SAFETY_ROOT"
ensure_owned root 0711 "$SAFETY_DIR"
ensure_owned "$PG_BECOME" 0700 "$SAFETY_DIR/database"
ensure_owned root 0700 "$MEDIA_SAFETY_ROOT"

if [ "$db_exists" = 1 ]; then
    step="Take safety dump of the live database"
    with_pgpass "$PG_BECOME" "$PG_DUMP" "${CONN_ARGS[@]}" --format=custom "--file=$SAFETY_DUMP" "--dbname=$PG_DATABASE"
    step="Check the safety dump"
    as_user "$PG_BECOME" "$PG_RESTORE" --list "$SAFETY_DUMP" >/dev/null
fi

step="Snapshot media and config files"
if [ -e "$MEDIA_SAFETY" ]; then
    echo "media safety directory already exists: $MEDIA_SAFETY" >&2
    exit 1
fi
if [ "$media_enabled" = 1 ] && [ -d "$MEDIA" ]; then
    # Hard links share the files with the live tree, so the copy is cheap;
    # rsync writes restored files to new inodes and leaves the snapshot
    # intact. Fall back to a full copy across devices. Copy the contents
    # ("/."), so a symlinked media root is followed instead of being copied as
    # a link to the live tree.
    mkdir -m 0700 "$MEDIA_SAFETY"
    if ! cp -al "$MEDIA/." "$MEDIA_SAFETY/" 2>/dev/null; then
        rm -rf "$MEDIA_SAFETY"
        mkdir -m 0700 "$MEDIA_SAFETY"
        cp -a "$MEDIA/." "$MEDIA_SAFETY/"
    fi
fi
config_targets=("$ENV_FILE" "$TRAEFIK" "$NGINX")
for path in "${unit_files[@]}"; do config_targets+=("$UNIT_DIR/${path##*/}"); done
files="$SAFETY_DIR/files"
mkdir -p "$files"
chmod 0700 "$files"
: >"$SAFETY_DIR/files.manifest"
for path in "${config_targets[@]}"; do
    printf '%s\n' "$path" >>"$SAFETY_DIR/files.manifest"
    if [ -e "$path" ] || [ -L "$path" ]; then
        mkdir -p "$files$(dirname "$path")"
        cp -a "$path" "$files$path"
    fi
done
sync
echo "Pre-restore database dump: $([ "$db_exists" = 1 ] && printf '%s' "$SAFETY_DUMP" || printf 'none (no live database)')"
echo "Pre-restore media snapshot: $([ "$media_enabled" = 1 ] && printf '%s' "$MEDIA_SAFETY" || printf 'none (media not restored)')"
echo "Pre-restore config files: $files"

# -- overwrite; any failure rolls back to the safety copies -----------------------
phase=restore
step="Drop Mastodon database"
with_pgpass "$PG_BECOME" "$PG_DROPDB" "${ADMIN_ARGS[@]}" --if-exists "$PG_DATABASE"
step="Recreate Mastodon database"
with_pgpass "$PG_BECOME" "$PG_CREATEDB" "${ADMIN_ARGS[@]}" "--owner=$PG_USER" "$PG_DATABASE"
step="Restore PostgreSQL dump"
with_pgpass "$PG_BECOME" "$PG_RESTORE" "${CONN_ARGS[@]}" "--dbname=$PG_DATABASE" --single-transaction --clean \
    --if-exists --no-owner "$dump"

# --ignore-times makes rsync rewrite every file to a new inode (temp file +
# rename), so the hard-linked media snapshot keeps its content and metadata.
# The media excludes keep the live paths they match (rsync does not delete
# excluded files on the receiving side).
if [ "$media_enabled" = 1 ]; then
    step="Restore media directory"
    rsync -a --delete --ignore-times "${exclude_args[@]}" "$payload/media/" "$MEDIA/"
fi
if [ "$has_env" = 1 ]; then
    step="Restore environment file"
    copy_file "$USER_NAME" "$GROUP_NAME" 0600 "$payload/config/mastodon.env" "$ENV_FILE"
fi
step="Copy systemd unit files"
for path in "${unit_files[@]}"; do copy_file root root 0644 "$path" "$UNIT_DIR/${path##*/}"; done
route_skipped=0
if [ "$has_traefik" = 1 ]; then
    step="Restore Traefik configuration"
    if [ "$traefik_changed" = 1 ] && ! "${ROUTE_GUARD[@]}"; then
        # A transaction took the lock after the first check: leave the route
        # alone, finish the restore and fail at the end.
        echo "A Traefik transaction took its lock during the restore; the route $TRAEFIK was not restored." >&2
        route_skipped=1
    else
        route_written=$traefik_changed
        copy_file root root 0644 "$payload/traefik/${TRAEFIK##*/}" "$TRAEFIK"
    fi
fi
if [ "$has_nginx" = 1 ]; then
    step="Restore nginx configuration"
    copy_file root root 0644 "$payload/nginx/${NGINX##*/}" "$NGINX"
fi
step="Reload systemd"
systemctl daemon-reload
if [ "$RUN_MIGRATIONS" = 1 ]; then
    step="Run migrations after restore"
    runuser -u "$USER_NAME" -- env HOME="$HOME_PATH" bash -c '
        set -euo pipefail
        export RBENV_ROOT="$1"
        export PATH="$1/bin:$1/shims:/usr/local/bin:/usr/bin:/bin"
        set -a
        . "$2"
        set +a
        cd "$3"
        bundle exec rails db:migrate
    ' mastodon-migrate "$RBENV_ROOT" "$ENV_FILE" "$SITE"
fi
step="Start Mastodon services after restore"
for service in "${SERVICES[@]}"; do
    systemctl daemon-reload
    systemctl enable "$service"
    if [ "$RESTART" = 1 ]; then systemctl restart "$service"; else systemctl start "$service"; fi
done
phase=done

echo "Mastodon restored from $archive."
echo "Pre-restore database dump: $([ "$db_exists" = 1 ] && printf '%s' "$SAFETY_DUMP" || printf none)"
echo "Pre-restore media snapshot: $([ "$media_enabled" = 1 ] && printf '%s' "$MEDIA_SAFETY" || printf none)"
echo "Remove the safety copies once the restored instance is verified."
if [ "$route_skipped" = 1 ]; then
    echo "Mastodon restored without its Traefik route; restore $TRAEFIK from $base when the transaction is done." >&2
    exit 1
fi
