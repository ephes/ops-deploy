# nyxmon_backup's stop/copy/start block. The caller prepends the settings
# (see lifecycle.py) and runs this with bash.
start_services() {
    [ "$STOP" = 1 ] || return 0
    # Like the role's loop: every unit is started, then a failure is reported.
    local unit failed=0
    for unit in "${START_ORDER[@]}"; do systemctl daemon-reload && systemctl start "$unit" || failed=1; done
    return "$failed"
}

# sqlite_backup DB COPY: ops-library's SQLite runner semantics (2.53.0).
# `.timeout` waits for a committing writer instead of failing with "database
# is locked"; a failed attempt is retried; the copy counts only when
# `PRAGMA integrity_check` prints exactly `ok`, and a failed copy is removed.
sqlite_backup() {
    local attempt check
    for ((attempt = 1; attempt <= SQLITE_ATTEMPTS; attempt++)); do
        rm -f "$2"
        check=""
        if sqlite3 "$1" ".timeout $SQLITE_TIMEOUT_MS" ".backup '$2'" && [ -f "$2" ] &&
            check=$(sqlite3 "$2" 'PRAGMA integrity_check;') && [ "$check" = ok ]; then
            return 0
        fi
        echo "nyxmon_backup: SQLite backup attempt $attempt/$SQLITE_ATTEMPTS failed${check:+ (integrity check: ${check:0:200})}" >&2
        [ "$attempt" -ge "$SQLITE_ATTEMPTS" ] || sleep "$SQLITE_RETRY_DELAY"
    done
    rm -f "$2"
    echo "nyxmon_backup: SQLite backup of $1 failed" >&2
    return 1
}

if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$ROOT"; fi
if [ "$RECORD" = 1 ]; then require_new_snapshot "$ROOT" "${DIR##*/}"; fi
ensure_dir root root 0700 "$ROOT"
ensure_dir root root 0700 "$DIR"
for sub in database media static cache logs config systemd traefik; do ensure_dir root root 0700 "$DIR/$sub"; done

# The role's block/always: the services start again whatever failed.
trap start_services EXIT
if [ "$STOP" = 1 ]; then
    for unit in "${STOP_ORDER[@]}"; do systemctl daemon-reload && systemctl stop "$unit"; done
fi

db_copy="$DIR/database/$(basename "$DB")"
if [ "$SQLITE_BACKUP" = 1 ]; then
    sqlite_backup "$DB" "$db_copy"
else
    copy_file root root 0600 "$DB" "$db_copy"
fi

delete=()
[ "$DELETE" = 1 ] && delete=(--delete)
for spec in "${DIRS[@]}"; do
    IFS=: read -r include src dest <<<"$spec"
    if [ "$include" = 1 ] && [ -e "$src" ]; then rsync -a "${delete[@]}" "$src/" "$DIR/$dest/"; fi
done

for spec in "${COPIES[@]}"; do
    IFS=: read -r mode src dest <<<"$spec"
    if [ -e "$src" ]; then copy_file root root "$mode" "$src" "$DIR/$dest"; fi
done
