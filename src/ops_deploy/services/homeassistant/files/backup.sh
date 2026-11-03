# homeassistant_backup's snapshot: directories, SQLite copy, extra state and
# supporting files. The caller prepends the settings (see lifecycle.py) and
# runs this with bash. Home Assistant keeps running, as with the role.

if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$ROOT"; fi
if [ "$RECORD" = 1 ]; then require_new_snapshot "$ROOT" "${DIR##*/}"; fi
ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$ROOT"
restrict_archives "$ROOT" 0600
ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$DIR"
for sub in config data; do ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$DIR/$sub"; done
if [ "$INCLUDE_LOGS" = 1 ]; then ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$DIR/logs"; fi
for spec in "${EXTRAS[@]}"; do
    ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$DIR/${spec%%:*}"
done

# `.timeout` waits for a committing writer instead of failing with "database
# is locked"; like the role, three attempts five seconds apart.
if [ "$SQLITE_BACKUP" = 1 ] && [ -e "$DB" ]; then
    for attempt in 1 2 3; do
        if sqlite3 "$DB" ".timeout 30000" ".backup '$DIR/config/$(basename "$DB")'"; then break; fi
        if [ "$attempt" = 3 ]; then
            echo "homeassistant_backup: SQLite backup of $DB failed" >&2
            exit 1
        fi
        sleep 5
    done
fi

delete=()
[ "$DELETE" = 1 ] && delete=(--delete)
exclude=()
[ "$SQLITE_BACKUP" = 1 ] && exclude=(--exclude "$(basename "$DB")")
if [ -e "$CONFIG" ]; then rsync -a "${delete[@]}" "${exclude[@]}" "$CONFIG/" "$DIR/config/"; fi
if [ -e "$DATA" ]; then rsync -a "${delete[@]}" "$DATA/" "$DIR/data/"; fi
if [ "$INCLUDE_LOGS" = 1 ] && [ -e "$LOGS" ]; then rsync -a "${delete[@]}" "$LOGS/" "$DIR/logs/"; fi
for spec in "${EXTRAS[@]}"; do
    src=${spec#*:}
    if [ -e "$src" ]; then rsync -a "${delete[@]}" "$src/" "$DIR/${spec%%:*}/"; fi
done

for spec in "${COPIES[@]}"; do
    src=${spec%%:*}
    if [ -e "$src" ]; then copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$src" "$DIR/${spec#*:}"; fi
done
