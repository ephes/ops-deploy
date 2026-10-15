# nyxmon_backup's stop/copy/start block. The caller prepends the settings
# (see lifecycle.py) and runs this with bash.
start_services() {
    [ "$STOP" = 1 ] || return 0
    # Like the role's loop: every unit is started, then a failure is reported.
    local unit failed=0
    for unit in "${START_ORDER[@]}"; do systemctl daemon-reload && systemctl start "$unit" || failed=1; done
    return "$failed"
}

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
    sqlite3 "$DB" ".backup '$db_copy'"
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
