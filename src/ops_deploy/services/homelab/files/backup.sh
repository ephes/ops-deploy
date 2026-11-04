# homelab_backup on the host: directories, SQLite copy (hot, or offline with
# the service stopped and always started again), files, metadata, manifest
# and archive. The caller prepends the settings (see backup_restore.py).
if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$ROOT"; fi
if [ "$RECORD" = 1 ]; then require_new_snapshot "$ROOT" "${DIR##*/}"; fi
ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$ROOT"
restrict_archives "$ROOT" 0600
ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$DIR"
for sub in database static media cache configs env; do ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$DIR/$sub"; done

target="$DIR/database/$(basename "$DB")"
mode=missing
if [ -e "$DB" ]; then
    mode=hot
    if [ "$FORCE_STOP" = 1 ]; then
        mode=offline
    else
        # The role's retried `sqlite3 .backup`; when every attempt fails, the offline copy.
        hot=0
        for ((attempt = 1; attempt <= SQLITE_ATTEMPTS; attempt++)); do
            if sqlite3 "$DB" ".timeout 30000" ".backup '$target'"; then
                hot=1
                break
            fi
            [ "$attempt" -ge "$SQLITE_ATTEMPTS" ] || sleep 2
        done
        if [ "$hot" = 0 ]; then
            echo "homelab_backup: SQLite hot backup failed; falling back to an offline copy" >&2
            mode=offline
        fi
    fi
    if [ "$mode" = offline ]; then
        # The role's block/always: homelab is started again whatever the copy did.
        trap 'systemctl start "$SERVICE" || true' EXIT
        systemctl stop "$SERVICE"
        cp "$DB" "$target"
        systemctl start "$SERVICE" || true
        trap - EXIT
    fi
fi

delete=()
[ "$DELETE" = 1 ] && delete=(--delete)
for spec in "${DIRS[@]}"; do
    IFS=: read -r include src dest <<<"$spec"
    if [ "$include" = 1 ] && [ -e "$src" ]; then rsync -a "${delete[@]}" "$src/" "$DIR/$dest/"; fi
done
for spec in "${COPIES[@]}"; do
    IFS=: read -r include src dest <<<"$spec"
    if [ "$include" = 1 ] && [ -e "$src" ]; then copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$src" "$DIR/$dest"; fi
done

metadata="$DIR/metadata.yml"
printf '%s' "${METADATA/@SQLITE_MODE@/$mode}" >"$metadata.new"
copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$metadata.new" "$metadata"
rm -f "$metadata.new"

if [ "$MANIFEST" = 1 ]; then
    (cd "$DIR" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum >manifest.sha256)
fi
if [ "$ARCHIVE" = 1 ]; then
    name=${DIR##*/}
    (cd "$ROOT" && tar -C "$ROOT" -czf "$name.tar.gz" "$name")
    chmod 0600 "$ROOT/$name.tar.gz"
fi
