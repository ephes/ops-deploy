# vaultwarden_backup on the host: directories, the vault copied with the
# service stopped (and started again whatever the copy did, if this run
# stopped it), manifest, archive, optional age encryption and retention. The
# caller prepends the settings (see backup_restore.py).
if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$ROOT"; fi
for path in "$ROOT" "$DIR" "$DIR/data" "$DIR/config" "$DIR/systemd" "$DIR/traefik"; do
    ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$path"
done
restrict_archives "$ROOT" 0600
for path in "$DATA" "$CONFIG"; do
    if [ ! -e "$path" ]; then
        echo "Required Vaultwarden path missing: $path" >&2
        exit 1
    fi
done

started=1
start_service() {
    # The role's always: start only what this run stopped (or failed to stop).
    if [ "$started" = 0 ]; then
        started=1
        systemctl daemon-reload || true
        systemctl start "$SERVICE"
    fi
}
trap start_service EXIT
if [ "$STOP" = 1 ]; then
    case $(systemctl is-active "$SERVICE" || true) in inactive | failed) ;; *) started=0 ;; esac
    systemctl stop "$SERVICE"
fi
if [ "$INCLUDE_DATA_DIR" = 1 ]; then
    sqlite3 "$DATA/db.sqlite3" ".backup '$DIR/data/db.sqlite3'"
    for sub in attachments sends; do
        if [ -e "$DATA/$sub" ]; then rsync -a "$DATA/$sub/" "$DIR/data/$sub/"; fi
    done
    # The role ignores a missing key file (failed_when: false).
    for key in rsa_key.pem rsa_key.pub.pem; do
        if [ -e "$DATA/$key" ]; then copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$DATA/$key" "$DIR/data/"; fi
    done
fi
if [ "$INCLUDE_CONFIG" = 1 ]; then copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$CONFIG" "$DIR/config/${CONFIG##*/}"; fi
if [ "$INCLUDE_SYSTEMD" = 1 ] && [ -e "$OVERRIDE" ]; then
    copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$OVERRIDE" "$DIR/systemd/override.conf"
fi
if [ "$INCLUDE_TRAEFIK" = 1 ] && [ -e "$TRAEFIK" ]; then
    copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$TRAEFIK" "$DIR/traefik/${TRAEFIK##*/}"
fi
start_service
trap - EXIT

printf '%s' "$MANIFEST" >"$DIR/.manifest.yml.new"
copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$DIR/.manifest.yml.new" "$DIR/manifest.yml"
rm -f "$DIR/.manifest.yml.new"

[ "$ARCHIVE" = 1 ] || exit 0
name=${DIR##*/}
archive="$ROOT/$name.tar.gz"
(umask 077 && tar -C "$ROOT" -czf "$archive" "$name")
chmod 0600 "$archive"
rm -rf -- "$DIR"
if [ "$ENCRYPT" = 1 ]; then
    (umask 077 && age -r "$RECIPIENT" -o "$archive.age" "$archive")
    chmod 0600 "$archive.age"
    rm -f -- "$archive"
fi
if [ "$RETAIN" -gt 0 ]; then
    # The role's pruning: the newest RETAIN <prefix>-*.tar.gz and .tar.gz.age by mtime stay.
    find "$ROOT" -mindepth 1 -maxdepth 1 -type f ! -name '.*' \
        \( -name "$PREFIX-*.tar.gz" -o -name "$PREFIX-*.tar.gz.age" \) -printf '%T@ %p\n' |
        LC_ALL=C sort -rn | tail -n +"$((RETAIN + 1))" | cut -d' ' -f2- | while IFS= read -r old; do
            rm -f -- "$old"
        done
fi
echo "Vaultwarden backup stored at ${archive}$([ "$ENCRYPT" = 1 ] && printf '.age (encrypted with age)')"
