# vaultwarden_restore on the host (the legacy path; Echoport is the
# documented restore runner). The archive arrives base64-encoded on stdin.
# Validate the staged payload before anything is stopped, stop (fail closed),
# take a safety copy, overwrite; any failure while overwriting puts the safety
# copy back and leaves Vaultwarden stopped. The staging directory always goes;
# the safety copy is never removed. The caller prepends the settings (see
# backup_restore.py).
# The mount check comes before the cleanup trap: a rejected path is never removed.
if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$STAGING"; fi
cleanup() {
    if [ "$CLEANUP" = 1 ]; then rm -rf -- "$STAGING" || echo "Could not remove $STAGING" >&2; fi
}
trap cleanup EXIT
OVERRIDE="$OVERRIDE_DIR/override.conf"

# The safety copy keeps symlinks as links; a restore through a linked path
# would overwrite the very files the safety copy points to.
links=()
for name in attachments sends db.sqlite3 rsa_key.pem rsa_key.pub.pem; do
    if [ -L "$DATA/$name" ]; then links+=("$name"); fi
done
check_links() {
    if [ "${#links[@]}" -gt 0 ]; then
        echo "Refusing the restore: ${links[*]} under $DATA is a symlink, so the safety copy would not" \
            "protect its contents. Replace the link with the real directory or file first." >&2
        exit 1
    fi
}

rm -rf -- "$STAGING"
# Only a missing parent is created; an existing one (such as /tmp) keeps its owner and mode.
staging_parent=$(dirname "$STAGING")
[ -d "$staging_parent" ] || ensure_dir root root 0755 "$staging_parent"
# A fresh directory: mkdir fails if another account recreated it meanwhile.
mkdir -m 0700 -- "$STAGING"
if [ "$DRY_RUN" = 1 ]; then
    check_links
    echo "Dry run: $ARCHIVE_NAME (encrypted: $([ "$ENCRYPTED" = 1 ] && echo True || echo False)) selected; nothing uploaded or changed."
    exit 0
fi
echo "Restoring Vaultwarden from $ARCHIVE_NAME (encrypted: $([ "$ENCRYPTED" = 1 ] && echo True || echo False))"
(umask 077 && base64 -d >"$STAGING/backup.tar.gz")
tar -xzf "$STAGING/backup.tar.gz" -C "$STAGING"
payload=$(find "$STAGING" -mindepth 1 -maxdepth 1 -type d | LC_ALL=C sort | head -n 1)
if [ -z "$payload" ]; then
    echo "Unable to locate payload directory inside restore archive" >&2
    exit 1
fi
if [ ! -d "$payload/data" ]; then
    echo "Vaultwarden data directory missing inside archive: $payload/data" >&2
    exit 1
fi
if [ ! -f "$payload/data/db.sqlite3" ]; then
    echo "Vaultwarden database missing inside archive: $payload/data/db.sqlite3" >&2
    exit 1
fi
check=$(sqlite3 "$payload/data/db.sqlite3" "PRAGMA integrity_check;")
if [ "$check" != ok ]; then
    echo "The staged database failed its integrity check: ${check:0:200}" >&2
    exit 1
fi

ensure_dir "$USER_NAME" "$GROUP_NAME" 0750 "$DATA"
ensure_dir "$USER_NAME" "$GROUP_NAME" 0750 "$DATA/attachments"
ensure_dir "$USER_NAME" "$GROUP_NAME" 0750 "$DATA/sends"
ensure_dir "$USER_NAME" "$GROUP_NAME" 0750 "$LOG_DIR"
ensure_dir root root 0755 "$OVERRIDE_DIR"
ensure_dir root root 0755 "$(dirname "$TRAEFIK")"
check_links

route="$payload/traefik/${TRAEFIK##*/}"
if [ -e "$route" ] && ! cmp -s "$route" "$TRAEFIK" && ! "${ROUTE_GUARD[@]}"; then
    echo "A Traefik transaction holds its lock; the restore changes nothing. Retry when it is done." >&2
    exit 1
fi

# -- stop (fail closed) and take the safety copy ------------------------------------
installed=0
if [ "$(systemctl show -p LoadState --value "$SERVICE.service" 2>/dev/null || true)" != not-found ]; then installed=1; fi
abort_untouched() {
    echo "Vaultwarden restore aborted before any live file was overwritten: the service did not stop" \
        "cleanly or the safety copy at $SAFETY_DIR could not be taken. The live data is untouched." \
        "Check \`systemctl status $SERVICE\` and start it again with \`systemctl start $SERVICE\` if it is stopped." >&2
    exit 1
}
if [ "$installed" = 1 ]; then systemctl stop "$SERVICE" || abort_untouched; fi
# Also without an installed unit file: nothing may still be running.
case $(systemctl is-active "$SERVICE" || true) in inactive | failed) ;; *) abort_untouched ;; esac
take_safety_copy() {
    set -euo pipefail
    if [ -e "$SAFETY_DIR" ]; then
        echo "safety directory already exists: $SAFETY_DIR" >&2
        exit 1
    fi
    install -d -m 0700 -o root -g root "$SAFETY_ROOT"
    install -d -m 0700 -o root -g root "$SAFETY_DIR" "$SAFETY_DIR/files"
    if [ -d "$DATA" ]; then
        # Copy the contents ("/."), so a symlinked data dir is followed.
        mkdir -m 0700 "$SAFETY_DIR/data"
        cp -a "$DATA/." "$SAFETY_DIR/data/"
        echo present >"$SAFETY_DIR/data.state"
    else
        echo absent >"$SAFETY_DIR/data.state"
    fi
    local name src
    for name in config override traefik; do
        case $name in
            config) src=$CONFIG ;;
            override) src=$OVERRIDE ;;
            traefik) src=$TRAEFIK ;;
        esac
        if [ -e "$src" ] || [ -L "$src" ]; then cp -a "$src" "$SAFETY_DIR/files/$name"; fi
    done
    sync
}
# errexit only holds outside a tested context (`if`, `||`, `!`), so each
# guarded step runs as a plain subshell and its status is tested afterwards.
set +e
(take_safety_copy)
status=$?
set -e
[ "$status" = 0 ] || abort_untouched
echo "Pre-restore safety copy of Vaultwarden data and config: $SAFETY_DIR"

# -- overwrite; any failure rolls back to the safety copy ---------------------------
overwrite() {
    set -euo pipefail
    rm -f -- "$DATA/db.sqlite3-wal" "$DATA/db.sqlite3-shm" "$DATA/db.sqlite3-journal"
    copy_file "$USER_NAME" "$GROUP_NAME" 0640 "$payload/data/db.sqlite3" "$DATA/db.sqlite3"
    local sub key
    for sub in attachments sends; do
        if [ -e "$payload/data/$sub" ]; then rsync -a "$payload/data/$sub/" "$DATA/$sub/"; fi
    done
    for key in rsa_key.pem rsa_key.pub.pem; do
        if [ -e "$payload/data/$key" ]; then copy_file "$USER_NAME" "$GROUP_NAME" 0600 "$payload/data/$key" "$DATA/$key"; fi
    done
    if [ -e "$payload/config/$CONFIG_NAME" ]; then
        copy_file root "$GROUP_NAME" 0640 "$payload/config/$CONFIG_NAME" "$CONFIG"
    fi
    if [ -e "$payload/systemd/override.conf" ]; then copy_file root root 0644 "$payload/systemd/override.conf" "$OVERRIDE"; fi
    if [ -e "$route" ]; then
        if ! cmp -s "$route" "$TRAEFIK"; then "${ROUTE_GUARD[@]}"; fi
        copy_file root root 0644 "$route" "$TRAEFIK"
    fi
    systemctl daemon-reload
    chown_tree "$USER_NAME" "$GROUP_NAME" "$DATA"
    systemctl enable "$SERVICE"
    if [ "$RESTART" = 1 ]; then systemctl restart "$SERVICE"; else systemctl start "$SERVICE"; fi
}
# The role's rollback: the route goes back without the Traefik lock check.
put_back() {
    set -euo pipefail
    local state
    state=$(cat "$SAFETY_DIR/data.state")
    if [ "$state" = present ]; then
        rsync -a --delete --checksum "$SAFETY_DIR/data/" "$DATA/"
    fi
    local name dest
    for name in config override traefik; do
        case $name in
            config) dest=$CONFIG ;;
            override) dest=$OVERRIDE ;;
            traefik) dest=$TRAEFIK ;;
        esac
        rm -f -- "$dest"
        if [ -e "$SAFETY_DIR/files/$name" ] || [ -L "$SAFETY_DIR/files/$name" ]; then
            cp -a "$SAFETY_DIR/files/$name" "$dest"
        fi
    done
    systemctl daemon-reload
}
set +e
(overwrite)
status=$?
set -e
if [ "$status" != 0 ]; then
    systemctl stop "$SERVICE" || true
    case $(systemctl is-active "$SERVICE" 2>/dev/null || true) in
        inactive | failed)
            set +e
            (put_back)
            status=$?
            set -e
            if [ "$status" = 0 ]; then
                outcome="The pre-restore safety copy was put back"
            else
                outcome="Putting the safety copy back FAILED"
            fi
            ;;
        *) outcome="Vaultwarden could not be stopped, so the safety copy was NOT put back" ;;
    esac
    echo "Vaultwarden restore failed while overwriting live files. $outcome. Safety copy: $SAFETY_DIR." \
        "Vaultwarden is left stopped; check the data, then run \`systemctl start $SERVICE\`." >&2
    exit 1
fi
echo "Vaultwarden restored from $ARCHIVE_NAME. Pre-restore safety copy: $SAFETY_DIR (remove it once the restored vault is verified)."
