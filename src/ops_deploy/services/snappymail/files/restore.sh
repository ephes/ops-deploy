# snappymail_restore on the host: resolve and validate the archive in a
# staging directory next to the data directory, then (unless a dry run) stop
# nginx and PHP-FPM, keep the live data as a pre-restore copy, restore the
# payload and restart the units. The staging directory always goes; a
# pre-restore copy is never removed. The caller prepends the settings (see
# backup_restore.py).
if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$DATA"; fi
preserve() { "${PRESERVE[@]}" "$@"; }
# Running: active, activating or reloading (Ansible's systemd module counts
# active and activating; a reloading unit is stopped here too).
running() {
    case $(systemctl is-active "$1" || true) in active | activating | reloading) return 0 ;; esac
    return 1
}

stage=""
stopped=()
touched=0
cleanup() {
    local status=$? index
    if [ -n "$stage" ]; then rm -rf -- "$stage" || echo "Could not remove the staging directory $stage" >&2; fi
    if [ "$status" != 0 ] && { [ "$touched" = 1 ] || [ "${#stopped[@]}" -gt 0 ]; }; then
        # The role's rescue: units this run stopped start again only while the
        # live data is untouched; otherwise the retained copy needs a look first.
        if [ "$touched" = 0 ]; then
            for ((index = 0; index < ${#stopped[@]}; index++)); do systemctl start "${stopped[index]}" || true; done
        fi
        echo "SnappyMail restore failed. Units stopped before preservation were restarted best-effort" \
            "if live data was untouched. Otherwise inspect the retained copy before restarting services." >&2
    fi
}
trap cleanup EXIT

# -- resolve the archive ----------------------------------------------------------
if [ "$ARCHIVE" = latest ]; then
    # The role's find: non-hidden regular *.tar.gz/*.tar.zst directly in the root, newest by mtime.
    if [ -d "$ROOT" ]; then
        source=$(find "$ROOT" -mindepth 1 -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.tar.zst' \) \
            ! -name '.*' -printf '%T@ %p\n' | LC_ALL=C sort -n | tail -n 1 | cut -d' ' -f2-)
    else
        source=""
    fi
    if [ -z "$source" ]; then
        echo "No SnappyMail backups found under $ROOT" >&2
        exit 1
    fi
else
    source="$ROOT/$ARCHIVE"
fi
if [ ! -f "$source" ] || [ -L "$source" ]; then
    echo "Restore source not found at $source" >&2
    exit 1
fi
preserve --validate-layout "$DATA" --source "$source"

# -- validate in staging ----------------------------------------------------------
if [ ! -d "$PARENT" ]; then
    if [ "$DRY_RUN" = 1 ]; then
        echo "Dry run: $PARENT does not exist yet; the restore would create it." >&2
        exit 0
    fi
    ensure_dir root root 0755 "$PARENT"
fi
stage=$(mktemp -d "$PARENT/.snappymail-restore-XXXXXXXXXX")
case $source in
    *.tar.zst) tar --use-compress-program=unzstd -xf "$source" -C "$stage" ;;
    *) tar -xzf "$source" -C "$stage" ;;
esac
payload="$stage/$BASENAME"
if [ ! -d "$payload" ] || [ -L "$payload" ]; then
    echo "The archive has no $BASENAME directory at its top" >&2
    exit 1
fi
pool=$(find "$PHP_ETC" -type f -name snappymail.conf 2>/dev/null | LC_ALL=C sort | head -n 1 || true)
if [ "$RESTART" = 1 ] && [ -z "$pool" ]; then
    echo "SnappyMail PHP-FPM pool not found; refusing to stop nginx." >&2
    exit 1
fi
if [[ $pool =~ ^$PHP_ETC/([^/]+)/fpm/ ]]; then php="php${BASH_REMATCH[1]}-fpm"; else php=php-fpm; fi
keep=()
[ "$CLEAN" = 1 ] || keep=(--keep-live)
preserve "$DATA" --preflight "${keep[@]}"
if [ "$DRY_RUN" = 1 ]; then
    echo "Dry run: $source is valid for $DATA; nothing changed."
    exit 0
fi

# -- restore ----------------------------------------------------------------------
# The caller installs rsync (the role's package task) before a real restore.
command -v rsync >/dev/null || {
    echo "rsync is required for the SnappyMail restore" >&2
    exit 1
}
if [ "$RESTART" = 1 ]; then
    for unit in nginx "$php"; do
        if running "$unit"; then
            systemctl stop "$unit"
            stopped+=("$unit")
        else
            systemctl stop "$unit"
        fi
    done
fi
# Once preserve.py reports a copy (or succeeds) the live data counts as
# touched: a later failure leaves the units stopped, as in the role.
if ! report=$(preserve "$DATA" "${keep[@]}"); then
    printf '%s\n' "$report"
    if grep -q '^RESTORE_PRESERVED ' <<<"$report"; then touched=1; fi
    exit 1
fi
touched=1
report=$(grep '^RESTORE_PRESERVED ' <<<"$report" | tail -n 1)
printf '%s\n' "$report"
ensure_dir "$OWNER" "$GROUP" "$MODE" "$DATA"
rsync -a "$payload/" "$DATA/"
# The role's recursive file task: owner, group and mode on every entry.
chown_tree "$OWNER" "$GROUP" "$DATA"
find "$DATA" ! -type l ! -perm "$MODE" -exec chmod "$MODE" {} +
if [ "$RESTART" = 1 ]; then
    for unit in nginx "$php"; do
        systemctl enable "$unit"
        systemctl restart "$unit"
    done
fi
echo "SnappyMail data restored from $source into $DATA"
echo "Pre-restore copy: ${report#RESTORE_PRESERVED }. Owner prunes copies by hand."
