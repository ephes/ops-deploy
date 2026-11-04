# snappymail_backup on the host: optionally stop nginx and PHP-FPM, archive
# the data directory, start the units this run stopped (or failed to stop)
# again whatever the archive did, then manifest and retention. The caller
# prepends the settings (see backup_restore.py).
if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$ROOT"; fi

# The role's PHP-FPM service: from the first <PHP_ETC>/<version>/fpm/.../snappymail.conf.
php_service() {
    local pool
    pool=$(find "$PHP_ETC" -type f -name snappymail.conf 2>/dev/null | LC_ALL=C sort | head -n 1 || true)
    if [[ $pool =~ ^$PHP_ETC/([^/]+)/fpm/ ]]; then
        printf 'php%s-fpm' "${BASH_REMATCH[1]}"
    else
        printf php-fpm
    fi
}

# Running: active, activating or reloading (Ansible's systemd module counts
# active and activating; a reloading unit is stopped here too).
running() {
    case $(systemctl is-active "$1" || true) in active | activating | reloading) return 0 ;; esac
    return 1
}

restart=()
restart_units() {
    # Reverse stop order (PHP-FPM, then nginx); failures are ignored, as in the role.
    local index
    for ((index = ${#restart[@]} - 1; index >= 0; index--)); do systemctl start "${restart[index]}" || true; done
}
trap restart_units EXIT
if [ "$STOP" = 1 ]; then
    for unit in nginx "$(php_service)"; do
        # Restart what this run stopped or failed to stop; units already stopped stay stopped.
        if running "$unit"; then
            restart+=("$unit")
            systemctl stop "$unit" || echo "snappymail_backup: stopping $unit failed (ignored)" >&2
        fi
    done
fi

if [ ! -e "$DATA" ]; then
    echo "SnappyMail data directory not found at $DATA" >&2
    exit 1
fi
ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$ROOT"
restrict_archives "$ROOT" 0600
if [ "$ZSTD" = 1 ]; then compress=--zstd; else compress=-z; fi
tar -C "$PARENT" "$compress" -cf "$ARCHIVE" "$BASENAME"
set_attrs "$OWNER" "$GROUP" "$MODE" "$ARCHIVE"
restart_units
trap - EXIT

if [ -n "$MANIFEST" ]; then
    # A hidden temporary name: retention's <prefix>-*.tar.* never sees it.
    manifest_tmp="$ROOT/.${ARCHIVE##*/}.yml.new"
    printf '%s' "$MANIFEST" >"$manifest_tmp"
    copy_file "$OWNER" "$GROUP" "$MODE" "$manifest_tmp" "$ARCHIVE.yml"
    rm -f "$manifest_tmp"
fi
if [ "$RETAIN" -gt 0 ]; then
    # The role's pruning: keep the newest RETAIN <prefix>-*.tar.* (by mtime), with their manifests.
    { ls -1t "$ROOT/$PREFIX"-*.tar.* 2>/dev/null || true; } | { grep -v '\.yml$' || true; } |
        tail -n +"$((RETAIN + 1))" | while read -r old; do
            rm -f "$old" "$old.yml"
        done
fi
echo "SnappyMail backup created: $ARCHIVE"
