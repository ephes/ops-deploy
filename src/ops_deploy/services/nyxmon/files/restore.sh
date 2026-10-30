# nyxmon_restore: validate, prepare, restore (rollback on failure), verify,
# and always clean up. The caller prepends the settings (see lifecycle.py).
# The mount check comes before the cleanup trap: a rejected path is never removed.
if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$STAGING_BASE"; fi
staging="$STAGING_BASE/$STAMP"
safety=""

cleanup() {
    rm -rf "$staging"
    if [ "$SAFETY" = 1 ] && [ "$CLEANUP_SAFETY" = 1 ] && [ -n "$safety" ]; then rm -rf "$safety"; fi
}
trap cleanup EXIT

start_services() {
    # Like the role's loop: every unit is started, then a failure is reported.
    local unit failed=0
    for unit in "${START_ORDER[@]}"; do systemctl daemon-reload && systemctl start "$unit" || failed=1; done
    return "$failed"
}

# -- validate ---------------------------------------------------------------
# Owner unchanged (the role gives none): the connecting user's, root.
ensure_dir root root "$STAGING_MODE" "$STAGING_BASE"
if [ "$ARCHIVE" = latest ]; then
    archive=$(ls -1t "$SEARCH_ROOT"/*.tar.gz | head -n 1)
else
    archive="$SEARCH_ROOT/$ARCHIVE"
fi
if [ ! -e "$archive" ]; then
    echo "Backup archive $archive not found on $HOST_NAME." >&2
    exit 1
fi
ensure_dir root root "$STAGING_MODE" "$staging"
tar -xzf "$archive" -C "$staging"
content="$staging/$(basename "$archive" .tar.gz)"
metadata=$(cat "$content/metadata.yml")
for field in "${REQUIRED_FIELDS[@]}"; do
    if ! grep -q "^$field:" <<<"$metadata"; then
        echo "Metadata missing required field $field" >&2
        exit 1
    fi
done
if [ "$VALIDATE" = 1 ]; then (cd "$content" && sha256sum --quiet -c manifest.sha256); fi

# -- prepare ----------------------------------------------------------------
size=$(du -sb "$content" | awk '{print $1}')
if [ "$CHECK_DISK" = 1 ]; then
    free=$(df -B1 --output=avail "$SITE" | tail -1)
    if ! awk -v free="$free" -v size="$size" -v m="$MULTIPLIER" 'BEGIN { exit !(free + 0 > size * m) }'; then
        echo "Insufficient disk space for restore." >&2
        exit 1
    fi
fi
if [ "$DRY_RUN" = 1 ]; then
    echo "Dry run enabled, stopping before changes."
    exit 0
fi
if [ "$SAFETY" = 1 ]; then
    safety="$SITE.$SAFETY_PREFIX-$STAMP"
    if [ "$SAFETY_DELETE" = 1 ]; then rsync -a --delete "$SITE/" "$safety/"; else rsync -a "$SITE/" "$safety/"; fi
fi

# -- restore ----------------------------------------------------------------
restore() {
    for unit in "${STOP_ORDER[@]}"; do systemctl daemon-reload && systemctl stop "$unit"; done
    copy_file "$OWNER" "$GROUP" 0600 "$content/database/$(basename "$DB")" "$DB"
    if [ "$VERIFY_SQLITE" = 1 ] && command -v sqlite3 >/dev/null; then
        sqlite3 "$DB" 'PRAGMA integrity_check'
    fi
    for spec in "${DIRS[@]}"; do
        dest=${spec#*:}
        ensure_dir "$OWNER" "$GROUP" 0755 "$dest"
    done
    for spec in "${DIRS[@]}"; do
        src="$content/${spec%%:*}"
        dest=${spec#*:}
        if [ -d "$src" ]; then rsync -a --delete "$src/" "$dest/"; fi
    done
    # rsync -a also copies the archived directory's 0700 mode onto its destination.
    for spec in "${DIRS[@]}"; do
        ensure_dir "$OWNER" "$GROUP" 0755 "${spec#*:}"
    done
    for spec in "${CONFIGS[@]}"; do
        IFS=: read -r mode name dest <<<"$spec"
        if [ -e "$content/config/$name" ]; then
            copy_file "$OWNER" "$GROUP" "$mode" "$content/config/$name" "$dest"
        fi
    done
    if [ "$SYSTEM_FILES" = 1 ]; then
        for unit in "${UNITS[@]}"; do
            src="$content/systemd/$(basename "$unit")"
            if [ -e "$src" ]; then copy_file root root 0644 "$src" "$unit"; fi
        done
    fi
    if [ "$FIX_OWNERSHIP" = 1 ]; then chown_tree "$OWNER" "$GROUP" "$SITE" "$LOGS"; fi
    start_services
}
set +e
(
    set -e
    restore
)
failed=$?
set -e
if [ "$failed" != 0 ]; then
    if [ "$SAFETY" = 1 ]; then rsync -a --delete "$safety/" "$SITE/"; fi
    start_services
    echo "Nyxmon restore failed; safety snapshot reapplied." >&2
    exit 1
fi

# -- verify -----------------------------------------------------------------
systemctl enable "$PRIMARY"
for attempt in 1 2 3 4 5 6; do
    if systemctl start "$PRIMARY"; then break; fi
    [ "$attempt" = 6 ] && exit 1
    sleep 3
done
if [ -e "$MANAGE" ]; then
    (cd "$SITE" && "$SITE/.venv/bin/python" "$MANAGE" check --deploy)
    (cd "$SITE" && "$SITE/.venv/bin/python" "$MANAGE" showmigrations >/dev/null)
fi
if [ "$VERIFY_HTTP" = 1 ]; then
    attempt=0
    while :; do
        code=$(curl -sL --max-time 30 -o /dev/null -w '%{http_code}' "${HEALTH_HEADERS[@]}" "$HEALTH_URL" || true)
        [ "$code" = "$HEALTH_STATUS" ] && break
        attempt=$((attempt + 1))
        if [ "$attempt" -gt "$HEALTH_RETRIES" ]; then
            echo "$HEALTH_URL answered $code, expected $HEALTH_STATUS" >&2
            exit 1
        fi
        sleep "$HEALTH_DELAY"
    done
fi
