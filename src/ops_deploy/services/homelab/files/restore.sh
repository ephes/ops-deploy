# homelab_restore on the host: locate, extract and validate the archive, then
# (unless a dry run) stop homelab, keep a pre-restore copy of the site, copy
# the payload back, verify and start homelab. The staging directory always
# goes; the pre-restore copy stays unless SAFETY_DELETE and the restore
# succeeded. The caller prepends the settings (see backup_restore.py).
# The mount check comes before the cleanup trap: a rejected path is never removed.
if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$STAGING"; fi
safety=""
success=0

cleanup() {
    if [ "$CLEANUP" = 1 ]; then rm -rf "$STAGING"; fi
    if [ "$SAFETY" = 1 ] && [ "$SAFETY_DELETE" = 1 ] && [ -n "$safety" ] && [ "$success" = 1 ]; then rm -rf "$safety"; fi
    if [ -n "$safety" ] && [ -e "$safety" ]; then
        echo "Pre-restore copy of $SITE (database and .env included) kept at $safety." \
            "The restore does not remove it; prune it by hand once the restored Homelab is confirmed." >&2
    fi
}
trap cleanup EXIT

# meta_value KEY: a scalar of the role's one-line `key: "value"` metadata.
meta_value() {
    local value
    value=$(sed -n "s/^$1:[[:space:]]*//p" "$payload/metadata.yml" | head -n 1)
    value=${value%\"}
    printf '%s' "${value#\"}"
}

in_site() {
    (cd "$SITE" && runuser -u "$USER_NAME" -- env DJANGO_SETTINGS_MODULE="$SETTINGS" \
        bash -c 'set -a; . "$1"; set +a; shift; exec "$@"' homelab "$ENV_FILE" "$VENV_BIN/python" manage.py "$@")
}

# -- locate and validate --------------------------------------------------------
rm -rf "$STAGING"
ensure_dir root root "$STAGING_MODE" "$STAGING"
if [ "$ARCHIVE" = latest ]; then
    # The role's find: non-hidden regular *.tar.gz directly in the root, newest by mtime.
    if [ ! -d "$SEARCH_ROOT" ]; then
        echo "No homelab backup archives found under $SEARCH_ROOT" >&2
        exit 1
    fi
    archive=$(find "$SEARCH_ROOT" -mindepth 1 -maxdepth 1 -type f -name '*.tar.gz' ! -name '.*' -printf '%T@ %p\n' |
        sort -n | tail -n 1 | cut -d' ' -f2-)
    if [ -z "$archive" ]; then
        echo "No homelab backup archives found under $SEARCH_ROOT" >&2
        exit 1
    fi
else
    archive="$SEARCH_ROOT/$ARCHIVE"
fi
if [ ! -f "$archive" ] || [ -L "$archive" ]; then
    echo "Restore archive $archive does not exist" >&2
    exit 1
fi
base=$(basename "$archive")
tar -xzf "$archive" -C "$STAGING"
payload="$STAGING/${base%.tar.gz}"
if [ ! -d "$payload" ]; then
    payload=$(find "$STAGING" -mindepth 1 -maxdepth 1 -type d | LC_ALL=C sort | head -n 1)
fi
if [ -z "$payload" ] || [ ! -d "$payload" ] || [ -L "$payload" ]; then
    echo "Archive $base did not contain the expected payload directory" >&2
    exit 1
fi
has() { [ -e "$payload/$1" ]; }
if ! has metadata.yml; then
    echo "Archive $base has no metadata.yml" >&2
    exit 1
fi
slug=$(meta_value slug)
if [ "$slug" != "$SLUG" ]; then
    echo "Archive slug ($slug) does not match expected homelab slug ($SLUG)" >&2
    exit 1
fi
for field in "${REQUIRED_FIELDS[@]}"; do
    if ! grep -q "^$field:" "$payload/metadata.yml"; then
        echo "metadata.yml missing required field '$field'" >&2
        exit 1
    fi
done
archived=$(meta_value ops_library_version)
archived=${archived:-unknown}
if [ "$archived" != "$LIBRARY_VERSION" ]; then
    if [ "$ALLOW_MISMATCH" != 1 ]; then
        echo "Archive was produced with ops-library $archived, but current control host is running" \
            "$LIBRARY_VERSION. Override with homelab_restore_allow_version_mismatch=true to continue." >&2
        exit 1
    fi
    echo "Version mismatch detected (archive=$archived, current=$LIBRARY_VERSION) - continuing" \
        "due to homelab_restore_allow_version_mismatch=true." >&2
fi
if [ "$VALIDATE" = 1 ] && has manifest.sha256; then (cd "$payload" && sha256sum --quiet -c manifest.sha256); fi

database="database/$(basename "$DB")"
yes_no() { if has "$1"; then printf True; else printf False; fi; }
env_planned=False
if has env/.env && [ "$RESTORE_ENV" = 1 ]; then env_planned=True; fi
echo "Archive: $base"
echo "Components -> database=$(yes_no "$database"), static=$(yes_no static), media=$(yes_no media), env=$env_planned"
echo "Dry-run: $([ "$DRY_RUN" = 1 ] && printf True || printf False)"
if [ "$DRY_RUN" = 1 ]; then
    exit 0
fi

# -- restore --------------------------------------------------------------------
if has "$database" && ! command -v sqlite3 >/dev/null; then
    echo "sqlite3 is required on the target to verify the restored database" >&2
    exit 1
fi
# A changed route is written only while no Traefik transaction holds its lock;
# check that before anything changes, so a held lock never stops homelab.
traefik_changed=0
if has configs/traefik.yml && ! cmp -s "$payload/configs/traefik.yml" "$TRAEFIK"; then
    traefik_changed=1
    if ! "${ROUTE_GUARD[@]}"; then
        echo "A Traefik transaction holds its lock; the restore changes nothing. Retry when it is done." >&2
        exit 1
    fi
fi
# Stop first (and fail if that fails): neither the safety snapshot nor the
# database replacement may run against a live SQLite database.
systemctl stop "$SERVICE"
safety="$SITE.$SAFETY_PREFIX-$STAMP"
if [ "$SAFETY" = 1 ]; then
    ensure_dir "$USER_NAME" "$GROUP_NAME" "$MEDIA_MODE" "$safety"
    rsync -a "$SITE/" "$safety/"
fi

dirs=("$STATIC:0755" "$MEDIA:$MEDIA_MODE" "$CACHE:0755")
for spec in "${dirs[@]}"; do ensure_dir "$USER_NAME" "$GROUP_NAME" "${spec##*:}" "${spec%:*}"; done
delete=()
[ "$RSYNC_DELETE" = 1 ] && delete=(--delete)
if [ "$REBUILD_STATIC" != 1 ] && has static; then rsync -a "${delete[@]}" "$payload/static/" "$STATIC/"; fi
if has media; then rsync -a "${delete[@]}" "$payload/media/" "$MEDIA/"; fi
if has cache; then rsync -a "${delete[@]}" "$payload/cache/" "$CACHE/"; fi
# rsync -a copies the backup's 0700 directory mode onto the destinations.
for spec in "${dirs[@]}"; do ensure_dir "$USER_NAME" "$GROUP_NAME" "${spec##*:}" "${spec%:*}"; done

if has "$database"; then
    rm -f "$DB-wal" "$DB-shm" "$DB-journal"
    copy_file "$USER_NAME" "$GROUP_NAME" 0644 "$payload/$database" "$DB"
fi
if [ "$RESTORE_ENV" = 1 ] && has env/.env; then
    copy_file "$USER_NAME" "$GROUP_NAME" "$ENV_MODE" "$payload/env/.env" "$ENV_FILE"
fi
env_present=0
if [ -e "$ENV_FILE" ]; then
    env_present=1
else
    echo "homelab restore: $ENV_FILE not found, skipping Django management commands." \
        "Set homelab_restore_restore_env=true or ensure the file exists before running verification." >&2
fi
unit_changed=0
if has configs/homelab.service; then
    cmp -s "$payload/configs/homelab.service" "$UNIT" || unit_changed=1
    copy_file root root 0644 "$payload/configs/homelab.service" "$UNIT"
fi
if has configs/traefik.yml; then
    if [ "$traefik_changed" = 1 ]; then "${ROUTE_GUARD[@]}"; fi
    copy_file root root 0644 "$payload/configs/traefik.yml" "$TRAEFIK"
fi
if [ "$REBUILD_STATIC" = 1 ] && [ "$env_present" = 1 ]; then in_site collectstatic --noinput; fi
if [ "$FIX_PERMISSIONS" = 1 ]; then chown_tree "$USER_NAME" "$GROUP_NAME" "$STATIC" "$MEDIA" "$CACHE"; fi
if [ "$RELOAD_SYSTEMD" = 1 ] && [ "$unit_changed" = 1 ]; then systemctl daemon-reload; fi
if [ "$RELOAD_TRAEFIK" = 1 ] && [ "$traefik_changed" = 1 ]; then systemctl reload "$TRAEFIK_SERVICE" || true; fi
if [ "$env_present" = 1 ]; then
    in_site check --deploy
    in_site showmigrations
fi
if has "$database"; then
    check=$(sqlite3 "$DB" "PRAGMA integrity_check")
    if [ "$(printf '%s' "$check" | tr -d '[:space:]')" != ok ]; then
        echo "SQLite integrity check of $DB failed: ${check:0:200}" >&2
        exit 1
    fi
fi
systemctl restart "$SERVICE"

if [ "$VERIFY_HTTP" = 1 ]; then
    body="$STAGING/health-body"
    attempt=0
    while :; do
        code=$(curl -skL --max-time 30 -o "$body" -w '%{http_code}' "$HEALTH_URL" || true)
        if [ "$code" = 200 ] && { [ -z "$EXPECTED" ] || grep -qF -- "$EXPECTED" "$body"; }; then break; fi
        attempt=$((attempt + 1))
        if [ "$attempt" -gt "$HEALTH_RETRIES" ]; then
            echo "$HEALTH_URL answered $code (expected 200${EXPECTED:+ containing the expected content})" >&2
            exit 1
        fi
        sleep "$HEALTH_DELAY"
    done
fi
success=1
