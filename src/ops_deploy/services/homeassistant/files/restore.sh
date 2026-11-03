# homeassistant_restore: validate, prepare, restore, verify (rollback on
# failure) and always clean up. The caller prepends the settings (see
# lifecycle.py) and runs this with bash.
# The mount check comes before the cleanup trap: a rejected path is never removed.
if [ -n "$REQUIRED_MOUNT" ]; then require_mount "$REQUIRED_MOUNT" "$STAGING_BASE"; fi
staging=""
safety=""
# The state outside the site a restore overwrites: included Thread/Matter
# directories and, with SYSTEM_FILES, the unit and the route.
safety_extra=""
successful=0
rolled_back=0

cleanup() {
    local rc=$?
    if [ -n "$staging" ]; then rm -rf -- "$staging"; fi
    if [ -n "$safety" ]; then
        if { [ "$successful" = 1 ] && [ "$rolled_back" = 0 ] && [ "$CLEANUP_SAFETY" = 1 ]; } ||
            { [ "$rolled_back" = 1 ] && [ "$CLEANUP_AFTER_ROLLBACK" = 1 ]; }; then
            rm -rf -- "$safety" "$safety_extra"
        else
            echo "Safety snapshot kept at $safety (and $safety_extra)"
        fi
    fi
    if [ "$DRY_RUN" = 1 ]; then
        echo "Home Assistant restore validation (dry-run only) of ${archive:-unknown} finished (exit $rc)."
    else
        echo "Home Assistant restore of ${archive:-unknown}: $([ "$successful" = 1 ] && echo completed || echo failed);" \
            "rollback executed: $([ "$rolled_back" = 1 ] && echo true || echo false)."
    fi
}
trap cleanup EXIT

# known UNIT: systemd knows UNIT (a unit file or a loaded unit), like
# Ansible's service_facts listing it.
known() {
    local load
    load=$(systemctl show -p LoadState --value "$1" 2>/dev/null) || return 1
    [ -n "$load" ] && [ "$load" != not-found ]
}

# wait_active UNIT: poll `systemctl is-active` like the role's until loop.
wait_active() {
    local attempt
    for ((attempt = 0; attempt <= START_RETRIES; attempt++)); do
        [ "$(systemctl is-active "$1" 2>/dev/null || true)" = active ] && return 0
        [ "$attempt" -lt "$START_RETRIES" ] && sleep "$START_POLL"
    done
    echo "$1 did not become active" >&2
    return 1
}

# -- validate ---------------------------------------------------------------
if [ "$ARCHIVE" = latest ]; then
    archive=$(find "$SEARCH_ROOT" -mindepth 1 -maxdepth 1 -type f -name '*.tar.gz' -printf '%T@ %p\n' 2>/dev/null |
        sort -rn | head -n 1 | cut -d' ' -f2-)
    if [ -z "$archive" ]; then
        echo "No backup archives were found under $SEARCH_ROOT. Provide an archive explicitly or copy one to the host." >&2
        exit 1
    fi
else
    archive="$SEARCH_ROOT/$ARCHIVE"
fi
if [ ! -f "$archive" ]; then
    echo "Backup archive $archive does not exist on the target host (an archive from $LOCAL_CACHE is not uploaded by this run)." >&2
    exit 1
fi
# Never follow a planted link: the base must be a real directory (or absent),
# and the extraction directory is new.
if [ -L "$STAGING_BASE" ] || { [ -e "$STAGING_BASE" ] && [ ! -d "$STAGING_BASE" ]; }; then
    echo "Staging directory $STAGING_BASE is not a plain directory; refusing to use it" >&2
    exit 1
fi
ensure_dir root root "$STAGING_MODE" "$STAGING_BASE"
mkdir -m 0700 -- "$STAGING_BASE/$(basename "$archive")-$STAMP"
staging="$STAGING_BASE/$(basename "$archive")-$STAMP"
tar -xzf "$archive" -C "$staging"
mapfile -t candidates < <(find "$staging" -mindepth 1 -maxdepth 1 -type d)
if [ "${#candidates[@]}" != 1 ]; then
    echo "Unable to determine snapshot directory inside $staging. Expected exactly one directory from the archive contents." >&2
    exit 1
fi
snapshot=${candidates[0]}
if [ ! -f "$snapshot/metadata.yml" ]; then
    echo "metadata.yml is missing from snapshot $snapshot" >&2
    exit 1
fi
# Line-based, so archives whose metadata.yml the role wrote unparsable
# (its extra_paths list) restore as well.
for field in "${REQUIRED_FIELDS[@]}"; do
    if ! grep -q "^$field:" "$snapshot/metadata.yml"; then
        echo "Metadata field '$field' is missing from metadata.yml" >&2
        exit 1
    fi
done
if [ "$ENFORCE_HOST" = 1 ]; then
    backup_host=$(sed -n 's/^host:[[:space:]]*//p' "$snapshot/metadata.yml" | head -n 1)
    backup_host=${backup_host%\"}
    backup_host=${backup_host#\"}
    if [ "$backup_host" != "$HOST_NAME" ]; then
        echo "Backup archive $(basename "$archive") was taken from host ${backup_host:-unknown}, which does not match current inventory host $HOST_NAME." >&2
        exit 1
    fi
fi
if [ "$VALIDATE" = 1 ]; then
    if [ ! -f "$snapshot/manifest.sha256" ]; then
        echo "manifest.sha256 is missing from $snapshot" >&2
        exit 1
    fi
    (cd "$snapshot" && grep -vE '  \./manifest\.sha256$' manifest.sha256 | sha256sum --quiet -c -)
fi

# -- prepare ----------------------------------------------------------------
if [ "$CHECK_DISK" = 1 ]; then
    python3 - "$archive" "$SITE" "$MULTIPLIER" <<'PY'
import os
import sys
import tarfile

archive, target, multiplier = sys.argv[1], sys.argv[2], float(sys.argv[3])
with tarfile.open(archive, "r:*") as tar:
    total = sum(member.size for member in tar.getmembers())
candidate = target
while not os.path.exists(candidate):
    parent = os.path.dirname(candidate)
    if not parent or parent == candidate:
        candidate = "/"
        break
    candidate = parent
stat = os.statvfs(candidate)
free, required = stat.f_bavail * stat.f_frsize, int(total * multiplier)
if free < required:
    raise SystemExit(f"INSUFFICIENT_DISK:{required}:{free}")
print(f"OK:{required}:{free}")
PY
fi
if [ "$DRY_RUN" = 1 ]; then
    echo "Dry run enabled - skipping account, safety snapshot, service stop and file sync."
    exit 0
fi
# The role's account step, for a host without the account. An existing account
# keeps the shell and home the deploy gave it.
if ! getent group "$GROUP" >/dev/null; then groupadd --system "$GROUP"; fi
if ! getent passwd "$OWNER" >/dev/null; then
    useradd --system --gid "$GROUP" --home-dir "$(dirname "$SITE")" --create-home --shell /usr/sbin/nologin "$OWNER"
fi
if [ "$SAFETY" = 1 ]; then
    safety="$SITE.$SAFETY_PREFIX-$STAMP"
    safety_extra="$safety.extra"
    for path in "$safety" "$safety_extra"; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            echo "$path already exists; refusing to overwrite a safety snapshot" >&2
            safety=""
            safety_extra=""
            exit 1
        fi
    done
    ensure_dir root root 0700 "$safety_extra"
    mkdir -p "$safety_extra/dirs" "$safety_extra/absent" "$safety_extra/system"
    for spec in "${EXTRAS[@]}"; do
        IFS=: read -r name dest _ <<<"$spec"
        if [ -e "$dest" ]; then rsync -a "$dest/" "$safety_extra/dirs/$name/"; else : >"$safety_extra/absent/$name"; fi
    done
    if [ "$SYSTEM_FILES" = 1 ]; then
        for path in "$UNIT_PATH" "$TRAEFIK_PATH"; do
            if [ -e "$path" ]; then cp -p -- "$path" "$safety_extra/system/$(basename "$path")"; fi
        done
    fi
    if [ -e "$SITE" ]; then
        ensure_dir "$OWNER" "$GROUP" 0750 "$safety"
        delete=()
        [ "$SAFETY_DELETE" = 1 ] && delete=(--delete)
        rsync -a "${delete[@]}" "$SITE/" "$safety/"
        echo "Created safety snapshot at $safety"
    else
        echo "Skipping the site's safety snapshot; $SITE does not exist."
    fi
fi

# -- restore ----------------------------------------------------------------
service_available=0
[ -e "$UNIT_PATH" ] && service_available=1
otbr_available=0
if [ "$MANAGE_OTBR" = 1 ] && known "$OTBR_SERVICE.service"; then otbr_available=1; fi
matter_available=0
if [ "$MANAGE_MATTER" = 1 ] && known "$MATTER_SERVICE.service"; then matter_available=1; fi

rollback() {
    if [ "$ROLLBACK" != 1 ]; then return 0; fi
    if [ -z "$safety_extra" ] || [ ! -d "$safety_extra" ]; then
        echo "Rollback requested but no safety snapshot is available; skipping automatic rollback." >&2
        return 0
    fi
    # Stop what may run on restored state; an absent unit must not stop the recovery.
    systemctl stop "$SERVICE" 2>/dev/null || true
    if [ "$matter_available" = 1 ]; then systemctl stop "$MATTER_SERVICE" || true; fi
    if [ "$otbr_available" = 1 ]; then systemctl stop "$OTBR_SERVICE" || true; fi
    if [ -d "$safety" ]; then
        ensure_dir "$OWNER" "$GROUP" 0750 "$SITE"
        rsync -a --delete "$safety/" "$SITE/"
        if [ "$FIX_OWNERSHIP" = 1 ]; then chown_tree "$OWNER" "$GROUP" "$SITE"; fi
    fi
    local spec name dest
    for spec in "${EXTRAS[@]}"; do
        IFS=: read -r name dest _ <<<"$spec"
        if [ -d "$safety_extra/dirs/$name" ]; then
            rsync -a --delete "$safety_extra/dirs/$name/" "$dest/"
        elif [ -e "$safety_extra/absent/$name" ]; then
            rm -rf -- "$dest"
        fi
    done
    if [ "$SYSTEM_FILES" = 1 ]; then
        local path saved reload=0
        for path in "$UNIT_PATH" "$TRAEFIK_PATH"; do
            saved="$safety_extra/system/$(basename "$path")"
            if [ -e "$saved" ]; then
                cmp -s "$saved" "$path" && continue
                if [ "$path" = "$TRAEFIK_PATH" ] && ! "${ROUTE_GUARD[@]}"; then
                    echo "$path not rolled back: a Traefik transaction is active" >&2
                    continue
                fi
                cp -p -- "$saved" "$path"
            elif [ -e "$path" ]; then
                if [ "$path" = "$TRAEFIK_PATH" ] && ! "${ROUTE_GUARD[@]}"; then
                    echo "$path not rolled back: a Traefik transaction is active" >&2
                    continue
                fi
                rm -f -- "$path"
            else
                continue
            fi
            [ "$path" = "$UNIT_PATH" ] && reload=1
        done
        if [ "$reload" = 1 ]; then systemctl daemon-reload; fi
    fi
    if [ "$otbr_available" = 1 ]; then systemctl start "$OTBR_SERVICE" || true; fi
    if [ "$matter_available" = 1 ]; then systemctl start "$MATTER_SERVICE" || true; fi
    if [ -e "$UNIT_PATH" ]; then systemctl start "$SERVICE"; fi
    rolled_back=1
    echo "Rollback completed using snapshot $safety"
}

restore_files() {
    if [ "$service_available" = 1 ]; then systemctl stop "$SERVICE"; fi
    if [ "$matter_available" = 1 ]; then systemctl stop "$MATTER_SERVICE"; fi
    if [ "$otbr_available" = 1 ]; then systemctl stop "$OTBR_SERVICE"; fi
    local spec name dest optional owner group mode
    for spec in "${DIRS[@]}"; do
        IFS=: read -r name dest optional <<<"$spec"
        ensure_dir "$OWNER" "$GROUP" 0750 "$dest"
    done
    for spec in "${EXTRAS[@]}"; do
        IFS=: read -r name dest owner group mode <<<"$spec"
        ensure_dir "$owner" "$group" "$mode" "$dest"
    done
    for spec in "${DIRS[@]}"; do
        IFS=: read -r name dest optional <<<"$spec"
        if [ ! -e "$snapshot/$name" ] && [ "$optional" != 1 ]; then
            echo "Required directory '$name' is missing from the backup snapshot" >&2
            return 1
        fi
    done
    for spec in "${DIRS[@]}"; do
        IFS=: read -r name dest optional <<<"$spec"
        if [ -e "$snapshot/$name" ]; then rsync -a --delete "$snapshot/$name/" "$dest/"; fi
    done
    for spec in "${EXTRAS[@]}"; do
        IFS=: read -r name dest owner group mode <<<"$spec"
        if [ -e "$snapshot/$name" ]; then rsync -a --delete "$snapshot/$name/" "$dest/"; fi
    done
    if [ "$SYSTEM_FILES" = 1 ]; then
        local reload=0
        if [ -e "$snapshot/homeassistant.service" ]; then
            cmp -s "$snapshot/homeassistant.service" "$UNIT_PATH" || reload=1
            copy_file root root 0644 "$snapshot/homeassistant.service" "$UNIT_PATH"
        fi
        if [ -e "$snapshot/homeassistant.traefik.yml" ] && ! cmp -s "$snapshot/homeassistant.traefik.yml" "$TRAEFIK_PATH"; then
            # Route writers wait for no Traefik transaction.
            "${ROUTE_GUARD[@]}"
            copy_file root root 0644 "$snapshot/homeassistant.traefik.yml" "$TRAEFIK_PATH"
        fi
        if [ "$reload" = 1 ]; then systemctl daemon-reload; fi
    fi
    [ -e "$UNIT_PATH" ] && service_available=1 || service_available=0
    if [ "$FIX_OWNERSHIP" = 1 ]; then chown_tree "$OWNER" "$GROUP" "$SITE"; fi
}

verify() {
    if [ "$otbr_available" = 1 ]; then
        systemctl start "$OTBR_SERVICE"
        wait_active "$OTBR_SERVICE"
    fi
    if [ "$matter_available" = 1 ]; then
        systemctl daemon-reload
        systemctl start "$MATTER_SERVICE"
        wait_active "$MATTER_SERVICE"
    fi
    if [ "$service_available" != 1 ]; then
        echo "Home Assistant systemd unit not found; skipping service start and health verification."
        return 0
    fi
    systemctl daemon-reload
    systemctl start "$SERVICE"
    wait_active "$SERVICE"
    if [ "$VERIFY_HTTP" = 1 ]; then
        local headers=("${HEALTH_HEADERS[@]}") forwarded=$FORWARDED_FOR attempt code
        if [ "$forwarded" = "@default-ipv4" ]; then
            # Ansible's ansible_default_ipv4.address | default('192.168.0.1').
            forwarded=$(ip -4 route get 8.8.8.8 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1)
            forwarded=${forwarded:-192.168.0.1}
        fi
        [ -n "$forwarded" ] && headers+=(-H "X-Forwarded-For: $forwarded")
        [ -n "$FORWARDED_PROTO" ] && headers+=(-H "X-Forwarded-Proto: $FORWARDED_PROTO")
        for ((attempt = 0; attempt <= HEALTH_RETRIES; attempt++)); do
            code=$(curl -sL --max-time 10 -o /dev/null -w '%{http_code}' "${headers[@]}" "$HEALTH_URL" || true)
            [ "$code" = "$HEALTH_STATUS" ] && break
            if [ "$attempt" -ge "$HEALTH_RETRIES" ]; then
                echo "$HEALTH_URL answered $code, expected $HEALTH_STATUS" >&2
                return 1
            fi
            sleep "$HEALTH_DELAY"
        done
    fi
    successful=1
}

set +e
(
    set -e
    restore_files
    verify
    # Hand the outcome to the parent shell.
    echo "$successful" >"$staging/.successful"
)
failed=$?
set -e
if [ "$failed" = 0 ]; then
    successful=$(cat "$staging/.successful")
else
    # The role rolls back after a failed verification; a failure while the
    # files were copied rolls back the same way.
    rollback
    echo "Home Assistant restore failed; see previous errors." >&2
    exit 1
fi
