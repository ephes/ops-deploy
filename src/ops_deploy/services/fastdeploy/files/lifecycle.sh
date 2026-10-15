# fastdeploy_backup and fastdeploy_restore as bash functions. The caller
# prepends the settings (B_* for a backup, R_* for a restore; see
# lifecycle.py), reads the database password from stdin into PGPW and calls
# fd_backup or fd_restore. PGPW never reaches a command line.
cd /

fail() {
    echo "$*" >&2
    exit 1
}

as_postgres() {
    # runuser keeps the environment apart from HOME, SHELL, USER and LOGNAME.
    runuser -u "$PG_ADMIN" -- "$@"
}

# Non-hidden entries of one type directly below a directory (Ansible's find).
count_dirs() {
    if [ -d "$1" ]; then find "$1" -mindepth 1 -maxdepth 1 -type d ! -name '.*' | wc -l; else echo 0; fi
}

# ---------------------------------------------------------------- backup --

fd_backup() {
    local required=("$B_SITE" "$B_ENV" "$B_SERVICES")
    [ "$B_REQUIRE_RUNNERS" = 1 ] && required+=("$B_RUNNERS")
    [ "$B_INCLUDE_WORKSPACE" = 1 ] && required+=("$B_WORKSPACE")
    local path
    for path in "${required[@]}"; do
        [ -e "$path" ] || fail "fastdeploy_backup: required path not found: $path"
    done
    if [ ! -e "$B_RUNNERS" ] && [ "$B_REQUIRE_RUNNERS" != 1 ]; then
        echo "Deploy runner root $B_RUNNERS is missing. Continuing backup but runner scripts will not be included."
    fi
    local usage=("$B_SERVICES")
    [ -e "$B_RUNNERS" ] && usage+=("$B_RUNNERS")
    [ "$B_INCLUDE_WORKSPACE" = 1 ] && [ -e "$B_WORKSPACE" ] && usage+=("$B_WORKSPACE")

    ensure_dir root "$PG_ADMIN" 0750 "$B_ROOT"
    ensure_dir root "$PG_ADMIN" 0750 "$B_DIR"
    local sub
    for sub in database services config deploy_runners deploy_workspace systemd traefik sudoers logs; do
        if [ "$sub" = database ]; then
            ensure_dir "$PG_ADMIN" "$PG_ADMIN" 0750 "$B_DIR/$sub"
        else
            ensure_dir root "$PG_ADMIN" 0750 "$B_DIR/$sub"
        fi
    done

    if [ "$B_DISK_CHECK" = 1 ]; then
        local available required_bytes
        available=$(df -B1 --output=avail "$B_ROOT" | tail -1 | tr -d ' ')
        required_bytes=$(du -sb "${usage[@]}" | awk -v r="$B_OVERHEAD" '{ s += $1 } END { x = s * r; c = int(x); if (x > c) c++; print c }')
        if [ "$available" -lt "$required_bytes" ]; then
            fail "Insufficient disk space under $B_ROOT (available=$available bytes, required~=$required_bytes bytes including overhead)."
        fi
    fi

    local version
    version=$(runuser -u "$B_USER" -- "$B_PYTHON" - 2>/dev/null <<'PY' || true
import importlib.metadata as im
try:
    print(im.version("fastDeploy"))
except Exception:
    print("unknown")
PY
)
    local services runners
    services=$(count_dirs "$B_SERVICES")
    runners=$(count_dirs "$B_RUNNERS")

    local flags=()
    [ -n "$B_PG_HOST" ] && flags+=("--host=$B_PG_HOST")
    flags+=("--port=$B_PG_PORT" "--username=$B_PG_USER" "${B_DUMP_OPTIONS[@]}" "$B_PG_DATABASE")
    (
        [ -n "$PGPW" ] && export PGPASSWORD="$PGPW"
        as_postgres bash -c 'set -euo pipefail; out=$1; shift; "$@" > "$out"' _ \
            "$B_DIR/database/$B_PG_DATABASE.sql" "$B_DUMP_BINARY" "${flags[@]}"
    )

    local delete=()
    [ "$B_RSYNC_DELETE" = 1 ] && delete=(--delete)
    local excludes=() pattern
    for pattern in "${B_RUNNER_EXCLUDES[@]}"; do excludes+=("--exclude=$pattern"); done
    rsync -a "${delete[@]}" "$B_SERVICES/" "$B_DIR/services/"
    if [ -e "$B_RUNNERS" ]; then rsync -a "${delete[@]}" "${excludes[@]}" "$B_RUNNERS/" "$B_DIR/deploy_runners/"; fi
    if [ "$B_INCLUDE_WORKSPACE" = 1 ] && [ -e "$B_WORKSPACE" ]; then
        rsync -a "${delete[@]}" "$B_WORKSPACE/" "$B_DIR/deploy_workspace/"
    fi

    copy_file root "$PG_ADMIN" "$B_FILE_MODE" "$B_ENV" "$B_DIR/config/fastdeploy.env"
    local unit
    for unit in "${B_UNITS[@]}"; do
        if [ -e "$unit" ]; then copy_file root "$PG_ADMIN" "$B_FILE_MODE" "$unit" "$B_DIR/systemd/"; fi
    done
    if [ -n "$B_TRAEFIK" ] && [ -e "$B_TRAEFIK" ]; then
        copy_file root "$PG_ADMIN" "$B_FILE_MODE" "$B_TRAEFIK" "$B_DIR/traefik/"
    fi
    find "$B_SUDOERS_DIR" -mindepth 1 -maxdepth 1 -type f -name "$B_SUDOERS_PATTERN" ! -name '.*' -print0 |
        while IFS= read -r -d '' path; do copy_file root "$PG_ADMIN" 0440 "$path" "$B_DIR/sudoers/"; done
    if [ "$B_INCLUDE_LOGS" = 1 ]; then journalctl -u fastdeploy -o export > "$B_DIR/$B_LOGS_OUTPUT"; fi

    local workspace=False create=False
    [ "$B_INCLUDE_WORKSPACE" = 1 ] && workspace=True
    [ "$B_CREATE_ARCHIVE" = 1 ] && create=True
    local stamp=${B_DIR##*-}
    install -o root -g "$PG_ADMIN" -m "$B_FILE_MODE" /dev/null "$B_DIR/metadata.yml"
    cat > "$B_DIR/metadata.yml" <<META
timestamp: "$stamp"
host: "$B_HOST"
backup_dir: "$B_DIR"
fastdeploy_version: "$(echo "$version" | tr -d '[:space:]')"
components:
  database: true
  services_tree: true
  deploy_runners: true
  deploy_workspace: $workspace
  sops_key_included: false
postgres:
  database: "$B_PG_DATABASE"
  host: "$B_PG_HOST"
  port: $B_PG_PORT
  options: $B_DUMP_OPTIONS_JSON
services:
  count: $services
deploy_runners:
  count: $runners
archive:
  create: $create
  format: "$B_FORMAT"
disk_overhead_ratio: $B_OVERHEAD
extra: $B_EXTRA
META

    if [ "$B_CHECKSUMS" = 1 ]; then
        (cd "$B_DIR" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum > manifest.sha256)
    fi
    local name=${B_DIR##*/}
    local artifact=$B_DIR
    if [ "$B_CREATE_ARCHIVE" = 1 ]; then
        artifact="$B_DIR.$B_FORMAT"
        if [ "$B_FORMAT" = tar.gz ]; then
            (cd "$B_ROOT" && tar -C "$B_ROOT" -czf "$name.tar.gz" "$name")
        else
            (cd "$B_ROOT" && tar -C "$B_ROOT" --zstd -cf "$name.tar.zst" "$name")
        fi
        if [ "$B_FETCH" = 1 ]; then chmod 0644 "$artifact"; fi
    fi
    if [ "$B_REPORT_SIZE" = 1 ]; then
        echo "Backup complete: $artifact"
        echo "Size: $(du -sh "$artifact")"
    fi
}

# --------------------------------------------------------------- restore --

# meta FILE SECTION KEY DEFAULT: a "  KEY: value" line below "SECTION:".
meta() {
    awk -v s="$2" -v k="$3" -v d="$4" '
        /^[^ #][^:]*:/ { section = $0; sub(/:.*/, "", section) }
        section == s && $0 ~ "^  " k ":" { v = $0; sub(/^[^:]*:[ ]*/, "", v); gsub(/"/, "", v); found = 1 }
        END { print (found ? v : d) }' "$1"
}

truthy() {
    case "${1,,}" in true | yes | on | 1) echo 1 ;; *) echo 0 ;; esac
}

load_metadata_facts() {
    local file="$snapshot/metadata.yml"
    includes_database=$(truthy "$(meta "$file" components database true)")
    includes_workspace=$(truthy "$(meta "$file" components deploy_workspace false)")
    services_expected=$(meta "$file" services count 0)
}

resolve_artifact() {
    if [ "$R_ARCHIVE" = latest ]; then
        local found filtered
        found=$(find "$R_SEARCH_ROOT" -mindepth 1 -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.tar.zst' \) \
            ! -name '.*' -printf '%T@ %p\n' 2>/dev/null || true)
        [ -n "$found" ] || fail "No FastDeploy archives found under $R_SEARCH_ROOT"
        filtered=$(grep -v -- "/$R_SAFETY_PREFIX-" <<<"$found" || true)
        [ -n "$filtered" ] || filtered=$found
        artifact=$(sort -rn <<<"$filtered" | awk 'NR == 1 { sub(/^[^ ]* /, ""); print }')
    else
        local candidate
        artifact=""
        for candidate in "$R_ARCHIVE" "$R_SEARCH_ROOT/$R_ARCHIVE" "$R_SEARCH_ROOT/$R_ARCHIVE.tar.gz" \
            "$R_SEARCH_ROOT/$R_ARCHIVE.tar.zst"; do
            if [ -e "$candidate" ]; then
                artifact=$candidate
                break
            fi
        done
        [ -n "$artifact" ] || fail "Unable to locate FastDeploy restore artifact \"$R_ARCHIVE\"."
    fi
}

validate_phase() {
    resolve_artifact
    if [[ "$artifact" =~ [.]tar[.](gz|zst)$ ]]; then
        ensure_dir "$PG_ADMIN" "$PG_ADMIN" 0750 "$stage"
        extracted=1
        tar -C "$stage" -xf "$artifact"
        snapshot="$stage/$(basename "$artifact" | sed -E 's/[.]tar[.](gz|zst)$//')"
        local found
        found=$(find "$stage" -type f -name metadata.yml ! -path '*/.*' -print -quit)
        [ -z "$found" ] || snapshot=$(dirname "$found")
    else
        snapshot=$artifact
    fi
    [ -d "$snapshot" ] || fail "Snapshot directory $snapshot does not exist."
    [ -e "$snapshot/metadata.yml" ] || fail "metadata.yml not found in snapshot $snapshot"
    if [ "$R_VALIDATE_CHECKSUMS" = 1 ]; then
        [ -e "$snapshot/manifest.sha256" ] ||
            fail "Checksum validation enabled, but manifest.sha256 is missing in $snapshot"
        (cd "$snapshot" && sha256sum --quiet --check manifest.sha256)
    fi
    load_metadata_facts
    if [ "$R_REQUIRE_SOPS_KEY" = 1 ] && [ "$R_DRY_RUN" != 1 ] && [ ! -e "$R_SOPS_KEY" ]; then
        fail "SOPS key $R_SOPS_KEY is missing. Restore cannot continue."
    fi
}

safety_phase() {
    B_DIR="$B_ROOT/$R_SAFETY_PREFIX-$STAMP"
    B_INCLUDE_WORKSPACE=$includes_workspace
    (fd_backup)
    safety_dir=$B_DIR
}

restore_database() {
    systemctl stop "$R_SERVICE" || true
    as_postgres dropdb --if-exists "$R_PG_DATABASE"
    as_postgres createdb --owner="$R_PG_USER" "$R_PG_DATABASE"
    local dump="$snapshot/database/$R_PG_DATABASE.sql"
    if [ "$includes_database" = 1 ]; then
        ensure_dir "$PG_ADMIN" "$PG_ADMIN" 0750 "$snapshot"
        ensure_dir "$PG_ADMIN" "$PG_ADMIN" 0750 "$snapshot/database"
        set_attrs "$PG_ADMIN" "$PG_ADMIN" 0640 "$dump"
    fi
    local passfile_env=()
    if [ -n "$PGPW" ]; then
        pgpass_dir=$(as_postgres mktemp -d /tmp/fastdeploy_restore-pgpass-XXXXXXXXXX)
        local escaped=${PGPW//\\/\\\\}
        escaped=${escaped//:/\\:}
        as_postgres sh -c 'umask 077; cat > "$1"' _ "$pgpass_dir/pgpass" <<<"*:*:*:*:$escaped"
        passfile_env=(env "PGPASSFILE=$pgpass_dir/pgpass")
    fi
    as_postgres "${passfile_env[@]}" bash -c \
        'set -euo pipefail; { printf "SET ROLE %s;\n" "$1"; cat "$2"; } | "$3" "$4"' _ \
        "$R_PG_USER" "$dump" "$R_PSQL" "$R_PG_DATABASE"
    if [ -n "$pgpass_dir" ]; then
        rm -rf "$pgpass_dir"
        pgpass_dir=""
    fi
}

restore_phase() {
    restore_database
    local items=(
        "services:$R_SERVICES:$R_USER:$R_GROUP:1"
        "deploy_runners:$R_RUNNERS:$R_DEPLOY_USER:$R_DEPLOY_GROUP:1"
        "deploy_workspace:$R_WORKSPACE:$R_DEPLOY_USER:$R_DEPLOY_GROUP:$includes_workspace"
    )
    local item name dest owner group include
    for item in "${items[@]}"; do
        IFS=: read -r name dest owner group include <<<"$item"
        [ "$include" = 1 ] || continue
        ensure_dir "$owner" "$group" 0755 "$dest"
    done
    for item in "${items[@]}"; do
        IFS=: read -r name dest owner group include <<<"$item"
        if [ "$include" = 1 ] && [ -e "$snapshot/$name" ]; then rsync -a --delete "$snapshot/$name/" "$dest/"; fi
    done
    for item in "${items[@]}"; do
        IFS=: read -r name dest owner group include <<<"$item"
        [ "$include" = 1 ] || continue
        chown_tree "$owner" "$group" "$dest"
    done
    copy_file "$R_USER" "$R_GROUP" 0600 "$snapshot/config/fastdeploy.env" "$R_ENV"
    local path
    if [ -d "$snapshot/systemd" ]; then
        find "$snapshot/systemd" -mindepth 1 -maxdepth 1 -type f ! -name '.*' -print0 |
            while IFS= read -r -d '' path; do
                copy_file root root 0644 "$path" "/etc/systemd/system/$(basename "$path")"
            done
    fi
    if [ -n "$R_TRAEFIK" ] && [ -e "$snapshot/traefik/$(basename "$R_TRAEFIK")" ]; then
        copy_file root root 0644 "$snapshot/traefik/$(basename "$R_TRAEFIK")" "$R_TRAEFIK"
    fi
    if [ -d "$snapshot/sudoers" ]; then
        find "$snapshot/sudoers" -mindepth 1 -maxdepth 1 -type f ! -name '.*' -print0 |
            while IFS= read -r -d '' path; do
                copy_file root root 0440 "$path" "/etc/sudoers.d/$(basename "$path")"
            done
    fi
    systemctl daemon-reload
    systemctl enable "$R_SERVICE"
    systemctl start "$R_SERVICE"
}

verify_phase() {
    local state
    state=$(systemctl is-active "$R_SERVICE" || true)
    [ "$state" = active ] || fail "$R_SERVICE is $state, not active"
    if [ "$R_HTTP_CHECK" = 1 ]; then
        local attempt=0 code
        while :; do
            code=$(curl -skL --max-time 30 -o /dev/null -w '%{http_code}' "$R_HEALTH_URL" || true)
            [ "$code" = 200 ] && break
            attempt=$((attempt + 1))
            [ "$attempt" -le "$R_HTTP_RETRIES" ] || fail "$R_HEALTH_URL answered $code, expected 200"
            sleep "$R_HTTP_DELAY"
        done
    fi
    local actual table_sql
    table_sql="SELECT CASE WHEN to_regclass('public.services_service') IS NOT NULL THEN 'services_service'"
    table_sql+=" WHEN to_regclass('public.service') IS NOT NULL THEN 'service' ELSE '' END;"
    actual=$(as_postgres bash -c 'set -euo pipefail
        table=$("$1" -tA "$2" -c "$3" | tr -d "[:space:]")
        if [ -z "$table" ]; then echo 0; else "$1" -tA "$2" -c "SELECT COUNT(*) FROM $table;"; fi' _ \
        "$R_PSQL" "$R_PG_DATABASE" "$table_sql" | tr -d '[:space:]')
    if [ "$R_SERVICE_COUNT_CHECK" = 1 ] && [ "$services_expected" -gt 0 ] && [ "$actual" -ne "$services_expected" ]; then
        fail "Restored FastDeploy database reports $actual services, but metadata expected $services_expected."
    fi
}

can_rollback() {
    [ "$R_SAFETY" = 1 ] && [ -n "$safety_dir" ] && [ "$R_DRY_RUN" != 1 ]
}

rollback() {
    echo "Restore failed. Attempting rollback using safety snapshot at $safety_dir"
    snapshot=$safety_dir
    load_metadata_facts
    restore_phase
    verify_phase
}

# The role's rescue (rollback, then fail) and always (cleanup, summary).
restore_finish() {
    local rc=$1 ok=False
    trap - EXIT
    set +e
    if [ "$rc" = 0 ]; then
        ok=True
    elif can_rollback; then
        (
            set -e
            # The rollback's own passfile, if replaying fails.
            trap 'if [ -n "$pgpass_dir" ]; then rm -rf "$pgpass_dir"; fi' EXIT
            rollback
        )
        [ $? = 0 ] && rollback_executed=True
    fi
    [ "$ok" = True ] || echo "FastDeploy restore failed. Check prior log output for details." >&2
    if [ -n "$pgpass_dir" ]; then rm -rf "$pgpass_dir"; fi
    if [ "$extracted" = 1 ]; then rm -rf "$stage"; fi
    local outcome=failed
    [ "$ok" = True ] && outcome="completed successfully"
    echo "FastDeploy restore $outcome. Rollback executed: $rollback_executed"
    [ "$ok" = True ]
    exit
}

fd_restore() {
    stage="$R_TEMP/fastdeploy-restore-$STAMP"
    snapshot="" safety_dir="" pgpass_dir="" extracted=0 rollback_executed=False
    includes_database=1 includes_workspace=0 services_expected=0
    trap 'restore_finish $?' EXIT
    validate_phase
    if [ "$R_DRY_RUN" != 1 ]; then
        if [ "$R_SAFETY" = 1 ]; then safety_phase; fi
        restore_phase
        verify_phase
    fi
}
