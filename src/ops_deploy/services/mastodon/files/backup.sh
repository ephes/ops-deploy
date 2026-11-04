# mastodon_backup on the host: version, directories, the payload (database
# dump, media, env file, units, Traefik and nginx config) with the services
# stopped and always started again, manifest and archive. The caller prepends
# the settings (see backup_restore.py) and sends the database password on
# stdin (postgres.sh, sent in front of this script, reads it); it never
# reaches a command line.

capturing=0
start_services() {
    # The role's always: started with a daemon reload, failures ignored.
    systemctl daemon-reload || true
    local service
    for service in "${SERVICES[@]}"; do systemctl start "$service" || true; done
}
on_exit() {
    local rc=$?
    set +e
    drop_pgpass
    if [ "$capturing" = 1 ] && [ "$STOP" = 1 ]; then start_services; fi
    exit "$rc"
}
trap on_exit EXIT

# copy_present SRC DEST: the role's stat + copy for a file that may be absent.
copy_present() {
    if [ -e "$1" ] || [ -L "$1" ]; then copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$1" "$2"; fi
}

# The role's `cat VERSION` as the Mastodon user (failures ignored).
version=unknown
if [ -d "$SITE" ]; then
    version=$(cd "$SITE" && as_user "$USER_NAME" cat "$SITE/VERSION" 2>/dev/null) || true
    version=$(printf '%s' "$version" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
fi

for path in "$ROOT" "$DIR" "$DIR/database" "$DIR/media" "$DIR/config" "$DIR/systemd" "$DIR/traefik" "$DIR/nginx"; do
    ensure_dir "$OWNER" "$GROUP" "$DIR_MODE" "$path"
done
restrict_archives "$ROOT" 0600

# -- the payload (the role's block; on_exit is its always) ----------------------
capturing=1
if [ "$STOP" = 1 ]; then
    for service in "${SERVICES[@]}"; do systemctl stop "$service" || true; done
fi

dump_args=()
if [ -n "$PG_HOST" ]; then dump_args+=("--host=$PG_HOST"); fi
if [ -n "$PG_PORT" ]; then dump_args+=("--port=$PG_PORT"); fi
with_pgpass "$PG_BECOME" "$PG_DUMP" "${dump_args[@]}" "--username=$PG_USER" "--format=$PG_FORMAT" \
    "--compress=$PG_COMPRESS" --file "$DUMP" "$PG_DATABASE"

if [ "$INCLUDE_MEDIA" = 1 ] && { [ -e "$MEDIA" ] || [ -L "$MEDIA" ]; } && [ "$STORAGE" = local ]; then
    rsync_args=(-a)
    if [ "$DELETE" = 1 ]; then rsync_args+=(--delete); fi
    for exclude in "${EXCLUDES[@]}"; do rsync_args+=("--exclude=$exclude"); done
    rsync "${rsync_args[@]}" "$MEDIA/" "$DIR/media/"
fi
# An absent env file fails the backup, as the role's copy does.
if [ "$INCLUDE_ENV" = 1 ]; then copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$ENV_FILE" "$DIR/config/mastodon.env"; fi
if [ "$INCLUDE_SYSTEMD" = 1 ]; then
    for unit in "${UNITS[@]}"; do copy_present "$unit" "$DIR/systemd/${unit##*/}"; done
fi
if [ "$INCLUDE_TRAEFIK" = 1 ]; then copy_present "$TRAEFIK" "$DIR/traefik/${TRAEFIK##*/}"; fi
if [ "$INCLUDE_NGINX" = 1 ]; then copy_present "$NGINX" "$DIR/nginx/${NGINX##*/}"; fi
if [ "$STOP" = 1 ]; then start_services; fi
capturing=0

# -- manifest and archive --------------------------------------------------------
if [ "$MANIFEST" = 1 ]; then
    manifest="$DIR/manifest.yml"
    # Quoted, so an "&" in the version stays literal (bash 5.2 patsub_replacement).
    printf '%s' "${MANIFEST_TEXT/@VERSION@/"$version"}" >"$manifest.new"
    copy_file "$OWNER" "$GROUP" "$FILE_MODE" "$manifest.new" "$manifest"
    rm -f "$manifest.new"
fi
if [ "$ARCHIVE" = 1 ]; then
    name=${DIR##*/}
    (umask 077 && tar -C "$ROOT" -czf "$ROOT/$name.tar.gz" "$name")
    chmod 0600 "$ROOT/$name.tar.gz"
fi
