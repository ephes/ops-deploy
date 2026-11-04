# mastodon_backup's prune.yml on the host: keep the newest RETAIN archives
# (only when the backup writes archives) and payload directories (by mtime)
# directly in ROOT whose names match GLOB; hidden entries never count. The
# caller prepends the settings (see backup_restore.py).

# prune_newest TYPE PATTERN: remove all but the newest RETAIN entries of find
# type TYPE named PATTERN (Ansible's find: not recursive, no hidden entries,
# no symlinks).
prune_newest() {
    local type=$1 pattern=$2 path entry
    local entries=()
    while IFS= read -r -d '' path; do
        entries+=("$(stat -c %Y -- "$path") $path")
    done < <(find "$ROOT" -mindepth 1 -maxdepth 1 -type "$type" ! -name '.*' -name "$pattern" -print0)
    [ "${#entries[@]}" -gt "$RETAIN" ] || return 0
    while IFS= read -r -d '' entry; do
        echo "Pruning old Mastodon backup ${entry#* }"
        rm -rf -- "${entry#* }"
    done < <(printf '%s\0' "${entries[@]}" | sort -z -s -n -r -k1,1 | tail -z -n +"$((RETAIN + 1))")
}

if [ "$RETAIN" -gt 0 ] && [ -d "$ROOT" ]; then
    if [ "$ARCHIVE" = 1 ]; then prune_newest f "$GLOB.tar.gz"; fi
    prune_newest d "$GLOB"
fi
