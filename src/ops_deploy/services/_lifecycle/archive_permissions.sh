# Match Ansible find: non-hidden regular archives directly in the backup root.
# Never follow symlinks, recurse into snapshots, or chmod already-correct files.
restrict_archives() {
    find "$1" -mindepth 1 -maxdepth 1 -type f ! -name '.*' \
        \( -name '*.tar' -o -name '*.tar.*' -o -name '*.tgz' \) \
        ! -perm "$2" -exec chmod -- "$2" {} +
}
