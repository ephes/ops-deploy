# Helpers shared by the backup and restore scripts. Like Ansible's file and
# copy modules they change owner and mode only where they differ: chown and
# chmod update a file's ctime even when nothing changes, and uv treats a
# project whose pyproject.toml or src/ ctime moved as changed (it rebuilds it).

# set_attrs OWNER GROUP MODE PATH
set_attrs() {
    local want
    want="$1:$2 $(printf '%o' "$((8#$3))")"
    if [ "$(stat -c '%U:%G %a' "$4")" != "$want" ]; then
        chown "$1:$2" "$4" && chmod "$3" "$4"
    fi
}

# chown_tree OWNER GROUP PATH...: Ansible's file recurse with owner and group.
chown_tree() {
    local owner=$1 group=$2
    shift 2
    find "$@" \( ! -user "$owner" -o ! -group "$group" \) -exec chown -h "$owner:$group" {} +
}

# Ansible's file state=directory: missing parents get the same owner and mode.
ensure_dir() {
    local owner=$1 group=$2 mode=$3 path=$4 current="" part parts
    IFS=/ read -ra parts <<<"${path#/}"
    for part in "${parts[@]}"; do
        current="$current/$part"
        if [ ! -d "$current" ]; then mkdir "$current" && chown "$owner:$group" "$current" && chmod "$mode" "$current"; fi
    done
    set_attrs "$owner" "$group" "$mode" "$path"
}

# Ansible's copy with remote_src: the file is rewritten only when its content
# differs (an unchanged file keeps its times).
copy_file() {
    local owner=$1 group=$2 mode=$3 src=$4 dest=$5
    if [ -d "$dest" ]; then dest="$dest/$(basename "$src")"; fi
    if cmp -s "$src" "$dest"; then
        set_attrs "$owner" "$group" "$mode" "$dest"
    else
        install -o "$owner" -g "$group" -m "$mode" "$src" "$dest"
    fi
}

# require_mount MOUNT PATH...: stop the script unless MOUNT is mounted and
# every PATH resolves below it, so a backup or a restore's work directory never
# lands on the root filesystem when the external disk is missing. Listing the
# mount point first triggers an automount; an automount without the real
# filesystem behind it does not count.
require_mount() {
    local mount path resolved
    mount=$(realpath -e -- "$1" 2>/dev/null) || {
        echo "Required mount $1 does not exist; refusing to write below it" >&2
        exit 1
    }
    shift
    ls -d -- "$mount/." >/dev/null 2>&1 || true
    if ! findmnt --mountpoint "$mount" --types noautofs >/dev/null 2>&1; then
        echo "Required mount $mount is not mounted; refusing to write below it" >&2
        exit 1
    fi
    for path in "$@"; do
        resolved=$(realpath -m -- "$path")
        case $resolved in
            "$mount"/?*) ;;
            *)
                echo "$path resolves to $resolved, outside the required mount $mount" >&2
                exit 1
                ;;
        esac
    done
}

# Snapshots written under a retention policy are recorded here, one empty file
# per snapshot name; retention never touches anything without a record.
SNAPSHOT_RECORDS=.ops-deploy-snapshots

# require_new_snapshot ROOT NAME: stop when ROOT/NAME, one of its archives or
# its record already exists, so retention never enrolls what another run (or
# another tool) wrote under the same name.
require_new_snapshot() {
    local path
    for path in "$1/$2" "$1/$2.tar.gz" "$1/$2.tar.zst" "$1/$SNAPSHOT_RECORDS/$2"; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            echo "$path already exists; refusing to write a snapshot under retention with the same name" >&2
            exit 1
        fi
    done
}

# record_snapshot ROOT NAME: NAME (ROOT/NAME and its archive) falls under retention.
record_snapshot() {
    ensure_dir root root 0700 "$1/$SNAPSHOT_RECORDS"
    : >"$1/$SNAPSHOT_RECORDS/$2"
}

# prune_snapshots ROOT KEEP CUTOFF CURRENT: remove recorded snapshots (the
# directory, its .tar.gz/.tar.zst archive, then the record) beyond the newest
# KEEP of their prefix (0: no count limit) or with a timestamp before CUTOFF
# (YYYYmmddTHHMMSS; empty: no age limit). CURRENT, the snapshot just written,
# always stays.
prune_snapshots() {
    local root=$1 keep=$2 cutoff=$3 current=$4 records="$1/$SNAPSHOT_RECORDS" name prefix stamp path
    local -A seen=()
    [ -d "$records" ] || return 0
    local names=()
    # find, not a glob: a prefix may start with a dot. NUL-separated, so a
    # record whose name holds a newline cannot pass for another snapshot.
    while IFS= read -r -d '' path; do
        name=${path##*/}
        if [[ $name =~ ^[A-Za-z0-9._-]+-[0-9]{8}T[0-9]{6}$ ]]; then names+=("${name##*-} $name"); fi
    done < <(find "$records" -mindepth 1 -maxdepth 1 -type f -print0)
    [ "${#names[@]}" -gt 0 ] || return 0
    while IFS=' ' read -r stamp name; do
        prefix=${name%-*}
        seen[$prefix]=$((${seen[$prefix]:-0} + 1))
        [ "$name" != "$current" ] || continue
        if { [ "$keep" -gt 0 ] && [ "${seen[$prefix]}" -gt "$keep" ]; } ||
            { [ -n "$cutoff" ] && ((10#${stamp/T/} < 10#${cutoff/T/})); }; then
            echo "Pruning local snapshot $root/$name"
            rm -rf -- "${root:?}/$name" "$root/$name.tar.gz" "$root/$name.tar.zst"
            rm -f -- "$records/$name"
        fi
    done < <(printf '%s\n' "${names[@]}" | LC_ALL=C sort -r)
}
