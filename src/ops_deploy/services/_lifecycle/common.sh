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
