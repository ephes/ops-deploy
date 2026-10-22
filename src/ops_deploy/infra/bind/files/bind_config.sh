# bind_config.sh: compare, validate and install the BIND configuration (ops_deploy.infra.bind).
#
# Run as: bash -c "$(this file)" bind-config MODE CONFIG_DIR WORKING_DIR SERVICE KEYS_FILE \
#             [KIND PATH ZONE USER GROUP FILE_MODE SIZE]...
# MODE is "probe" (read-only, prints its findings) or "apply". KIND is one of
# config, keys, zone (static zone file), seed (dynamic zone file, written only
# when missing) or absent (a file to remove; the other fields are "-"). Entries
# come in the order they are installed. Standard input holds one base64 line
# per entry that is not "absent", in the same order; it carries the TSIG key
# file, so nothing here prints file contents.
#
# Nothing is backed up or rolled back: every candidate is checked before the
# first file is touched (named-checkzone for each changed zone file, with a
# serial greater than the installed one, and named-checkconf on a copy of the
# configuration tree with the candidates in place, chrooted with -t), then each
# changed file is renamed into place. A dynamic zone file is never replaced:
# "ln" refuses to overwrite one, and its journal is never touched.
#
# probe prints "change PATH", "leftover PATH", "refuse MESSAGE",
# "reload-pending" (an installed file is newer, in whole seconds, than named's
# last configuration load, so a run ended before its reload; apply waits for
# the next second after that load before it writes) and exits 0; it fails
# only on an error of its own. apply holds an flock on CONFIG_DIR, fails on a
# refusal before changing anything and prints "installed PATH" for each file
# it changed.

set -euo pipefail
shopt -s inherit_errexit
umask 077

mode=$1 config_dir=$2 working_dir=$3 service=$4 keys_file=$5
shift 5
kinds=() paths=() zones=() users=() groups=() modes=() sizes=()
while [ $# -gt 0 ]; do
    [ $# -ge 7 ] || { echo "bind-config: incomplete entry" >&2; exit 2; }
    kinds+=("$1") paths+=("$2") zones+=("$3") users+=("$4") groups+=("$5") modes+=("$6") sizes+=("$7")
    shift 7
done

staged() { printf '%s/.ops-deploy-new.%s' "${1%/*}" "${1##*/}"; }

tmp=$(mktemp -d /run/ops-deploy-bind.XXXXXX)
locked=no
cleanup() {
    rm -rf -- "$tmp"
    # Staged files are shared with other runs: only the lock holder removes them.
    if [ "$locked" = yes ]; then
        for path in "${paths[@]}"; do rm -f -- "$(staged "$path")"; done
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# The candidates, decoded into the private temporary directory.
mkdir "$tmp/in"
for i in "${!kinds[@]}"; do
    if [ "${kinds[i]}" = absent ]; then continue; fi
    IFS= read -r line || { echo "bind-config: input ends early" >&2; exit 2; }
    printf '%s' "$line" | base64 -d > "$tmp/in/$i"
    [ "$(stat -c %s "$tmp/in/$i")" = "${sizes[i]}" ] || { echo "bind-config: input is damaged" >&2; exit 2; }
done
exec < /dev/null
if [ "$mode" = apply ]; then
    # One apply (or reload) at a time; released when the script exits.
    exec 9< "$config_dir"
    flock -w 120 9 || { echo "bind-config: another run holds the lock on $config_dir" >&2; exit 2; }
    locked=yes
fi

refusals=() changes=() leftovers=()
refuse() { refusals+=("$*"); }

# Prints the zone's serial; fails when named-checkzone rejects the file.
loaded_serial() {
    local out
    out=$(named-checkzone "$1" "$2" 2>&1) || return 1
    printf '%s\n' "$out" | sed -n 's/^zone .*: loaded serial \([0-9][0-9]*\).*/\1/p'
}

# RFC 1982 serial arithmetic: is $1 greater than $2?
serial_greater() {
    local d=$(( ($1 - $2 + 4294967296) % 4294967296 ))
    [ "$d" -gt 0 ] && [ "$d" -lt 2147483648 ]
}

# Seconds since the epoch of named's last configuration load ("" when named is not running).
last_loaded() {
    local when
    systemctl is-active --quiet "$service" || return 0
    when=$(rndc status | sed -n 's/^last configured: //p')
    [ -n "$when" ] || { echo "bind-config: rndc status shows no configuration time" >&2; exit 2; }
    date -d "$when" +%s
}

same_file() {
    local i=$1 path=${paths[$1]}
    [ -f "$path" ] && cmp -s "$tmp/in/$i" "$path" || return 1
    read -r user group perm < <(stat -c '%U %G %a' "$path")
    [ "$user" = "${users[i]}" ] && [ "$group" = "${groups[i]}" ] && [ $((8#$perm)) -eq $((8#${modes[i]})) ]
}

for i in "${!kinds[@]}"; do
    path=${paths[i]}
    if [ -e "$(staged "$path")" ] || [ -L "$(staged "$path")" ]; then
        leftovers+=("$(staged "$path")")
    fi
    if [ -L "$path" ] || { [ -e "$path" ] && [ ! -f "$path" ]; }; then
        refuse "$path is not a regular file"
        continue
    fi
    case ${kinds[i]} in
        absent)
            if [ -e "$path" ]; then changes+=("$i"); fi
            ;;
        seed)
            # The role's "force: false": an existing dynamic zone file is named's.
            if [ -e "$path" ]; then continue; fi
            if [ -e "$path.jnl" ] || [ -L "$path.jnl" ]; then
                refuse "$path is missing but its journal $path.jnl exists; refusing to seed the dynamic zone" \
                    "(named would reject the journal). Restore the file or remove the journal deliberately first."
                continue
            fi
            changes+=("$i")
            ;;
        *)
            if same_file "$i"; then continue; fi
            if [ "${kinds[i]}" = zone ] && { [ -e "$path.jnl" ] || [ -L "$path.jnl" ]; }; then
                refuse "$path.jnl exists; refusing to replace a zone file that named keeps a journal for"
                continue
            fi
            changes+=("$i")
            ;;
    esac
done

checkers=no
if command -v named-checkzone > /dev/null && command -v named-checkconf > /dev/null; then checkers=yes; fi
if [ "$mode" = apply ] && [ "$checkers" = no ]; then
    echo "bind-config: named-checkzone and named-checkconf are required" >&2
    exit 2
fi

# Validate the candidates (while planning only once BIND is installed).
if [ ${#changes[@]} -gt 0 ] && [ ${#refusals[@]} -eq 0 ] && [ "$checkers" = yes ]; then
    for i in "${changes[@]}"; do
        case ${kinds[i]} in zone | seed) ;; *) continue ;; esac
        if ! new=$(loaded_serial "${zones[i]}" "$tmp/in/$i") || [ -z "$new" ]; then
            refuse "named-checkzone rejects the new file for zone ${zones[i]}"
            continue
        fi
        # Stricter than the role: a changed static zone needs a greater serial,
        # or secondaries would never transfer it.
        if [ "${kinds[i]}" = zone ] && [ -f "${paths[i]}" ] \
            && old=$(loaded_serial "${zones[i]}" "${paths[i]}") && [ -n "$old" ] \
            && ! serial_greater "$new" "$old"; then
            refuse "zone ${zones[i]}: the new file keeps serial $new, which is not greater than the installed $old"
        fi
    done
    root=$tmp/root
    mkdir -p "$root$config_dir" "$root$working_dir"
    # -L: the copy holds no symlinks, so the candidates below cannot land outside it.
    if [ -d "$config_dir" ]; then cp -RL -- "$config_dir/." "$root$config_dir/"; fi
    for i in "${!kinds[@]}"; do
        case ${kinds[i]} in
            config | keys) mkdir -p "$root${paths[i]%/*}" && cp "$tmp/in/$i" "$root${paths[i]}" ;;
            absent) rm -f -- "$root${paths[i]}" ;;
        esac
    done
    if ! out=$(named-checkconf -t "$root" "$config_dir/named.conf" 2>&1); then
        refuse "named-checkconf rejects the new configuration:"
        # A message about the key file may quote its contents.
        while IFS= read -r line; do
            case $line in
                "$keys_file:"*) refuse "  $keys_file: (message withheld, it may quote key material)" ;;
                *) refuse "  $line" ;;
            esac
        done <<< "$out"
    fi
fi

if [ "$mode" = probe ]; then
    for i in "${changes[@]}"; do echo "change ${paths[i]}"; done
    for path in "${leftovers[@]}"; do echo "leftover $path"; done
    for message in "${refusals[@]}"; do echo "refuse $message"; done
    loaded=$(last_loaded)
    if [ -n "$loaded" ]; then
        for i in "${!kinds[@]}"; do
            case ${kinds[i]} in config | keys | zone) ;; *) continue ;; esac
            if [ -f "${paths[i]}" ] && [ "$(stat -c %Y "${paths[i]}")" -gt "$loaded" ]; then
                echo reload-pending
                break
            fi
        done
    fi
    exit 0
fi

if [ ${#refusals[@]} -gt 0 ]; then
    printf 'bind-config: %s\n' "${refusals[@]}" >&2
    exit 1
fi
# Installed files must be newer (in whole seconds) than named's last load, so a
# probe can tell that a reload is missing if this run ends before it.
loaded=$(last_loaded)
if [ ${#changes[@]} -gt 0 ] && [ -n "$loaded" ]; then
    while [ "$(date +%s)" -le "$loaded" ]; do sleep 0.2; done
fi
for i in "${changes[@]}"; do
    path=${paths[i]} new=$(staged "${paths[i]}")
    case ${kinds[i]} in
        absent) rm -f -- "$path" ;;
        seed)
            install -T -o "${users[i]}" -g "${groups[i]}" -m "${modes[i]}" "$tmp/in/$i" "$new"
            ln -T -- "$new" "$path"
            ;;
        *)
            install -T -o "${users[i]}" -g "${groups[i]}" -m "${modes[i]}" "$tmp/in/$i" "$new"
            mv -fT -- "$new" "$path"
            ;;
    esac
    echo "installed $path"
done
