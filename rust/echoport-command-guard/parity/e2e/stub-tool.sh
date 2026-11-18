#!/bin/sh
# Layer 3 stub (PLAN.md 7.6) for the tools the containers do not have or
# must not run for real: systemctl, sudo, pg_dump, pg_restore, psql,
# createdb, dropdb, sqlite3, curl. Installed in /usr/local/bin under each
# name. It records what the guard passed on (argv, environment, the targets
# of fds 0-2, ignored signals, umask, uid, the open fds) into
# $E2E_PROBE_DIR (default /var/lib/e2e-probe), copies stdin, and then acts
# just enough like the tool for the runner shapes: pg_dump writes a dump,
# sqlite3 writes the `.backup` snapshot or prints `ok`, psql prints a value,
# `systemctl show` prints `loaded`.
#
# `/proc/$$` is this shell; the targets of fds 0-2 are read before any
# redirection, and the fd list comes from an `exec`'d `ls` at the end (the
# shell's own script fd is close-on-exec).
# The signal mask and dispositions first, with shell builtins only: while
# the shell waits for a child, it blocks signals itself.
status=
while IFS= read -r line; do
    case "$line" in
        SigBlk:* | SigIgn:* | Umask:* | Uid:*) status="$status$line
" ;;
    esac
done < /proc/$$/status
dir=${E2E_PROBE_DIR:-/var/lib/e2e-probe}
out="$dir/$(/usr/bin/basename "$0").$$"
std0=$(/usr/bin/readlink /proc/$$/fd/0)
std1=$(/usr/bin/readlink /proc/$$/fd/1)
std2=$(/usr/bin/readlink /proc/$$/fd/2)
printf '%s\n' "$std0" "$std1" "$std2" > "$out.std"
printf '%s' "$status" > "$out.status"
/usr/bin/tr '\0' '\n' < /proc/$$/environ | /usr/bin/sort > "$out.env"
printf '%s\n' "$0" "$@" > "$out.argv"
/usr/bin/cat > "$out.stdin"
case "$(/usr/bin/basename "$0")" in
    pg_dump)
        file=
        for arg in "$@"; do
            case "$arg" in --file=*) file=${arg#--file=} ;; esac
        done
        if [ -n "$file" ]; then
            printf 'PGDMP stub dump\n' > "$file"
        else
            printf 'PGDMP stub dump\n'
        fi
        ;;
    psql) printf '1\n' ;;
    sqlite3)
        last=
        for arg in "$@"; do last=$arg; done
        case "$last" in
            ".backup '"*)
                target=${last#.backup \'}
                printf 'SQLite stub snapshot\n' > "${target%\'}"
                ;;
            *) printf 'ok\n' ;;
        esac
        ;;
    systemctl)
        if [ "$1" = show ]; then
            printf 'loaded\n'
        fi
        ;;
esac
exec /usr/bin/ls /proc/self/fd/ > "$out.fds"
