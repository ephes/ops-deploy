# The PostgreSQL helpers both Mastodon scripts share; the caller sends this
# file in front of backup.sh or restore.sh (see backup_restore.py). The
# database password arrives on stdin and never reaches a command line.
IFS= read -r PGPW || true
cd /

# as_user USER COMMAND...: COMMAND as USER (Ansible's become_user).
as_user() {
    local user=$1
    shift
    if [ "$user" = root ]; then "$@"; else runuser -u "$user" -- "$@"; fi
}

pgpass_dir=""
drop_pgpass() {
    if [ -n "$pgpass_dir" ]; then
        rm -rf "$pgpass_dir"
        pgpass_dir=""
    fi
}

# with_pgpass USER COMMAND...: COMMAND as USER with a private 0600 passfile in
# a fresh 0700 directory (removed afterwards); without a password, libpq's
# own authentication.
with_pgpass() {
    local user=$1 rc=0
    shift
    local env_args=()
    if [ -n "$PGPW" ]; then
        pgpass_dir=$(as_user "$user" mktemp -d "/tmp/$PASSFILE_PREFIX-pgpass-XXXXXXXXXX") || return 1
        pgpass_line "$PGPW" | as_user "$user" sh -c 'umask 077; cat > "$1"' _ "$pgpass_dir/pgpass" || {
            drop_pgpass
            return 1
        }
        env_args=("PGPASSFILE=$pgpass_dir/pgpass")
    fi
    as_user "$user" env "${env_args[@]}" "$@" || rc=$?
    drop_pgpass
    return "$rc"
}

