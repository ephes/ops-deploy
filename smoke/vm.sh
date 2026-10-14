#!/usr/bin/env bash
# Local lima VM used as the smoke target: Ubuntu 24.04 (the prod host OS),
# root SSH with a dedicated key, uv and Traefik installed like on prod.
#
#   smoke/vm.sh up      create/start and provision (idempotent)
#   smoke/vm.sh env     print the connection settings as shell assignments
#   smoke/vm.sh ssh     open a root shell (or run the given command)
#   smoke/vm.sh down    delete the VM and its key material
#
# SMOKE_VM overrides the instance name, SMOKE_STATE_DIR the key directory.
set -euo pipefail

VM="${SMOKE_VM:-ops-deploy-smoke}"
STATE_DIR="${SMOKE_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/ops-deploy/smoke/$VM}"
KEY="$STATE_DIR/id_ed25519"
KNOWN_HOSTS="$STATE_DIR/known_hosts"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ "$VM" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || { echo "invalid SMOKE_VM: $VM" >&2; exit 2; }

log() { printf '%s\n' "smoke-vm: $*" >&2; }

ensure_lima() {
    if ! command -v limactl >/dev/null 2>&1; then
        log "limactl not found; installing lima with Homebrew"
        brew install lima
    fi
}

status() { limactl list --format '{{.Status}}' "$VM" 2>/dev/null || true; }

ssh_port() { limactl list --format '{{.SSHLocalPort}}' "$VM"; }

up() {
    ensure_lima
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    [[ -f "$KEY" ]] || ssh-keygen -q -t ed25519 -N '' -C "ops-deploy-smoke@$VM" -f "$KEY"

    case "$(status)" in
        "")
            log "creating $VM (Ubuntu 24.04)"
            limactl create --tty=false --name="$VM" --plain --vm-type=vz \
                --cpus=2 --memory=2 --disk=20 template:ubuntu-24.04
            # A new VM has a new host key.
            rm -f "$KNOWN_HOSTS"
            limactl start --tty=false "$VM"
            ;;
        Running) ;;
        *) limactl start --tty=false "$VM" ;;
    esac

    log "provisioning $VM"
    limactl shell --workdir / "$VM" sudo bash -s -- "$(cat "$KEY.pub")" <"$HERE/provision.sh"

    # Pin the host key now, through lima's own SSH channel, so later
    # connections can use StrictHostKeyChecking=yes.
    local port
    port="$(ssh_port)"
    limactl shell --workdir / "$VM" cat /etc/ssh/ssh_host_ed25519_key.pub \
        | awk -v host="[127.0.0.1]:$port" '{print host, $1, $2}' >"$KNOWN_HOSTS"
    ssh_cmd true
    log "ready: root@127.0.0.1 port $port"
}

env_vars() {
    [[ "$(status)" == Running ]] || { log "$VM is not running; run 'just smoke-up'"; exit 1; }
    # Shell-quoted: the recipe evaluates these lines.
    printf 'SMOKE_SSH_HOST=127.0.0.1\nSMOKE_SSH_PORT=%q\nSMOKE_SSH_KEY=%q\nSMOKE_SSH_KNOWN_HOSTS=%q\n' \
        "$(ssh_port)" "$KEY" "$KNOWN_HOSTS"
}

ssh_cmd() {
    # Host key pinned in KNOWN_HOSTS for [127.0.0.1]:<port>; refreshed by `up`.
    ssh -i "$KEY" -p "$(ssh_port)" -o IdentitiesOnly=yes -o BatchMode=yes \
        -o UserKnownHostsFile="$KNOWN_HOSTS" -o StrictHostKeyChecking=yes \
        root@127.0.0.1 "$@"
}

down() {
    if [[ -n "$(status)" ]]; then
        log "deleting $VM"
        limactl delete --force "$VM"
    else
        log "$VM does not exist"
    fi
    rm -rf "$STATE_DIR"
}

case "${1:-}" in
    up) up ;;
    env) env_vars ;;
    ssh) shift; ssh_cmd "$@" ;;
    down) down ;;
    *) echo "usage: $0 up|env|ssh [command]|down" >&2; exit 2 ;;
esac
