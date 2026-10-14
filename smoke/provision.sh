#!/usr/bin/env bash
# Runs as root inside the smoke VM (from smoke/vm.sh up); idempotent.
# $1: the public key allowed to log in as root.
#
# Installs what the prod host provides before a service deploy: rsync and
# python3, uv in /usr/local/bin, Traefik (file provider on
# /etc/traefik/dynamic, entry point web-secure on :443) as traefik.service, and
# PostgreSQL from the PGDG repository (what postgres_install sets up).
set -euo pipefail

PUBKEY="$1"
UV_VERSION="0.13.0"
TRAEFIK_VERSION="3.7.14"  # what macmini runs
POSTGRES_VERSION="17"  # what macmini runs

case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
grep -qxF "$PUBKEY" /root/.ssh/authorized_keys || printf '%s\n' "$PUBKEY" >>/root/.ssh/authorized_keys

missing=()
# build-essential: wheels missing for the VM (arm64, new Pythons) build from source, as macmini can.
for pkg in rsync python3 curl ca-certificates build-essential; do
    dpkg-query -W -f '${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || missing+=("$pkg")
done
if ((${#missing[@]})); then
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${missing[@]}"
fi

if ! dpkg-query -W -f '${Status}' "postgresql-$POSTGRES_VERSION" 2>/dev/null | grep -q "install ok installed"; then
    # The repository file postgres_install's deb822_repository task writes, so
    # an Ansible run on the VM finds it in place instead of adding a second one.
    install -d -m 755 /etc/apt/keyrings
    curl -fsSL -o /etc/apt/keyrings/postgresql.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc
    chmod 644 /etc/apt/keyrings/postgresql.asc
    codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
    cat >/etc/apt/sources.list.d/postgresql.sources <<SOURCES
Components: main
Enabled: yes
Signed-By: /etc/apt/keyrings/postgresql.asc
Suites: $codename-pgdg
Types: deb
URIs: https://apt.postgresql.org/pub/repos/apt
X-Repolib-Name: postgresql
SOURCES
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
        "postgresql-$POSTGRES_VERSION" "postgresql-client-$POSTGRES_VERSION" "postgresql-contrib-$POSTGRES_VERSION"
fi
systemctl enable --now postgresql.service

if [[ "$(/usr/local/bin/uv --version 2>/dev/null)" != "uv $UV_VERSION"* ]]; then
    curl -LsSf "https://astral.sh/uv/$UV_VERSION/install.sh" \
        | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh
fi

changed=0
if [[ "$(/usr/local/bin/traefik version 2>/dev/null | awk '/^Version:/ {print $2}')" != "$TRAEFIK_VERSION" ]]; then
    tmp="$(mktemp -d)"
    curl -LsSf -o "$tmp/traefik.tgz" \
        "https://github.com/traefik/traefik/releases/download/v$TRAEFIK_VERSION/traefik_v${TRAEFIK_VERSION}_linux_$ARCH.tar.gz"
    tar -xzf "$tmp/traefik.tgz" -C "$tmp" traefik
    install -m 755 "$tmp/traefik" /usr/local/bin/traefik
    rm -rf "$tmp"
    changed=1  # a running Traefik keeps the old binary until restarted
fi

install -d -m 755 /etc/traefik /etc/traefik/dynamic
cat >/etc/traefik/traefik.yml.new <<'YAML'
# Smoke VM Traefik: the entry point and file provider the deploy helpers target.
entryPoints:
  web-secure:
    address: ":443"
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
log:
  level: INFO
YAML
cat >/etc/systemd/system/traefik.service.new <<'UNIT'
[Unit]
Description=Traefik (ops-deploy smoke VM)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/traefik --configfile=/etc/traefik/traefik.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
for f in /etc/traefik/traefik.yml /etc/systemd/system/traefik.service; do
    if cmp -s "$f.new" "$f"; then rm "$f.new"; else mv "$f.new" "$f"; changed=1; fi
done
if ((changed)); then
    systemctl daemon-reload
    systemctl enable traefik.service
    systemctl restart traefik.service
else
    systemctl enable --now traefik.service
fi
