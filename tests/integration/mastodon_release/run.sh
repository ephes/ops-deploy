#!/usr/bin/env bash
# Run ONLY on a disposable GitHub Ubuntu VM, never an inventory host.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(ps -p 1 -o comm=) == systemd ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ ]]
if id mastodon >/dev/null 2>&1; then
  echo 'Refusing VM that already has a mastodon user' >&2
  exit 1
fi
[[ ! -e /var/tmp/mastodon-release-owned-vm.json ]]
[[ ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
HERE_HARNESS=$(cd -- "$(dirname -- "$0")" && pwd)/harness.py
"${CONTROLLER_PYTHON:?}" - "$HERE_HARNESS" <<'PYMARKER'
import os, runpy, sys
from pathlib import Path
create_marker = runpy.run_path(sys.argv[1])['create_vm_marker']
create_marker(Path('/var/tmp/mastodon-release-owned-vm.json'), os.environ['GITHUB_RUN_ID'],
              Path('/etc/machine-id').read_text().strip())
PYMARKER
echo OWNED_VM_PROVISION_START
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
EVIDENCE=/var/tmp/mastodon-release-evidence
install -d -m 0700 "$EVIDENCE"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends git curl ca-certificates build-essential ruby-full ruby-dev nodejs npm \
  libssl-dev libyaml-dev libreadline-dev zlib1g-dev libffi-dev libgdbm-dev \
  libjemalloc-dev libpq-dev libxml2-dev libxslt1-dev libidn-dev libicu-dev \
  libjpeg-dev libvips-dev libvips-tools imagemagick ffmpeg postgresql \
  postgresql-contrib redis-server nginx rsync pkg-config
systemctl start postgresql redis-server
systemctl stop nginx
useradd --create-home --shell /bin/bash mastodon
install -d -o mastodon -g mastodon -m 0750 /home/mastodon/live
install -d -o mastodon -g mastodon -m 0750 /var/log/mastodon-nginx \
  /var/lib/mastodon-nginx/body /var/cache/mastodon/nginx/temp \
  /var/cache/mastodon/nginx-federation/temp
install -d /etc/mastodon /etc/traefik/dynamic
# Isolated VM test databases. Dummy password never printed.
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -q <<'SQL'
CREATE ROLE mastodon LOGIN PASSWORD 'fixture-database-only';
CREATE DATABASE mastodon OWNER mastodon;
SQL
runuser -u postgres -- psql -d mastodon -v ON_ERROR_STOP=1 -q <<'SQL'
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS unaccent;
SQL
"${CONTROLLER_PYTHON:?}" "$HERE/harness.py" "$EVIDENCE"
