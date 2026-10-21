#!/bin/sh
# Managed by Ansible (ops-library gotosocial_deploy).
# Run a GoToSocial admin CLI command as the service user with the deployed
# config, e.g. `gotosocial-admin account create --username show ...`.
# Some commands (promote, disable, ...) need `systemctl restart gts`.
set -eu
cd /srv/gts/current
exec runuser -u gts -- /srv/gts/current/gotosocial --config-path /srv/gts-etc/config.yaml admin "$@"
