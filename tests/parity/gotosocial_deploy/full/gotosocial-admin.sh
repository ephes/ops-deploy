#!/bin/sh
# Managed by Ansible (ops-library gotosocial_deploy).
# Run a GoToSocial admin CLI command as the service user with the deployed
# config, e.g. `gotosocial-admin account create --username show ...`.
# Some commands (promote, disable, ...) need `systemctl restart gotosocial`.
set -eu
cd /opt/gotosocial/current
exec runuser -u gotosocial -- /opt/gotosocial/current/gotosocial --config-path /etc/gotosocial/config.yaml admin "$@"
