#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/mongodb/mongod.log"
MAX_SIZE=$((500 * 1024 * 1024))

if [[ -f "${LOG_FILE}" ]]; then
  SIZE=$(stat -c%s "${LOG_FILE}")
  if [[ "${SIZE}" -gt "${MAX_SIZE}" ]]; then
    echo "MongoDB log larger than 500MB ($((SIZE / 1024 / 1024))MB)" | logger -t mongodb-log-check
    /usr/sbin/logrotate -f "/etc/logrotate.d/mongodb" || true
  fi
fi
