#!/usr/bin/env bash
set -euo pipefail

pool="tank"
spindown_device_count=1
spindown_retries=10
spindown_sleep_sec=60

spindown_devices=(
  "/dev/disk/by-id/owned"
)

if [[ -n "${pool}" ]]; then
  if command -v zpool >/dev/null 2>&1; then
    attempt=0
    while true; do
      stats=$(zpool iostat -H -p "${pool}" 1 2 | tail -n 1 || true)
      if [[ -n "${stats}" ]]; then
        read -r _pool _alloc _free read_ops write_ops read_bytes write_bytes <<<"${stats}"
        if [[ "${read_ops:-0}" != "0" || "${write_ops:-0}" != "0" || "${read_bytes:-0}" != "0" || "${write_bytes:-0}" != "0" ]]; then
          if [[ "${attempt}" -ge "${spindown_retries}" ]]; then
            logger -t zfs-syncoid-spindown "Pool ${pool} active (r=${read_ops:-0} w=${write_ops:-0} rb=${read_bytes:-0} wb=${write_bytes:-0}); giving up after ${attempt} retries."
            exit 0
          fi
          attempt=$((attempt + 1))
          logger -t zfs-syncoid-spindown "Pool ${pool} active (r=${read_ops:-0} w=${write_ops:-0} rb=${read_bytes:-0} wb=${write_bytes:-0}); retrying in ${spindown_sleep_sec}s (attempt ${attempt}/${spindown_retries})."
          sleep "${spindown_sleep_sec}"
          continue
        fi
      fi
      break
    done
  fi
fi

if [[ "${spindown_device_count}" -eq 0 ]]; then
  logger -t zfs-syncoid-spindown "No spindown devices configured; skipping."
  exit 0
fi

for dev in "${spindown_devices[@]}"; do
  if [[ -b "${dev}" ]]; then
    if ! hdparm -y "${dev}" >/dev/null 2>&1; then
      logger -t zfs-syncoid-spindown "hdparm failed for ${dev}"
    fi
  else
    logger -t zfs-syncoid-spindown "Device ${dev} not found; skipping."
  fi
done
