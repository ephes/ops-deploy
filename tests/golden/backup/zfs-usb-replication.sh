#!/usr/bin/env bash
set -euo pipefail

log_tag="zfs-usb-replication"
pool="vault"
key_path="/root/.zfs-key-vault"
syncoid_bin="/usr/sbin/syncoid"
force_export="false"
spindown_enabled="true"
spindown_script="/usr/local/bin/zfs-usb-spindown.sh"
state_path="/var/lib/zfs-usb-replication/status.json"
state_writer="/usr/local/bin/zfs_usb_replication_state.py"
retention_script="/usr/local/bin/zfs_usb_snapshot_retention.py"
exportfs_lock_dir="/etc/exports.d"
set_canmount_off_for_readonly_recursive_targets="true"
anchor_helper="/usr/local/bin/zfs_usb_bookmark_anchors.py"
anchor_state_path="/var/lib/zfs-usb-replication/anchors.json"

# Drives of the offsite rotation. They share one pool name, so each present
# drive is imported, replicated and exported on its own.
device_names=(
  "owned-a"
  "owned-b"
)
device_paths=(
  "/dev/disk/by-id/owned-a"
  "/dev/disk/by-id/owned-b"
)
device_pool_guids=(
  "1234"
  ""
)

# write_state RESULT EXIT_CODE DEVICE_INDEX|"" [writer args...]
write_state() {
  local result="$1"
  local exit_code="$2"
  local index="$3"
  shift 3
  local -a device_args=()
  if [[ -n "${index}" ]]; then
    device_args=(--device-path "${device_paths[$index]}")
    if [[ -n "${device_names[$index]}" ]]; then
      device_args+=(--device-name "${device_names[$index]}")
    fi
  else
    device_args=(--device-path "$(IFS=,; echo "${device_paths[*]}")")
  fi
  if [[ -x "${state_writer}" ]]; then
    if ! "${state_writer}" \
      --state-path "${state_path}" \
      --result "${result}" \
      --exit-code "${exit_code}" \
      --pool "${pool}" \
      "${device_args[@]}" \
      "$@"; then
      logger -t "${log_tag}" "Failed to persist USB replication state (${result})"
      return 1
    fi
  else
    logger -t "${log_tag}" "USB replication state writer not executable: ${state_writer}"
    return 1
  fi
}

device_label() {
  local index="$1"
  if [[ -n "${device_names[$index]}" ]]; then
    printf '%s (%s)' "${device_names[$index]}" "${device_paths[$index]}"
  else
    printf '%s' "${device_paths[$index]}"
  fi
}

# Print the -d arguments that restrict a pool import to one drive, so a second
# attached drive carrying the same pool name can never be picked up instead.
import_search_args() {
  local device="$1"
  local found=false
  local member
  for member in "${device}"-part*; do
    if [[ -e "${member}" ]]; then
      printf '%s\n' "-d" "${member}"
      found=true
    fi
  done
  if [[ "${found}" != "true" ]]; then
    printf '%s\n' "-d" "${device}"
  fi
}

pool_imported() {
  zpool list -H -o name 2>/dev/null | grep -qx "${pool}"
}

# True when the imported pool has a vdev on this drive (whole disk or one of
# its partitions), compared by resolved device node.
pool_on_device() {
  local device="$1"
  local device_real vdev vdev_real
  device_real="$(readlink -f "${device}" 2>/dev/null || true)"
  [[ -n "${device_real}" ]] || return 1
  while IFS= read -r vdev; do
    [[ "${vdev}" == /* ]] || continue
    vdev_real="$(readlink -f "${vdev}" 2>/dev/null || true)"
    if [[ "${vdev_real}" == "${device_real}" || "${vdev_real}" =~ ^${device_real}p?[0-9]+$ ]]; then
      return 0
    fi
  done < <(zpool list -v -H -P "${pool}" 2>/dev/null | awk -F'\t' '{print $2}')
  return 1
}

# Runs in its own subshell per drive. Its variables are deliberately not local:
# the EXIT trap (finish) runs after the function returned and still needs them.
replicate_device() {
  index="$1"
  device="${device_paths[$index]}"
  expected_guid="${device_pool_guids[$index]}"
  label="$(device_label "${index}")"
  pool_preexisting=false
  observed_guid=""
  signal_exit_code=0

  handle_signal() {
    signal_exit_code="$1"
    exit "${signal_exit_code}"
  }
  finish() {
    local exit_code=$?
    if [[ ${signal_exit_code} -ne 0 ]]; then
      exit_code=${signal_exit_code}
    fi
    local -a usage_args=()
    local export_failed=false
    trap - EXIT
    if pool_imported && pool_on_device "${device}"; then
      local usage_line
      usage_line=$(zpool list -Hp -o size,alloc,free "${pool}" 2>/dev/null || true)
      if [[ -n "${usage_line}" ]]; then
        local size_bytes alloc_bytes free_bytes
        IFS=$'\t' read -r size_bytes alloc_bytes free_bytes <<< "${usage_line}"
        if [[ "${size_bytes}" =~ ^[0-9]+$ && "${alloc_bytes}" =~ ^[0-9]+$ && "${free_bytes}" =~ ^[0-9]+$ ]]; then
          usage_args=(
            --size-bytes "${size_bytes}"
            --alloc-bytes "${alloc_bytes}"
            --free-bytes "${free_bytes}"
          )
        fi
      fi
      if [[ "${pool_preexisting}" == "true" && "${force_export}" != "true" ]]; then
        :
      else
        logger -t "${log_tag}" "Exporting pool ${pool} from ${label}"
        zfs unmount -r "${pool}" >/dev/null 2>&1 || true
        if ! zpool export "${pool}" >/dev/null 2>&1; then
          export_failed=true
          logger -t "${log_tag}" "Failed to export pool ${pool} from ${label}"
        fi
      fi
    fi
    if [[ -n "${observed_guid}" ]]; then
      usage_args+=(--pool-guid "${observed_guid}")
    fi
    if [[ "${export_failed}" == "true" && ${exit_code} -eq 0 ]]; then
      exit_code=1
    fi
    if [[ ${exit_code} -eq 0 ]]; then
      if ! write_state "success" 0 "${index}" "${usage_args[@]}"; then
        exit_code=1
      fi
    else
      write_state "failed" "${exit_code}" "${index}" "${usage_args[@]}" || true
    fi
    exit "${exit_code}"
  }
  trap finish EXIT
  trap 'handle_signal 129' HUP
  trap 'handle_signal 130' INT
  trap 'handle_signal 143' TERM

  if pool_imported; then
    if ! pool_on_device "${device}"; then
      logger -t "${log_tag}" "Pool ${pool} is already imported from another device; cannot replicate to ${label}"
      exit 1
    fi
    pool_preexisting=true
  else
    local -a search_args=()
    mapfile -t search_args < <(import_search_args "${device}")
    if [[ -n "${expected_guid}" ]]; then
      logger -t "${log_tag}" "Importing pool ${pool} (guid ${expected_guid}) from ${label}"
      zpool import "${search_args[@]}" -o cachefile=none "${expected_guid}"
    else
      logger -t "${log_tag}" "Importing pool ${pool} from ${label}"
      zpool import "${search_args[@]}" -o cachefile=none "${pool}"
    fi
  fi

  observed_guid=$(zpool get -H -o value guid "${pool}" 2>/dev/null || echo "")
  if [[ -n "${expected_guid}" && "${observed_guid}" != "${expected_guid}" ]]; then
    logger -t "${log_tag}" "Pool ${pool} on ${label} has guid ${observed_guid}, expected ${expected_guid}; refusing to replicate"
    exit 1
  fi

  keystatus=$(zfs get -H -o value keystatus "${pool}" 2>/dev/null || echo "")
  if [[ "${keystatus}" != "available" ]]; then
    logger -t "${log_tag}" "Loading key for pool ${pool}"
    zfs load-key -L "file://${key_path}" "${pool}"
  fi

  mkdir -p "${exportfs_lock_dir}"

  if [[ "${set_canmount_off_for_readonly_recursive_targets}" == "true" ]]; then
    :
    if zfs list -H -o name "tank/owned" >/dev/null 2>&1; then
      job_canmount=$(zfs get -H -o value canmount "tank/owned" 2>/dev/null || echo "")
      job_readonly=$(zfs get -H -o value readonly "tank/owned" 2>/dev/null || echo "")
      if [[ "${job_readonly}" == "on" && "${job_canmount}" != "off" ]]; then
        logger -t "${log_tag}" "Setting canmount=off on readonly recursive target tank/owned"
        zfs set canmount=off "tank/owned"
      fi
    fi
  fi

  zfs mount -a

  logger -t "${log_tag}" "Applying snapshot retention: vault/owned (60 days)"
  "${retention_script}" --source "tank/owned" --target "vault/owned" --keep-days "60" --prefix "autosnap_" --prefix "syncoid_"

  freeing_bytes=$(zpool get -Hp -o value freeing "${pool}" 2>/dev/null || echo 0)
  if [[ "${freeing_bytes}" =~ ^[0-9]+$ && ${freeing_bytes} -gt 0 ]]; then
    logger -t "${log_tag}" "Waiting for ${freeing_bytes} bytes of asynchronous frees on ${pool}"
    zpool wait -t free "${pool}"
  fi

  if [[ -x "/usr/local/bin/zfs-syncoid-abort-partial-receive.sh" ]]; then
    "/usr/local/bin/zfs-syncoid-abort-partial-receive.sh" "tank/owned" "true"
  else
    logger -t "${log_tag}" "WARNING: abort-partial-receive script not found at /usr/local/bin/zfs-syncoid-abort-partial-receive.sh"
  fi
  logger -t "${log_tag}" "Running syncoid: fast/owned -> tank/owned"
  "${syncoid_bin}" --recursive --recvoptions="o readonly=on" --force-delete --no-sync-snap --no-sync-snap fast/owned tank/owned
  logger -t "${log_tag}" "Running syncoid: fast/second -> tank/second"
  "${syncoid_bin}" --no-sync-snap --no-rollback fast/second tank/second

  logger -t "${log_tag}" "Recording incremental anchors for ${label}"
  "${anchor_helper}" \
    --state-path "${anchor_state_path}" \
    --device-name "${device_names[$index]}" \
    --rotation-device "owned-a" \
    --rotation-device "owned-b" \
    --job "fast/owned" "tank/owned" "true" \
    --job "fast/second" "tank/second" "false" \
    --prune-prefix "autosnap_" \
    --prune-prefix "syncoid_" \
    

  logger -t "${log_tag}" "USB replication complete for pool ${pool} on ${label}"
}

if [[ -z "${pool}" || -z "${device_paths[0]:-}" ]]; then
  logger -t "${log_tag}" "Missing device or pool configuration; aborting."
  exit 1
fi

present=()
present_count=0
for index in "${!device_paths[@]}"; do
  if [[ -e "${device_paths[$index]}" ]]; then
    present+=("${index}")
    present_count=$((present_count + 1))
  fi
done

if [[ ${present_count} -eq 0 ]]; then
  logger -t "${log_tag}" "USB device $(IFS=,; echo "${device_paths[*]}") not present; skipping replication."
  for index in "${!device_paths[@]}"; do
    if [[ -n "${device_names[$index]}" ]]; then
      write_state "skipped_absent" 0 "${index}" --device-only || true
    fi
  done
  write_state "skipped_absent" 0 ""
  exit 0
fi

for index in "${!device_paths[@]}"; do
  if [[ ! -e "${device_paths[$index]}" && -n "${device_names[$index]}" ]]; then
    logger -t "${log_tag}" "USB device $(device_label "${index}") not present; skipping it."
    write_state "skipped_absent" 0 "${index}" --device-only || true
  fi
done

# A signal stops the loop after the running drive recorded its failure.
parent_signal=0
trap 'parent_signal=129' HUP
trap 'parent_signal=130' INT
trap 'parent_signal=143' TERM

overall_rc=0
for index in "${present[@]}"; do
  # Run each drive in its own subshell, outside any conditional context so
  # errexit (re-enabled inside) still applies, and so its EXIT trap exports
  # that drive's pool before the next drive is imported.
  set +e
  ( set -e; replicate_device "${index}" )
  rc=$?
  set -e
  if [[ ${rc} -ne 0 && ${overall_rc} -eq 0 ]]; then
    overall_rc=${rc}
  fi
  if [[ ${parent_signal} -ne 0 ]]; then
    exit "${parent_signal}"
  fi
done

if [[ ${overall_rc} -ne 0 ]]; then
  exit "${overall_rc}"
fi

if [[ "${spindown_enabled}" == "true" ]]; then
  if [[ -x "${spindown_script}" ]]; then
    "${spindown_script}" || true
  else
    logger -t "${log_tag}" "Spindown script not executable: ${spindown_script}"
  fi
fi
