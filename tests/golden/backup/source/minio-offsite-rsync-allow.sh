#!/usr/bin/env bash
set -euo pipefail

log_tag="minio-offsite-rsync-auth"
allowed_source="/owned/archive"
original_command="${SSH_ORIGINAL_COMMAND:-}"

deny() {
  logger -t "${log_tag}" "Denied command: ${original_command}"
  echo "Access denied." >&2
  exit 1
}

[[ -n "${original_command}" ]] || deny

read -r -a cmd_parts <<< "${original_command}"
cmd_count="$(printf '%s\n' "${cmd_parts[@]}" | wc -l | tr -d ' ')"
[[ "${cmd_count}" -ge 5 ]] || deny
[[ "${cmd_parts[0]}" == "rsync" ]] || deny
[[ "${cmd_parts[1]}" == "--server" ]] || deny
[[ "${cmd_parts[2]}" == "--sender" ]] || deny

requested_path="${cmd_parts[-1]}"
requested_path="${requested_path%/}"
requested_path="${requested_path%/.}"
[[ "${requested_path}" == "${allowed_source}" ]] || deny

exec /usr/bin/rsync "${cmd_parts[@]:1}"
