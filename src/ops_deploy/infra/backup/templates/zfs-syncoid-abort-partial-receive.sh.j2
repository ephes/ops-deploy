#!/usr/bin/env bash
set -euo pipefail
# Abort any partial ZFS receive on a target dataset (and optionally its descendants).
# Usage: zfs-syncoid-abort-partial-receive.sh <target_dataset> [recursive]
#
# Exit 0 always — partial receives that are aborted are logged, datasets
# without a pending receive are silently skipped.

log_tag="zfs-syncoid-abort-partial"
target="${1:-}"
recursive="${2:-false}"

if [[ -z "${target}" ]]; then
  logger -t "${log_tag}" "Usage: ${0} <target_dataset> [recursive]"
  exit 1
fi

abort_if_pending() {
  local ds="${1}"
  # zfs get -H -o value receive_resume_token returns "-" when there is no
  # pending receive, and a base64 token string when there is one.
  local token
  token="$(zfs get -H -o value receive_resume_token "${ds}" 2>/dev/null || echo "-")"
  if [[ "${token}" != "-" && -n "${token}" ]]; then
    logger -t "${log_tag}" "Aborting partial receive on ${ds}"
    local abort_output abort_rc
    abort_output="$(zfs receive -A "${ds}" 2>&1)" && abort_rc=0 || abort_rc=$?
    if [[ ${abort_rc} -eq 0 ]]; then
      logger -t "${log_tag}" "Successfully aborted partial receive on ${ds}"
    else
      logger -t "${log_tag}" "WARNING: zfs receive -A on ${ds} exited ${abort_rc}: ${abort_output}"
    fi
  fi
}

if [[ "${recursive}" == "true" ]]; then
  # Process the target and all descendants
  while IFS= read -r ds; do
    abort_if_pending "${ds}"
  done < <(zfs list -r -H -o name "${target}" 2>/dev/null || echo "${target}")
else
  abort_if_pending "${target}"
fi
