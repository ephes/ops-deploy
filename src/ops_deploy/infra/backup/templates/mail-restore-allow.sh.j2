#!/usr/bin/env bash
set -euo pipefail

log_tag="mail-restore-rsync-auth"
original_command="${SSH_ORIGINAL_COMMAND:-}"

deny() {
  logger -t "${log_tag}" "Denied command: ${original_command}"
  echo "Access denied." >&2
  exit 1
}

[[ -n "${original_command}" ]] || deny

if [[ "${original_command}" == "zfs list -t snapshot -o name,creation -s creation tank/backups/mail" ]]; then
  exec /usr/sbin/zfs list -t snapshot -o name,creation -s creation tank/backups/mail
fi

if [[ "${original_command}" == "zfs list tank/backups/mail" ]]; then
  exec /usr/sbin/zfs list tank/backups/mail
fi

if [[ "${original_command}" == "zfs list tank/restore" ]]; then
  exec /usr/sbin/zfs list tank/restore
fi

if [[ "${original_command}" == "zfs create tank/restore" ]]; then
  exec /usr/sbin/zfs create tank/restore
fi

if [[ "${original_command}" =~ ^zfs[[:space:]]+clone[[:space:]]+tank/backups/mail@([A-Za-z0-9_.:-]+)[[:space:]]+tank/restore/mail$ ]]; then
  snapshot_name="${BASH_REMATCH[1]}"
  exec /usr/sbin/zfs clone "tank/backups/mail@${snapshot_name}" "tank/restore/mail"
fi

if [[ "${original_command}" == "zfs destroy tank/restore/mail" ]]; then
  exec /usr/sbin/zfs destroy tank/restore/mail
fi

read -r -a cmd_parts <<< "${original_command}"
cmd_count="$(printf '%s\n' "${cmd_parts[@]}" | wc -l | tr -d ' ')"
[[ "${cmd_count}" -ge 5 ]] || deny
[[ "${cmd_parts[0]}" == "rsync" ]] || deny
[[ "${cmd_parts[1]}" == "--server" ]] || deny
[[ "${cmd_parts[2]}" == "--sender" ]] || deny

requested_path="${cmd_parts[-1]}"
requested_path="${requested_path%/}"
requested_path="${requested_path%/.}"
[[ "${requested_path}" == /* ]] || deny
[[ "${requested_path}" == *".."* ]] && deny
[[ "${requested_path}" == *"//"* ]] && deny

case "${requested_path}" in
  /tank/backups/mail|/tank/backups/mail/vmail|/tank/backups/mail/vmail/*|/tank/backups/mail/stage|/tank/backups/mail/stage/*|/tank/restore/mail|/tank/restore/mail/vmail|/tank/restore/mail/vmail/*|/tank/restore/mail/stage|/tank/restore/mail/stage/*) ;;
  *) deny ;;
esac

exec /usr/bin/rsync "${cmd_parts[@]:1}"
