#!/usr/bin/env bash
set -euo pipefail

unit_name="${1:-unknown}"
subject="[mail-offsite] ${unit_name} failed on $(hostname -s)"

journal_output="$(journalctl -u "${unit_name}" -n 200 --no-pager --output=short-iso || true)"

mail_body=$(cat <<MAIL
Mail offsite replication failure
Host: $(hostname -f)
Unit: ${unit_name}
Time: $(date -Is)

Last 200 journal lines:
${journal_output}
MAIL
)

echo "${mail_body}" | mail -s "${subject}" "root"
