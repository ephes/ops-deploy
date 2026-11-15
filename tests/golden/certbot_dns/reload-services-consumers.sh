#!/bin/bash
set -uo pipefail

# Managed by Ansible - commands run after certificate renewal

hook_status=0
(
  set -e
systemctl restart traefik
)
hook_rc=$?
if [ "$hook_rc" -ne 0 ]; then
  printf 'Certbot renewal hook item 1 failed (rc=%s) lineage=%s\n' \
    "$hook_rc" "${RENEWED_LINEAGE:-unknown}" >&2
  hook_status=1
fi
(
  set -e
systemctl reload postfix@-
)
hook_rc=$?
if [ "$hook_rc" -ne 0 ]; then
  printf 'Certbot renewal hook item 2 failed (rc=%s) lineage=%s\n' \
    "$hook_rc" "${RENEWED_LINEAGE:-unknown}" >&2
  hook_status=1
fi
(
  set -e
systemctl reload dovecot
)
hook_rc=$?
if [ "$hook_rc" -ne 0 ]; then
  printf 'Certbot renewal hook item 3 failed (rc=%s) lineage=%s\n' \
    "$hook_rc" "${RENEWED_LINEAGE:-unknown}" >&2
  hook_status=1
fi
exit "$hook_status"
