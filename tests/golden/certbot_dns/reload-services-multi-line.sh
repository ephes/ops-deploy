#!/bin/bash
set -uo pipefail

# Managed by Ansible - commands run after certificate renewal

hook_status=0
(
  set -e
one
)
hook_rc=$?
if [ "$hook_rc" -ne 0 ]; then
  printf 'Certbot renewal hook item 1 failed (rc=%s) lineage=%s\n' \
    "$hook_rc" "${RENEWED_LINEAGE:-unknown}" >&2
  hook_status=1
fi
(
  set -e
two
three
)
hook_rc=$?
if [ "$hook_rc" -ne 0 ]; then
  printf 'Certbot renewal hook item 2 failed (rc=%s) lineage=%s\n' \
    "$hook_rc" "${RENEWED_LINEAGE:-unknown}" >&2
  hook_status=1
fi
(
  set -e
printf "%s\n" x

)
hook_rc=$?
if [ "$hook_rc" -ne 0 ]; then
  printf 'Certbot renewal hook item 3 failed (rc=%s) lineage=%s\n' \
    "$hook_rc" "${RENEWED_LINEAGE:-unknown}" >&2
  hook_status=1
fi
exit "$hook_status"
