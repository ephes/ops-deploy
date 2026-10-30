set -eu
label=$1
plist=$2
changed=0

if ! launchctl print-disabled system | grep -E -q "\"${label}\" => (true|disabled)"; then
  launchctl disable "system/${label}"
  changed=1
fi

if launchctl print "system/${label}" >/dev/null 2>&1; then
  launchctl bootout system "${plist}"
  changed=1
fi

launchctl print-disabled system | grep -E -q "\"${label}\" => (true|disabled)"
if launchctl print "system/${label}" >/dev/null 2>&1; then
  echo 'reconcile LaunchDaemon is still loaded' >&2
  exit 1
fi

if [ "${changed}" -eq 1 ]; then
  echo DAYBOOK_RECONCILE_DISABLED_CHANGED
else
  echo DAYBOOK_RECONCILE_ALREADY_DISABLED
fi
