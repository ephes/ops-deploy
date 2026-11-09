set -u
# deploy.py runs this with PATH=/usr/bin:/bin:/usr/sbin:/sbin, so id, launchctl,
# grep and rm are /usr/bin/id, /bin/launchctl, /usr/bin/grep and /bin/rm.
owner=$1
label=$2
plist=$3
retired=$4

fail() {
  printf 'voice-memo-work: %s\n' "$1" >&2
  exit 1
}

uid=$(id -u "${owner}") || fail 'owner uid is unavailable'
domain="gui/${uid}"
service="${domain}/${label}"
absent="Could not find service \"${label}\" in domain for user gui: ${uid}"

# 0: the owner's Aqua domain exists; 112: logged out (no domain to probe).
domain_rc=0
launchctl print "${domain}" >/dev/null 2>&1 || domain_rc=$?
if [ "${domain_rc}" -ne 0 ] && [ "${domain_rc}" -ne 112 ]; then
  fail "GUI domain probe returned ${domain_rc}"
fi

loaded_rc=113
if [ "${domain_rc}" -eq 0 ]; then
  loaded_rc=0
  loaded_err=$(launchctl print "${service}" 2>&1 >/dev/null) || loaded_rc=$?
  if [ "${loaded_rc}" -ne 0 ]; then
    if [ "${loaded_rc}" -ne 113 ] ||
      ! printf '%s\n' "${loaded_err}" | grep -F -q -- "${absent}"; then
      fail "loaded-state probe returned ${loaded_rc}"
    fi
  fi
fi

launchctl disable "${service}" || fail 'launchctl disable failed'

booted_out=0
if [ "${domain_rc}" -eq 0 ] && [ "${loaded_rc}" -eq 0 ]; then
  launchctl bootout "${service}" || fail 'launchctl bootout failed'
  booted_out=1
fi

plist_removed=0
if [ "${domain_rc}" -eq 0 ]; then
  verify_rc=0
  verify_err=$(launchctl print "${service}" 2>&1 >/dev/null) || verify_rc=$?
  if [ "${verify_rc}" -ne 113 ] ||
    ! printf '%s\n' "${verify_err}" | grep -F -q -- "${absent}"; then
    fail "label is not proven unloaded (rc=${verify_rc})"
  fi
  # Only once the label is proven unloaded; the database, cutoff and logs stay.
  if [ "${retired}" = true ]; then
    if [ -d "${plist}" ] && [ ! -L "${plist}" ]; then
      fail 'the retired plist path is a directory'
    fi
    if [ -e "${plist}" ] || [ -L "${plist}" ]; then
      rm -f -- "${plist}" || fail 'removing the retired plist failed'
      plist_removed=1
    fi
  fi
fi

if [ "${domain_rc}" -eq 0 ]; then
  domain_state=available
else
  domain_state=logged_out
fi
printf 'DAYBOOK_VOICE_MEMO_WORK_DISABLED domain=%s booted_out=%s plist_removed=%s\n' \
  "${domain_state}" "${booted_out}" "${plist_removed}"
