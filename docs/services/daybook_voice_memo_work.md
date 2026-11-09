# Voice Memo work LaunchAgent (disabled state)

`VoiceMemoWorkConfig` and `apply_voice_memo_work_state` port the disabled branch
of ops-library's `daybook_voice_memo_work_deploy` role: the Studio capable-work
LaunchAgent `de.wersdoerfer.daybook.voice-memo-work` is disabled, unloaded and,
once retired, its plist deleted. Memo work runs as the operations supervisor's
`memo-work` source; this operator only keeps the old timer from running it too.
It never reads or changes the work database, notification state, credentials,
import cutoff or logs.

```python
from ops_deploy.services.daybook_voice_memo_work import (
    VoiceMemoWorkConfig,
    apply_voice_memo_work_state,
)

apply_voice_memo_work_state(VoiceMemoWorkConfig(owner="operator", retired=True))
```

| Field | Default and contract |
| --- | --- |
| `owner` | Required non-root GUI owner |
| `enabled` | Strict boolean, default false. `true` is refused: the role's enabled branch (credentials, cutoff, plist, bootstrap) is not ported |
| `retired` | Strict boolean, default false. `true` also deletes the plist once the label is proven unloaded |
| `home` | Derived `/Users/<owner>`; other values refused |
| `label` | `de.wersdoerfer.daybook.voice-memo-work`; other values refused |
| `plist` | Derived `<home>/Library/LaunchAgents/<label>.plist`; other values refused |

The operator keeps the role's root connection; every fact and the operation
clear inherited sudo, su, doas and dzdo settings, and a non-root connection or
a non-macOS host is refused before any change. One shell sequence follows the
role's disabled branch in order:

1. Resolve the owner's uid and probe its Aqua domain `gui/<uid>`. Exit code 0
   (logged in) and 112 (logged out) are accepted; anything else fails.
2. With the domain present, probe the label: loaded (0) or absent (113 with
   launchd's `Could not find service "<label>" in domain for user gui: <uid>`
   on stderr). Anything else fails before a change.
3. `launchctl disable gui/<uid>/<label>`, always; a failure fails the run.
4. With the domain present and the label loaded, `launchctl bootout`.
5. With the domain present, prove the label absent (113 and the message).
6. Retired and the domain present: delete the plist. A symlink is removed
   without following it; a directory at the plist path fails closed (the role
   would delete it recursively).

With the owner logged out only the disable override is persisted, as in the
role; nothing is proven unloaded and the plist stays. The output is one token,
`DAYBOOK_VOICE_MEMO_WORK_DISABLED domain=<available|logged_out>
booted_out=<0|1> plist_removed=<0|1>`; launchd's own output is never printed.

Every run, including an already retired repeat, executes the sequence (the
role disables on every run), so a repeat is a managed operation, not a
read-only check. `tests/test_daybook_voice_memo_work.py` runs the shell against
shadowed `id`/`launchctl` for every branch and failure, checks the SDK
connection, and with `OPS_LIBRARY_PATH` compares the role's disabled-branch task
order and conditions; `tests/parity/ops_library_roles.json` records the role's
digest.
