# Weeknotes schedule emergency disable

`WeeknotesDisableConfig` and `disable_weeknotes_schedule` port the original
Studio emergency disable of the exact system LaunchDaemon. They do not install
Sessions, read OAuth or application state, stop the operations source, or run
identity preparation, reconciliation, migration, verification or activation.

```python
from ops_deploy.services.daybook_weeknotes_controls import (
    WeeknotesDisableConfig,
    disable_weeknotes_schedule,
)

disable_weeknotes_schedule(WeeknotesDisableConfig())
```

The config fixes `label` to `de.wersdoerfer.daybook.weeknotes-reconcile` and
`plist` to `/Library/LaunchDaemons/<label>.plist`; alternate production values
are refused. The original root connection is required. All SDK facts and the
operator clear inherited sudo, su, doas and dzdo settings explicitly.

The embedded shell preserves the original sequence: inspect the persistent
system disable override, disable only when missing, boot out the original plist
only when the label is loaded, then check the override again and require the
label no longer loaded. It reports only the original changed/already-disabled
metadata token. It never opens the plist, state, lock, authentication, drafts,
comments or quote data. The shell retains the original service-probe semantics;
a nonzero `launchctl print` result is treated as not loaded, independently of
the separate required persistent-disable check.

Every call executes one managed shell sequence, including an already-disabled
repeat. A repeat can avoid both launchd mutations while still being a managed
operator invocation; it is not a read-only fact or zero-managed-operation claim.
The retired timer remains retired. Disabling this label does not stop the
operations supervisor's separate `weeknotes` source.

The disposable native fixture validates the original declarations and then
substitutes a unique owned system label/plist with `model_copy`, without
revalidation. It uses only a fixture-created sleep job, checks protected
synthetic metadata and an unrelated GUI keeper, and proves root/direct-user
transport admission. It checks the exact persistent override and original
first/repeat result tokens, then re-enables the unique owned system label and
proves that its disabled override is cleared during cleanup. This is a mechanism proof; it does not qualify an actual
inventory operator or a default service deployment.
