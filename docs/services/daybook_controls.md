# Daybook launchd operators

`DaybookControlConfig` and `run_daybook_control` provide the original explicit
Photos/archive emergency disable and attention plist removal operations.
They do not install or update application source, invoke Daybook, inspect media,
read configuration/state/log bodies, or change any other launchd label.

| Field | Default and contract |
| --- | --- |
| `service` | Required: `photos`, `archive`, or `attention` |
| `action` | `disable` for Photos/archive; `remove` for attention |
| `owner` | Required original non-root GUI owner |
| `home` | Derived `/Users/<owner>`; alternate production paths refused |
| `label` | Derived original fixed service label; alternate labels refused |
| `confirmed` | Strict boolean, default false; attention removal requires true |

```python
from ops_deploy.services.daybook_controls import DaybookControlConfig, run_daybook_control

run_daybook_control(DaybookControlConfig(service="photos", action="disable", owner="jochen"))
```

Photos and attention retain their original root connection; archive retains its
original direct owner connection. Every fact and operation clears all inherited
privilege switches and refuses a different connecting UID before any change.
Only the selected owner's GUI domain and exact label are controlled. Attention
removal checks its original path lineage, proves the label disabled/unloaded,
and removes only that single regular plist with one link through its directory fd.
It retains the complete installation, configuration, authentication, state and
logs. Links, unexpected file types and loss of the GUI domain fail closed.

Each call performs one managed operator sequence, including repeat cleanup
attempts. A repeat is not read-only or a zero-managed-operation claim. Photos
still tries both disable and bootout after a disable failure; archive/attention
retain immediate disable failure. Archive retains its original bounded unload
wait. No existing business confirmation or activation policy is weakened.

The disposable native proof uses fixture-created sleep jobs and synthetic
protected files. It validates original declarations, then deliberately uses
`model_copy` for owned homes/unique labels; those substitutions are not
revalidated. Its receipt states that mechanism-only scope. Original production
home/label validation is tested separately. The inherited owned root transport
may install rsync on the disposable VM; the operator itself transfers no file.
No inventory removal, restoration, application or real data operation is part
of this source proof, and no default service migration is claimed.
