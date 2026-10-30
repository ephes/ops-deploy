# Disabled Daybook voice-memo attention installation

`services.daybook_voice_memo_attention` ports the original disabled wheel
installation. `DaybookVoiceMemoAttentionConfig` keeps all original defaults in
`defaults.json`; the original disabled launchd template is retained byte for byte.
It accepts a prepared controller-local `daybook-*.whl`, a non-root GUI owner and
an explicitly disabled private configuration. The component provides no
activation, discovery, initialization, baseline, model or notification API.

```python
from ops_deploy.services.daybook_voice_memo_attention import (
    DaybookVoiceMemoAttentionConfig,
    install_daybook_voice_memo_attention,
)

install_daybook_voice_memo_attention(
    DaybookVoiceMemoAttentionConfig(
        daybook_voice_memo_attention_service_user="example",
        daybook_voice_memo_attention_wheel_src="/private/build/daybook-0.0.0-py3-none-any.whl",
        daybook_voice_memo_attention_config={
            "version": 1,
            "enabled": False,
            "profile": "synthetic",
            "state_path": "/Users/example/.local/state/daybook/voice-memo-attention/state.sqlite3",
            "source": {"kind": "synthetic"},
        },
    )
)
```

Installation resolves the original owner GUI domain, disables and unloads only
the attention label, and verifies that state before changing files. It installs
the exact configured uv-managed Python patch into the shared root-owned Daybook
Python tree and creates the separate root-owned virtual environment. A venv
built on another interpreter is replaced without executing its old Python.
The supplied wheel is installed with its declared dependencies. This preserves
the original worktree-wheel contract; it does not assert a locked dependency
environment or an application release pin.

The original isolated `import daybook.attention` runs as the GUI owner from that
owner's home, after root-code metadata admission. This application import is a
managed operation on every converge. A repeat therefore retains that real work;
it is not described as zero managed changes. Pure planning checks never import
the application. The successful wheel receipt is published only after the
actual import succeeds. Failed installation keeps the label disabled/unloaded
and preserves the prior receipt, runtime state, activation records and logs.
Recovering with a corrected wheel transfers its current bytes before installing
the environment, including recovery within the same controller process.
The import retains the original role's unbounded command lifetime. No new
deadline is imposed on application code during this compatibility migration.

The supplied disabled configuration is a fresh-install seed. An existing valid,
disabled synthetic or production configuration remains byte for byte unchanged,
including formatting, owner, permissions, inode and modification timestamps.
The target validates its bounded contents against the application configuration
shape in memory; it never opens the referenced reader credentials or follows
transport or activation references. Unsafe or enabled configurations fail before
managed installation work. Missing configuration is published with no-replace
semantics: a concurrent creator wins and its disabled configuration is validated
without overwriting it. This intentionally fixes the original template overwrite
behavior, which could replace a retired production configuration with the
synthetic fresh-install default. The public controller model remains unchanged:
an existing valid configuration is authoritative, so an unused supplied seed
does not block its preservation. A malformed fresh seed is refused by target
validation before publication. Activation remains a separate operator action.

Private seed configuration travels on protected stdin.
No private configuration checksum, application output or exception detail is
published. The disabled plist retains `RunAtLoad`, failed-exit `KeepAlive` and
the original 900-second throttle, but is never bootstrapped or enabled. The
component reads no tracking database, recording, memo, provider session or log
body. An operator must preserve any separately documented retirement and
activation policy when binding this component.

Source tests cover the original declarations, actual controller operation
ordering, disabled/unload failures, old-interpreter rebuild, managed GUI import
and failed-import receipt continuity, existing disabled configuration/authentication
continuity, unsafe/enabled configuration refusal and real no-replace publication
races. The owned macOS fixture repeats those configuration cases through actual
SSH and runs an inert wheel import on every successful converge. Disposable native mechanism qualification
and a real inventory migration remain separate evidence; source tests alone do
not establish either.
