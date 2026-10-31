# Shared Daybook notifier endpoint

`services.daybook_voice_memo_attention_notifier` installs the existing standalone,
recipient-pinned forced-command endpoint. The service name is historical: use
Daybook's `work_notify.py` for the shared interactive-work endpoint, not the
retired reviewer's `attention_notify.py`. An explicitly supplied standalone
source remains supported. Installation does not activate an application or send
a notification, and deployment success does not imply phone acceptance.

```python
from ops_deploy.services.daybook_voice_memo_attention_notifier import (
    DaybookVoiceMemoAttentionNotifierConfig,
    DaybookVoiceMemoAttentionNotifierPins,
    install_daybook_voice_memo_attention_notifier,
)

install_daybook_voice_memo_attention_notifier(
    DaybookVoiceMemoAttentionNotifierConfig(script_src="/prepared/work_notify.py"),
    pins=DaybookVoiceMemoAttentionNotifierPins(
        public_key=secrets["public_key"],
        native_host=secrets["native_host"],
        recipient=secrets["recipient"],
    ),
)
```

The original Linux/root contract and fixed paths remain:

| Resource | Owner/mode |
| --- | --- |
| `/usr/local/libexec` | root/root `0755` |
| `/usr/local/libexec/daybook-attention-notify.py` | root/root `0755` |
| `/etc/daybook-attention-notify.json` | root/root `0600` |
| `/root/.ssh` | root/root `0700` |
| `/root/.ssh/authorized_keys` | root/root `0600` |

`/usr/local` must already exist. Managed paths reject links, hard-linked files,
non-root ownership and group/world writable resources. The existing `openclaw-gateway`
container is fixed; there is no Docker operation. Key, native-host and numeric
recipient validation preserve the original role's constraints. The dedicated
Ed25519 authorization has exactly the original `restrict,command=...` options.
Same-key/different-options and another live notifier-marked key retain the
original role refusals. Existing same-key/same-options duplicate lines remain
accepted and keep their original bytes and metadata. Unrelated administrator keys and comments are
preserved. Key rotation requires deliberate removal of the old authorization.

The controller freezes the source once through a bounded regular-file descriptor,
refusing replacement, growth, symlinks and nonregular input without blocking.
The same frozen payload feeds status and managed installation.

The status fact checks only bounded fixed resources and compiles the prepared
source without importing/executing it or writing bytecode. It creates no path
and performs no managed convergence. The normal installer runs one genuine
managed validation on every deployment, including repeat. That step repeats
validation, atomically publishes changed resources and verifies the resulting
state. A fully current repeat reports `changed=false` from the helper but still
counts as managed work.

Existing semantically exact private configuration and exact authorization keep
their original bytes and metadata, including JSON formatting and unrelated keys.
This intentionally fixes unconditional configuration reserialization during
migration. Fresh installation seeds the original three config pins using the original
Ansible JSON formatting and adds
only the dedicated key. Explicitly changed desired config pins still converge;
conflicting authorization refuses. Source is bounded to 128 KiB, private config
to 8 KiB and authorized keys to 128 KiB. Private pins, config and keys stay in
RAM/stdin, never command arguments or diagnostics. Only fixed status booleans
and result categories leave the target helper.

The managed script is syntax-compiled, never imported or executed by installation.
No application state, caller payload, audio/model data or notification ledger is
read. Current shared-source security fixes and production file preservation
require separate source and protected inventory qualification; this public
component alone does not claim those outcomes.

Paired original-role controls evaluate the actual Ansible Templar validation and
key-conflict expressions and execute the actual `ansible.posix.authorized_key`
module transition algorithm against owned temporary files. They compare fresh,
existing administrator and current dedicated-key semantics plus conflict
refusals. Existing JSON formatting and whole-file authorization bytes are
intentionally preserved more strictly; this is not a claim of universal original
byte equality. Run the optional oracle with `OPS_LIBRARY_PATH` and
`ANSIBLE_POSIX_MODULE` pointing to the owned original collection module, with
`ansible-core` available in that same test interpreter. These are test tools, not
product dependencies.
