# Dedicated Daybook attention reader access

`services.daybook_voice_memo_attention_reader` installs the original fixed-policy MinIO
provisioner and runs it with private credentials on stdin. This is the dedicated
voice-memo prefix reader. Its IAM identity and the
application retirement state are separate: installing or verifying this identity
does not activate the reviewer, discovery, approval or any LaunchAgent.

```python
from ops_deploy.services.daybook_voice_memo_attention_reader import (
    DaybookVoiceMemoAttentionReaderConfig,
    DaybookVoiceMemoAttentionReaderCredentials,
    install_daybook_voice_memo_attention_reader,
)

install_daybook_voice_memo_attention_reader(
    DaybookVoiceMemoAttentionReaderConfig(),
    DaybookVoiceMemoAttentionReaderCredentials(
        access_key=secrets["access_key_id"],
        secret_key=secrets["secret_access_key"],
    ),
)
```

The original defaults are `mc_bin=/usr/local/bin/mc`, `alias=local`,
`python=/usr/bin/python3`, and
`state_dir=/var/lib/daybook-voice-memo-attention-reader`. Execution requires Linux and
root. The directory and installed public helper converge to root-owned `0700`.
The original provisioner is packaged byte for byte, including its exclusive
`0600` provisioning lock and credential-ownership marker.

The fixed `daybook-voice-memo-attention-read` policy permits only `s3:ListBucket`
on `obsidian` with the exact `Inbox/Voice Memos/` prefix, and `s3:GetObject` only
on `obsidian/Inbox/Voice Memos/*`. An owned existing user must be
enabled, have exactly that policy, no groups, and matching marker fingerprints.
Disabled users, changed credentials, broader policies, foreign users, unsafe
markers and partial creation are refused. Installation never enables an
existing disabled identity or silently updates its secret. Only a proven-absent
fresh identity can be created; partial effects remain visible for recovery.

Global dry planning only inspects ordinary directory/helper metadata and queues
provisioning. It never calls the provisioner as a fact. A successful repeat
still performs the real managed lock-and-verification operation even when the
helper reports `changed=false`; it is not a zero-operation repeat.

Private credential values stay off controller command lines, environment,
logs and deployment representations. The original remote `mc` contract passes
the dedicated access identifier in user-info and policy-attachment arguments;
user creation receives both credentials on stdin. Raw MinIO responses stay in
the helper, which emits fixed result categories. The original configured MinIO
admin alias must already exist. This component does not list objects, read
object contents, or restart any application or retired LaunchAgent.

Validation includes original role byte/default oracles, managed repeat planning,
owned identity/drift/failure tests and a disposable Ubuntu fixture. The fixture
runs the real helper, file operations, private lock and stdin transport against
a local fake `mc`; it proves these mechanisms without claiming production
MinIO or application qualification.
