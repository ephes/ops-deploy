# Owned Linux attention-reader proof

The workflow runs only on a disposable GitHub-hosted Ubuntu VM as root. It
installs the exact immutable Git implementation, compares every installed
resource against that commit, and uses a unique newly-created fixture directory.
The real installer, original provisioner, file operations, flock and private
stdin transport run normally. A local fake `mc` accepts only the original
commands; it has no network or production credentials. Evidence records command
categories and operation outcomes, not fixture credential values.

Fresh setup creates policy/user/attachment and the private marker. Repeat really
runs managed verification while preserving marker/policy/lock contents and
metadata. Disabled user, broadened policy, extra attachment and foreign marker
refuse without IAM mutation. Partial attachment failure retains the user and
refuses a later silent upsert. Cleanup removes only the newly-created exact
fixture root, with an explicit absence receipt.

This validates native mechanisms, not production MinIO state or data access.
The canonical suite separately covers original-byte/default parity, unsafe
markers, credential change, ambiguous MC responses and managed dry planning.
