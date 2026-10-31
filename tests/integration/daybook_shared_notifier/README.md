# Owned Linux shared-notifier installer proof

This fixture runs as root inside a disposable Ubuntu 24.04 Docker container on
a GitHub-hosted Linux VM, using the exact immutable Git package. The checkout and
UV executable are read-only mounts; only a unique evidence/scratch parent is
writable from the host. The host root authorization is never read or mounted.
The owned container and unique image tag are removed on exit, including fixture
failure; the wrapper records cleanup failure separately. Shared Ubuntu base-image
and builder caches are left intact. A preexisting container/image name is refused
before any cleanup trap is installed. Local Docker-double controls exercise
success, failed fixture, both name collisions and failed cleanup. It verifies every installed resource and noneditable
provenance. The fixed notifier script, private config and root authorized_keys
must all be absent before the fixture starts; preexisting private files cause
refusal before any work. Existing managed parent directories must have their
original root modes. Cleanup removes only the fixture-created fixed files,
newly-created directories and unique scratch tree, recording absence.

Eight phases cover fresh installation, genuine managed repeat, a source update
preserving formatted configuration and unrelated administrator authorizations,
conflicting dedicated options, a foreign notifier marker, symlink, hardlink and
invalid source. The synthetic source writes a sentinel if executed: the sentinel
must remain absent. No real notification, gateway Docker command, SSH session or application
payload is invoked. Docker is used only to isolate the disposable test filesystem. Source validation is compile-only. Local tests separately
exercise descriptor changes and interrupted atomic publication.

Every successful phase uses the real SDK local connector, private stdin,
injected packaged helper and fixed original paths. Repeats are managed
validation, not zero-operation claims. Expected refusal phases occur in status
validation before the managed operation. These native results do not establish
production endpoint continuity or phone delivery; protected actual observations
and normal inventory deployment remain separate qualification steps.
