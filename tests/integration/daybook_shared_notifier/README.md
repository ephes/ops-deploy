# Owned Linux shared-notifier installer proof

This fixture requires a disposable GitHub-hosted Linux VM as root and the exact
immutable Git package. It verifies every installed resource and noneditable
provenance. The fixed notifier script, private config and root authorized_keys
must all be absent before the fixture starts; preexisting private files cause
refusal before any work. Existing managed parent directories must have their
original root modes. Cleanup removes only the fixture-created fixed files,
newly-created directories and unique scratch tree, recording absence.

Eight phases cover fresh installation, genuine managed repeat, a source update
preserving formatted configuration and unrelated administrator authorizations,
conflicting dedicated options, a foreign notifier marker, symlink, hardlink and
invalid source. The synthetic source writes a sentinel if executed: the sentinel
must remain absent. No real notification, Docker, SSH session or application
payload is invoked. Source validation is compile-only. Local tests separately
exercise descriptor changes and interrupted atomic publication.

Every successful phase uses the real SDK local connector, private stdin,
injected packaged helper and fixed original paths. Repeats are managed
validation, not zero-operation claims. Expected refusal phases occur in status
validation before the managed operation. These native results do not establish
production endpoint continuity or phone delivery; protected actual observations
and normal inventory deployment remain separate qualification steps.
