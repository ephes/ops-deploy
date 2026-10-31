# Operations API owned Linux qualification

This fixture owns a disposable PostgreSQL17 container. It mounts only public
implementation source and a new evidence directory, never host SSH, application
configuration, database storage or credentials. The Daybook source selection is
an immutable public Git commit; fixtures use synthetic profiles and work rows.

The real packaged management helper runs `migrate --noinput` and
`provision_operations` under a dedicated service user, sourcing the rendered
0600 shell companion. The owned database verifies the eight-migration graph,
repeat source/offer/credential continuity, schema and purpose-conflict failures,
and the existing-to-new shared protocol adapter delta. Failed commands perform
real reads; successful provisioning performs real enabled-field writes.

Explicit enabled/disabled/restart routing is additionally tested through the
actual SDK with existing/source/dependency/configuration/ownership states. Docker
does not provide a real systemd host; this fixture does not claim systemd or live
inventory qualification. Normal target dry/first/repeat evidence remains required.

The configured `Daybook Operations API native` workflow runs on the dedicated
feature branch and accepts an explicit immutable implementation SHA for manual
dispatch. `run-container.sh` refuses non-hosted execution and object collisions;
it removes only its newly created container, anonymous volumes and image tag.
The actual installed package is checked against every Git resource and its
noneditable `direct_url.json` before fixture preparation.

The fixture also records paired original rsync → frozen uv → repeat and typed
rsync → frozen uv → repeat itemization. Any generated package metadata churn is
reported honestly and requires a narrow idempotence correction before live
qualification; no extra source exclusion is silently introduced. Real descendant
ownership drift is repaired without changing an already-owned peer. The fixture asserts real `systemd-analyze verify` on generated
units; no successful native result has yet been recorded, and no enable/start/restart coverage is
claimed from a container without systemd as PID1.

The implementation is still being qualified. No successful native receipt exists
yet. Keep every failed attempt and cleanup receipt when running qualification.
