# Native MeTube

`ops_deploy.services.metube` deploys MeTube from Git with its Angular frontend,
frozen uv environment and systemd service. It uses the existing native layout;
it does not run a Compose stack. Supply a `MetubeConfig` and a `BasicAuth` value
for the Traefik route. Production configuration and passwords belong in the
private inventory/SOPS adapter.

The controller resolves one Git revision through `GitSource` and checks that
revision's lock against the Python trust floors before planning host changes.
The host checks out that exact revision under `build_root/src`, performs a
frozen runtime sync in `build_root/venv`, verifies its trust bundle, and builds
the actual Angular UI using pinned Corepack/pnpm or `npm ci`. An unsuccessful
staged runtime or frontend build never reaches the live source tree.

Only a successful same-revision build can be published. The live Git checkout,
UI and frozen runtime converge before the role-compatible environment/unit and
Traefik route are written. Source, runtime, environment or unit changes trigger
the systemd rollout. An incomplete rollout retains its pending marker so a retry
cannot incorrectly skip the restart. The marker is removed after HTTP health
passes. The route reuses a matching bcrypt hash and Traefik's watched provider.

The current supported runtime selection uses checksum-pinned uv 0.13.4. Python
is selected explicitly (default 3.14.0). Existing Node.js 24 releases meeting
24.15.0 are retained; missing/wrong-major/older Node installs use the role's
MeTube NodeSource key and repository paths. Changing a uv version requires
reviewed matching checksums. No deployment-time lock overlay disables a stale
upstream lock: maintain a reviewed source correction or select a suitable
source revision.

State, home and media directories are separate from both source and staging.
Only directory metadata is managed; their contents are never recursively
chowned, copied or removed. Symlink traversal is refused. A running service's
read-only history endpoint must show an empty queue and pending list before a
source/runtime/UI or environment/unit rollout. Unchanged and route-only deploys
remain read-only and succeed while downloads are busy. A stopped service can be
recovered without querying an unavailable HTTP endpoint. This check never enqueues, cancels or deletes a download. It cannot
prevent a new user request arriving after the check; coordinate the actual live
window with the operator.

The environment/unit/route preserve the deployed role defaults. The public
config intentionally exposes the qualified native path rather than every role
option. This module implements deploy only: backup, restore, removal and fresh
media-volume provisioning are separate concerns.

Run the dedicated actual Linux qualification with:

```sh
bash smoke/run_metube_native.sh /absolute/path/to/reviewed/metube COMMIT
```

It owns a named Lima VM and fixture paths only. The fixture starts from a
prepared systemd host: its base image has Git/build tools and the smoke
provisioner installs uv/uvx 0.13.4. MeTube's first application install exercises
its apt packages, NodeSource install, service account/directories, actual Python
download via uv, source/runtime/UI and systemd. The inherited shared uv
installer's missing-binary branch is not exercised by that fixture; complete
fresh-machine or media-volume provisioning is not claimed. It builds actual upstream
Angular, installs real frozen Python dependencies, tests first deployment,
Python update, busy-queue no-op/refusal, inactive recovery, UI update, a real
Angular build that succeeds in the wrong output directory, build failure and
retry, and requires each
immediate repeat to have zero mutating operations. Owned media/state sentinels
must survive every pass. It never downloads real media.
