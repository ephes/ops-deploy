# Pinned native llama-server

`LlamaServerConfig` / `deploy_llama_server` port the existing Darwin
`llama_server_deploy` detector role. The service account and (in the default
Homebrew mode) the Homebrew owner must already exist; source mode (below) needs
no `brew_user`. No service account, authentication policy, GUI conversion or
package upgrade is introduced.

```python
from pathlib import Path
from ops_deploy.services.llama_server import LlamaServerConfig, deploy_llama_server

cfg = LlamaServerConfig(
    user="detector",
    brew_user="operator",
    wrapper_source=Path("/controller/source/scripts/detector-server.sh"),
    bind_host="tailnet",
    port=8177,
)
deploy_llama_server(cfg, secrets)  # SecretValues containing api_key
```

The defaults preserve the role's pinned llama.cpp build b11669-620d2225c,
Qwen3 model URL/commit/SHA, alias, wrapper/config/model/log paths and system
LaunchDaemon label. The controller wrapper must carry the same model pin and
the role's private-runtime flags. A key must satisfy the existing one-line
32-character token grammar; it travels only on masked stdin, never in argv or
environment. The plist names the private key file, not its contents.

`tailnet` resolves exactly one Tailscale IPv4 address. Explicit bindings accept
only loopback or Tailscale IPv4. Homebrew installs a missing formula and never
upgrades an existing one; a different installed build fails validation. Planning
uses the role's per-formula `brew list --versions` check, which also resolves
renamed formulae; a formula from a repository that is not tapped counts as absent
and is not resolved, so planning never taps a repository automatically.

Fresh or explicitly changed model provisioning stages and checks the declared
SHA before replacing any existing model. On an existing unchanged wrapper/pin,
the model is observed by regular-file ownership/mode and nonempty metadata;
deployment does not read/hash weights or create a provenance marker merely for
engine migration. This is existing-model continuity, not a fresh checksum proof
or detection of arbitrary same-path weight tampering. The wrapper still verifies
the full pin at every explicitly requested process start.

Unchanged configuration preserves the running process, key/wrapper/plist bytes,
model data and log timestamps. Actual runtime-content changes unload the exact
job before publishing its new files; interrupted publication therefore remains
visibly unloaded and the next deploy can recover without a second journal.
Metadata-only repairs do not restart an already running process (Homebrew
mode; in source mode a wrapper, key or plist that is not exactly right is
replaced, which counts as a change and restarts the job). Health checks
require the exact model alias, build and one slot, authenticated `/v1/models`
and `/props`, and unauthenticated `/v1/models` returning401. They perform no
inference. `healthcheck_enabled=False` keeps launchd-state verification only.

`enabled=False` unloads this job and removes only its plist and API-key file;
model, wrapper and package remain. Fresh package/model installation, authenticated
readiness, configuration changes, fault preservation, disable and zero-change
repeats passed on the owned ARM fixture at `cd4ee3e7920232aabcf142971bec96e044611f55`.
The fixture issued no inference request; normal server startup may warm the model.
Inventory rollout is separate from this fixture proof.

## Source build

Homebrew's `llama.cpp` cannot hold a pin: other formulae depend on it (on the
Studio `whisper.cpp`), so their upgrades move it (0.7.0/b11669 to 0.8.0 on
2026-10-28 and 1.0.0 on 2026-11-13), and the wrapper then refuses to start the
pinned detector. `source_build` builds the pinned release tag from source
instead and leaves Homebrew's formula alone:

```python
from ops_deploy.services.llama_server import LlamaServerConfig, LlamaSourceBuild

cfg = LlamaServerConfig(
    user="detector",
    wrapper_source=Path("/controller/source/scripts/detector-server.sh"),
    source_build=LlamaSourceBuild(tag="b11669", commit="620d2225cc436ab0b001e3200e590e3b286ef9ab"),
)
```

- **Pin.** `tag` must be `b<build number>` of `build` and `commit` the full
  hash starting with its short commit. The host verifies after the checkout
  that `HEAD` and `refs/tags/<tag>` are `commit`, that `git rev-list --count`
  is the build number and that the tree is clean (before and after the build),
  and that the binary's `--version` is the pinned build. Root writes the full
  commit into `<prefix>/SOURCE_COMMIT` at publication; a prefix is reused only
  when that marker matches (the prefix name carries only the short hash).
  Binaries are not bit-reproducible (embedded paths), so the pin is the source,
  not a hash.
- **Build.** A static `llama-server` with the ggml of the same commit, Metal
  library embedded, no OpenSSL, no web UI (`CMAKE_FLAGS` in
  `files/llama_server_host.py`); about a minute on an M4 Max including the
  blobless clone. It links only system frameworks.
- **Trust boundary.** The build runs as the non-root service user, with that
  user's toolchain (`git`, `cmake` from `/opt/homebrew/bin`; never installed by
  the role), in a workspace it creates under
  `~/Library/Caches/llama-server-build/run.*` and removes again; each step in its
  own process group with `cwd=/` and a 600 s timeout. A small `/bin/sh` leader
  runs the step, reports its exit status on a pipe and then waits for root, so
  the group still exists when root sends the final `SIGKILL` to it (no signal
  can reach a reused group ID); captured output goes to an unlinked root file
  capped by `RLIMIT_FSIZE`. Git runs
  without system/global configuration and hooks. Root never executes anything
  from the toolchain or the workspace and never opens a path in it: the service
  user streams the binary into a file root created (size-capped), and every
  `--version` check of a source-mode binary runs as the service user. The
  binary is published root-owned (`root:wheel 0755`, single link, no ACL) under
  `/opt/llama-server/llama.cpp-<build>/bin/llama-server` by an atomic rename;
  the plist's `DELVE_LLAMA_SERVER` points there. An existing prefix is reused
  only when it passes those checks, otherwise the deploy refuses.
- **Fixed layout.** Source mode refuses overrides of the install, config, log
  and model directories, the wrapper, key, log and plist paths and `binary`, and a
  service user `root`. Before any change the host checks that every managed
  directory and all its ancestors are root-owned, not group/other-writable,
  free of ACLs, and not symlinks (only the system links `/etc` and `/var` are
  followed).
- **Status, readiness and removal.** Status and readiness check the same
  chains before reading runtime files (readiness also requires the key file to
  be exactly owned); `enabled=False` in source mode takes the lock and checks
  the plist and key directories before unloading and removing.
- **Serialization and order.** One lock,
  `/private/var/db/de.wersdoerfer.llama-server-deploy.lock`, is held for the whole
  source-mode apply: directory checks, build and publication of the binary (the
  live job is untouched until then), unload of a changed job, publication of
  model/wrapper/key/plist, then `launchctl enable` and `bootstrap` (enable now
  comes first in both modes, so a job disabled by hand can be recovered) and
  `kickstart`.
- **Runtime files.** In source mode the wrapper, key and plist are never
  repaired in place: unless a file is exactly right (bytes, owner, mode, single
  link, no ACL) it is replaced by a new inode, and status reports such files as
  drift. A wrapper that fails those checks is not read either, so the model is
  then provisioned again (download and SHA-256 check).
- **Leftovers.** A killed deploy can leave `run.*` in the service user's cache or
  a root-only `/opt/llama-server/.llama-install-*`; both are inert and can be
  removed by hand when no deploy runs.

Homebrew mode (`source_build=None`, the default) is unchanged apart from the
enable-before-bootstrap order.
