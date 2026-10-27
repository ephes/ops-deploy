# Pinned native llama-server

`LlamaServerConfig` / `deploy_llama_server` port the existing Darwin
`llama_server_deploy` detector role. The service account and Homebrew owner must
already exist. No service account, authentication policy, GUI conversion or
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
Metadata-only repairs do not restart an already running process. Health checks
require the exact model alias, build and one slot, authenticated `/v1/models`
and `/props`, and unauthenticated `/v1/models` returning401. They perform no
inference. `healthcheck_enabled=False` keeps launchd-state verification only.

`enabled=False` unloads this job and removes only its plist and API-key file;
model, wrapper and package remain. Fresh package/model installation, authenticated
readiness, configuration changes, fault preservation, disable and zero-change
repeats passed on the owned ARM fixture at `cd4ee3e7920232aabcf142971bec96e044611f55`.
The fixture issued no inference request; normal server startup may warm the model.
Inventory rollout is separate from this fixture proof.
