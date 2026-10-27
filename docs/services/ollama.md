# Ollama on macOS

`OllamaConfig` and `deploy_ollama` port the macOS-only `ollama_install` role
from ops-library `56495f751c1c664ad9ff2be73403e23efda02621` (2.75.1).
This is the Homebrew CLI and a system LaunchDaemon. Linux and the desktop app
are outside this API.

```python
from pathlib import PurePosixPath
from ops_deploy.services.ollama import OllamaConfig, deploy_ollama

deploy_ollama(
    OllamaConfig(
        brew_user="brewowner",
        user="ollama",
        group="ollama",
        site_path=PurePosixPath("/usr/local/var/ollama"),
    )
)
```

Connect with the existing privileged macOS account. Homebrew must already be
installed. Set `brew_user` to its existing non-root owner; the deployment runs
Homebrew through `sudo -H -u` as that owner. It does not change SSH, sudo or
authentication settings. The host needs `/usr/bin/python3` (3.9+), `dscl`,
`dseditgroup`, `defaults` and `launchctl`. The controller uses Python 3.12+.

## Configuration and behavior

| Field | Default / behavior |
| --- | --- |
| `enabled` | `True`; false performs no operations |
| `brew_package`, `brew_update` | `ollama`, `False`; install only if absent, never upgrade an installed formula. Explicit update runs `brew update`, which is a mutation on every requested run. |
| `brew_bin`, `brew_user` | Auto-detect `/opt/homebrew/bin/brew`, then `/usr/local/bin/brew`; existing Homebrew owner is required |
| `disable_brew_service`, `brew_service_name` | `True`, `ollama`; stop an actually loaded/running/registered owner-managed Brew service |
| `stop_conflicting_processes`, `conflicting_process_pattern` | `True`, `[/]ollama serve`; send SIGTERM only to matching processes whose owner differs from `user`. Re-check process identity before killing. |
| `binary_path` | Optional override; otherwise `<brew --prefix>/bin/ollama` |
| `launchd_label`, `launchd_plist_path` | `com.ollama.ollama`, `/Library/LaunchDaemons/<label>.plist` |
| `launchd_command`, `launchd_command_args` | `serve`, empty tuple |
| `manage_user`, `user`, `group`, `uid`, `gid` | `True`, `ollama`, `ollama`, optional numeric overrides. Create/update native records and hide the system user as the role does. Existing IDs are retained unless explicitly selected. |
| `site_path`, `models_dir`, `log_dir` | Fixed defaults `/usr/local/var/ollama`, `/usr/local/var/ollama/models`, `/usr/local/var/ollama/logs`; mode `0750`. Override all desired paths explicitly. Manage ownership only when `manage_user=True`. Changes are nonrecursive. |
| `env` | `OLLAMA_HOST=127.0.0.1:11434`, `OLLAMA_MODELS=<models_dir>`; an explicit dictionary replaces the default dictionary, matching Ansible |
| `health_url` | Optional HTTP 200 readiness endpoint; otherwise verify launchd running state. No inference request is sent. |

The plist has root/wheel ownership and mode `0644`, `RunAtLoad`, `KeepAlive`,
the selected user/group, working directory and stdout/stderr log paths. Its
ordinary rendered bytes match the role. XML special characters are escaped so
arguments and environment values remain valid XML.

Native `IsHidden=1` is authoritative for existing system accounts. Their legacy
global loginwindow hidden-user list is preserved; a new account is added to
that list as the role does. This avoids routine rewrites of unrelated existing
loginwindow preferences.

A changed plist (including its metadata) reloads and restarts **this system
label** using bootout/bootstrap/enable/kickstart. Missing jobs are bootstrapped;
stopped jobs are kickstarted. Directory metadata repairs do not restart it.
Replacing the executable file behind an unchanged path or upgrading Homebrew
separately does not trigger a restart when the plist and running job are unchanged,
matching the role. Changing `binary_path` changes the plist and restarts the job.
No-op deployments preserve the running executable even if an installed symlink
now points at a newer version.

There is no inference-activity heuristic or acknowledgement flow. Cached models
are not evidence of active inference. Intentional plist changes restart Ollama
and can interrupt requests; coordinate these changes with callers as for the
original role. An unchanged busy deployment is allowed.

The deployment never downloads models, performs inference, hashes model blobs,
changes model contents, or recursively changes retained data. It does not manage
proxy/auth settings or unrelated inference services. Status and verification
write no helper, staging or marker files; host Python bytecode writes and
Homebrew automatic updates/analytics are disabled. A converged repeat has no
mutating operation; its launchd/optional HTTP checks are recorded as read-only.

## Qualification

`tests/test_ollama.py` checks role rendering, XML validity, disabled/no-op/error
paths, nonrecursive retained-directory repairs, installation and restart
selection. `OPS_LIBRARY_PATH` enables the explicit source-template comparison;
that comparison is skipped when the source checkout is absent.

The `Ollama native macOS integration` workflow builds and installs a wheel from
the exact PR head SHA for Ollama changes, or the selected immutable
`implementation_sha` on manual dispatch, on a disposable GitHub-hosted macOS
runner. The PR trigger permits feature qualification before this new workflow
exists on Main; GitHub requires default-branch presence for initial manual
dispatch ([GitHub workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch)).
The guarded fixture creates its own unique service
identity, system label, loopback port and empty private model store. It checks
an actual absent-formula install, package presence on repeats, real API health,
plist configuration update/restart, missing-binary failure without replacing
the working plist, cleanup of an owned foreign-user manual server while keeping
the managed PID, unloaded-job recovery and repeats with zero deploy mutations.
The fixture attempts to clean up its label, identity, hidden-user entry and
private tree. If its job cannot unload, it records that failure and retains
the associated identity/tree rather than deleting beneath a running process;
the disposable runner is then destroyed by GitHub. Cleanup errors do not hide
the original failure or prevent writing the result artifact.
The ephemeral runner owns any installed formula/dependencies.

This proves package installation/presence and configuration updates, **not** a
formula upgrade or a second Ollama runtime version. It does not download models
or exercise inference. Inventory hosts are never used as fixtures. Inspect the
workflow result artifact for the actual executed implementation SHA, package,
binary hash and operation outcomes; source code alone is not execution evidence.
