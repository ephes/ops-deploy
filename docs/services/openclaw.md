# openclaw

Port of the `openclaw_deploy` and `openclaw_remove` Ansible roles: the OpenClaw
gateway (a Docker Compose project built on the host from a release tag), its
managed skills and plugins, the Traefik route, log rotation and the Nyxmon
metrics endpoint, plus the private playbook's Nyxmon json-metrics checks.

```python
from ops_deploy.services.openclaw import (
    OpenClawConfig,
    OpenClawSecrets,
    deploy_openclaw,
    deploy_openclaw_nyxmon_checks,
)

cfg = OpenClawConfig(variables={"openclaw_version": "v2026.10.2", "openclaw_data_dir": "/srv/openclaw"})
secrets = OpenClawSecrets(variables={"openclaw_gateway_token": "...", "openclaw_anthropic_api_key": "..."})
deploy_openclaw(cfg, secrets)
```

The operations are named `Deploy OpenClaw | ...`, `Remove OpenClaw | ...` and
`OpenClaw Nyxmon checks | ...`.

## Inputs

The role's interface is kept as it is: about 230 variables (`defaults/main.yml`)
checked by its `tasks/validate.yml`. Both files ship unchanged
(`files/deploy_defaults.yml`, `files/validate.yml`) and the port evaluates them
as Ansible does (`variables.py`, `validate.py`): a default that refers to
another variable (`{{ openclaw_data_dir }}/credentials/...`) follows a
playbook value, and every `ansible.builtin.assert` of `validate.yml` runs with
its `when`, `loop` and `vars`, together with the two asserts of
`tasks/metrics.yml` (credentials and bind/port, synthetic canary bounds), all
before any change. A failure names the task, never a value.

| Input | Content |
|---|---|
| `OpenClawConfig.variables` | the non-secret role variables, by their role names |
| `OpenClawSecrets.variables` | the credentials (`SECRET_VARIABLES`: tokens, API keys, the IMAP/SMTP/calendar maps, the metrics password, the full `openclaw_gateway_config` override) |
| `OpenClawConfig.httpd` | the fleet's `metrics_httpd_impl` / `_rust_version` / `_rust_sha256` (`openclaw_metrics_endpoint_impl`) |
| `OpenClawConfig.docker` | `docker_install` with its defaults (`openclaw_install_docker`) |
| `OpenClawNyxmonChecks` | the playbook's `_nyxmon_checks_json` rows, login data included |
| `OpenClawRemoveConfig` | the removal toggles (`openclaw_remove_*`) and the role's other variables |

Unknown names, a credential on the public side and a public variable on the
secret side are refused. Not ported: the heartbeat-recovery extension and the
Codex v2026.9.1 registration backport (the playbook retired both; managing
either is refused).

## What it does

The role's `tasks/main.yml` order: the two stat-based asserts (the `mc` client,
the prepared CA bundle) as read-only checks; Docker; the account; the
directories; the release tag checkout and the image build (when the image is
missing or the checkout moved); the `.env`; the gateway config; Doctor
activation of a new image; the pinned Codex plugin; the upgrade migrations;
the audio SecretRef plan; the Compose file and unit; the route; log rotation;
the health check; the weeknotes skills and reminder cron job; the mail,
calendar, Paperless, Home Assistant and OpsGate skills; the workspace skills;
the metrics endpoint (with the metrics-httpd switch); the managed-skills
manifest and the session reset.

The release checkout follows `openclaw_repo_url`: an existing checkout with
another `origin` is repointed and fetched, as the `git` module does. The route
file is written only while no Traefik transaction holds its lock (like its
removal).

Every file is the role's bytes, owner and mode (`layout.py`); the templates are
the role's, rendered as the `template` module renders them. The bind-mounted
data tree belongs to the container's uid/gid 1000, which may have another name
on the host, so those files and directories are compared and set by number.

The steps that depend on what the host holds at run time run the role's logic
in `files/openclaw_host.py` (`STEP check|apply`, the request on stdin):
`config` (the v2026.9.1 key migration, the runtime patch merged into the
existing `openclaw.json`, the Telegram streaming alias normalization, which
also runs on a freshly seeded file),
`doctor`, `plugins`, `migrations`, `audio`, `cron`, `health` and `session`.
The `check` mode decides while planning, so a converged host gets no mutating
operation; a failed check runs the step.

The role's handlers become change-gated operations where the role flushes them
(`restart openclaw` before the health check, before the cron registration and
with the metrics units). The `reload traefik` handler, a Traefik restart, is not
ported: the route is a file-provider file, and the pyinfra deploys never restart
Traefik.

Removal follows `openclaw_remove`: `confirm` is required; data, image and the
account stay unless their toggles are set; the route goes by default. Like the
role it leaves the metrics endpoint in place.

## Parity

`tests/parity/openclaw_deploy/` holds three cases (the playbook's values with
synthetic secrets and a legacy gateway config, managed audio switched off, a
seeding first deploy) and what ansible-core 2.21 computed for them with the
role's own task files (`generate.py`): each file's sha256, owner, group and
mode, the directories, the patched `openclaw.json` and the `.env`.
`tests/test_ops_library_drift.py` records both roles' digests.
