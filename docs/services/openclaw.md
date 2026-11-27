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

The gateway container logs to the host journal (Docker's `journald` driver,
tagged with `openclaw_container_name`), which Logyard ships as
`service=<container name>`; `docker logs` keeps working.

## Inputs

The role's interface is kept as it is: about 230 variables (`defaults/main.yml`)
checked by its `tasks/validate.yml`. Both files ship unchanged
(`files/deploy_defaults.yml`, `files/validate.yml`) and the port evaluates them
as the former Ansible role did (`variables.py`, `validate.py`): a default that refers to
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

The Codex plugin is installed with `plugins install --force --pin <spec>`. From
OpenClaw 2026.11.5 a bare package name resolves on ClawHub, so the spec is
`npm:@openclaw/codex@<version>` there and `@openclaw/codex@<version>` before
(`render.plugin_install_spec`). Since 2026.11.5 `plugins.allow` also gates
bundled plugins; `openclaw_plugin_allow_extra` (default `[]`) appends further
plugin ids, such as `senseaudio` for audio transcription and `memory-core`.
The runtime patch only adds to an existing allowlist; it never removes ids.

The release checkout follows `openclaw_repo_url`: an existing checkout with
another `origin` is repointed and fetched, as the `git` module does. The route
file is written only while no Traefik transaction holds its lock (like its
removal).

Every file is the role's bytes, owner and mode (`layout.py`); the templates are
the role's, rendered as the Ansible `template` task rendered them. The exception is
the weekly restart timer and its service, which are new in this port (not in
the role); `tests/test_openclaw.py` pins their bytes. The bind-mounted
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

The `weeknotes-reminder` cron job (`openclaw_weeknotes_reminder_cron`,
default weekdays 09:00 in the gateway's timezone) has two forms. With
`openclaw_weeknotes_reminder_deliver_to` empty (the default, the role's
behaviour) it is a system event (`openclaw_weeknotes_reminder_command`) in
the main session, and the agent decides whether to send anything. In
`message_tool_only` delivery mode the agent can stay silent every day. With a
Telegram chat id (digits, `-` for groups; any other value is refused before
any change), the job is an operator command payload instead. It runs the
weeknotes handler's `reminder` command on the gateway with no model call,
and `--announce --channel telegram --to <id>` delivers its output. When the
handler prints nothing (no open todos, or snoozed today) the job prints
`NO_REPLY` and nothing is sent. A failing handler fails the run. The `cron`
step replaces a job of the other form, or one with another chat or script.

Every deploy also installs `openclaw-gateway-weekly-restart.timer`
(`OnCalendar=Sun *-*-* 04:00:00`, host local time; a missed run is not made
up at boot) and its oneshot service, which runs `systemctl try-restart` of
the gateway unit (a stopped gateway stays stopped). It is a workaround for
upstream openclaw#181687: the prepared-model-catalog worker grows with every
catalog sync until the gateway restarts. The schedule is fixed. Check it with
`systemctl list-timers openclaw-gateway-weekly-restart.timer`.

The role's handlers become change-gated operations where the role flushes them
(`restart openclaw` before the health check, before the cron registration and
with the metrics units). The `reload traefik` handler, a Traefik restart, is not
ported: the route is a file-provider file, and the pyinfra deploys never restart
Traefik.

Removal follows `openclaw_remove`: `confirm` is required; data, image and the
account stay unless their toggles are set; the route goes by default. Like the
role it leaves the metrics endpoint in place; the weekly restart timer and its
service go.

## Rendered files

`tests/fixtures/openclaw/` holds three cases (production-shaped values with
synthetic secrets and a legacy gateway config, managed audio switched off, a
seeding first deploy); `tests/golden/openclaw/<case>.json` records what the
deploy writes for them: each file's sha256, owner, group and mode, the
directories, the patched `openclaw.json` and the `.env`. They were first
recorded when they equalled what ansible-core computed from the
`openclaw_deploy` role's task files. They do not hold the weekly restart
units, which the role never had.
