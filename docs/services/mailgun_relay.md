# Mailgun relay

`MailgunRelayConfig` / `deploy_mailgun_relay` deploy the existing Mailgun-compatible
HTTP→SMTP relay and optional Traefik ingress. They port `mailgun_relay_deploy` and
`mailgun_relay_ingress_deploy`, including their Python/Rust implementation switch.
They do not change the application, SMTP backend, sender policy or mail semantics.

The host needs Linux, systemd, Python 3.11+, curl and runuser. Explicit Python
installation additionally needs rsync (or git), and uv at `/usr/local/bin/uv`;
this service does not upgrade or downgrade those host tools.

## Existing installations and rollback

`python_deploy="preserve"` is the default. It requires the existing Python project,
lockfile and executable venv interpreter and leaves source, venv, dependencies,
interpreter and trust store untouched. There is no date-triggered retirement.
This is useful while a Rust installation retains Python as its rollback path.
Select `python_deploy="rsync"` with `source_path`, or `"git"` with `git_repo` and
`git_version`, explicitly to install/update Python. Both methods retain `.venv`;
rsync uses the original role excludes, including `.vault_password`, `.git`, local
env files, caches, build output and the root `/rust/` tree. Source content changes
(not checkout timestamps) trigger uv sync and a restart. uv sync uses the role's
runtime-only arguments and requested Python major/minor; it only runs after a
source change or when the interpreter is absent. Keep its inputs pinned when an
explicit Python update must reproduce a particular runtime.

`impl="python"` removes the Rust drop-in before attempting any pinned Rust
release. A failed release emits a warning and allows the Python switch to finish;
it never blocks rollback. Rust selections require a pinned release, use the same
base unit/environment/policy and add only the exact `impl.conf` override. The unit
keeps its existing identity, working directory, journal routing, strict sandbox
and fixed `MALLOC_MMAP_THRESHOLD_=131072` for Rust.

## Configuration and defaults

```python
from ops_deploy.core.secrets import SecretRef
from ops_deploy.services.mailgun_relay import MailgunRelayConfig, deploy_mailgun_relay

cfg = MailgunRelayConfig(
    secrets=SecretRef("secrets/prod/relay.yml"),
    impl="rust",
    rust_version="0.2.2",
    rust_sha256="<verified lowercase archive sha256>",
    ingress_enabled=True,
    ingress_host="relay.example.test",
    ingress_traefik_cert_resolver="letsencrypt",
)
# The private controller decrypts/maps SecretValues, then:
# deploy_mailgun_relay(cfg, secrets)
```

Replace the checksum placeholder with the release's verified 64-character digest.
Versions are operator pins; this service never chooses the newest release.

| Fields | Defaults / contract |
| --- | --- |
| `service_name`, `user`, `group` | `mailgun-relay` |
| `home`, `site_path` | `/opt/apps/mailgun-relay`, `<home>/site` (independent explicit fields) |
| `venv_path`, `env_path`, `secrets_path` | unset: derive `<site_path>/.venv`, `<env_dir>/mailgun-relay.env`, `<env_dir>/secrets.yml` |
| `env_dir` | `/etc/mailgun-relay`, root:service group 0750; env/policy 0640 |
| `python_deploy`, `source_path` | `preserve`, unset |
| `git_repo`, `git_version` | public ephes/mailgun-relay HTTPS repository, `main`; explicit opt-in only |
| `rsync_excludes` | original role excludes described above plus mandatory sync-tree tooling exclusions |
| `python_version`, `uv_sync_args` | `3.14`, `--no-default-groups --no-dev` |
| `impl`, `rust_version`, `rust_sha256`, `rust_local_archive` | `python`, empty, empty, unset; checksum or controller archive required with a version |
| `rust_release_url` | GitHub `rs-v{version}/mailgun-relay-{version}-x86_64-unknown-linux-gnu.tar.gz`; alternate HTTP(S) endpoints permitted |
| `rust_install_root`, `rust_keep_versions` | `/opt/mailgun-relay`, 3 newest installs; pinned/live/previous versions retained additionally |
| `bind_host`, `bind_port`, `public_host` | `127.0.0.1`, 8085, `mailgun.home.xn--wersdrfer-47a.de` |
| `smtp_host`, `smtp_port`, `smtp_starttls`, `smtp_timeout_s` | `smtp.home.xn--wersdrfer-47a.de`, 587, true, 30 |
| `smtp_max_concurrency`, `smtp_ca_file` | unset: application defaults (8 concurrent submissions, system CA trust); optional explicit CA bundle for owned sinks/private PKI |
| `max_body_bytes`, `max_attachments`, `max_attachment_bytes` | 26214400, 10, 10485760 |
| `max_recipients`, `max_header_value_length`, `log_level` | 100, 998, INFO |
| `healthcheck_enabled`, `healthcheck_retries`, `healthcheck_delay_seconds`, `healthcheck_timeout_seconds`, `healthcheck_url` | true, 20, 1, 5, derived bind `/health` URL |
| `ingress_enabled`, `ingress_host`, `ingress_backend_url` | false, `mailgun.home.xn--wersdrfer-47a.de`, `http://127.0.0.1:8085` |
| `ingress_traefik_config_path`, `ingress_traefik_cert_resolver`, `ingress_max_request_body_bytes` | `/etc/traefik/dynamic/mailgun-relay.yml`, empty (existing TLS), 26214400 |

## Secrets and ingress

`SecretValues` must supply `smtp_username`, `smtp_password`, `envelope_sender`
and `tokens`. `tokens` is a JSON-encoded nonempty list of objects with `label`,
`token_sha256` (64 hex characters), nonempty `mailgun_domains` and
`allowed_from_domains`, and optional `allowed_from_addresses`. Only verifiers
belong on the relay, never raw caller tokens. The private controller must mark
the list as structured when mapping SOPS data. Credentials and policies use the
unchanged quoted role template: controls, double quotes and backslashes are
refused rather than producing ambiguous YAML. Errors omit values.

Environment and policy use the existing `secret_file` stdin transport, never
plaintext controller files, argv or diffs. The envelope sender belongs to the
SMTP login under the backend's existing sender binding. Traefik terminates TLS,
redirects HTTP and forwards bodies/Host unchanged with the existing security
headers and buffering. Application Basic auth (`api:<token>`) and sender policy
remain authoritative; no proxy Basic auth or auth bypass is added. Traefik's
dynamic directory must already exist; the file provider reloads the route.
The existing native `route_put` primitive guards changes against a held Traefik
transaction lock. An unchanged route remains a no-op even while that lock is held.

## Release validation, failures and repeat runs

The archive must match its checksum and contain exactly two regular files:
`mailgun-relay` and `LICENSE`, each once. Links, devices, extra members and path
traversal are rejected before extraction. Root stages and atomically publishes
the version with its `.archive-sha256`; an installed version is never replaced
in place. Before selecting it, the binary must report the pinned version as the
service user and accept the production environment/policy via a transient
systemd `--check-config` unit with the production sandbox. A rejected fresh
version and staging are removed; the selection and running process stay intact.

**Rejected configuration remains on disk.** Matching the original role's task
order, env and policy are written to their production paths before the candidate
check. A failed check preserves the currently running process's old in-memory
settings, but leaves the rejected files installed and a restart owed. A crash,
manual restart or reboot can therefore fail with that configuration. Correct the
shared configuration and rerun deployment promptly; an implementation switch
alone does not repair it. Fresh-release cleanup removes the rejected binary and
staging, and does not roll back the env or policy. The native fixture asserts
both the unchanged current PID and this persisted failure state before recovery.

Fresh archive installation uses the existing `helpers.rust_release` installer
without changing that shared helper. Installed candidates use a separate relay
config check, preserving their root metadata on a converged run. The service
retains the legacy `.previous-version` contract; it does not convert installations
to another pin layout. A checksum-pinned HTTP mirror is transported to an upload
and then processed by the same shared installer; it never bypasses archive checks.

Successful selection restarts only for changed runtime inputs. A small root-only
restart marker under `/var/lib/ops-deploy/<service_name>` preserves restart intent
across a failed/interrupted run and is cleared after verification. `/health` must
return status `ok` without a version, then `/proc/<MainPID>/exe` must equal the
versioned Rust binary, or Python must have the exact venv module argv. Only then
are old version-shaped directories pruned, preserving pinned, live, previous
and newest configured releases. Other directories remain untouched.

A converged repeat has no deployment mutations or restart. Candidate validation
and health/process checks are classified separately; the config check creates
transient systemd/journal bookkeeping, so this does not mean zero physical writes.
An HTTP health check proves neither SMTP TLS/authentication nor delivery/DKIM.
Monitoring mailboxes/probes/timers belong to the separate mail-monitoring service.

## Validation

`tests/test_mailgun_relay.py` exercises malformed inputs, secret redaction,
archive rejection/cleanup and retention. Set `OPS_LIBRARY_PATH` for exact template
byte parity. `tests/smoke/test_mailgun_relay_smoke.py` opts into a disposable
systemd Linux target with actual 0.2.1/0.2.2 release archives, a Python source
checkout and an owned STARTTLS/AUTH sink. It checks installation/update, repeats,
preserved fallback, interrupted config recovery, policy/MIME/envelope, temporary
and permanent SMTP failures, failed trust, rejected candidates and Python rollback.
All mail data and credentials are synthetic, with no external delivery.

On ARM Linux with Rosetta, `MAILGUN_FIXTURE_TRANSLATED=rosetta` enables a
**test-only** executable probe that verifies the translator and exact translated
binary argv. This explicitly does not qualify the production native x86 `/proc`
identity check; production code retains the strict executable comparison.

The `Mailgun relay native integration` workflow runs the same scenario on an
owned Ubuntu x86_64 systemd runner, with translation unset and the production
process probe unchanged. It triggers for relevant pull requests or an explicit
immutable implementation selection. Its bootstrap refuses ordinary machines,
uses only loopback root SSH, pins both release checksums and the Python source,
and publishes phase/mutation and artifact receipts. It uses `pull_request`, never
`pull_request_target`; no private inventory or production secret is supplied.
