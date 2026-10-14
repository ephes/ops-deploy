# Changelog

## 0.1.0 (unreleased)

- Project skeleton: uv, ruff, mypy (strict), pytest, mkdocs, GitHub Actions CI.
  pyinfra pinned to `3.10.*`, Python 3.12+.
- `BaseServiceConfig` with `CHANGEME` rejection, `ServiceName` and `UnixUser`
  field types, and `required_secret_keys`.
- `SecretRef`, `SecretValues` (redacted, unpicklable) and the `SecretStore`
  protocol.
- `ops_deploy.testing`: `run_deploy_fake` with recording of facts, shell
  commands, uploads and `FunctionCommand` callbacks; `RecordingRsyncRunner`.
- Injectable controller-side rsync runner (`ops_deploy.core.rsync`).
- `toy` service deploy with first-run, no-op and change-run tests.
