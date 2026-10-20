# Secrets

This package never decrypts anything. It defines the types the private side
fills in.

## `SecretRef`

A reference to an encrypted file, relative to the private repository root:

```python
SecretRef("secrets/prod/nyxmon.yml")
```

Configs also accept a plain string (`secrets="secrets/prod/nyxmon.yml"`). The
path must be relative, must not contain `..`, and must end in `.yml` or
`.yaml`.

## `SecretValues`

A read-only mapping of decrypted values. `repr()` and `str()` show the file
and the key names, never the values. Instances refuse to be pickled.
`require(keys)` raises `MissingSecretKeysError` naming every missing or empty
key.

## `SecretStore`

A protocol with one method, `load(ref: SecretRef) -> SecretValues`. The private
repository implements it (SOPS, decrypting on the controller once per file per
run). Deploys receive `SecretValues`, never a store.

## Rules

- Secrets never go into pyinfra host data (`pyinfra debug-inventory` prints it).
- Secret command arguments are wrapped in `HiddenValue` so pyinfra prints
  `*MASKED*`; the test harness records the masked form, so tests can assert a
  secret never appears (`FakeRun.all_text()`).
- Secret files are written only with `secret_file` and `SecretContent`
  ([Operations](operations.md#secret_file)). Only `secret_file` calls
  `SecretContent.reveal()` (enforced by `tests/test_policy.py`).
- No `_sudo` uploads (enforced by `tests/test_policy.py`).
- No secret on a command line and none in the environment of a command run
  as another user. The `runuser -u <user> -- env NAME=value ...` that deploys
  use to drop privileges is the argument list of the remote shell, `runuser`
  and `env`, which any local user reads from `/proc/<pid>/cmdline` while it
  runs (masking only hides it from pyinfra's output); pyinfra's `_env`
  argument is the same. Secrets go on stdin (`secret_stdin`,
  `probe(..., stdin=...)`) or into a 0600 file (`secret_file`); a host script
  may read them there and export them to the program that uses them. A fact
  that needs stdin gets it through `helpers.probes.stdin_arguments`, never a
  plain `_stdin=` string: pyinfra logs fact arguments in its debug output. Structured payloads
  count as secret too (names ending in `_JSON`, `_DATA`, `_SPEC`: Nyxmon
  check data can carry a monitor login). Enforced by
  `tests/test_become_environment_secrets.py`, a static scan with an explicit
  allowlist (empty), like ops-control's and ops-library's guards of the same
  name.

## `SecretContent`

File content for `secret_file`. Built from `str` (UTF-8) or `bytes`; `repr()`
and `str()` print `SecretContent(<redacted>)` and pickling is refused. pyinfra
prints the string form of an unnamed operation's arguments, so a plain string
passed as `content` would show up there: always wrap it, for example
`SecretContent(values["DJANGO_SECRET_KEY"])`.
