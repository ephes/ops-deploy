# Explicit Weeknotes identity rail

`WeeknotesIdentityConfig` and `run_weeknotes_identity` expose the original
separate `prepare`, `dry-run`, `apply`, `verify` and `status` operator actions.
They do not install/update Sessions, rotate auth, reconcile a week or activate
a timer. Normal role deployment does not select this rail. Apply requires the
original phrase `APPLY monday-after-v1 draft identity migration`.

The config requires the original non-root owner, exact forty-hex resolved Main
revision and, except for status, a nonempty ordered private intent. Each move
contains only week/audience/blog/post/revision identity and original title/slug;
no post body or protected-fields hash is shipped in deployment config. Private
intent and confirmation are hidden from model repr/errors and carried over
protected stdin. The narrow template mapping renders only the existing helper
and launcher; it does not request unrelated Sessions storage credentials.

| Field | Original default or contract |
| --- | --- |
| `owner` | Required non-root GUI owner |
| `action` | Required: prepare, dry-run, apply, verify or status |
| `required_revision` | Required exact resolved Main SHA |
| `confirmation` | Hidden; exact original phrase required for apply |
| `moves` | Hidden ordered strict private intent; positive integer identifiers |
| `home` | `/Users/<owner>` |
| `checkout` | `<home>/.local/share/daybook/sessions/daybook` |
| `runtime` | `<home>/.daybook/weeknotes-reconcile` |
| `config_dir` | `/etc/daybook-sessions` |
| `helper`, `launcher` | Original weeknotes-identity-ops.py / .sh in config_dir |
| `env_file`, `env_checksum` | Original weeknotes-reconcile.env / .env.sha256 |
| `seed`, `plan`, `attestation` | Original identity-migration-*.json in runtime |
| `state` | `<runtime>/state.json` |
| `proof` | Original root weeknotes-identity-activation-proof.json |
| `uv_bin`, `path` | Original `/opt/homebrew/bin/uv` and fixed launchd PATH |
| `scheduler_label`, `scheduler_plist` | Original exact system timer declarations |

Alternate production paths/executables/labels are refused. A content-free status
example, using the once-resolved Main revision from the normal controller:

```python
from ops_deploy.services.daybook_weeknotes_identity import (
    WeeknotesIdentityConfig,
    run_weeknotes_identity,
)

run_weeknotes_identity(
    WeeknotesIdentityConfig(
        owner="operator",
        action="status",
        required_revision=resolved_main,
    )
)
```

Execution retains the original root connection and service-user login context.
All SDK facts and operations explicitly clear inherited sudo/su/doas/dzdo
settings. Only OS and UID metadata are facts. The target first executes the
original exact system-timer disable, then one managed operator sequence: clean
owner checkout/.git at exact Main; root 0755 single-link helper/launcher bytes;
owner 0600 environment and root 0644 checksum; and original exact private seed
binding. The environment body/checksum and intent equality stay in target RAM,
never diagnostics. No source or environment convergence is added as a deployment
prerequisite; the original installed launcher retains its frozen isolated UV
behavior and application locks.

Prepare publishes only a missing owner 0600 seed with atomic no-replace
semantics. It never replaces a seed, plan, state, lock, auth or attestation to
make an operation pass. Apply additionally runs the installed verifier and only
checks that both reports bind the same plan hash, then publishes the original
root 0600 activation proof. Its private plan hash
stays in target memory/the proof, not the deployment report. Reports retain only
the original closed content-free metadata; unexpected output and private errors
fail with a fixed diagnostic. Raw app stderr never escapes.

All five actions, including dry-run, verification and status, are managed app
work. Every admitted invocation/repeat plans two managed sequences and zero
uploads; no read-only-fact or zero-managed-operation repeat is claimed. A
pyinfra dry plan does not invoke the application. Controller Main/intent
validation precedes SSH; target quiescence precedes target operator work.

Disposable proof uses only owned synthetic intent/state and inert app/UV
executables, with original declaration validation followed by disclosed
unvalidated model_copy path/label substitutions. It cannot qualify actual post,
content, app data, auth rotation or inventory execution. Existing timer retirement
and all original business confirmations remain unchanged. Root independently
qualifies source/pin publication and actual inventory work.

Seed publication uses the existing Sessions descriptor helper and original
`staff` group. It syncs the file before no-replace linking; it does not promise
parent-directory crash durability or automatically recover an interrupted link.
A residual second hard link fails closed for operator inspection. Existing
private intent is never overwritten to recover from an interruption.
