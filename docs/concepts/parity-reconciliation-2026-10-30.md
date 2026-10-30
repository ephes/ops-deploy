# Role parity reconciliation — 2026-10-30

Reviewed the twelve baseline failures against ops-library
`2adca51d` (the immutable full revision is recorded per role in
`tests/parity/ops_library_roles.json`). Only the ten changed role digests
advance; unchanged entries retain their earlier provenance. These digests
mean the source changes were reviewed, not that every role entry point is
implemented by pyinfra.

| Role or template | Disposition and evidence |
|---|---|
| `fastdeploy_backup` | Ported owner-only archive creation, final configurable `archive_mode` (default `0600`), and restriction of existing regular archives. Credential transport already uses stdin; line breaks remain refused by the documented passfile API. `test_backup_permissions.py` executes the real backup script with external account/database commands stubbed. |
| `graphyard_auth_bootstrap_deploy` | Already uses credential stdin and exact `MATCH`/`MISMATCH` verdicts (`services/graphyard/auth.py`, `test_graphyard_parts.py`). No credential or Grafana mutation is needed to reconcile this fingerprint. |
| `minio_deploy` | Matching-password hash reuse and removal of HSTS preload are already implemented by the shared Traefik route helpers and MinIO route contract (`test_minio.py`, `test_traefik_hsts.py`). |
| `nyxmon_backup` | SQLite busy timeout, retries and integrity checking already exist. Added restriction of existing archives and `umask 077` plus final `0600` for new archives. |
| `nyxmon_deploy` | Configured-account creation, Rust-only monitor, legacy-drop-in retirement and version preservation already exist. Sync ownership uses `--chown` rather than recursively walking the running database. SQLite privacy now tolerates disappearance only for transient `db.sqlite3-*` sidecars and verifies that the main database remains present. `test_nyxmon.py` injects actual file disappearance. |
| `nyxmon_remove` | Removes only the owned `sqlite-privacy.conf`; preserves operator drop-ins and uses nonrecursive `rmdir` for an empty directory. `test_nyxmon_lifecycle.py` covers both cases and an absent second removal. |
| `nyxmon_restore` | Resets destination directory metadata after `rsync -a`, so archived `0700` directories do not change deployed `0755` modes. The production restore function is exercised against local files in `test_backup_permissions.py`. |
| `traefik_deploy` | Probe capture and the vendored probe program already match. `acme_storage`, enrollment, alias and metrics-bind transactions remain Ansible-owned under the existing [transaction API](../traefik.md); the pyinfra engine deliberately refuses these actions. It retains its own reviewed binary/resume/rebaseline implementation. This reconciliation does not expand transaction ownership. |
| `uv_install` | Defaults now select `0.13.5` and the role's matching Linux checksums. The pyinfra dry plan already separates read-only version facts from installation operations; Ansible check-mode task changes do not require copying task control flow. `test_base_uv.py` covers missing/current/old/link/forced installations. Darwin stays explicit with caller-supplied native checksums and ownership. |
| `work_app_backup` | SQLite lock waiting, integrity checks and private new archives already exist. Added restriction of existing regular archives and explicit final `0600`. |
| Chesslab and weeknotes environment templates | Re-vendored the role's quoting macros. The default systemd environment output remains byte-identical in the existing awkward-secret parity cases. The role's shell-companion mode does not change these deploys, which parse environment data rather than shell-source it. |

Archive restriction is limited to non-hidden regular `*.tar`, `*.tar.*`
and `*.tgz` files directly below the configured backup root. It neither
follows symlinks nor traverses snapshot directories; a repeat does not chmod
already-correct files. Required-mount and snapshot-name checks run first.
FastDeploy's explicit `archive_mode` can support a separately arranged
non-root fetch; ownership/group access must be configured accordingly.

Consumers of the shared uv default now observe `0.13.5`; their converged
host fixtures and base smoke expectation use that pin. MeTube's separately
qualified staged API explicitly selects `0.13.4`, so its installer now passes
that version and its matching checksums explicitly instead of inheriting a
possibly different shared default. This preserves its selected toolchain.

The regressions also check that archive bytes are unchanged, tar starts with
the private umask, and retention/mount guards keep their existing boundaries.
