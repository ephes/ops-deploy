# RustFS container fixture

```bash
tests/integration/rustfs/run-container.sh /path/to/extracted/rustfs EVIDENCE_DIR
```

The executable must be the pinned 1.0.4 `rustfs` for the Docker host's
architecture (see `docs/services/rustfs.md`). The script builds an Ubuntu 24.04
systemd image, starts a privileged container named `ops-rustfs-svc-it-<pid>`
with an anonymous volume at `/mnt/cryptdata`, copies this checkout (no `.git`,
no virtualenv) and the executable in, and runs `harness.py` with real pyinfra
and the local connector. Container, image and volume are removed on exit.
`EVIDENCE_DIR` receives `summary.json`, one sanitized log per phase and the
guest init log; every value the harness generated is redacted and a phase fails
if one reaches its log.

Last run: arm64 Docker Desktop, aarch64 artifact, all phases passed.
