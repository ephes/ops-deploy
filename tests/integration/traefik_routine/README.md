# Traefik ordinary routine native qualification

Manual workflow `traefik-routine-integration.yml` checks out an exact 40-character
implementation commit in a GitHub-hosted Ubuntu24.04 x86_64 VM. The harness refuses
an existing Traefik installation and binds an exclusive fixture marker to the
machine ID/run. Never run this harness on inventory machines.

The production ordinary API installs3.7.13 and repeats without changes; an owned
fixture enrollment then exercises3.7.14 update, static configuration change, unit
and owned certificate-list repair, missing-record refusal and full filesystem
zero repeats. A fixture-only trust anchor and TLS certificate avoid ACME issuance.
The real loopback nginx backend returns200 and stays enabled with the same PID;
UFW stays inactive with the intended rules. Isolated proofs cannot reach that
backend, but still verify HTTPS certificate and redirect/auth expectations.
Every no-op observation subprocess is traced for filesystem writes and payload
absence from untruncated execve argv; a real intentional argv-leak negative check
verifies the trace detector on the VM. Transient files are not hidden by before/after snapshots.

Detached death cases use an explicitly recorded instrumented copy of the engine:
only wrappers around production atomic writes/systemctl calls inject SIGKILL.
They cover binary/static/unit/watched-file and metadata writes, daemon-reload,
restart and before clear publication. The original runner loads the same engine
without the executable-only injection and calls the shared restore helper. Every
case requires the injection marker, real OnFailure completion, restored resource
bytes/absence and baseline running identity before fixture-only reconciliation.
This is fault injection, not a claim that the injected engine byte hash equals the
immutable package. Ordinary deploy phases execute the unmodified installed API.

Artifacts retain operation classifications, errors, recovery records and exact
implementation/harness references. Every failed run is retained. Workflow discovery
may use a separate reviewed Main bootstrap containing only this workflow/harness;
the implementation remains the exact feature commit selected by the input.
