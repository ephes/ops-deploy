# macOS owner-session SSH tunnel

The planned native port preserves the existing `macos_ssh_tunnel` role's local
owner and Aqua-session model. Its deployment will install the tunnel stopped,
including when the existing label is enabled and loaded. The existing explicit
lifecycle commands start it.
This package is under implementation; no deployment API or inventory engine
switch is published by the descriptor-probe prerequisite alone.

`identity.probe_identity` inspects an existing Ed25519 forwarding identity using
OpenSSH through a pinned regular-file descriptor. It creates no temporary key
copy and passes no private bytes in argv, stdin, environment or logs. Missing
or drifted public material is reported for the separately owned mutation path;
it never rotates a key. When both private/public files are absent the result is
`missing`; an existing private file with no public counterpart reports `drift`.
An orphan `.pub` and exact-mode violations are refused, matching the original
mutation algorithm's contract (including public mode `0644`, not `0600`). Unsafe
links, ownership and replacement races are also refused. A missing identity in
dry planning needs no prospective key.

The original ops-library mutation/recovery algorithm will remain byte-identical
when packaged for actual creation and reconciliation. No-op probes must not call
its temporary-key derivation path.

The PR-path-triggered and manually dispatchable `Native Mac applications integration` workflow builds and installs
the exact requested Git wheel, requires actual ARM Darwin and the non-root
hosted-runner identity, and proves real OpenSSH derivation with unchanged fixture
metadata across twenty repeats. Its evidence records explicit pass/fail status,
cleanup (including cleanup errors), and limitations. The metadata observer covers
the owned fixture tree; it does not claim a whole-host filesystem syscall trace.
It creates only disposable owned identities, never uses an inventory host or
changes SSH authentication. GitHub's current [runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
lists `macos-15` for ARM; the fixture independently checks the actual architecture.
