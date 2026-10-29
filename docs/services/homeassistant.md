# Home Assistant implementation in preparation

The Home Assistant port is being implemented against the original public
`homeassistant_deploy`, backup, restore, remove and trust-maintenance contracts.
There is no deployment API, private engine switch or native qualification yet.
The selected application, Python and Matter versions are not being upgraded.

## Configuration ownership foundation

`services.homeassistant.configuration` models the original task ordering using
synthetic, in-memory inputs. It does not connect to a target, parse arbitrary user
YAML, write files or invoke Ansible. Later host integration must keep configuration
and credential bodies protected and retain actual backup and notification behavior.

- Management flags default off. Existing `configuration.yaml` and include files,
  including empty files, are preserved unless overwrite is enabled.
- Secrets management is independent of the overwrite flag. A changed managed
  secrets file still requires the original protected backup and mode0600.
- Only the exact old role-generated MET, system-monitor and discovery blocks
  are removed. MET removal has its original separate flag; other bytes remain
  untouched. Cleanup uses whether the file existed before the template task.
- The ordered edit records preserve separate original template/replacement
  tasks, backup requirements and replacement-only restart notifications. They
  are desired edits, not evidence that a file or service has changed. Bodies
  are hidden from repr and must never enter controller receipts.

The bound unmodified original task file and tests cover flag combinations,
new/existing/empty files, near-match preservation, task order and exact repeats.
This is source-level behavior proof only. Native application/API, real canaries,
venv recovery, backup/restore and removal qualification remain outstanding.

## Physical runtime input foundation

`HomeAssistantRuntimeConfig` follows original user/home/site/path derivations,
including independent explicit config/data/log/venv/unit overrides. Home Assistant
and Matter unit templates are unmodified original source, rendered with the
original whitespace behavior. Optional Matter dependencies, logging and original
Python/package guards are covered by source tests. The original default package
spec remains unpinned; actual selected private versions will be mapped explicitly.

This schema does not yet install dependencies or perform service rollout. UV
private include-variable mapping, package/security/environment recovery, application flows and
all lifecycle paths remain implementation work. No physical no-op or application
acceptance follows from template or input tests.

The prepared UV component uses the original Home Assistant 0.13.5 version and
complete checksum defaults, leaving the shared installer's 0.13.4 defaults
unchanged. Its nested `uv` settings represent the resolved original include:
HA version/path/update/force settings are distinct from generic checksum/owner/
group settings. The original `homeassistant_uv_install_user` is inert in the
dependency role and gains no new ownership authority. Deprecated symlinks remain
disabled. `manage_uv=false` skips this entire component; an explicit `uv_path`
for later application commands remains independent of the install directory.
When enabled, it uses the existing checksum-verified installer and retains the
original final version/help checks, classified as read-only commands. Fake-host
tests cover current, outdated, update-disabled, forced, symlink and explicit
path/owner cases. Its original role gate runs before the shared installer:
with updates disabled, a broken existing UV is not silently replaced and must
fail its final functionality check; a missing UVX alone is not an original
replacement trigger. The shared installer's broader recovery behavior remains
unchanged for other callers. Real install,
ownership, interruption and healthy-repeat proof remains part of the forthcoming
native matrix, not a consequence of these synthetic command checks.

## Python replacement decisions in preparation

The prepared `python_state` module evaluates the original Home Assistant and
Matter replacement/install decisions without executing probes or changing a host.
Home Assistant replacement includes force, llama.cpp rebuild, missing or mismatched
Python, broken pip and legacy Matter contamination. Matter uses its separate
environment, pip and chip dependency checks. Unpinned application specifications
retain the original behavior: an existing binary does not implicitly upgrade.

Replacement preserves the original ordering: stop an existing Matter unit before
an existing Home Assistant unit when replacing the old Home Assistant environment,
even when Matter management is now disabled. Missing environments do not invent
existing-unit stop actions. A malformed interpreter response remains an error.
Tests evaluate the bound original task expressions over all combinations of these
predicates. This is source parity, not an executed virtualenv or recovery proof;
host probe wiring, UV installation, package security constraints, service rollout
and native recovery remain unfinished.

Prepared observation wiring runs the bounded original interpreter/package probes
as the declared service user, with bytecode disabled and status-only results.
It separates interpreter/pip/legacy-package inspection from application version
and Matter chip imports: an environment selected for replacement never runs the
old application's version/import commands first. Tests execute the actual encoded
helper using owned synthetic executables and a local identity stub. They prove
command sequencing and response validation, not actual Home Assistant or Matter
behavior, service-user privilege separation, or physical no-op on a target.
Existence follows the original `stat` behavior without following symlinks. A
dangling Python link therefore fails version inspection before replacement;
a failed application command retains the original empty-version/install
decision, including the lack of an implicit upgrade for an unpinned spec.

The prepared unit-trust adapter sends the unchanged original systemd/proc
inspection program and exact managed drop-in bytes. It preserves the original
unknown-drop-in, manager/environment trust, reload and running-process guards,
including the explicit missing-unit preflight option. Owned synthetic systemctl
and proc fixtures exercise its actual encoded command and verify that private
environment values never enter its status output. This does not install the
drop-in, restart a unit, qualify a real systemd process, or complete the separate
UV system-certificate maintenance workflow.

The prepared account/layout component retains the original append-only dialout
membership, home/shell settings and ordered0755 directory ownership. It returns
the exact static udev-rule dependency for the original deferred handler boundary;
reload-rules and tty trigger run only when that rule changed. Synthetic connector
checks cover current-rule suppression and unrelated group preservation. This is
not a public deploy entry point or a native udev/radio/system-account proof; full
validation, trust and package prerequisites must precede its eventual caller.
