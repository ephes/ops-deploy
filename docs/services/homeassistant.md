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
include precedence, package/security/environment recovery, application flows and
all lifecycle paths remain implementation work. No physical no-op or application
acceptance follows from template or input tests.

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
