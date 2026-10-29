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


## Trust-floor component in preparation

The prepared `security` component copies the original `python_security_floor`
inspectors and controller policy. Nested `security` inputs carry the original
package floors, Requires-Python constraints, distrusted fingerprints, optional
managed-base binding and explicit policy overrides. The original HA/Matter
list of environments remains independently overridable. Missing interpreters
are skipped only during preflight; a dangling link counts as an existing path
and its failed inspection is not silently treated as absent.

Preflight inspects existing environments and, when enabled, the system CA
store before deployment writes. Constraint files limit package resolution and
do not install packages. The post-install read-only operation obtains fresh
reports at execution time and applies the same policy; it does not reuse a
planning report. Inspector programs import certifi/pip only, never Home Assistant,
and retain isolated Python execution with added bytecode suppression. These
checks cannot prove global zero I/O or physical-device behavior. Original policy
failures are not silently remediated, and explicit existing trust overrides are
not rewritten. Caller sequencing, application/package installation and native
qualification remain unfinished; this component is not yet a deployment API.


The prepared interpreter component preserves `uv python find VERSION` followed
by installation only on a nonzero find result. The managed operation performs
fresh queries at execution and verifies availability after installation. Its
actual change result is intended for the original deferred HA/optional Matter
restart notifications. Later virtualenv observations must occur after this step:
installing a Python patch can retarget UV's minor-version link and make an
existing virtualenv current without rebuilding it. Cold-plan deferral is limited
to declared earlier user/UV creation prerequisites. Synthetic SDK tests establish
operation ordering and failure behavior, not real UV download or symlink changes.


The prepared recursive environment-ownership component checks descendant
metadata, because the SDK directory operation only recurses when the root's
owner/group differs. It preserves the original role's `follow=true` behavior:
symlinks and existing targets participate, including linked directory contents
and intermediate links. Thus the scope includes UV interpreter targets reached
from the declared virtualenv; it is not confined to lexical descendants. No file
bodies or path listings are returned. Existing modes and modification times stay
unchanged, and already-correct ownership never invokes chown. Missing ancestors
are created with the original ownership/umask behavior. Only a root link is
resolved first; a missing root beneath a dangling ancestor retains the original
failure instead of creating that ancestor link's target. A link cycle or a root
resolving to `/` fails before repair; this is an early guard, not a claim that the
original module had identical partial-failure effects.

Owned local Colima ARM/Linux primitive tests exercise real descendant ownership
repair, hardlinks, dangling links, existing external targets, link chains and
strict full-metadata repeats. The test container has no network or host mounts,
a read-only root filesystem and a bounded temporary filesystem; its owned image
and container are removed afterward. These are typed filesystem primitive tests,
not execution of the complete original Ansible role or native Home Assistant,
Matter, radio or inventory qualification. Caller sequencing and full native
application/lifecycle proof remain unfinished.

### Prepared virtualenv replacement

The unexported environment component resolves the selected interpreter and reads
Python/pip/legacy-package state again at execution, after the requested Python
installation. It preserves Matter-before-HA stopping for an existing HA
environment, including an old Matter unit when Matter management is disabled.
The missing-Python case preserves the original no-stop path. Removal handles
files, links and directories; creation uses the original service user, HOME,
site working directory, implicit HA `.venv` and explicit Matter destination.
Cold plans with a known pending creation prerequisite expose an unresolved
creation row; execution always performs the real observation. A failed creation
after stopping/removal remains failed with those partial effects, with no
automatic restart or invented rollback. SDK sequencing tests use synthetic
facts; real HA/Matter replacement and recovery remain in the future native
matrix. Package installation, record/link/ownership composition and deployment
entry point are still being implemented.

The caller passes the actual preceding `install_python` operation as
`python_install` to `prepare_environment`. A planned Python installation thus
makes environment planning explicitly unresolved even when user and UV already
exist; it is not misclassified as an unavailable prerequisite. Execution still
fails before any stop/removal if the requested interpreter remains unavailable.
