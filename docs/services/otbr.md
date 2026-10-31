# OpenThread Border Router

`OtbrConfig` and `deploy_otbr` port the original `otbr_deploy` source/build,
agent, optional web and USB-rule workflow. Supply the existing RCP device and
infra interface; no radio firmware, Thread dataset or new network policy is
invented. The original templates, including their provenance comment, are
packaged byte for byte. Public source and owned synthetic fixtures are distinct
from a real radio or application qualification.

```python
from ops_deploy.infra import OtbrConfig, deploy_otbr

deploy_otbr(
    OtbrConfig(
        rcp_device="/dev/serial/by-id/owned-example",
        infra_interface="eth0",
    )
)
```

Defaults follow the original role. The recursive, forced upstream checkout is
`https://github.com/openthread/ot-br-posix.git` at moving `main`, under
`/opt/ot-br-posix`. Managed prerequisites are ca-certificates, curl, git,
lsb-release and sudo. The original implicit OS python3-apt module dependency is
declared explicitly before the cache refresh and selected package operations.
`manage_packages=False` suppresses prerequisite installation
and BIND package purge; it does not suppress `remove_bind` service stop/disable.
BIND service presence is inspected inside its operation after bootstrap/setup,
including services installed by bootstrap in this same run. The default selected
BIND package is bind9; selected services are named.service
and named-resolvconf.service. Both lists remain configurable.

Bootstrap runs when forced, source changed, or its marker is absent. Setup runs
when forced, source changed, the original eleven-line build record differs
(including its root ownership/mode), or the agent binary is absent. Defaults for
marker/record follow install_dir: `.otbr-bootstrap` and `.otbr-build-config`.
`force_bootstrap` and `force_rebuild` remain independent. `build_env=None` derives
the original eleven environment settings; an explicit mapping, including an
empty mapping, replaces the whole default environment. As originally, changing
only a custom environment is not itself an additional build-record trigger.

The defaults enable REST on 127.0.0.1:8081, use wpan0 at 460800 baud, disable the
web UI, enable backbone/border routing, NAT64, discovery proxy and firewall,
choose OpenThread mDNS and no DHCPv6 PD client, and permit auto-attach. The infra
interface falls back to the original default IPv4 route interface if unset.
Backbone defaults to that resolved infra interface only when unspecified;
explicit empty or custom backbone values retain their literal original meaning.
The exact original USB rule covers vendor303a, products4001/831a, groupdialout,
mode0660; all rule variables, its destination and manage_udev remain configurable.

Two narrow failed-build repairs are deliberate. Internal metadata no longer
replaces the bootstrap marker path with an Ansible stat-result object. Before
a selected source/bootstrap/setup attempt, invalidate the selected bootstrap
marker and/or build record; publish each success record only after its successful
step. This preserves the original eleven settings lines while making a failed
source-only advance retryable even when an old agent binary and identical settings
remain. The old role could prematurely record settings or leave the old success
marker and subsequently skip failed work. Owned negative/fixed controls must
qualify these failure cases before adoption.

The original systemd enabled/state values and unconditional daemon reload are
retained. A setup or changed agent defaults restarts agent only when
restart_on_change and service_state=started; setup also restarts enabled web.
Disabling web does not stop an existing web service. Changed udev rules run the
original rule reload and tty trigger handlers. The normal recursive Git fetch
remains visible repeat I/O; neither it nor daemon reload is claimed read-only or
zero managed work.

Before a real window, inspect a fresh installed-versus-resolved source effect
map. Moving upstream main can bootstrap, compile/install and restart the radio
network stack, remove the selected BIND services/packages and trigger udev. The
pure `source_effect_map` exposes those effects; it never substitutes an installed
ref to manufacture a quiet plan. Global pyinfra dry mode can still resolve the
upstream source and read declared build metadata; it is not a no-network fact.
No actual radio, production BIND or network action is source qualification.

Original custom ref forms include `HEAD`, branch, tag, full commit and abbreviated
commit. On an existing checkout, `HEAD` follows that checkout's branch (or its
cached origin/HEAD when detached), matching the original Git module. A historical
abbreviated commit can remain unresolved until the scheduled original fetch;
that state is explicit in the effect map and conservatively selects bootstrap
and setup. Subsequent local resolution permits a quiet build repeat. Before a
real window, resolve that source effect explicitly; never substitute the installed
commit or mutate the host from a planning probe.

Original HTTP/Git/file/SSH transports and plain local repository paths remain
configurable, as do apt package-version pins and extended octal udev modes.
Planning Git commands disable optional locks so status/submodule stat-cache
refreshes cannot rewrite indexes. Path probe diagnostics identify OTBR directly.

Selected package state is inspected inside its operation, after preceding cache
updates/bootstrap/setup. Memory-only python-apt metadata retains the original
name/version fnmatch, matching-candidate upgrades and configured purge behavior;
ordinary pyinfra operations run only the selected apt-get commands. Wildcard
version pins are resolved to their selected exact candidate instead of being
treated as literal installed versions. Owned Debian package controls cover first
install, repeat, newer matching candidate, wildcard purge and residual conffile
purge against the actual original Ansible APT module. These are synthetic package
controls, separate from genuine upstream OTBR and hardware qualification.

Standalone selected-package dry planning cannot install a missing OS Python APT
library. It refuses when that library cannot be imported, matching the original
APT module's check-mode dependency refusal. Full OTBR deployment instead records
explicit unresolved selected-package work during prepare (and global dry), then
inspects metadata only after the declared dependency/cache operations execute.
It never presents that deferred dry decision as a resolved/noop package plan.
A normal managed deployment can therefore install the declared dependency and
refresh empty/stale lists before selecting candidates. The dependency bootstrap
refresh runs only when its OS package is absent; the original unconditional
selected-package cache refresh follows it. Installed dpkg metadata alone is not
claimed to prove that the library imports successfully. Owned isolated mount-namespace controls
prove both refusal paths without uninstalling the host library. This is a dry
planning limit, not a permanent supported-host exception or manual prerequisite.

Plain relative repository paths are normalized against the original command
working directory before resolving, cloning, comparing or setting origin. A
repeat therefore uses the same repository. Leading Git options are rejected as
source values; transport and authenticated URL configuration stay supported.

The private original-role adapter can retain `original_template_flags` for the
original eight template/build-record flags: REST, web, backbone, border routing,
NAT64, discovery proxy, firewall and no-auto-attach. This finite map preserves
raw Ansible ternary/Jinja truthiness, which differs from the role's `|bool`
operation conditions for values such as quoted `"false"`. It affects only the
original rendered templates and eleven build settings lines/default environment;
service/build predicates continue to use the normalized boolean fields. It
cannot override nonflag settings, service actions, hardware or arbitrary render
values. Native booleans and an absent map keep the previous exact behavior.
Each retained raw flag must normalize to its matching boolean condition using
the original core boolean semantics; inconsistent pairs are rejected. This
retains one original input's two meanings without admitting unrelated settings.
