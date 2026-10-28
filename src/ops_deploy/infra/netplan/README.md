# Persistent Netplan networking

`NetplanConfig` and `deploy_netplan` preserve the original `netplan_config`
YAML and route-guard script, service and timer. They support networkd static
configuration and NetworkManager DHCP, including both DHCP hostname fields.
The normal private wrappers select their original fixed host and policy.

Admission reads the explicit managed paths, native unit state, and declared
networkd carrier/setup/routes. It refuses linked/shared or unowned guard
files before persistent configuration changes. Native distribution tools are
required. A healthy repeat makes no managed activation command; the final
verification is explicitly read-only. A dry plan never runs native generation,
activation, recovery or temporary validation.

On configuration or declared health drift, a private temporary tree containing
the existing flat inputs from `/lib`, `/etc` and `/run/netplan` and proposed configuration is validated with
`netplan generate --root-dir` before publication. Validation is part of the
managed operation. Only declared configuration and cleanup paths are changed.
The original route-guard lock, periodic policy and carrier protection remain.
A healthy invocation does not gratuitously reconfigure an interface or exercise
the guard. Actual configuration/health drift exercises the normal recovery path.

Activation runs in one bounded transient systemd oneshot. `--no-block` lets the
controller observe it across a networkd restart using the same SSH identity and
operation privilege arguments. The systemd job owns its process group and the
controller waits through queued/never-executed jobs, checks terminal result,
stops only its unique unit, resets an owned
failed unit, and verifies inactive state with zero main/control PIDs. Unknown
remote outcome or unproven cleanup requires retaining the deployment writer
slot; it must not trigger automatic replay or manual network repair. The job
has an overall activation deadline (720 seconds, extended for a
longer configured guard), plus a 120-second reconnection margin. Individual
native command maxima do not sum into a claim that every command can exhaust
its limit in the same job; an overall deadline fails closed with an uncertain
result retained. The guard-start wait includes its rendered per-interface
recovery budget. It is not an adoption marker, persistent attestation or a reboot operation.

`single_static_default=True` is the original Fractal playbook's additional
strict contract: one configured static networkd interface, exactly one IPv4
default through its declared gateway/device, no DHCP default, and configured
setup state. DHCP observed before or after apply invokes the original
networkd-restart recovery. Fixture substitutions do not attest physical LAN,
boot/initramfs recovery, hardware or real inventory continuity.

The four vendored templates are byte-identical to selected source role cf3a0c7;
`tests/parity/netplan_sources.json` records this narrow provenance without
rebasing the repository's unrelated original-role baseline. Model, controller
failure and owned native tests are separate evidence. Inventory adoption and
live qualification remain separate from this implementation.
