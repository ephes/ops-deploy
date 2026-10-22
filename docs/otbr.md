# OpenThread Border Router

`ops_deploy.infra.otbr` exports `OtbrConfig` and `deploy_otbr`. This deploy-only
candidate ports `otbr_deploy` from ops-library main `3110a0f1` (2.68.0).
It has no Thread dataset, firmware, backup, restore or removal operations.

A full upstream commit, stable `/dev/serial/by-id/` character-device path and
infrastructure interface are required. Unlike the role's floating `main`, the
port requires an immutable source revision. Review that deviation and the
upstream scripts before authorizing a deployment. Source revision alone never
proves the installed binary was built from it.

`build_window_approved` defaults to false and refuses even a plan before writes.
Set it only for an explicitly approved build/device window. Actual read-only
checks still refuse a dirty, non-root-owned or writable source checkout,
unsafe source ancestors, existing BIND packages/units, any DNS listener (including a local
resolver), missing socket inspection, missing RCP or missing interface. A DNS
collision needs a separate approved resolution; this deploy never resolves it
by removing an existing DNS service.

The supported paths and source URL are fixed. Builds use upstream bootstrap
and setup scripts with the role's build environment. They can install packages,
change networking/firewall settings and start services; this is an invasive
operation even with a pinned revision. The port removes only bootstrap's
transient BIND package, after refusing any pre-existing BIND. Retaining BIND
(`remove_bind=false`) and disabling package management are unsupported and
rejected. REST listens on loopback only; arbitrary extra options/build options,
package lists, service names, udev IDs and path overrides are rejected.

The first qualified run bootstraps/builds when its own successful-build marker
is absent. That marker records source revision and build environment only after
service/configuration operations succeed. Missing binary, changed source/env,
forced bootstrap or forced rebuild also rebuild. An applied-defaults marker
keeps an interrupted configuration restart pending on retry. The role's old
markers are not accepted as build provenance. Successful stable runs neither
build nor reload udev nor restart services. As in the role, disabling web support
does not stop an already existing web unit.

Udev changes reload rules and trigger tty devices. Agent defaults match the
role's template. This does not flash the RCP or issue Thread control commands.
The operator must establish an external restore path and record Thread/device
invariants before the device window; no local snapshot mechanism is added.

Run the committed tests normally. Run fresh-role template parity separately:

```sh
OTBR_PARITY_LIBRARY_PATH=/path/to/fresh/ops-library uv run --locked pytest tests/test_infra_otbr.py
```

No live qualification or engine switch is implied by these tests.

## Partial failures

Planned rebuilds invalidate the prior build proof before bootstrap/build begins;
planned bootstraps also invalidate the prior bootstrap proof. This includes forced
attempts at the same SHA/environment, so a failed forced attempt followed by a
normal deployment cannot reuse stale success markers.

Bootstrap success records the exact source revision and build environment;
a stale marker never skips bootstrap after a failed revision update. Submodule
initialization runs again whenever a build is planned, including retries after
checkout already reached the desired HEAD. First clones stage in an owned
private directory under `/opt` and publish only after checkout/submodules succeed.

A failed bootstrap/setup may leave its transient BIND package installed or
listening. The next run deliberately refuses that state before any writes; it
cannot distinguish it safely from an operator's DNS service. Stop for an
owner-approved, separately reviewed recovery deployment rather than purging
BIND manually or weakening the guards. No automatic failed-build recovery is
claimed in this case. A dirty existing checkout similarly needs an approved
recovery plan; it is never forcibly reset or removed by this deploy.
