# Real UniFi routine integration

Dispatch `.github/workflows/unifi-routine-integration.yml` with an exact reviewed
`implementation_sha`. The harness checks disposable GitHub-hosted Ubuntu
x86/systemd and absence of existing UniFi/MongoDB state before provisioning,
then records run/machine ownership. Never run it on an inventory host.

Real fixture: MongoDB 8.0.34 with authorization enabled from startup, then production routine API installs Java17 and vendor UniFi9.4.19
with its real package and custom unit. The deployment under test repeats with
zero mutations, then updates to checksum-selected9.5.21, creates the HA integration, preserves
site IDs and a DB sentinel, and must produce zero mutating operations on each
repeat. It repairs deliberately introduced Mongo logging and HA password/role
drift without changing HA ID. Wrong authentication and a bad package digest
must fail without modifying the protected state or stopping the controller.

The fixture's localhost-exception database initialization is fixture setup;
production fresh bootstrap remains unsupported. No real credentials, device
adoptions or inventory hosts are used. Evidence JSON omits operation arguments;
service logs and provenance are uploaded for seven days.

The localhost exception creates a fixture-only user administrator first; that
account authenticates to create the role-parity UniFi Mongo user. MongoDB
authorization remains enabled throughout. Creating the application user as the
first user was rejected in run40316009319 and reproduced on real Mongo8.0.34;
that failed run is retained as evidence. The receipt records the actual
controller process JVM executable and version before/after the selected update,
without assuming that the installed Java17 package is the selected runtime.
