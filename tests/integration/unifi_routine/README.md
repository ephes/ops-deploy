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

Run40318175856 installed9.4.19 and updated9.5.21 with zero-mutation repeats,
then refused admission after the fixture's explicit Mongo restart. Its evidence
is retained as a failed run. The fixture now waits for authenticated Mongo and
the dependent controller to become ready after that deliberate restart, records
only fixed admission status labels on failure, and persists runtime evidence at
each phase instead of only on complete success. Its journal also exposed a
controller-owned Mongo process on the fresh installation; external-database
application use must be proven before the complete path is qualified.

The corrected production path initializes external database selectors only for
an admitted absent controller with no existing data. The fixture requires an
authenticated HA API login and matching default-site identity in the external
MongoDB, plus exactly the system mongod process and no embedded database.
Both application and statistics connections select authenticated external DBs.
Existing controller configuration is never migrated by this initialization.

Run40322273105 reached authenticated external MongoDB during fresh9.4.19
startup and failed because the initialized fixture user lacked `unifi_audit`
access. The fixture adds only `readWrite` for that database, preserving
authorization and avoiding administrative or wildcard grants. Existing live
controller roles and database selection are not changed by fixture setup.

Fresh-controller admission verifies effective database privileges and refuses
nonempty application/statistics/audit databases before any controller writes.
The VM exercises all three nonempty refusals, missing audit-write access, and
actual scoped audit CRUD/index operations under the application identity. Those
CRUD operations are fixture evidence, not a claim of controller-generated audit
events. The existing installed-controller path does not acquire audit grants.

Before inserting protected records or updating the controller, the fixture
completes the real setup wizard using the bundled frontend's `add-default-admin`
and `set-installed` API commands with a fixture-only administrator. It verifies
`is_default=false` and the API/external-DB site identity. No site is fabricated
in MongoDB. The initialized state must survive update and repair; otherwise
vendor Factory Default could reinitialize databases and invalidate preservation
proof. This setup API is never called by the production deployment.

Run40332163946 passed all four admission refusal cases, scoped audit CRUD,
real9.4.19 installation and its zero-mutation repeat. It failed while parsing
a wizard HTTP response, before any selected-version update. Its artifacts are
retained. Wizard diagnostics now persist each fixed phase's response status,
content type and redirect flag without bodies, cookies or credentials; the
actual JVM is recorded before that step too.
