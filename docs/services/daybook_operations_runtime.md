# Daybook operations runtime

This implementation slice defines the protected schema-five profile, original
runtime resource rendering and monitor-only verification boundary. Host install,
stop/update transitions and normal routing are being qualified separately; this
slice does not switch an inventory engine or authorize a live source update.

`DaybookRuntimeConfig`, `RuntimeKind` and `RuntimeWorkers` preserve the original
`daybook_operations_runtime_deploy` role's profile, worker reserve, deadline/lease,
owner and capability-host interfaces. Fresh installation renders disabled;
`cutover` is the only action that renders enabled. Existing transition
confirmation and action/start restrictions remain. The three packaged templates
are byte-for-byte copies of ops-library cf3a0c74.

The normal default decision uses the current Main revision resolved once for the
whole run. An enabled installation with exact declared source/lock/runtime and
resource equality selects pure verification. A change selects the original
guarded stop → importer install → replace → cutover/start → verify update flow,
once all dependent APIs are qualified. Fresh or disabled installations stay
disabled. The installed old commit must never replace desired Main to manufacture
a no-op. Revision text alone is not proof of source/resource equality.

The new pure verification contract uses `GET /v1/status` with a separate existing
**monitor-purpose** credential through the existing redacted `SecretValues`
container, under its `monitor_token` key. The executor credential is denied by that route.
There is no retry, redirect or fallback to executor `operations status --binding`,
which can expire server authority and opens a local Journal. Existing guarded
update effects remain separate and must be counted as managed effects.

The HTTPS client retains exactly `binding`, `enabled`, `active_state`,
`expiry_pending`, `unapplied_receipts` and `needs_operator` for explicitly declared
sources. It discards the rest of the response and emits fixed failure categories;
no raw response/error body, principal, IDs, arbitrary blocker text or token enters
its results. It verifies TLS normally, limits the body to 256 KiB, uses a 30-second
socket timeout and performs one request. A failed monitor call remains a failure.

The reviewed deployed handler and reachable helper source have a dedicated
aggregate read path before expiry/contact/write transactions; no local Journal
constructor is used. Actual endpoint use requires that same source boundary and
the existing monitor credential purpose, without permission or policy changes.

Run the paired resource oracle explicitly with the actual original role:

```sh
OPS_LIBRARY_PATH=../ops-library uv run --locked --with ansible-core \
  pytest tests/test_daybook_runtime_contract.py tests/test_daybook_runtime_status_tls.py
```

The owned local HTTPS fixture checks certificate denial, exact route, monitor vs
executor purpose, repeated reads, redirect denial and oversized-response failure.
It has synthetic operational metadata and no personal data or inventory access.
