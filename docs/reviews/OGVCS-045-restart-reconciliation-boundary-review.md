# OGVCS-045 restart-reconciliation boundary review

**Decision:** SHIP the current-authority detection-and-quarantine tranche only.
HOLD automatic container/tmpfs settlement, public conformance claims, and every
OGVCS-045 acceptance criterion.

**Reviewed source:** restart change
`3049f81880712cb1aead1e7634001f82b08ae76d`, rechecked in integration at
`eba66db8fdfa6da3fbbf5369711ad9f3023514f8`.

## Accepted boundary

The private Linux adapter now accepts one state-root-owned daemon authority key,
derives an authority identifier, and authenticates the exact Docker resource
bindings created under that authority. On service open it reads durable
nonterminal jobs before local recovery, asks the adapter to discover and inspect
only current-authority resources, and proceeds with local restart denial only
when that namespace is provably empty.

When resources exist, discovery or inspection is incomplete, a binding is
invalid, a job is unknown, or the resource graph is ambiguous, the adapter
returns a closed quarantine report and poisons itself. The state layer persists
only allowlisted diagnostic codes and SHA-256 resource fingerprints. Raw Docker
identifiers, paths, labels, authority material, and command failure details do
not enter shared evidence.
The state boundary accepts only the six reconciliation codes emitted by this
adapter plus its two service-local failure codes; every unregistered diagnostic
is collapsed to `RECONCILIATION_CONTROL_UNPROVABLE` before persistence.

This is fail-closed detection, not cleanup, and performs no orphan deletion.
The reconciliation path issues only bounded list and inspect controls. Unit
fixtures assert that every represented
crash topology, forgery, overflow, timeout, malformed response, mixed graph,
foreign authority, and legacy-resource case performs no destructive Docker
call. A quarantined report prevents the state layer from rewriting an
interrupted job as locally denied.

## Authority and inventory limits

The authority record is owner-only and opened with no-follow, nonblocking,
pinned identity checks. The HMAC key is copied only into the adapter for the
service lifetime and is zeroed after reconciliation failure or service close.
Resource labels are treated as discovery hints: inspected container and volume
shape, names, roles, mounts, policy, runtime, job, and binding MAC must all
match before a resource is classified as authenticated.

Discovery is intentionally scoped to the current authority identifier. A
foreign authority, a legacy branded resource without authority labels, or an
ambiguous resource is never claimed or deleted. Consequently an empty result is
only an absence proof for the current authority namespace; it is not an
exclusive whole-daemon inventory.

## Local evidence

On 2026-09-02, Node 24.9.0 `npm run test:sandbox` passed:

- five contract and packed-package cases;
- 54 of 61 runtime cases, with seven Linux-only cases skipped on macOS; and
- three retained-evidence/workflow policy cases.

The restart-focused runtime cases cover every modeled create/start/exit/cleanup
topology, repeated detection, request-shape attacks, authority substitution,
binding and graph forgeries, bounded-list and inspect failures, foreign/legacy
exclusion, restart ordering, and closed quarantine persistence. This is local
model evidence. It does not execute the new reconciliation tranche against a
live Linux Docker daemon and is not a retained hosted report.

## Completion blockers

Automatic settlement remains destructive and requires explicit approval plus a
new implementation and hosted live-Docker proof. Any future settlement path
must delete only a fully authenticated current-authority graph, prove exact
container settlement before volume removal, remain retry-safe across every
delete boundary, retain closed receipts, and leave foreign, legacy, unknown, or
ambiguous resources untouched.

Exact deployed runtime-binary attestation, the complete broker/runner/output-
validator kill matrix, independent full isolation review, public conformance
admission, consumer integration, operations/runbooks, and rollout also remain
open. OGVCS-045 stays Todo and AC-01 through AC-05 remain open.
