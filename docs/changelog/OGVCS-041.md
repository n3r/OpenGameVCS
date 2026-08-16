# OGVCS-041 — Public protocol baseline and generated bindings

**Validation candidate:** 2026-08-16

**Release:** R0 — Engineering Foundation

**Packages:** `@opengamevcs/protocol-contract-v1`,
`@opengamevcs/protocol-types-v1`, `@opengamevcs/protocol-baseline`, and
`@opengamevcs/protocol-baseline-independent-adapter` 1.0.0-rc.1

## Delivered candidate

OpenGameVCS now has one executable public protocol baseline before domain API
implementation. ADR-0013 fixes TLS 1.3 over HTTP/1.1 with bounded I-JSON/JCS
control messages, explicit canonical-JSONL stream completion, deterministic
capability negotiation, closed safe errors, idempotency and cursor semantics,
and an application-neutral HTTP range/resume carrier. Production object routes,
upload sessions, packs, placement, and availability remain owned by OGVCS-008.

One numbered declarative model generates 46 closed schemas/messages, 352 field
assignments, 35 finite limits, 25 errors, 16 registries, normative documents,
and immutable descriptor tables for Rust, C++, C#, and TypeScript. The generated
contract contains 360 executable scenarios: 87 accepts and 273 fail-closed
results across negotiation, envelopes, idempotency, cursors, streams, transfer,
release preflight, malformed input, resources, and security.

## Compatibility and security behavior

- Negotiation independently selects protocol, schema, repository format,
  authorization, path contract/profile, event, transfer, and extension axes.
  Unknown required capabilities, absent tuples, downgrade, forbidden lifecycle
  state, and required-but-unoffered extensions fail before mutation.
- Mutation receipts bind the exact selected tuple and authority state. Request
  fingerprints are domain-separated hashes of validated semantic JCS, never raw
  received JSON bytes.
- Errors use a closed RFC 9457 subset with fixed safe parameter domains. Free
  detail, credentials, grants, protected paths/objects, hidden cardinalities,
  and arbitrary extensions cannot enter an error or retained trace.
- Idempotency survives lost responses and late mutation settlement, rechecks
  authorization before replay, rejects semantic key reuse, and never silently
  re-executes an expired committed key.
- Cursors are opaque, scoped to all five dimensions, expiring, and explicit
  about gaps. Streams require a registered terminal frame; EOF is incomplete.
- The transfer carrier validates actual range bytes, strong ETags, RFC 9530
  `Content-Digest`, half-open range mapping, interruption, and completion. It
  carries only compact request-root grants and invokes the exact digest-pinned
  OGVCS-003 verifier without reinterpreting its claims.

## Independent conformance and packaging

The reference runtime and a separate-process independent adapter share no
negotiation, idempotency, cursor, mutation, schema, or selector engine. The
runner randomizes opaque handles and ordering, strips expected outcomes, stages
only a manifest-authenticated public execution view, and confines the Node
adapter to its isolated package closure and that view. Protocol and predecessor
vector packages are physically absent from the permitted closure.

Both adapters produced the same result and trace digest for all 360 scenarios.
An additional 28,889-case bounded mutation sweep over all nine operations found
and drove fixes for combined-invalid precedence, closed cursor scope,
idempotency schedule and authorization, transfer preflight, canonical nonce,
receipt authentication, stream framing, and extension selection. A corrected
stripped-RunnerCase boundary sweep then drove transport, clock, expiry-overflow,
grant-shape/resource, and range-precedence regressions to exact parity.

Six exact MIT npm archives—the four protocol packages plus the OGVCS-003
contract/runtime predecessors—install in separate clean consumers without
network access. The packed proof regenerates checked-in outputs, runs both
adapters, retains exact package/report/source hashes, and proves the independent
adapter cannot read either outcome corpus. A commit-pinned workflow repeats the
proof and compiles retained Rust, C++, C#, and TypeScript consumers on Ubuntu,
macOS, and Windows before comparing exact packages, generated sources, and
semantic decisions.

## Review remediation

The critical review closed faults in authorization-detail safety, retry commit
reconciliation, replay authorization, cancellation, working-memory accounting,
contract loading, stream and transfer framing, cursor semantics, extension
lifecycle, release semantic drift, generated public types, oracle isolation,
predecessor provenance, HTTP range/digest/validator precedence, and independent
adapter parity. No live P0 or P1 remains in the frozen candidate.

## Rollout and deferred work

The candidate version remains `1.0.0-rc.1`; registry state is candidate and is
not falsely advertised as ratified. Domain services may consume it for R1
implementation, but a private incompatible protocol is not permitted.
Withdrawal disables new sessions without reinterpreting existing receipts,
cursors, idempotency records, assignments, or errors.

OGVCS-041 stays in Validation while OGVCS-002 and OGVCS-004 remain incomplete.
Per maintainer direction, the OGVCS-002 exact one-million-entry tree and
logical-1-TiB tests were not run here and remain deferred to the final R0
campaign. Hosted three-OS evidence is also pending and will be linked from the
[evidence packet](../evidence/OGVCS-041/README.md) before any completion claim.
