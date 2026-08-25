# OGVCS-041 — Public protocol baseline and generated bindings

**Completed:** 2026-08-25

**Release:** R0 — Engineering Foundation

**Packages:** `@opengamevcs/protocol-contract-v1`,
`@opengamevcs/protocol-types-v1`, `@opengamevcs/protocol-baseline`, and
`@opengamevcs/protocol-baseline-independent-adapter` 1.0.0-rc.1

## Delivered baseline

OpenGameVCS now has an executable public protocol baseline before domain API
implementation. ADR-0013 fixes TLS 1.3 over HTTP/1.1 with bounded I-JSON/JCS
control messages, explicit canonical-JSONL stream completion, deterministic
capability negotiation, closed safe errors, idempotency and cursor semantics,
and an application-neutral HTTP range/resume carrier. OGVCS-008 still owns
production object routes, upload sessions, packs, placement, and availability.

One numbered declarative model generates 46 schemas/messages, 352 field
assignments, 35 finite limits, 25 errors, 16 registries, normative documents,
and complete descriptor tables for Rust, C++, C#, and TypeScript. The generated
contract contains 360 executable scenarios: 87 accepts and 273 fail-closed
results across negotiation, envelopes, idempotency, cursors, streams, transfer,
release preflight, malformed input, resources, and security.

## Compatibility and security behavior

- Negotiation independently selects protocol, schema, repository format,
  authorization, path contract/profile, event, transfer, and extension axes.
  Unknown required capabilities, absent tuples, downgrade, forbidden lifecycle
  state, and required-but-unoffered extensions fail before mutation.
- Mutation receipts bind the exact selected tuple and authority state. Request
  fingerprints are domain-separated hashes of validated semantic JCS.
- Errors use a closed RFC 9457 subset with fixed safe parameter domains.
  Credentials, grants, protected paths/objects, hidden cardinalities, arbitrary
  details, and arbitrary extensions cannot enter retained problems or traces.
- Idempotency survives lost responses and late settlement, rechecks
  authorization before replay, rejects semantic key reuse, and never silently
  re-executes an expired committed key.
- Cursors are opaque, scoped to all five dimensions, expiring, and explicit
  about gaps. Streams require registered terminal frames; EOF is incomplete.
- The transfer carrier validates actual range bytes, strong ETags, RFC 9530
  `Content-Digest`, half-open range mapping, interruption, and completion. It
  invokes the exact digest-pinned OGVCS-003 verifier without claim reinterpretation.

## Final review hardening

Implementation revision
[`dfdd7ad`](https://github.com/n3r/OpenGameVCS/commit/dfdd7adcf07a3e6c964e97d21434f370c3664250)
closed the final hostile-input, resource, and lifecycle boundaries:

- all public JavaScript host records and callback results are snapshotted as
  inert exact data before semantic use; proxies, accessors, inherited fields,
  mutable collections, and caller exceptions fail through typed protocol paths;
- one composite working-memory budget now includes scenario plans, traces,
  canaries, pages, envelopes, streams, transfer data, external-runner input,
  captured output, and parsed results;
- operation-scoped deadlines compose abort sources without listener retention
  and preserve the first authenticated boundary result;
- schema inventories are authenticated and reused without duplicate full clones,
  while caller-selected schemas are cloned and charged;
- idempotency replay is bound to stored authority and immutable committed
  outcomes, including settlement that crosses a caller deadline;
- the transfer HTTP body is accounted as transfer data rather than a 64-KiB
  control string, with a positive valid payload larger than that control limit;
- external adapter descriptors are validated inertly and charged before process
  isolation, and stdout/stderr parsing/capture is bounded.

The runtime README now states the trust, cancellation, and composite-resource
contract explicitly. Regression tests cover each boundary and preserve exact
error/trace precedence.

## Independent conformance and packaging

The reference runtime and a separate-process adapter share no negotiation,
idempotency, cursor, mutation, schema, or selector engine. The runner randomizes
opaque handles and ordering, removes expected outcomes, stages only a
manifest-authenticated execution view, and confines the adapter to its isolated
package closure. Protocol and predecessor vector corpora are absent from that
closure.

Both adapters produced the same digest for all 360 scenarios. Six exact MIT npm
archives installed, regenerated, and ran without network access. Hosted run
[`32843391920`](https://github.com/n3r/OpenGameVCS/actions/runs/32843391920)
compiled retained Rust/C++/C#/TypeScript consumers and reproduced identical
package, source, and semantic authorities on Ubuntu, macOS, and Windows. The
downloaded strict comparison was independently replayed byte-for-byte. The
current benchmark/fault-harness compatibility workflow also passed in
[`32843391941`](https://github.com/n3r/OpenGameVCS/actions/runs/32843391941).

## Version lifecycle

The delivered contract remains `1.0.0-rc.1`, candidate, and unratified by
design. OGVCS-041 is complete because it owns the public R0 candidate baseline;
OGVCS-005 consumes that baseline before a later compatible transition may mark
`1.0.0` ratified. Consumers must not create a private alternative protocol.

The separate OGVCS-002 one-million-entry/logical-1-TiB campaign is already
complete and was not rerun here. Routine protocol pull requests continue to run
only bounded conformance; exact scale remains monthly or major-release work.
The durable [completion packet](../evidence/OGVCS-041/README.md) records current
authorities, packages, reports, jobs, and the full acceptance map.
