# OGVCS-003 — Authorization contract package and threat test kit

**Completed:** 2026-08-16

**Release:** R0 — Engineering Foundation

**Packages:** `@opengamevcs/authorization-contract-v1` 1.0.0 and
`@opengamevcs/authorization-contract` 1.0.0

**Frozen product source:** [`dcaae7e2c3cb966e9698cf86ee52ecc81f6381d3`](https://github.com/n3r/OpenGameVCS/commit/dcaae7e2c3cb966e9698cf86ee52ecc81f6381d3)

## Delivered outcome

OpenGameVCS now has one language-neutral authorization and threat-test contract
before production service work begins. The contract package ships ten closed
JSON Schemas, thirteen immutable security registries, two reference policies,
40 golden decisions, 30 executable abuse vectors, 16 signed grant cases, a
mixed-visibility authorized-view fixture, complete roadmap-surface coverage,
privacy/threat/operations/versioning documentation, and exact artifact digests.

The JavaScript package ships generated types and validation, a deterministic
fixture evaluator, authorized-view construction, Ed25519 grant verification,
sandbox requirement evaluation, fixture-operation mapping, and the `ogvcs-authz`
CLI. The CLI runs the corpus either against the packaged reference semantics or
against any bounded canonical-NDJSON adapter, making the test kit reusable by
future server, client, cache, and sandbox implementations.

## Frozen security contract

- Decisions bind actor and credential state, tenant/repository, reference or
  snapshot, canonical path/`FileID`/object context, permission, policy generation,
  and authority epoch. Matching denies override allows; no match denies.
- Explicit deny and absent allow share `DENY_NOT_AUTHORIZED`, and public results
  contain no protected path, existence, hash, count, policy, or claims detail.
- Authorized filtering precedes counting, ordering, ranking, pagination,
  aggregation, cursor construction, cache publication, and serialization.
- Object hashes are never credentials. Transfer grants bind the full caller and
  resource context, have a five-minute ceiling, and use trusted issuer key state.
  Request roots commit to a bounded canonical object plan supplied by the
  verifier, not by the holder.
- Deduplication, cache, encryption, quotas, purge, and metrics are tenant scoped.
- Privileged permissions are distinct, reason-bearing, and mapped to append-only
  redacted audit events. Audit access is independently privileged and audited.
- Hooks, merge drivers, import parsers, and preview tools receive no credentials
  or network by default and have explicit filesystem, CPU, memory, time, output,
  and fanout ceilings.

## Independent-review remediation

The first candidate was not accepted. The
[critical review](../reviews/OGVCS-003-critical-review.md) found public denial
oracle detail, insufficiently bound request-root and key-selection context,
self-consistent registry semantic drift, incomplete audit/decision relationship
proof, hostile JSON and adapter boundary gaps, authorized-view alias hazards,
and incomplete package/license/provenance evidence.

Remediation collapsed denial detail, added issuer/subject/permission/operation/
tenant/repository/audience/epoch/key/replay binding, froze a domain-separated
request-root algorithm and trusted verifier context, pinned every complete
registry document, added exact decision/audit relationships and mutation tests,
hardened canonical JSON and adapter process limits, rejected duplicate view IDs,
selected MIT, and retained offline packages and reports from all three operating
systems.

Hosted execution then exposed npm's platform-dependent tar mode for a declared
CLI. A bounded archive finalizer now validates tar structure, normalizes the
entry and header checksum, and emits portable deterministic gzip framing. The
installed npm shim is separately executed, and Linux/macOS/Windows now retain
byte-identical package archives.

## Validation evidence

- The ordinary root presubmit passed. Authorization runtime was 23/23;
  language-neutral validation/package testing was 15/15; packed report tooling
  passed; existing million-scale tests remained behind their explicit opt-in
  gates and were not run.
- The independent auditor validated 10 schemas, 13 full registries, two policies,
  40 decisions, 30 abuse cases, 16 grants, 45 roadmap mappings, all artifact
  hashes, both assignment and semantic authorities, and all required docs and
  MIT license identities.
- Both npm archives installed offline into a clean consumer. CLI, API, generated
  types, grant verification, reference corpus, and external adapter passed using
  package-public files only.
- [GitHub Actions run 31933804281](https://github.com/n3r/OpenGameVCS/actions/runs/31933804281)
  passed Ubuntu, macOS, Windows, and the six-report comparison at the exact
  product source. All 30 rows match with result SHA-256
  `6cf806951e198e71a616ed72362c7db5aedfb25230c3dd492fec897799d88c1f`.
- Exact package SHA-256 values are
  `766078f881bba7bd7f4e3657f506ce8270992667c425ec8054cf506e13170770`
  for the spec and
  `e28a0da4310b2bcdb12acdf6d39c55dea5221bdef451b15a601aaf63939b43c7`
  for the runtime on every hosted OS.

The complete run/job/artifact identities and acceptance map are in the
[evidence packet](../evidence/OGVCS-003/README.md).

## Operator and downstream impact

OGVCS-009 and later services must pin contract version 1 and the exact registry
digest, fail closed on unavailable or unknown security inputs, and expose only
registered privacy-safe outcomes. A service conformance adapter must execute
each vector against its real public response, aggregate, cursor, log, cache,
grant, or sandbox boundary; the packaged example adapter proves the protocol,
not a production service.

The static Ed25519 private key, actors, repositories, paths, policies, object
IDs, and audit values are synthetic conformance data. They must never be trusted
or installed in production. Default logs and reports remain free of protected
paths, hashes, content, policy text, claims, reasons, and customer identifiers.

No million-entry or logical-1-TiB workload was run for this delivery. Those are
maintainer-deferred OGVCS-002 scale gates for the final R0 campaign, not part of
the OGVCS-003 authorization contract acceptance boundary.

## Rollback and compatibility

Contract and package major version 1 are one compatibility boundary. Existing
registry assignments and semantics, signing domains/preimages, denial behavior,
authorized-view ordering, revocation ceilings, and sandbox requirements cannot
be reinterpreted in place. Incompatible behavior requires v2 and a deliberate
dual-evaluation migration.

A defective v1 package is withdrawn. Consumers may retain it only for explicit
deny-only compatibility while a replacement is validated. Rollback never
restores revoked credentials, old key/authority generations, consumed nonces,
stale cached allows, lock authority, or deleted audit evidence.
