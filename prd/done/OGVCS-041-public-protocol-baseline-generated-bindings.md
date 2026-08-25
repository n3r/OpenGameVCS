# OGVCS-041 — Public protocol baseline and generated bindings

**Status:** Done
**Release:** R0 — Engineering Foundation  
**Priority:** P0  
**Owner:** Codex and OpenGameVCS maintainers
**Depends on:** OGVCS-002, OGVCS-003, OGVCS-004  
**Blocks:** OGVCS-005, OGVCS-006, OGVCS-008, OGVCS-009, OGVCS-011, OGVCS-019, OGVCS-030, OGVCS-036, OGVCS-042, OGVCS-043  
**Source:** [ADR-0013 public protocol v1 transport, schema, and generation](../../adr/0013-protocol-v1-transport-schema-and-generation.md)
**Last updated:** 2026-08-25

## Outcome

Independent server, client, and tooling teams have an executable public protocol baseline before R1 implementation: normative schemas, negotiation, errors, retry/idempotency rules, pagination, limits, generated bindings, and a contract runner that reject incompatible or unsafe behavior before mutation.

## Problem

Repository services cannot be independently developed against prose and private in-process types. Deferring the normative transport and compatibility contract until Production Beta would freeze accidental implementation behavior and force clients and services to retrofit negotiation, bounded decoding, and safe retries.

## Scope

### In scope

- Reference TLS 1.3 HTTP/1.1 control profile and application-neutral transfer carrier/probe, message/schema registry, protocol/version envelopes, and capability negotiation.
- Typed error, retry, idempotency, cursor, cancellation, deadline, correlation, limit, and extension rules.
- Transfer-grant claims/envelope integration with the authorization contract without implementing identity policy.
- Reproducible code generation, generated binding smoke packages, reference client/server stubs, golden traces, malformed vectors, and offline contract runner.
- Initial machine-readable compatibility registry consumed by packaging and later public conformance work.

### Out of scope

- Domain behavior for metadata, content, identity, submit, locks, or automation.
- Production object routes, upload-session lifecycle, multipart behavior, pack framing, compression, placement, or availability owned by OGVCS-008.
- Long-term-support policy, ecosystem certification, production-wide skew matrix, or high-level integration SDK.
- Canonical repository-object encoding, authorization decisions, or path rules owned by predecessor PRDs.

## Users and journeys

- **Service engineer:** implements a new API family using generated types and passes negotiation/error/idempotency contracts without a client implementation checkout.
- **Client engineer:** upgrades one generated binding and receives deterministic rejection before mutation when a server lacks a required capability.
- **Protocol maintainer:** adds an optional field/feature with namespace, fallback, vector, and compatibility entry rather than redefining an existing message.

## Requirements

### Functional

- **OGVCS-041-FR-01:** The package SHALL select and publish one reference HTTPS transport/framing profile for control messages and one application-neutral range/resume carrier plus conformance probe for bulk transfer, including TLS, proxy, timeout, compression, and streaming rules, without defining OGVCS-008 routes, session lifecycle, packs, or placement.
- **OGVCS-041-FR-02:** Every session SHALL negotiate independent protocol, schema, repository-format, authorization-contract, path-contract/profile, event, transfer, and extension capabilities before mutation; unknown required capabilities SHALL fail safely.
- **OGVCS-041-FR-03:** Schemas SHALL define bounded message sizes, recursion, collection counts, strings/paths, pagination, streaming frames, cancellation, deadlines, and unknown-field behavior.
- **OGVCS-041-FR-04:** Errors SHALL carry a stable code, authorization-safe message class, retryability, conflict/current-generation data when visible, correlation ID, and optional bounded details.
- **OGVCS-041-FR-05:** Every retryable mutation SHALL carry an idempotency key and canonical request fingerprint; reuse with different semantic input SHALL be rejected.
- **OGVCS-041-FR-06:** Pagination/event cursors SHALL be opaque, scoped, expiring, and explicit about gaps or invalidation; clients SHALL never infer completion from transport closure alone.
- **OGVCS-041-FR-07:** The transfer carrier SHALL import and digest-bind the exact OGVCS-003 transfer-grant envelope/signing contract, require a compact request-root grant for bulk HTTP, and SHALL NOT duplicate or reinterpret its issuer/key generation, authority epoch, subject, tenant/repository, operation, audience, expiry, or replay fields.
- **OGVCS-041-FR-08:** Extension registration SHALL identify owner, namespace, stability, required/optional status, fallback, security/data impact, and version lifecycle.
- **OGVCS-041-FR-09:** Reproducible code generation from one numbered declarative model SHALL emit compilable reference bindings for Rust plus C++, C#, and TypeScript schema consumers without handwritten wire-name, type, or field-number forks.
- **OGVCS-041-FR-10:** An offline contract runner SHALL validate negotiation, golden traces, malformed input, retry/idempotency, cursor, downgrade, and bounded-resource behavior against reference stubs.

### Quality attributes

- **OGVCS-041-NFR-01:** Generated artifacts from a clean environment MUST be byte-for-byte reproducible or carry an explained, verified provenance difference.
- **OGVCS-041-NFR-02:** Malformed or oversized input MUST be rejected within declared CPU/memory bounds without partial mutation or authorization detail leakage.
- **OGVCS-041-NFR-03:** The protocol specification, schemas, generator configuration, vectors, and runner MUST be usable offline under an OSI-approved license.

## Interfaces and data

Deliver the protocol/profile/field registries, MAC-bound session negotiation,
request/response/event/terminal-stream envelopes, closed error model,
idempotency descriptor and semantic fingerprint, opaque cursor contract,
request-root transfer-grant carrier and synthetic range/resume probe, extension
registry, compatibility entry, code-generation manifests, trace/vector format,
and contract-runner adapter. Domain PRDs publish messages through these
envelopes rather than private transports. OGVCS-008 supplies production bulk
routes and sessions while preserving the carrier contract.

## Development plan

1. Record ADR-0013 and generate the numbered model, closed schemas, version/field/limit/error/extension registries, predecessor pins, compatibility entry, and deterministic manifests.
2. Implement bounded control parsing, independent capability negotiation with authenticated receipts, base and terminal-stream envelopes, and reference loopback client/server stubs.
3. Implement safe errors, semantic idempotency fingerprints, opaque cursors, deadlines/cancellation, request-root grant carriage, and the application-neutral range/resume probe with valid/malformed/security vectors.
4. Generate and compile Rust/C++/C#/TypeScript model packages, implement two independent semantic adapters, and run the offline black-box contract runner with proxy, disconnect, duplicate, reorder, downgrade, and resource faults.
5. Compare retained packed evidence on Windows, macOS, and Linux, critically review every acceptance criterion, and freeze/publish the R0 candidate after predecessor contracts are complete.

## Acceptance criteria

- **OGVCS-041-AC-01:** Two independently built reference adapters that share no semantic selector, idempotency, cursor, or mutation engine negotiate every finite registered supported/unsupported profile and produce the expected pre-mutation result from public artifacts only.
- **OGVCS-041-AC-02:** Duplicate, reordered, disconnected, expired-cursor, incompatible-version, downgrade, malformed, and oversized cases match golden traces without partial mutation.
- **OGVCS-041-AC-03:** Clean generation compiles all four language consumers and reproduces checked-in schema digests with no handwritten wire-model divergence.
- **OGVCS-041-AC-04:** Authorization red-team vectors find no protected path/object/policy detail in generic errors, negotiation, cursor, or transfer-grant failures.
- **OGVCS-041-AC-05:** The initial compatibility registry can drive an offline release preflight and refuses an unregistered required feature or unsupported schema pair.

## Verification plan

Cross-language schema tests, golden/malformed traces, proxy and connection-fault injection, idempotency properties, cursor expiry/gap cases, decoder fuzz/resource limits, downgrade/security probes, reproducible-generation checks, and independent adapter review.

## Telemetry and operations

Reference stubs expose negotiated versions/features, stable error codes, retry counts, rejected bounds, cursor expiry, downgrade attempts, and correlation IDs. Payload fields, paths, credentials, grants, and protected details are excluded.

## Rollout and rollback

The delivered R0 public baseline remains `1.0.0-rc.1`, candidate, and
unratified while OGVCS-005 consumes it. This deliberate lifecycle boundary does
not permit private alternatives: downstream services negotiate this contract
or fail closed. A later compatible ratification change may publish `1.0.0`;
assigned fields and semantics cannot be silently reinterpreted. Withdrawal
stops new sessions without changing existing receipts, cursors, idempotency
records, assignments, or errors.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Early wire choice freezes a weak transport | Reference implementation, proxy/load evidence, explicit versioning and replacement path |
| Generated bindings appear compatible but differ semantically | Golden traces and independent adapters test behavior, not compilation only |
| Error detail leaks protected state | Security contract vectors and safe bounded detail taxonomy |

## Completion evidence

The MIT-licensed `1.0.0-rc.1` public baseline is complete. Implementation
revision
[`dfdd7ad`](https://github.com/n3r/OpenGameVCS/commit/dfdd7adcf07a3e6c964e97d21434f370c3664250)
passed 111 runtime tests, 14 contract/generation tests, all 360 scenarios through
two independent adapters, and the retained Rust/C++/C#/TypeScript consumers.
Hosted workflow
[`32843391920`](https://github.com/n3r/OpenGameVCS/actions/runs/32843391920)
proved identical package/source/semantic authorities on Linux, macOS, and
Windows; the strict comparison was independently replayed byte-for-byte. All
predecessors are Done. OGVCS-002's separately owned exact-scale campaign is
already complete and was not duplicated here.

- Implementation changes: the [`dfdd7ad` implementation commit](https://github.com/n3r/OpenGameVCS/commit/dfdd7adcf07a3e6c964e97d21434f370c3664250) and [detailed changelog](../../docs/changelog/OGVCS-041.md#final-review-hardening) deliver the public runtime, independent adapter, generated consumers, hostile-input/resource hardening, and offline package boundary.
- Test and benchmark results: the [completion evidence packet](../../docs/evidence/OGVCS-041/README.md#local-and-hosted-gates) binds all 360 cases, six package identities, three host records, four generated-language consumers, comparator replay, and the downstream benchmark compatibility run.
- Security/reliability review: the [final independent review](../../docs/reviews/OGVCS-041-critical-review.md#final-verdict) records the complete threat/resource assessment, remediation history, requirement matrix, and no-live-P0/P1/P2 verdict.
- Documentation/runbooks: [ADR-0013](../../adr/0013-protocol-v1-transport-schema-and-generation.md) and the [completion/rollback boundary](../../docs/evidence/OGVCS-041/README.md#completion-and-rollback) document negotiation, transport, compatibility, observability, failure, candidate lifecycle, and rollback.
- Rollout result: implementation [run 32843391920](https://github.com/n3r/OpenGameVCS/actions/runs/32843391920) passed every Linux/macOS/Windows package job and strict comparison; benchmark integration [run 32843391941](https://github.com/n3r/OpenGameVCS/actions/runs/32843391941) also passed on the same revision.
- OGVCS-041-AC-01: the [retained comparison and adapter reports](../../docs/evidence/OGVCS-041/README.md#durable-reports) prove exact 360/360 equality between independently built engines using authenticated public authority only.
- OGVCS-041-AC-02: the [acceptance map](../../docs/evidence/OGVCS-041/README.md#acceptance-map) binds all 273 duplicate/reorder/disconnect/expiry/incompatibility/downgrade/malformed/resource rejects to exact pre-mutation outcomes.
- OGVCS-041-AC-03: the [hosted gate record](../../docs/evidence/OGVCS-041/github-actions-run-32843391920.json) proves clean generation and retained Rust/C++/C#/TypeScript compilation/execution on all three operating systems.
- OGVCS-041-AC-04: the [security assessment](../../docs/reviews/OGVCS-041-critical-review.md#security-and-reliability-assessment) covers red-team vectors, permission isolation, canary scans, inert host inputs, safe errors, and empty successful stderr.
- OGVCS-041-AC-05: the [requirement matrix](../../docs/reviews/OGVCS-041-critical-review.md#requirement-and-acceptance-matrix) records exact release-preflight coverage for unknown requirements, tuple/pin/assignment/lifecycle/semantic drift, and the sole pre-reserved addition.
