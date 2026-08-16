# OGVCS-041 — Public protocol baseline and generated bindings

**Status:** Validation
**Release:** R0 — Engineering Foundation  
**Priority:** P0  
**Owner:** Codex and OpenGameVCS maintainers
**Depends on:** OGVCS-002, OGVCS-003, OGVCS-004  
**Blocks:** OGVCS-005, OGVCS-006, OGVCS-008, OGVCS-009, OGVCS-011, OGVCS-019, OGVCS-030, OGVCS-036, OGVCS-042, OGVCS-043  
**Source:** [ADR-0013 public protocol v1 transport, schema, and generation](../../adr/0013-protocol-v1-transport-schema-and-generation.md)
**Last updated:** 2026-08-16

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

Publish as a draft profile until two adapters and every R0 consumer pass.
OGVCS-041 remains in validation while OGVCS-002 or OGVCS-004 is incomplete.
Ratification freezes assigned fields and semantics; corrections require errata
or a negotiated version. Downstream services may not ship a private alternative
protocol.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Early wire choice freezes a weak transport | Reference implementation, proxy/load evidence, explicit versioning and replacement path |
| Generated bindings appear compatible but differ semantically | Golden traces and independent adapters test behavior, not compilation only |
| Error detail leaks protected state | Security contract vectors and safe bounded detail taxonomy |

## Completion evidence

The MIT-licensed `1.0.0-rc.1` implementation candidate is complete. Two
independent adapters passed all 360 bounded scenarios with identical semantic
results, and the six exact npm packages installed, regenerated, and ran fully
offline. The local TypeScript and C++ consumers compile; the retained workflow
compiles all four generated consumers and compares exact packages, generated
source, and decisions on Linux, macOS, and Windows. Hosted execution remains
pending. Per maintainer direction, the OGVCS-002 one-million-entry tree and
logical-1-TiB cases were not run and remain deferred to the final R0 campaign.
This PRD remains in Validation until its OGVCS-002 and OGVCS-004 predecessors
are Done and hosted evidence is retained.

- Implementation changes: [Detailed candidate changelog](../../docs/changelog/OGVCS-041.md)
- Test and benchmark results: [Candidate evidence packet](../../docs/evidence/OGVCS-041/README.md)
- Security/reliability review: [Independent critical review](../../docs/reviews/OGVCS-041-critical-review.md)
- Documentation/runbooks: [Accepted ADR-0013 and generated protocol documentation](../../adr/0013-protocol-v1-transport-schema-and-generation.md)
- Rollout result: [Local candidate passed; hosted three-OS proof pending](../../docs/evidence/OGVCS-041/README.md#hosted-validation)
