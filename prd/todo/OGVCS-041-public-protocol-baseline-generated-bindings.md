# OGVCS-041 — Public protocol baseline and generated bindings

**Status:** Todo  
**Release:** R0 — Engineering Foundation  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-002, OGVCS-003, OGVCS-004  
**Blocks:** OGVCS-005, OGVCS-006, OGVCS-008, OGVCS-009, OGVCS-011, OGVCS-019, OGVCS-030, OGVCS-036, OGVCS-042, OGVCS-043  
**Source:** [Architecture ADR-0005](../../adr/0005-early-public-protocol-baseline.md)  
**Last updated:** 2026-08-14

## Outcome

Independent server, client, and tooling teams have an executable public protocol baseline before R1 implementation: normative schemas, negotiation, errors, retry/idempotency rules, pagination, limits, generated bindings, and a contract runner that reject incompatible or unsafe behavior before mutation.

## Problem

Repository services cannot be independently developed against prose and private in-process types. Deferring the normative transport and compatibility contract until Production Beta would freeze accidental implementation behavior and force clients and services to retrofit negotiation, bounded decoding, and safe retries.

## Scope

### In scope

- Reference control-plane and transfer-control transport profile over TLS, message/schema registry, protocol/version envelopes, and capability negotiation.
- Typed error, retry, idempotency, cursor, cancellation, deadline, correlation, limit, and extension rules.
- Transfer-grant claims/envelope integration with the authorization contract without implementing identity policy.
- Reproducible code generation, generated binding smoke packages, reference client/server stubs, golden traces, malformed vectors, and offline contract runner.
- Initial machine-readable compatibility registry consumed by packaging and later public conformance work.

### Out of scope

- Domain behavior for metadata, content, identity, submit, locks, or automation.
- Long-term-support policy, ecosystem certification, production-wide skew matrix, or high-level integration SDK.
- Canonical repository-object encoding, authorization decisions, or path rules owned by predecessor PRDs.

## Users and journeys

- **Service engineer:** implements a new API family using generated types and passes negotiation/error/idempotency contracts without a client implementation checkout.
- **Client engineer:** upgrades one generated binding and receives deterministic rejection before mutation when a server lacks a required capability.
- **Protocol maintainer:** adds an optional field/feature with namespace, fallback, vector, and compatibility entry rather than redefining an existing message.

## Requirements

### Functional

- **OGVCS-041-FR-01:** The package SHALL select and publish one reference HTTPS transport/framing profile for control messages and one range/resume profile for bulk transfer, including TLS, proxy, timeout, compression, and streaming rules.
- **OGVCS-041-FR-02:** Every session SHALL negotiate independent protocol, schema, repository-format, event, transfer, and extension capabilities before mutation; unknown required capabilities SHALL fail safely.
- **OGVCS-041-FR-03:** Schemas SHALL define bounded message sizes, recursion, collection counts, strings/paths, pagination, streaming frames, cancellation, deadlines, and unknown-field behavior.
- **OGVCS-041-FR-04:** Errors SHALL carry a stable code, authorization-safe message class, retryability, conflict/current-generation data when visible, correlation ID, and optional bounded details.
- **OGVCS-041-FR-05:** Every retryable mutation SHALL carry an idempotency key and canonical request fingerprint; reuse with different semantic input SHALL be rejected.
- **OGVCS-041-FR-06:** Pagination/event cursors SHALL be opaque, scoped, expiring, and explicit about gaps or invalidation; clients SHALL never infer completion from transport closure alone.
- **OGVCS-041-FR-07:** Transfer-grant schemas SHALL bind issuer/key generation, authority epoch, subject, tenant/repository, operation, bounded object/request root, audience, expiry, and replay fields from the security contract.
- **OGVCS-041-FR-08:** Extension registration SHALL identify owner, namespace, stability, required/optional status, fallback, security/data impact, and version lifecycle.
- **OGVCS-041-FR-09:** Reproducible code generation SHALL emit compilable reference bindings for Rust plus C++, C#, and TypeScript schema consumers without handwritten field-number forks.
- **OGVCS-041-FR-10:** An offline contract runner SHALL validate negotiation, golden traces, malformed input, retry/idempotency, cursor, downgrade, and bounded-resource behavior against reference stubs.

### Quality attributes

- **OGVCS-041-NFR-01:** Generated artifacts from a clean environment MUST be byte-for-byte reproducible or carry an explained, verified provenance difference.
- **OGVCS-041-NFR-02:** Malformed or oversized input MUST be rejected within declared CPU/memory bounds without partial mutation or authorization detail leakage.
- **OGVCS-041-NFR-03:** The protocol specification, schemas, generator configuration, vectors, and runner MUST be usable offline under an OSI-approved license.

## Interfaces and data

Deliver the protocol/profile registry, session negotiation, request/response/event envelopes, error model, idempotency descriptor, cursor contract, transfer-grant schema, extension registry, compatibility entry, code-generation manifest, trace/vector format, and contract-runner adapter. Domain PRDs publish messages through these envelopes rather than private transports.

## Development plan

1. Select and ADR-record the transport/framing profile; implement schema/version registries, negotiation, base envelopes, bounded decoder, and reference loopback stubs.
2. Implement errors, retries/idempotency fingerprints, pagination/cursors, deadlines/cancellation, transfer grants, and extension/compatibility manifests with valid/malformed vectors.
3. Build reproducible Rust/C++/C#/TypeScript generation and an offline black-box contract runner with proxy, disconnect, duplicate, downgrade, and resource fault cases.
4. Exercise two independently built adapters, freeze the R0 baseline, publish packages/specifications, and require downstream API PRDs to attach conformance evidence.

## Acceptance criteria

- **OGVCS-041-AC-01:** Two independently built reference adapters negotiate every supported/unsupported profile and produce the expected pre-mutation result from public schemas only.
- **OGVCS-041-AC-02:** Duplicate, reordered, disconnected, expired-cursor, incompatible-version, downgrade, malformed, and oversized cases match golden traces without partial mutation.
- **OGVCS-041-AC-03:** Clean generation compiles all four language consumers and reproduces checked-in schema digests with no handwritten wire-model divergence.
- **OGVCS-041-AC-04:** Authorization red-team vectors find no protected path/object/policy detail in generic errors, negotiation, cursor, or transfer-grant failures.
- **OGVCS-041-AC-05:** The initial compatibility registry can drive an offline release preflight and refuses an unregistered required feature or unsupported schema pair.

## Verification plan

Cross-language schema tests, golden/malformed traces, proxy and connection-fault injection, idempotency properties, cursor expiry/gap cases, decoder fuzz/resource limits, downgrade/security probes, reproducible-generation checks, and independent adapter review.

## Telemetry and operations

Reference stubs expose negotiated versions/features, stable error codes, retry counts, rejected bounds, cursor expiry, downgrade attempts, and correlation IDs. Payload fields, paths, credentials, grants, and protected details are excluded.

## Rollout and rollback

Publish as a draft profile until two adapters and every R0 consumer pass. Ratification freezes assigned fields and semantics; corrections require errata or a negotiated version. Downstream services may not ship a private alternative protocol.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Early wire choice freezes a weak transport | Reference implementation, proxy/load evidence, explicit versioning and replacement path |
| Generated bindings appear compatible but differ semantically | Golden traces and independent adapters test behavior, not compilation only |
| Error detail leaks protected state | Security contract vectors and safe bounded detail taxonomy |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
