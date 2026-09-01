# OGVCS-008 — Object storage and resumable transfer service

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-003, OGVCS-007, OGVCS-041  
**Blocks:** OGVCS-010, OGVCS-011, OGVCS-013, OGVCS-017, OGVCS-018, OGVCS-019, OGVCS-020, OGVCS-021, OGVCS-027, OGVCS-028, OGVCS-036, OGVCS-037  
**Source:** [Architecture ADR-0003](../../adr/0003-object-lifecycle-and-gc-fencing.md)  
**Last updated:** 2026-09-01

## Outcome

Authorized clients negotiate missing immutable content and upload/download it resumably through filesystem or S3-compatible storage, with end-to-end verification, bounded retries, and no snapshot publication responsibility.

## Problem

Large transfers fail routinely on slow or unstable links. The service must separate payload throughput from metadata transactions without treating object existence or a digest as authorization.

## Scope

### In scope

- Filesystem and S3-compatible immutable object backends.
- Missing-object negotiation, upload session, multipart/resumable upload, finalize, download/range, and batch operations.
- Short-lived audience/scope-bound transfer grants.
- Pack-object layout and chunk range retrieval.
- Idempotency, quotas, integrity verification, and unreferenced staging lifecycle.

### Out of scope

- Snapshot/reference mutation, repository policy UI, regional caches, retention/GC reachability, and client materialization.

## Users and journeys

- **Remote artist:** resumes a multi-gigabyte upload after interruption without restarting completed parts.
- **Client:** asks which manifest/chunk objects are missing and transfers only those.
- **Operator:** switches supported backend configuration and verifies content without changing logical IDs.

## Requirements

### Functional

- **OGVCS-008-FR-01:** All transfer operations SHALL require a valid OGVCS-003 grant containing tenant, repository, actor/session, allowed object set or bounded request, operation, audience, and expiry.
- **OGVCS-008-FR-02:** Missing-object negotiation SHALL be batchable, tenant-scoped, rate-limited, and indistinguishable for objects the actor cannot discover.
- **OGVCS-008-FR-03:** Upload sessions SHALL be resumable and idempotent; server state SHALL identify received verified parts without trusting client byte counts.
- **OGVCS-008-FR-04:** Finalization SHALL verify canonical object ID, length, and backend durability before atomically recording an `available` lifecycle receipt and generation.
- **OGVCS-008-FR-05:** Downloads SHALL verify stored metadata and support safe parallel/range reads needed for pack reconstruction.
- **OGVCS-008-FR-06:** Backend keys SHALL not expose tenant names, paths, messages, or user-controlled traversal components.
- **OGVCS-008-FR-07:** Quotas SHALL distinguish staging, durable unique bytes, request rate, and transfer bytes; rejection SHALL not leave unrecoverable sessions.
- **OGVCS-008-FR-08:** Unreferenced finalized objects and abandoned parts SHALL be retained for a configured safety window and exposed to OGVCS-018 GC, never immediately deleted by transfer code.
- **OGVCS-008-FR-09:** Filesystem and S3 backends SHALL pass one behavior contract for create-if-absent, read, range, verify, list-by-internal-prefix, and safe delete.
- **OGVCS-008-FR-10:** The shared lifecycle contract SHALL implement `staged → available ↔ quarantined → deleting → deleted` with compare-and-swap generations; transfer code SHALL not bypass or infer state from backend existence.
- **OGVCS-008-FR-11:** Transfer grants and receipts SHALL bind the OGVCS-041 authority/security epoch and reject old-epoch, wrong-audience, replayed, or lifecycle-stale operations.

### Quality attributes

- **OGVCS-008-NFR-01:** Repeated upload/finalize requests with the same idempotency key and bytes MUST yield one object and one stable result.
- **OGVCS-008-NFR-02:** A lost connection at every multipart boundary MUST resume without corruption or retransmitting verified completed parts.
- **OGVCS-008-NFR-03:** Known object IDs MUST not permit unauthorized existence checks or reads.

## Interfaces and data

Versioned APIs: negotiate, start/resume session, upload part/object, finalize, batch download plan, read range, session status/abort, backend verify, and generation-fenced lifecycle state. Emit content-available and integrity-failure internal events without path data. OGVCS-010 consumes the current receipt/state/generation, not backend internals.

## Development plan

1. Implement the backend contract and filesystem backend with immutable put/get/head, atomic finalize, verification, quotas, and capability reporting.
2. Implement upload sessions, missing-object negotiation, resumable parts, idempotent finalize, lifecycle receipts/generations, expiry/cleanup, and content-before-visibility rules.
3. Implement authorized download plans/grants, range/resume, client end-to-end verification, retry/backoff, and safe backend error translation.
4. Add the S3-compatible backend, cross-backend/fault/load/security suites, storage metrics/repair hooks, and staged rollout from single-part to resumable transfers.

## Acceptance criteria

- **OGVCS-008-AC-01:** Filesystem and S3-compatible backends pass the same conformance suite.
- **OGVCS-008-AC-02:** A 100 GiB interrupted upload resumes at every injected boundary and reconstructs to the expected whole-file hash.
- **OGVCS-008-AC-03:** Unauthorized and cross-tenant existence/read probes reveal no object status.
- **OGVCS-008-AC-04:** Backend acknowledgement-before-durability and corrupt-read fakes are detected before content becomes available.
- **OGVCS-008-AC-05:** Parallel transfer meets the declared reference throughput without exceeding configured memory, worker, or request limits.
- **OGVCS-008-AC-06:** Stale/reordered lifecycle transitions, old-epoch grants, backend-only objects, retry after receipt loss, and concurrent quarantine/finalize attempts cannot create a false available receipt or delete a referenced generation.

## Verification plan

Backend contract tests, network interruption/retry matrix, object corruption and stale-grant tests, quota/rate tests, fuzzed requests, and large-file throughput benchmarks.

## Telemetry and operations

Expose authorized operation class, bytes, duration, retry/resume, part count, backend latency/errors, staging/durable capacity, quota denial, integrity failure, and grant rejection. Never include object IDs in broad metrics labels.

## Rollout and rollback

Start with filesystem development backend and one supported S3 profile. New backend writers deploy read/verify support before use. Backend migration copies and verifies objects before routing reads; rollback keeps old objects until a completed verification window.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Object store semantics differ | Strict backend contract and durability probe |
| Resumable state grows without bound | Expiry, quota, safe sweeper, and operator visibility |
| Transfer grant is overbroad | Narrow claims, short TTL, audience binding, negative tests |

## Completion evidence

- Implementation changes: the candidate now has exact branded filesystem/S3
  backend ports, a SigV4 S3-compatible adapter, one shared backend suite, paged
  logical content plans, sealed batch/range plans, durable unique-byte quota,
  bounded internal events/telemetry, and an explicit repository-metadata
  lifecycle adapter seam. An additive opaque kind-2 production-acceptor
  candidate verifies durable manifests/chunks and enters atomic metadata
  availability only through the package production callback. Its dependency
  authority is explicitly limited to signed sets of at most 4,096 objects;
  request-root closure remains unavailable. The canonical object limit remains
  64 MiB.
- Test and benchmark results: local bounded runtime, generated/independently
  validated contract, workflow policy, and roadmap gates are recorded in the
  OGVCS-008 review. The offline 100-GiB logical-plan test proves 1,600
  descriptors in seven pages without allocating payload bytes. It is not the
  exact-byte acceptance run.
- Security/reliability review: hostile review covers adapter forgery,
  conditional-put races/response loss, acknowledgement-before-durability,
  corrupt metadata/body/range, pagination, redaction/deadlines, stale fences,
  quota replay, plan tampering, and hidden early/middle/last denial.
- Documentation/runbooks: contract `0.1.0-rc.6`, runtime README, changelog,
  review record, pinned MinIO provenance policy, and manual exact-scale workflow.
- Rollout result: not performed. Pinned loopback MinIO conformance is retained
  with current-source Linux/macOS/Windows evidence. The PRD remains Todo until
  the exact 100-GiB interrupted throughput/memory result and separately owned
  repository-metadata/identity lifecycle integration are complete. No real
  OGVCS-003/006/009 production adapter or public route currently backs the new
  acceptor, and its explicit-set profile cannot justify OGVCS-007 ratification.
