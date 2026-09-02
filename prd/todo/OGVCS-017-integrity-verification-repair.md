# OGVCS-017 — Integrity verification and repair

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-002, OGVCS-007, OGVCS-008, OGVCS-010  
**Blocks:** OGVCS-018, OGVCS-020, OGVCS-021, OGVCS-027, OGVCS-028, OGVCS-029, OGVCS-033, OGVCS-037  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-09-02

## Outcome

Every acknowledged snapshot can be proven to reference intact, correctly identified content, and detected corruption is quarantined and repaired from a trustworthy copy without inventing or silently changing user data.

## Problem

Checksums at upload time do not protect against latent disk faults, backend bugs, operator mistakes, or corrupt replicas. A reliable VCS needs end-to-end verification from snapshot roots through trees, manifests, chunks, and storage copies, plus explicit behavior when no good copy remains.

## Scope

### In scope

- Online read verification, scheduled sampling, full repository scrub, offline verification, quarantine, replica comparison, repair, and evidence reports.
- Graph reachability and referential-integrity checks across metadata and content.
- Operator controls for pause/resume/rate limits and health/readiness impact.

### Out of scope

- Backup policy and garbage collection, multi-region disaster recovery, or the clean-room export verifier.
- Content reconstruction when no verified source exists.

## Users and journeys

- **User:** fetches content and either receives bytes matching the manifest or an explicit integrity error—never plausible corrupt bytes.
- **Operator:** sees a failed sample, quarantines the bad copy, repairs it from a verified source, and retains evidence.
- **Auditor:** runs a full scrub and can trace its repository generation, coverage, findings, and disposition.

## Requirements

### Functional

- **OGVCS-017-FR-01:** Verification SHALL traverse the canonical snapshot → tree → file/version → manifest → chunk graph defined by OGVCS-002 and validate type, length, digest, and required references.
- **OGVCS-017-FR-02:** Client upload and download paths SHALL verify end-to-end object identity; a mismatched object SHALL never be published or returned as valid.
- **OGVCS-017-FR-03:** The system SHALL support configurable continuous sampling and resumable full scrubs with a captured metadata generation and explicit coverage report.
- **OGVCS-017-FR-04:** A corrupt or ambiguous storage copy SHALL be quarantined atomically from normal reads while preserving forensic metadata.
- **OGVCS-017-FR-05:** Repair SHALL copy only from a source whose digest and object framing independently verify; successful repair SHALL retain the canonical object identity.
- **OGVCS-017-FR-06:** When no verified source exists, the object and every known affected snapshot SHALL be marked degraded and reads SHALL fail explicitly; the service SHALL not synthesize replacement bytes.
- **OGVCS-017-FR-07:** Concurrent upload, replication, verification, repair, retention, and read operations SHALL use generation/precondition rules that prevent a stale verifier from overwriting newer valid state.
- **OGVCS-017-FR-08:** Reports SHALL distinguish metadata-reference failure, missing object, size mismatch, digest mismatch, framing/version error, replica disagreement, and authorization/configuration failure.
- **OGVCS-017-FR-09:** Verification and repair commands SHALL be permissioned, idempotent, resumable, rate-limited, and auditable.

### Quality attributes

- **OGVCS-017-NFR-01:** Injected bit flips at every serialized layer MUST be detected before corrupted bytes are accepted by a client.
- **OGVCS-017-NFR-02:** Sampling and scrubbing MUST have bounded CPU, I/O, concurrency, and backend request rates and MUST expose estimated completion/coverage.
- **OGVCS-017-NFR-03:** A verifier crash or restart MUST not lose findings or convert unverified/quarantined data to healthy.

## Interfaces and data

Define `VerificationRun`, immutable `Finding`, object-copy health state, quarantine/repair transitions, coverage cursor, affected-root query, and signed/exportable report schema. OGVCS-018 consumes reachability and health; OGVCS-033 reimplements the public verification contract independently.

## Development plan

1. Implement graph/object verification libraries, typed findings, copy-health/quarantine states, and read/upload verification hooks.
2. Implement scheduled sampling and resumable generation-pinned full scrubs with bounded work, coverage accounting, and affected-root queries.
3. Implement verified-source repair, concurrent generation/precondition handling, irrecoverable/degraded snapshot state, and audit controls.
4. Complete corruption/race/crash/backend and scale tests, add alerts/runbooks/reports, then enable report-only, quarantine, and repair in separate rollout stages.

## Acceptance criteria

- **OGVCS-017-AC-01:** The fault corpus corrupts snapshot, tree, manifest, chunk framing, chunk bytes, and storage metadata; each case yields the expected typed finding and no valid read.
- **OGVCS-017-AC-02:** With one corrupt and one good copy, reads avoid the corrupt copy and repair restores two independently verified copies without changing object ID.
- **OGVCS-017-AC-03:** With all copies missing/corrupt, affected snapshots are reported as degraded and no automated action fabricates data.
- **OGVCS-017-AC-04:** Full scrub can stop, restart, and complete with exact object/byte coverage for the captured generation while concurrent commits continue safely.
- **OGVCS-017-AC-05:** Verification of the reference large repository completes within the declared resource envelope and does not breach API latency/error SLOs.

## Verification plan

Golden-object vectors, mutation fuzzing, backend fault injection, graph corruption cases, concurrent repair/read/upload races, crash/restart tests, authorization tests, and full-corpus performance runs through OGVCS-005.

## Telemetry and operations

Expose last successful sample/scrub, coverage, queue age, verified bytes, findings by safe type/backend, quarantines, repairs, irrecoverable objects, and affected snapshot count. Page on acknowledged-root degradation or verifier staleness beyond policy.

## Rollout and rollback

Deploy read-only reporting first, validate false-positive rate, then enable automatic quarantine and finally repair per backend. Rollback stops mutations but preserves findings/quarantines until an operator explicitly resolves them.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Scrub overloads production storage | Rate budgets, priority classes, pause/resume, SLO guardrails |
| Repair copies corruption between replicas | Independent digest/framing validation before and after copy |
| False positive hides good data | Preserve copies, quarantine rather than delete, explicit operator disposition |
| Verification misses unreachable but retained objects | Separate graph reachability and physical-inventory scans |

## Completion evidence

- Implementation changes: Bounded candidate relevance only. The unpublished,
  unwired Rust rc.1 crate under `core/integrity-verifier/rust` pins an immutable
  supplied generation and traverses the content-only Snapshot root Tree →
  file/version entry → ContentManifest → Chunk closure. It composes the
  OGVCS-002 canonical identity/framing/schema codec with the OGVCS-007
  discard-only manifest/chunk verifier, emits no payload, and returns typed
  findings plus an opaque generation-bound metadata-page cursor and exact
  coverage/work ledger. A manifest is indivisible: a sub-closure limit returns
  `ManifestRestartRequired`, and the same/lower relevant envelope performs no
  reread. Page versus object transfer, general versus fragment work, decode,
  index, resident-ledger, and charged-memory stops bind distinct private
  recovery classes; this is not a sub-manifest continuation claim.
- Test and benchmark results: All 65 local Rust tests and 31 focused upstream
  OGVCS-002/007 contract tests pass. The fixture-derived golden and fault suite
  covers one-shot/page-equivalent traversal; missing reference versus object;
  declared and file-size mismatch; rebound framing/version and whole-file
  digest corruption; one-bit flips at snapshot, tree, manifest, and chunk
  layers; source/backend ambiguity; source and generation failure;
  cancellation; deterministic ordering; explicit count, byte, work, and
  charged-memory limits; and a multi-chunk sub-closure budget that cannot
  livelock on same-envelope retry, including after cancellation. Regression
  cases also cover complete cursor-state digest binding, fail-closed finding
  truncation, checked logical-byte overflow, terminal classification of the
  nonrecoverable OGVCS-007 ledger-counter overflow, precise
  declared-versus-observed chunk size evidence, pre-allocation source caps, and
  simultaneous manifest-plus-chunk memory admission. Additional cases prove
  index/ledger/decode-specific same-envelope no-reread and correct-limit
  recovery, charged-memory readmission of enlarged manifest reservations,
  page/object transfer and general/fragment work recovery specificity, atomic
  graph-edge and work admission, initial-root admission, in-read and
  manifest-parser cancellation, exact returned-payload effort under generation
  drift, unsupported-profile classification, simultaneous cursor/report
  finding-buffer admission, invalid-resume cursor preservation, and
  length/capacity enforcement for metadata and chunk source buffers. The
  bounded golden verifies 5 unique objects / 1,132
  bytes and 6 graph edges. No durable/full-scrub resumability. Shared subtree
  coverage is over unique object/entry definitions, not namespace-expanded
  path multiplicity. No hosted cross-OS, production-concurrency, or
  reference-scale campaign has run.
- Security/reliability review: See
  `docs/reviews/OGVCS-017-read-only-integrity-verifier-review.md`. Ambiguity
  never selects a copy; cancellation/source/limit/generation failures return no
  report and retain the current metadata-boundary cursor. This is not authorization,
  permission, audit, health-state, quarantine, or repair evidence.
- Documentation/runbooks: The private crate README defines validation order,
  ledger meanings, limits, and nonclaims. There is no operator runbook or
  public command because this candidate is not wired to a service or backend.
- Rollout result: Not rolled out. OGVCS-017 remains Todo. Snapshot auxiliary
  graphs and unreachable inventory, replicas, quarantine, repair,
  all-copies-lost degraded-root persistence, durable crash recovery,
  production concurrency, public commands, permission/audit semantics, hosted
  cross-OS evidence, and scale/SLO acceptance remain open.
