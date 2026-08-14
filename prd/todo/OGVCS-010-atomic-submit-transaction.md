# OGVCS-010 — Atomic submit and branch-head transaction

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-006, OGVCS-008, OGVCS-009  
**Blocks:** OGVCS-015, OGVCS-016, OGVCS-017, OGVCS-018, OGVCS-019, OGVCS-020, OGVCS-025, OGVCS-028, OGVCS-029, OGVCS-032, OGVCS-043  
**Source:** [Architecture ADR-0003](../../adr/0003-object-lifecycle-and-gc-fencing.md)  
**Last updated:** 2026-08-14

## Outcome

A client publishes code, assets, deletes, moves, and sidecars as one authorized, content-complete snapshot or publishes nothing. Concurrent submissions, retries, crashes, and event failures cannot lose or partially expose a change.

## Problem

Separating bulk upload from metadata improves scale but creates a dangerous boundary: a branch can reference absent data, uploaded data can be mistaken for committed work, or retries can duplicate/overwrite a change. Submit is the system's central correctness transaction.

## Scope

### In scope

- Submit draft/preflight, required-object closure, upload readiness, validation, snapshot creation, branch CAS, audit, and outbox event.
- Idempotency and stable result recovery.
- Path/FileID operation validation, policy hook result, and lock-proof extension point.
- Orphan object/draft lifecycle handed to OGVCS-018.

### Out of scope

- Merge computation, lock acquisition, review UI, CI policy engine, or object transfer implementation.

## Users and journeys

- **Contributor:** retries after an ambiguous timeout and receives the original success rather than a duplicate snapshot.
- **Concurrent contributor:** receives a conflict that names the new authorized head and next safe action.
- **Operator:** proves that every branch snapshot has complete verified content and corresponding audit/outbox state.

## Requirements

### Functional

- **OGVCS-010-FR-01:** Submit SHALL begin with repository, branch, expected head, ordered operations, manifest/object closure, message, client identity, and idempotency key.
- **OGVCS-010-FR-02:** Preflight SHALL validate canonical paths, FileIDs, repository rules, authorization, required policy/lock/review proofs, object closure, and structural limits without advancing a reference.
- **OGVCS-010-FR-03:** Finalize SHALL re-evaluate mutable inputs, confirm every referenced object is durable/available, create immutable metadata, CAS the branch head, append required audit, and enqueue event in one metadata transaction.
- **OGVCS-010-FR-04:** Branch CAS conflict SHALL leave the draft/content intact for merge/rebase and SHALL not publish a side branch implicitly.
- **OGVCS-010-FR-05:** Same actor/repository/idempotency key with identical request SHALL return the original result; changed request SHALL be rejected as key reuse.
- **OGVCS-010-FR-06:** A successful result SHALL contain snapshot ID, old/new head, audit/event correlation, and consistency token.
- **OGVCS-010-FR-07:** No read path SHALL treat a draft, staged object, or uncommitted snapshot as branch history.
- **OGVCS-010-FR-08:** Hook/policy timeouts or dependency failures SHALL fail closed with stable retryability classification.
- **OGVCS-010-FR-09:** Batch operation validation SHALL detect rename cycles, case collisions, conflicting operations, missing sidecars where policy requires them, and unauthorized hidden-path effects.
- **OGVCS-010-FR-10:** Finalize SHALL reference only current healthy `available` object lifecycle generations; it MAY atomically revive an exact quarantined generation while bytes remain verified and SHALL reject `deleting`, `deleted`, stale, or unhealthy generations before publication.
- **OGVCS-010-FR-11:** Create/copy/move/restore operations SHALL enforce the repository-lifetime FileID registry and expected-base semantics in the final transaction, including concurrent collision, delete/recreate, forged move, and import retry.
- **OGVCS-010-FR-12:** A successful result SHALL also include authority epoch and a durable receipt sufficient to reconcile the idempotency outcome against a later DR recovery boundary.

### Quality attributes

- **OGVCS-010-NFR-01:** Fault injection at every step MUST leave either the previous head or one complete new head, never missing referenced content.
- **OGVCS-010-NFR-02:** Payload-preuploaded submit with 100,000 path operations SHALL target the proposal's 30-second reference bound and publish measured results.
- **OGVCS-010-NFR-03:** Event delivery MAY be at-least-once, but event identity/order and idempotent consumption contract MUST make one committed submit observable without loss.

## Interfaces and data

APIs: create/inspect/cancel draft, preflight, missing-content plan, finalize, idempotency lookup, recovery-boundary reconciliation, conflict response. Internal contracts: OGVCS-008 object lifecycle receipt, OGVCS-009 authorize/audit/epoch, OGVCS-006 transaction/outbox/FileID registry. Lock/review/policy proofs are typed/versioned extensions validated before finalize.

## Development plan

1. Implement submit plan/intent schemas, ordered operation validation, base/head preconditions, idempotency state, and a dry-run prerequisite/policy response.
2. Implement content lifecycle/health staging, quarantine revival, FileID operation validation and snapshot/tree construction without branch visibility, including bounded retries and abandoned-intent cleanup.
3. Implement the single metadata transaction for authorization/lock revalidation, snapshot publication, branch advance, audit and outbox records, plus unknown-result resolution.
4. Execute the complete crash/concurrency/security/load matrix, add telemetry and repair/runbooks, and canary single-client submits before enabling contention.

## Acceptance criteria

- **OGVCS-010-AC-01:** Every OGVCS-005 submit fault point preserves the atomicity and content-completeness invariants after restart.
- **OGVCS-010-AC-02:** One hundred racing finalizations from one head yield one head advance and no lost/dangling visible snapshots.
- **OGVCS-010-AC-03:** Ambiguous client timeout followed by identical retry returns exactly the committed result.
- **OGVCS-010-AC-04:** Authorization/policy/lock changes between preflight and finalize are re-evaluated and correctly deny.
- **OGVCS-010-AC-05:** Independent verifier traverses every committed snapshot and finds all required objects available and hash-valid.
- **OGVCS-010-AC-06:** Submit racing quarantine/revival/deleting/repair either publishes with one current available generation or fails before branch advance; no newly reachable object is physically deleted.
- **OGVCS-010-AC-07:** FileID collision/forgery/delete-recreate/restore/import and post-DR receipt vectors produce the normative conflict or reconciliation result with no identity reuse or invented acknowledgement.

## Verification plan

State-machine/property tests, database/object-store fault injection, concurrency races, idempotency mutation tests, policy-change races, large-change benchmark, and event outbox recovery.

## Telemetry and operations

Expose phase latency, draft age, missing bytes/objects, validation failure class, CAS conflicts, idempotent replays, transaction retries, outbox lag, orphan candidates, and invariant-verifier results. Protect paths/messages.

## Rollout and rollback

Developer preview allows writes only to test repositories until invariant scans and restore pass. Protocol changes are versioned. Rollback stops new finalization first; already committed snapshots remain readable and exportable.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Cross-store atomicity is impossible | Upload immutable content first; publish only metadata transaction after verified availability |
| Preflight gives stale assurance | Revalidate every mutable condition in finalize |
| Huge operation sets hold locks too long | Bounded prevalidation, efficient set-based transaction, benchmark and limits |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
