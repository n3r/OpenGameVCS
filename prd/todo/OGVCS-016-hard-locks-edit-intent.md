# OGVCS-016 — Hard locks and advisory edit intent

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-006, OGVCS-009, OGVCS-010, OGVCS-011, OGVCS-012  
**Blocks:** OGVCS-022, OGVCS-023, OGVCS-024, OGVCS-025, OGVCS-028, OGVCS-029, OGVCS-031, OGVCS-032, OGVCS-042, OGVCS-043  
**Source:** [Architecture ADR-0004](../../adr/0004-dr-authority-security-epochs.md)  
**Last updated:** 2026-09-02

## Outcome

Studios can prevent conflicting binary edits with server-enforced locks while still using low-friction advisory edit intent for mergeable files. Lock identity survives path moves, and every acquire, renewal, release, expiry, override, and submit decision is explainable.

## Problem

Artist tools often rewrite opaque assets that cannot be merged safely. A local read-only bit is only a hint: correctness requires a server-side rule connected to stable file identity, branch state, authorization, and the atomic submit transaction. Networks also fail, so the product must distinguish a convenient lease from a false promise of offline exclusivity.

## Scope

### In scope

- Hard exclusive locks and advisory edit-intent records on FileID, path prefix, or declared asset group.
- Lease acquisition, heartbeat, explicit release, expiry, wait/notify, administrator break, and same-user workspace transfer.
- CLI commands and workspace read-only/writable hints driven by lock state.
- Submit-time enforcement and immutable audit events.

### Out of scope

- Offline exclusive-lock guarantees, arbitrary binary merge, and cross-branch retained integration domains; OGVCS-024 owns the latter.
- Rich desktop presentation or engine-specific checkout interception.

## Users and journeys

- **Artist:** requests edit, receives the lock, edits a binary asset, submits, and releases without using source-control jargon.
- **Collaborator:** sees who owns a conflicting edit and can wait or contact the owner without learning protected-path information.
- **Lead/admin:** breaks an abandoned lock with a reason and later audits the complete chain of events.

## Requirements

### Functional

- **OGVCS-016-FR-01:** Lock targets SHALL resolve to stable FileID where one exists; rename/move SHALL not silently abandon or duplicate the lock.
- **OGVCS-016-FR-02:** A lock request SHALL include repository, branch/domain, target, owner identity, workspace identity, base snapshot, mode, lease term, and idempotency key.
- **OGVCS-016-FR-03:** The service SHALL atomically grant at most one active hard lock for overlapping conflict targets and SHALL return a non-disclosing conflict response to unauthorized callers.
- **OGVCS-016-FR-04:** Lease renewal, explicit release, natural expiry, owner transfer, and administrative break SHALL use server time and monotonic lock generations to reject stale messages.
- **OGVCS-016-FR-05:** A submit that changes a hard-locked target SHALL be accepted only when OGVCS-010 validates an active compatible lock generation in the same transaction as branch-head advance.
- **OGVCS-016-FR-06:** Asset groups SHALL support a versioned, bounded expansion policy for primary files and sidecars; ambiguous or excessive expansion SHALL fail closed.
- **OGVCS-016-FR-07:** Advisory intent SHALL permit concurrent work but expose authorized owner/workspace/base/age details and produce conflict warnings before submit.
- **OGVCS-016-FR-08:** Waiters MAY subscribe to target availability; notification is advisory and SHALL never reserve or transfer ownership implicitly.
- **OGVCS-016-FR-09:** Administrative override SHALL require a dedicated permission and non-empty reason and SHALL notify the previous owner when policy permits.
- **OGVCS-016-FR-10:** Clients SHALL present local read-only state as a usability hint and recover it from authoritative server state after crash, reinstall, or manual filesystem changes.
- **OGVCS-016-FR-11:** Lock records and receipts SHALL bind authority epoch plus lock generation; promotion to a new epoch SHALL make restored locks expired/reacquire-required and SHALL reject old-epoch acquire/renew/release/transfer/submit proofs.

### Quality attributes

- **OGVCS-016-NFR-01:** Same-region uncontended acquisition p95 MUST be below 250 ms; at 200 ms simulated RTT it MUST be below one second, excluding interactive authentication.
- **OGVCS-016-NFR-02:** Duplicate/reordered acquire, renew, release, and break requests MUST be idempotent or rejected without creating split ownership.
- **OGVCS-016-NFR-03:** Lock lookup and conflict errors MUST obey OGVCS-003 non-disclosure rules.
- **OGVCS-016-NFR-04:** Loss of connectivity MUST be labeled as unknown/offline; the client MUST NOT claim continued exclusivity after it can no longer establish lease validity.

## Interfaces and data

Define `LockTarget`, `LockMode`, `LockGeneration`, `Lease`, `AssetGroupPolicy`, `EditIntent`, `WaitSubscription`, and versioned lock events. Expose acquire/renew/release/transfer/break/list/watch operations plus a submit-validation interface owned jointly with OGVCS-010.

## Development plan

1. Implement lock/edit-intent schemas, conflict-target normalization, lease/generation state machine, persistence, and authorized acquire/list APIs.
2. Implement renew/release/expiry/transfer/break/wait behavior, asset-group expansion, audit/notification hooks, and stale-message idempotency.
3. Integrate server-side lock proof into OGVCS-010 finalize and client read-only/start-edit recovery into CLI/index state.
4. Execute concurrency/partition/crash/non-disclosure/latency suites, add contention operations/runbooks, and roll out advisory observation before hard enforcement.

## Acceptance criteria

- **OGVCS-016-AC-01:** Under concurrent and partitioned fault tests, no two clients receive successful submit acknowledgements for overlapping valid hard-lock targets.
- **OGVCS-016-AC-02:** Rename, case-only rename, sidecar expansion, delete/recreate, lease expiry, delayed renewal, and stale release match normative vectors.
- **OGVCS-016-AC-03:** A server crash at every lock/submit fault point recovers to exactly one explainable owner/generation and never publishes an unauthorized change.
- **OGVCS-016-AC-04:** An authorized user can identify a conflict owner and wait; an unauthorized user cannot infer the target or owner.
- **OGVCS-016-AC-05:** Every break/transfer is permission-checked, reasoned, notified where allowed, and correlated to an immutable audit record.
- **OGVCS-016-AC-06:** Promotion/failover tests prove old-epoch lock messages and submit proofs cannot mutate or authorize the new authority and clients display reacquire-required rather than retained exclusivity.

## Verification plan

State-machine/property tests, concurrent acquisition stress, OGVCS-005 partition/crash injection, path/FileID/asset-group corpus, authorization probes, submit race tests, latency benchmarks, and manual three-OS read-only recovery checks.

## Telemetry and operations

Record grants, contention, wait duration, renewals, expiries, breaks, stale-generation rejects, submit rejects, and latency by region/mode. Never emit protected path names or owner identity into unauthorized/shared metrics.

## Rollout and rollback

Start per repository with advisory-only visibility, then enable hard enforcement by path policy. Rollback disables new enforcement only after operators confirm active-lock handling; stored locks and audit history remain readable.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Lease expiry causes an artist to keep editing without exclusivity | Prominent unknown/lost state, local checkpoint, reacquire flow, no false offline promise |
| Lock identity diverges during rename | Stable FileID targeting and atomic submit validation |
| Coarse groups create operational gridlock | Versioned bounded group rules, diagnostics, and contention metrics |
| Admin breaks become routine conflict resolution | Dedicated permission, mandatory reason, notification, audit review |

## Completion evidence

This section records bounded candidate relevance only. It is not completion
evidence sufficient to move this PRD out of Todo or close an acceptance
criterion.

- **Implementation changes:** `core/hard-lock/rust` is an unpublished,
  unwired Rust 1.82 pure state model. It composes OGVCS-002 `FileId` and
  snapshot references with OGVCS-004 path/prefix identity; normalizes bounded
  FileID/prefix/asset-group targets; models supplied server-time lease,
  generation and authority-epoch fencing; deterministically serializes
  simultaneous requests; retains exact idempotency for acquire, renew,
  release, transfer, break, expiry, wait and advisory intent; and exposes a
  pure submit-fact validation seam with private OGVCS-010-shaped plan bindings.
- **Test and benchmark results:** the bounded local suite covers simultaneous
  acquisition, reorder/replay, move, delete/recreate, case/Unicode paths,
  repository-root/nested prefix and FileID/group/prefix overlap, exact/max+1
  target bytes and member bounds, stale epoch/generation, transfer/break
  supplied facts and reasons, expiry/takeover plus historical replay,
  nonreserving wait, advisory concurrency, configuration/time-bound
  receipt/event/state commitments, cancellation/capacity rollback, exact
  retained queue/batch/reason/work admission, submit proof matching, and exact
  OGVCS-005 lock fault-boundary names. Rust 1.82 debug/release,
  formatting, warning-denied Clippy, package, predecessor-focused, Node source
  policy, and roadmap results are recorded only in the candidate worktree and
  review; there is no hosted, scale, latency, partition, database crash, or
  three-OS result.
- **Security/reliability review:**
  `docs/reviews/OGVCS-016-hard-lock-model-boundary-review.md` records that
  permission decisions, asset-group expansion, submit requirements, domain,
  epoch, and time are opaque supplied facts. Outcome shapes expose no owner,
  path, FileID, group membership, reason, or conflict count, but commitments
  may bind guessable values and are not safe unauthorized disclosure. The
  crate has no authorization, request-root, visibility, storage, transaction,
  or production enforcement brand.
- **Documentation/runbooks:** the crate README documents transition order,
  idempotency, target overlap, generation/epoch fencing, resource admission,
  fault-harness alignment, and explicit nonclaims. It is candidate developer
  documentation, not an operator runbook.
- **Rollout result:** none. No public protocol, CLI/route, database adapter,
  real clock, filesystem read-only hint, durable audit/outbox, notification
  delivery, submit mutation, or cross-branch integration domain imports this
  crate. OGVCS-016 remains Todo.
