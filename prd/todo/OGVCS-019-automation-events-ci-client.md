# OGVCS-019 — Automation API, events, and CI snapshot client

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-008, OGVCS-009, OGVCS-010, OGVCS-013, OGVCS-041  
**Blocks:** OGVCS-022, OGVCS-023, OGVCS-025, OGVCS-028, OGVCS-031, OGVCS-034, OGVCS-036, OGVCS-042  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-09-02

## Outcome

Build systems and studio automation can consume an exact authorized snapshot through stable APIs, receive replayable post-commit events, and produce provenance without pretending a long-lived CI machine is a human workspace.

## Problem

CI frequently creates enormous mutable workspaces, polls branch heads, and accumulates fragile client state. Automation also amplifies permission mistakes. The system needs snapshot-oriented, idempotent primitives and durable event delivery tied to the commit boundary.

## Scope

### In scope

- Versioned automation API/SDK surface for metadata, content, submit status, locks, and authorized events.
- Ephemeral read-only CI snapshot client with selective materialization and shared verified chunk cache.
- Transactional event outbox, signed webhooks, replay, service identities, and build provenance records.

### Out of scope

- A hosted CI scheduler, build execution fleet, code-review UI, bidirectional Git synchronization, or the general third-party integration SDK.

## Users and journeys

- **Build engineer:** resolves a branch once to an immutable snapshot, materializes declared inputs, builds, and records the exact snapshot/tool/input provenance.
- **Automation author:** processes commit events idempotently and can replay from a durable cursor after downtime.
- **Security admin:** grants a service identity only the paths and verbs required by one pipeline.

## Requirements

### Functional

- **OGVCS-019-FR-01:** Every API SHALL use OGVCS-041 negotiation/envelopes, be versioned and authenticated, accept a request/correlation ID, return typed errors, and implement its idempotency and pagination semantics.
- **OGVCS-019-FR-02:** Branch resolution SHALL return an immutable authorized snapshot ID; subsequent CI reads SHALL bind to that ID rather than follow a moving branch.
- **OGVCS-019-FR-03:** The CI client SHALL materialize include/exclude patterns into an ephemeral directory without a persistent per-path have-list and verify every downloaded object.
- **OGVCS-019-FR-04:** A shared cache SHALL key by canonical content identity, validate before reuse, isolate credentials from bytes, and tolerate eviction/corruption as a performance loss rather than correctness loss.
- **OGVCS-019-FR-05:** OGVCS-010 SHALL append a versioned event to a durable outbox in the same atomic transaction as acknowledgement-worthy state changes.
- **OGVCS-019-FR-06:** Event consumers SHALL support ordered per-repository cursors, at-least-once delivery, bounded retention, replay, and explicit gap/expiration errors.
- **OGVCS-019-FR-07:** Webhooks SHALL use signed timestamped envelopes, secret rotation, delivery IDs, retry/backoff, dead-letter inspection, and replay protection guidance.
- **OGVCS-019-FR-08:** Event payloads and API enumeration SHALL contain only fields/paths authorized for the consuming identity at the defined authorization time.
- **OGVCS-019-FR-09:** Service identities SHALL support scoped tokens, expiry/rotation/revocation, non-interactive authentication, and attributable audit records.
- **OGVCS-019-FR-10:** The client SHALL emit a machine-readable provenance statement containing repository, snapshot, selection policy, materialized root digest, client version, and optional build result reference.

### Quality attributes

- **OGVCS-019-NFR-01:** Retried operations and duplicate events MUST be safely deduplicable using stable IDs.
- **OGVCS-019-NFR-02:** A post-commit crash MUST not acknowledge a snapshot without making its event eventually readable from the outbox.
- **OGVCS-019-NFR-03:** Parallel CI materialization MUST scale without serializing on a global workspace state file.

## Interfaces and data

Publish OGVCS-041 API schemas/profile entries, compatibility rules, SDK generation inputs, `EventEnvelope`, cursor, delivery attempt, webhook registration, service principal, cache record, and provenance statement. Event payload schemas identify their authorization-evaluation semantics.

## Development plan

1. Implement OGVCS-041-conforming automation API schemas/SDK generation, service identities, snapshot resolution, idempotency, pagination, and typed errors.
2. Implement the ephemeral read-only CI client, selection materialization, verified shared cache, machine output, and provenance statement.
3. Implement the transactional event outbox, cursor/replay service, signed webhook delivery/rotation/retry/dead-letter behavior, and authorization filtering.
4. Complete SDK compatibility, event crash/replay, cache corruption, security and parallel-build tests, then roll out snapshot reads before events and mutation APIs.

## Acceptance criteria

- **OGVCS-019-AC-01:** Repeated builds of one snapshot and selection produce identical materialized root digests on supported platforms.
- **OGVCS-019-AC-02:** Commit/outbox fault injection yields exactly one committed snapshot and at least one consumable event with a stable event ID—never an acknowledged event gap.
- **OGVCS-019-AC-03:** Webhook duplicate, delay, reorder, forged signature, stale timestamp, rotation, and dead-letter/replay cases match the contract.
- **OGVCS-019-AC-04:** Shared-cache corruption is detected, refetched, and does not alter produced bytes; concurrent readers remain correct.
- **OGVCS-019-AC-05:** A least-privilege service identity cannot enumerate or fetch excluded paths/objects through API, event, error, or cache behavior.

## Verification plan

OGVCS-041 protocol/schema compatibility checks, SDK contract tests, outbox crash matrix, replay/load tests, webhook security tests, cache mutation/race tests, authorization probes, three-OS snapshot builds, and large-workspace benchmarks.

## Telemetry and operations

Expose API latency/error by operation/version, outbox lag, cursor age, webhook attempts/dead letters, snapshot materialization bytes/cache hit rate, verification failures, and provenance completion. Redact tokens, secret headers, hidden paths, and content.

## Rollout and rollback

Ship read-only snapshot APIs/client first, then events, then scoped submit/lock endpoints. New API/event versions run concurrently through their support window; rollback disables a version only after registered consumers migrate or an emergency compatibility policy applies.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Consumer assumes exactly-once delivery | Stable event IDs, explicit at-least-once contract, examples/tests |
| Event reveals a protected path | Per-consumer filtering and non-disclosure conformance tests |
| Shared cache crosses identity boundary | Content-only keys, verified bytes, no reusable credentials |
| Moving branch makes builds irreproducible | Resolve once and bind all reads/provenance to snapshot ID |

## Completion evidence

- Implementation changes: bounded private candidate relevance only. An
  unpublished, unwired Rust 1.82 crate under `core/automation-events/rust`
  binds supplied commit/outbox/authorization facts into deterministic private
  event IDs, validates exact contiguous replay pages with scoped expiring HMAC
  cursors, signs and verifies timestamped webhook projections with bounded key
  rotation and duplicate-attempt state, and binds one immutable OGVCS-002
  Snapshot plus selection/materialization/tool/input facts into a private build
  provenance digest. It accepts no payload/path bytes and performs no I/O,
  authorization, transaction, materialization, cache, delivery, or publication.
- Test and benchmark results: local Rust tests cover deterministic known-answer
  event, cursor, webhook and provenance binding, exhaustive field tamper,
  OGVCS-002 Snapshot kind and zero-digest handling, contiguous/missing/additional/
  reordered/cross-scope/causally-future replay, cursor
  tamper/future-use/expiry/retention/
  authority-epoch/generation/key rotation, webhook signature/body/time/key
  rotation/exact duplicate/conflicting-attempt behavior, replay-guard
  scope/pruning/capacity/
  overflow atomicity and skew/retention coupling, and exact/max+1 event/
  sequence/page/key/time/body/guard bounds. Rustfmt, debug/release,
  warning-denied Clippy, package, Node policy,
  roadmap, and upstream OGVCS-002 conformance are the candidate gate. No
  hosted, fault, service, cross-OS materialization, or reference-scale campaign
  is claimed.
- Security/reliability review: see
  [private automation-event boundary review](../../docs/reviews/OGVCS-019-automation-events-boundary-review.md).
  Commit, outbox, authorization, storage-window and provenance inputs are
  caller-supplied facts, not authority. Cursor integrity cannot prove a truthful
  high watermark; the replay guard is scoped but volatile; non-copyable key
  wrappers and all-zero secret rejection do not prove entropy, zeroization,
  custody, separation, revocation, or rotation.
- Documentation/runbooks: the crate README defines exact digest/MAC projections,
  validation order, hard bounds, rotation/replay semantics and nonclaims. There
  is no operator runbook because no service or external effect is wired.
- Rollout result: not rolled out. OGVCS-019 remains Todo. No acceptance
  criterion is closed. OGVCS-041 schemas/SDK, service identities, authenticated
  snapshot resolution, ephemeral materialization, verified shared cache,
  transactional outbox integration, durable replay/retention, authorization
  filtering, webhook transport/retry/dead-letter operations, provenance-object
  publication, telemetry/runbooks, hosted fault/security/scale evidence, and
  rollout remain open.
