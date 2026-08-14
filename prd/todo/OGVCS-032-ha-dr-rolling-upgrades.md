# OGVCS-032 — HA metadata, cross-region DR, and rolling upgrades

**Status:** Todo  
**Release:** R3 — Production Beta  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-009, OGVCS-010, OGVCS-016, OGVCS-018, OGVCS-021, OGVCS-027, OGVCS-028, OGVCS-030  
**Blocks:** OGVCS-040  
**Source:** [Architecture ADR-0004](../../adr/0004-dr-authority-security-epochs.md)  
**Last updated:** 2026-08-14

## Outcome

A production deployment survives a metadata-node failure without losing acknowledged transactions, can fail over to a verified cross-region recovery point without split authority, and upgrades supported versions while preserving quorum and compatibility.

## Problem

Metadata is the authority for snapshots, branches, locks, permissions, audit, and events. Replicating only the database or object store can expose branch roots with missing content or allow two regions to accept conflicting writes. High availability and disaster recovery require one transaction/fencing model, verified content readiness, observable lag, rehearsed failover, and explicit recovery objectives.

## Scope

### In scope

- One supported same-region quorum topology with automatic leader failover and strongly consistent authoritative metadata writes.
- Asynchronous cross-region disaster-recovery replica with verified reachable content, manual fenced promotion, failback/reseed, and drills.
- Rolling upgrade orchestration for compatible versions plus backup/restore integration and capacity guidance.

### Out of scope

- Active-active or multi-master metadata writes, automatic cross-region promotion, disconnected regional commits/locks, or arbitrary database/topology combinations.

## Users and journeys

- **On-call operator:** observes leader failure, confirms automatic same-region recovery, and sees clients retry safely with no acknowledged-write loss.
- **Incident commander:** selects a verified DR recovery point, proves the primary is fenced, promotes, validates repositories, and later performs a controlled failback/reseed.
- **Release operator:** drains and rolls compatible nodes one at a time while quorum, protocol, and correctness SLOs remain satisfied.

## Requirements

### Functional

- **OGVCS-032-FR-01:** The reference HA topology SHALL declare quorum/failure-domain rules, supported database/coordination mode, client endpoint behavior, clock/network assumptions, and minimum capacity.
- **OGVCS-032-FR-02:** Every authoritative write—branch/tag state, snapshots, locks/generations, permissions/policy, audit, outbox, repair/retention coordination—SHALL commit through one linearizable transaction authority.
- **OGVCS-032-FR-03:** Only a current fenced leader SHALL acknowledge mutations; terms/epochs SHALL prevent a paused, partitioned, restored, or demoted node/region from accepting stale writes.
- **OGVCS-032-FR-04:** Client mutation retries SHALL use idempotency/transaction IDs and return a resolvable committed/not-committed/unknown result after failover rather than create duplicate state.
- **OGVCS-032-FR-05:** Same-region failover SHALL not acknowledge or expose a snapshot until all content durability conditions of OGVCS-010 remain true in the active region.
- **OGVCS-032-FR-06:** DR replication SHALL track metadata log position plus every content object required by reachable roots and SHALL publish a monotonic `verified recovery point` only after graph/content validation.
- **OGVCS-032-FR-07:** DR promotion SHALL require authorized dual control, primary isolation/fencing evidence, chosen verified recovery point, object/metadata readiness, compatibility checks, DNS/client plan, audit record, and post-promotion validation.
- **OGVCS-032-FR-08:** A promoted region SHALL never expose a branch root newer than its verified content recovery point; later-arriving metadata/content SHALL not advance roots outside the recovery protocol.
- **OGVCS-032-FR-09:** Failback SHALL treat the promoted region as authority, reject divergent old-primary writes, and require controlled reseed/reconciliation before role change.
- **OGVCS-032-FR-10:** Rolling upgrade SHALL enforce OGVCS-030's adjacent-version/protocol/schema matrix, preserve quorum/fencing, gate each node on readiness/catch-up, and stop automatically on correctness/SLO regression.
- **OGVCS-032-FR-11:** Backup/restore SHALL remain an independent recovery path; HA replicas SHALL not be described or counted as backups.
- **OGVCS-032-FR-12:** Cross-region promotion SHALL create a new monotonic authority/security epoch before writes reopen and SHALL rotate/fence signing, service and infrastructure credentials issued by the former authority.
- **OGVCS-032-FR-13:** Restored old-epoch sessions, service tokens, transfer grants, authorization-cache decisions, lock leases/receipts and mutation proofs SHALL not authorize the promoted region; locks SHALL return expired/reacquire-required.
- **OGVCS-032-FR-14:** Promotion SHALL publish a signed recovery boundary containing old/new epoch, last verified metadata position, branch generations and content inventory generation plus an immutable promotion/reconciliation ledger.
- **OGVCS-032-FR-15:** Clients SHALL resolve pre-promotion idempotency/commit receipts against the boundary as present, `not present after recovery`, or `requires reconciliation`; a receipt beyond the promoted point SHALL never return invented success or disappear without an actionable resubmit/recovery result.

### Quality attributes

- **OGVCS-032-NFR-01:** Reference same-region HA MUST demonstrate RPO 0 for acknowledged metadata transactions and service RTO at or below five minutes under any single-node loss.
- **OGVCS-032-NFR-02:** Reference cross-region DR MUST demonstrate a verified RPO at or below five minutes and operator-driven RTO at or below 60 minutes under the declared workload/topology.
- **OGVCS-032-NFR-03:** No partition, clock skew, pause, packet reorder, node restore, or dual-promotion test may produce two writable authorities or violate snapshot/content/lock invariants.
- **OGVCS-032-NFR-04:** No promotion test may resurrect a revoked credential/lock/cached allow decision or silently lose an acknowledged result without a machine-readable boundary classification and retained recovery path.

## Interfaces and data

Define authority/security epoch, HA member/role, epoch-bound session/grant/lock/commit receipt, transaction resolution, replication position, content replication inventory, verified recovery point, signed recovery boundary, fencing evidence, promotion/reconciliation/failback ledger, rolling-upgrade state, and topology health/capacity report.

## Development plan

1. Implement the supported same-region quorum topology, leader/term fencing, endpoint discovery, idempotent transaction resolution and member health/capacity tooling.
2. Integrate all authoritative metadata domains, content-durability gates and automatic single-node failover, then prove linearizable histories under load/faults.
3. Implement cross-region metadata/content replication, monotonic verified recovery points, dual-controlled new-epoch promotion, session/grant/lock invalidation, signed recovery boundaries, lost-acknowledgement reconciliation, stale-primary fencing, reseed and failback workflows.
4. Implement compatible rolling-upgrade orchestration and complete recurring HA/DR/backup/upgrade chaos drills before enabling promotion credentials in production.

## Acceptance criteria

- **OGVCS-032-AC-01:** Leader kill, follower loss, process pause, disk-full, network partition, packet delay/reorder, and dependency failure preserve quorum safety and resolve retried mutations exactly once.
- **OGVCS-032-AC-02:** No acknowledged same-region transaction is lost after each supported single-node fault, and automatic recovery meets the five-minute RTO in repeated drills.
- **OGVCS-032-AC-03:** Region-loss drills promote only a verified point, meet declared RPO/RTO, pass full branch/content/lock/audit/event checks, and complete documented failback/reseed.
- **OGVCS-032-AC-04:** Deliberate dual-promotion and stale-primary restart attempts are fenced and cannot accept or serve authoritative mutations.
- **OGVCS-032-AC-05:** Every supported rolling upgrade/abort sequence retains quorum and SLOs or stops safely; incompatible versions/schema are rejected before joining.
- **OGVCS-032-AC-06:** Quarterly automated/operated HA, DR, backup-restore, and upgrade games retain evidence and actionable remediation.
- **OGVCS-032-AC-07:** Region-loss promotion with seeded revocations, active sessions/grants, locks, cached allows, acknowledged/unacknowledged submits and lost responses rejects all stale authority and classifies every client receipt against the signed boundary.
- **OGVCS-032-AC-08:** A client with retained draft/content safely reconciles and resubmits a `not present after recovery` receipt without duplicate publication, FileID reuse, stale lock acceptance, or hidden data loss.

## Verification plan

Jepsen-style history/model validation where applicable, OGVCS-005 network/process/disk faults, transaction retry tests, sustained-load leader churn, content-lag injection, epoch/revocation/lock/lost-ack region-loss exercises, stale-primary fencing, restore-versus-replica drills, and full supported rolling-upgrade matrix.

## Telemetry and operations

Expose authority term/leader/quorum, commit/apply latency and lag, transaction unknown resolution, content replication and verified-point lag, fencing status, promotion step, recovery objectives, upgrade state, and backup independence. Page on split-authority indicators, quorum loss, verified-point staleness, or invariant failure.

## Rollout and rollback

Prove a three-member nonproduction quorum, then shadow read traffic, then enable production writes. Add DR in replicate/verify-only mode before any promotion credential is active. Rolling upgrades start canary-first. Rollback uses version compatibility; topology rollback never creates a second leader and schema rollback follows OGVCS-030.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Database replication is mistaken for application correctness | End-to-end transaction model and history/invariant validation |
| Metadata outruns content in DR | Verified recovery point couples graph and object readiness |
| Old primary resumes after promotion | Durable epoch fencing, isolated credentials/network, reseed-only failback |
| HA copies replace backup discipline | Independent backup/restore SLO and drills remain release gates |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
