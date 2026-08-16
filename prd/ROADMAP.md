# OpenGameVCS delivery roadmap

**Roadmap state:** Proposed baseline  
**Planning horizon:** 42+ months  
**Last updated:** 2026-08-15
**Authoritative status:** file location in [`todo/`](todo/) or [`done/`](done/)  
**Architecture baseline:** [`architecture.md`](../architecture.md)

## Outcome and sequencing strategy

OpenGameVCS will be delivered as a series of separately reviewed, separately verifiable PRDs. The critical path proves data integrity and authorization before adding broad UX or scale features:

Every PRD implements a bounded part of the shared [architecture baseline](../architecture.md). Release sequencing may change through roadmap change control; architectural invariants may change only through an ADR and coordinated updates to every affected PRD.

```text
Executable foundation libraries and fixtures
  -> public protocol baseline
  -> metadata + content primitives
  -> authorized atomic submit
  -> workspace + sync + locks
  -> recovery + automation
  -> artist and engine workflows
  -> production HA, export, and compatibility
  -> virtualization and ecosystem
```

Calendar ranges are planning envelopes, not commitments. A release advances only when its evidence gate passes. Later work may develop against stable versioned contracts in parallel, but it may not declare completion before its runtime dependencies are done.

## Planning and gate controls

- **Clock:** Month 0 starts only when R0 has named owners, funded implementation capacity, access to at least two design-partner workloads, and an approved security reviewer. Partner recruitment or procurement before that point is not hidden inside the three-month R0 estimate.
- **Capacity assumption:** the calendar assumes the five execution lanes below can be staffed in parallel after R0. With fewer staffed lanes, the forecast must move; scope or evidence gates are not compressed to preserve dates.
- **Forecasting:** reforecast the remaining critical path at least monthly and after every release gate using observed PRD cycle time, dependency changes, partner availability, benchmark results, and defect load. Record material changes in roadmap history.
- **Status:** progress is counted by PRDs in `done`, not subjective percentage complete. A PRD in development remains incomplete until its evidence is recorded and reviewed.
- **Gate review:** the release owner, security owner, reliability owner, and affected design partner review a signed evidence packet. Any failed P0 criterion keeps the gate closed.
- **Exceptions:** a P1 may slip only with a named risk owner, documented product limitation, disabled unsafe surface, expiry/re-entry release, and approval in the gate record. P0 scope cannot be waived into a later release.
- **Critical-path changes:** adding/removing a dependency, changing an invariant, or moving a release requires the change-control process in [`README.md`](README.md) and a fresh gate forecast.

## Non-PRD program prerequisites

The following work can block a release but is not software development and therefore does not receive an OGVCS ID or live in `todo`/`done`:

- recruit and retain design partners, arrange legal/privacy-safe access to representative workload measurements, and conduct user research;
- fund and staff the parallel execution lanes and name product, security, reliability, and release decision owners;
- commission independent security, portability, recovery, and governance reviews where a gate requires external evidence;
- establish contributor, trademark, certification-authority, and neutral-governance organizations and transfer project/release control;
- recruit independent operators and third-party integrators for ecosystem validation.

These activities are tracked by the program owner in gate evidence. They may validate, reforecast, or stop a product increment, but they must not be represented as an implementation PRD or hidden inside a PRD's coding completion claim.

## Release gates

| Release | Indicative window | Product state | Required evidence |
|---|---:|---|---|
| R0 Engineering Foundation | Months 0–3 | Executable libraries, protocol, and test tooling are stable enough for independent service/client work | Deterministic fixtures; interoperable object libraries; authorization/path contracts; public protocol baseline; reproducible benchmark/fault harness |
| R1 Developer Preview | Months 4–10 | Native CLI vertical slice on one supported deployment | Clean-host integrated commit/fetch; content completeness; partial sync; locks; ACL; restore; CI; sandboxed Git/LFS import; three-OS correctness |
| R2 Studio Alpha | Months 11–17 | Real Unreal production can run in shadow mode | Artist client and no-CLI review; Unreal workflow; branch-aware locks; cache; observability; sandboxed P4 shadow migration; signed upgrades |
| R3 Production Beta | Months 18–28 | Two design partners can run production with recovery and exit paths | Unity; epoch-safe HA/DR; verified fidelity/projection exports; scaled secure review; compatibility/LTS; 90-day reliability evidence |
| R4 Ecosystem | Months 29–42+ | Extensible platform with multiple operating choices | Public SDK; third-party integration; independent hosting conformance; neutral release/governance control |

## Portfolio

### R0 — Engineering Foundation

| ID | PRD | Priority | Depends on |
|---|---|---|---|
| OGVCS-001 | [Deterministic workload fixture generator](done/OGVCS-001-deterministic-workload-fixture-generator.md) | P0 | None |
| OGVCS-002 | [Core object library and open repository format](todo/OGVCS-002-core-object-library-repository-format.md) | P0 | OGVCS-001 |
| OGVCS-003 | [Authorization contract package and threat test kit](done/OGVCS-003-authorization-contract-threat-test-kit.md) | P0 | OGVCS-001 |
| OGVCS-004 | [Cross-platform path and workspace filesystem library](todo/OGVCS-004-cross-platform-path-filesystem-library.md) | P0 | OGVCS-001, OGVCS-002 |
| OGVCS-041 | [Public protocol baseline and generated bindings](todo/OGVCS-041-public-protocol-baseline-generated-bindings.md) | P0 | OGVCS-002, OGVCS-003, OGVCS-004 |
| OGVCS-005 | [Benchmark, conformance corpus, and fault harness](todo/OGVCS-005-benchmark-and-fault-harness.md) | P0 | OGVCS-001, OGVCS-002, OGVCS-003, OGVCS-004, OGVCS-041 |

**R0 exit gate:** every R0 PRD is in `done`; their packages, CLIs, protocol bindings, vectors, and harnesses run from a clean environment; no unresolved decision can change object/FileID identity, root-snapshot encoding, path identity, authorization visibility, public negotiation/retry semantics, or the atomic-commit invariant. Separately, at least two design partners must confirm that the synthetic profiles cover their material Unreal/Unity workflows before the release owner closes the gate.

### R1 — Developer Preview

| ID | PRD | Priority | Depends on |
|---|---|---|---|
| OGVCS-006 | [Repository metadata and snapshot service](todo/OGVCS-006-repository-metadata-snapshot-service.md) | P0 | 002, 003, 004, 005, 041 |
| OGVCS-007 | [Chunking and content-manifest engine](todo/OGVCS-007-chunking-content-manifest-engine.md) | P0 | 002, 004, 005 |
| OGVCS-008 | [Object storage and resumable transfer service](todo/OGVCS-008-object-storage-transfer-service.md) | P0 | 003, 007, 041 |
| OGVCS-009 | [Identity, path authorization, and audit](todo/OGVCS-009-identity-path-authorization-audit.md) | P0 | 003, 006, 041 |
| OGVCS-010 | [Atomic submit and branch-head transaction](todo/OGVCS-010-atomic-submit-transaction.md) | P0 | 006, 008, 009 |
| OGVCS-011 | [Native CLI and workspace lifecycle foundation](todo/OGVCS-011-native-cli-workspace-lifecycle.md) | P0 | 004, 006, 008, 009, 041 |
| OGVCS-012 | [Workspace index and scalable status](todo/OGVCS-012-workspace-index-scalable-status.md) | P0 | 004, 005, 011 |
| OGVCS-013 | [Selective sync and explicit materialization](todo/OGVCS-013-selective-sync-materialization.md) | P0 | 007, 008, 009, 011, 012 |
| OGVCS-014 | [Local checkpoints and offline recovery](todo/OGVCS-014-local-checkpoints-offline-recovery.md) | P0 | 007, 011, 012, 013 |
| OGVCS-015 | [Branches, history, diff, merge, and revert](todo/OGVCS-015-branches-history-merge-revert.md) | P0 | 006, 010, 011, 014 |
| OGVCS-016 | [Hard locks and advisory edit intent](todo/OGVCS-016-hard-locks-edit-intent.md) | P0 | 006, 009, 010, 011, 012 |
| OGVCS-017 | [Integrity verification and repair](todo/OGVCS-017-integrity-verification-repair.md) | P0 | 002, 007, 008, 010 |
| OGVCS-018 | [Backup, restore, retention, and garbage collection](todo/OGVCS-018-backup-restore-retention-gc.md) | P0 | 006, 008, 009, 010, 017 |
| OGVCS-019 | [Automation API, events, and CI snapshot client](todo/OGVCS-019-automation-events-ci-client.md) | P0 | 008, 009, 010, 013, 041 |
| OGVCS-045 | [Untrusted parser sandbox and credential broker](todo/OGVCS-045-untrusted-parser-sandbox-credential-broker.md) | P0 | 003, 004, 009 |
| OGVCS-020 | [Git and Git LFS importer](todo/OGVCS-020-git-lfs-importer.md) | P0 | 002, 007, 008, 010, 015, 017, 045 |
| OGVCS-021 | [Starter deployment and administrator bootstrap](todo/OGVCS-021-starter-deployment-admin-bootstrap.md) | P0 | 006, 008, 009, 017, 018 |
| OGVCS-042 | [Minimal local agent and first-party IPC](todo/OGVCS-042-minimal-local-agent-first-party-ipc.md) | P0 | 004, 009, 011, 012, 013, 016, 019, 041 |
| OGVCS-043 | [R1 CLI vertical slice](todo/OGVCS-043-r1-cli-vertical-slice.md) | P0 | 010, 011, 012, 013, 016, 021, 041 |

**R1 exit gate:** all R1 P0 PRDs are done; OGVCS-043 passes from immutable checksummed preview artifacts on clean Windows, macOS, and Linux clients; the fault harness proves that no supported failure can publish missing content, bypass a hard lock, leak a protected path/object, delete a newly referenced object, parse imported data with credentials, or produce an unverifiable independently retained restore. OGVCS-030 owns signed release-train packaging in R2.

### R2 — Studio Alpha

| ID | PRD | Priority | Depends on |
|---|---|---|---|
| OGVCS-022 | [Desktop artist client](todo/OGVCS-022-desktop-artist-client.md) | P0 | 011–016, 019, 043 |
| OGVCS-023 | [Unreal Engine integration](todo/OGVCS-023-unreal-engine-integration.md) | P0 | 013, 016, 019, 022, 042 |
| OGVCS-024 | [Branch-aware integration domains and retained locks](todo/OGVCS-024-branch-aware-lock-domains.md) | P0 | 015, 016 |
| OGVCS-025 | [Shelves and review service](todo/OGVCS-025-shelves-review-service.md) | P0 | 009, 010, 013, 015, 016, 018, 019 |
| OGVCS-026 | [Sandboxed asset previews and diffs](todo/OGVCS-026-asset-preview-diff-sandbox.md) | P1 | 003, 009, 025, 045 |
| OGVCS-027 | [Regional content cache](todo/OGVCS-027-regional-content-cache.md) | P0 | 008, 009, 013, 017 |
| OGVCS-028 | [Observability, capacity, and diagnostics](todo/OGVCS-028-observability-capacity-diagnostics.md) | P0 | 005–010, 016–019, 021, 025, 027 |
| OGVCS-029 | [Perforce importer and shadow migration](todo/OGVCS-029-perforce-shadow-migration.md) | P0 | 002, 007, 010, 015–017, 020, 045 |
| OGVCS-044 | [Desktop shelves and review workflow](todo/OGVCS-044-desktop-shelves-review-workflow.md) | P0 | 022, 025 |
| OGVCS-030 | [Signed packaging and safe upgrades](todo/OGVCS-030-signed-packaging-safe-upgrades.md) | P0 | 021, 022, 023, 028, 041, 043, 044 |

**R2 exit gate:** all R2 P0 PRDs are done; artists complete the shelf/review/update/approval/promotion loop without CLI; an Unreal design partner shadows a real production for at least eight weeks, restores from backup, loses a cache without data loss, and produces matching incumbent/OpenGameVCS snapshot builds or explained deterministic differences. OGVCS-026 may remain P1 only if previews are disabled and review does not expose unsafe parsing.

### R3 — Production Beta

| ID | PRD | Priority | Depends on |
|---|---|---|---|
| OGVCS-031 | [Unity integration and semantic merge](todo/OGVCS-031-unity-integration-semantic-merge.md) | P0 | 013, 015, 016, 019, 022, 026, 042, 045 |
| OGVCS-032 | [HA metadata, cross-region DR, and rolling upgrades](todo/OGVCS-032-ha-dr-rolling-upgrades.md) | P0 | 009, 010, 016, 018, 021, 027, 028, 030 |
| OGVCS-033 | [Open export modes and independent verifier](todo/OGVCS-033-open-export-independent-verifier.md) | P0 | 002, 004, 007, 009, 017, 018, 020, 025, 029 |
| OGVCS-034 | [Git bridge and one-way mirror](todo/OGVCS-034-git-bridge-one-way-mirror.md) | P1 | 015, 019, 020, 025, 033 |
| OGVCS-035 | [Authorization-safe search and review scale](todo/OGVCS-035-authorization-safe-search-review-scale.md) | P0 | 009, 025, 026, 028 |
| OGVCS-036 | [Protocol conformance, compatibility, and LTS](todo/OGVCS-036-protocol-conformance-compatibility-lts.md) | P0 | 002, 008, 009, 019, 030, 033, 041 |

**R3 exit gate:** all R3 P0 PRDs are done; two studios complete 90 production days, a clean-room organization restores an export into a fresh deployment, failover and rollback meet declared RPO/RTO, and no unresolved P0/P1 durability or authorization defect remains.

### R4 — Ecosystem

| ID | PRD | Priority | Depends on |
|---|---|---|---|
| OGVCS-037 | [Virtual workspace and on-demand hydration](todo/OGVCS-037-virtual-workspace-hydration.md) | P1 | 004, 008, 012, 013, 017, 022, 030 |
| OGVCS-038 | [Public integration SDK and local-agent ecosystem](todo/OGVCS-038-integration-sdk-local-agent.md) | P1 | 022, 030, 036, 042 |
| OGVCS-039 | [Godot and DCC reference integrations](todo/OGVCS-039-godot-dcc-reference-integrations.md) | P2 | 026, 031, 038 |
| OGVCS-040 | [Hosting conformance and certification toolkit](todo/OGVCS-040-hosting-conformance-certification-toolkit.md) | P1 | 032, 033, 036, 038 |

**R4 exit gate:** OGVCS-040 is done; at least one independent operator passes its conformance and recovery profiles; one third party ships an SDK integration. As a separate non-PRD program gate, governance and release infrastructure are no longer controlled by one commercial actor.

## Parallel execution lanes

After R0, work should proceed in bounded lanes with versioned contracts:

| Lane | Critical PRDs | Primary risk |
|---|---|---|
| Metadata and correctness | 006, 010, 015, 017, 018, 032, 043 | Atomicity, recovery, history invariants |
| Content and geography | 007, 008, 013, 027, 037 | Integrity, throughput, cache correctness |
| Client and workflows | 011, 012, 014, 016, 022–026, 031, 042–044 | Cross-platform correctness and artist usability |
| Security and operations | 003, 009, 021, 028, 030, 032, 035, 045 | Metadata leakage, untrusted parsing, upgrades, operability |
| Interoperability | 019, 020, 029, 033, 034, 036, 038–041 | Fidelity, compatibility, credible exit |

No lane may invent a private version of a shared contract. Interface changes flow through the owning PRD or a new follow-up PRD.

## Program risks and decision triggers

| Risk | Trigger | Required decision |
|---|---|---|
| Workload model is synthetic or biased | R0 lacks two privacy-reviewed real workload traces, including Unreal and Unity patterns | Keep R0 open; do not freeze scale, path, chunk, or UX assumptions |
| Core correctness is not provable | Fault/conformance test publishes missing content, permits unauthorized discovery, or violates hard-lock exclusivity | Stop release promotion and fix the owning invariant before feature work proceeds |
| Performance target requires unsafe semantics | A target is met only by bypassing verification, authorization, durable acknowledgement, or explicit state | Reject the optimization; revise architecture or the evidence-backed target transparently |
| Cross-platform semantics diverge | The same repository cannot round-trip on the declared OS/case/Unicode matrix | Narrow the supported matrix or block the gate; never silently rewrite paths |
| Artist workflow is operationally worse | Partner shadow data misses task-success/support-rate thresholds or produces repeated local-work loss/confusion | Hold Studio Alpha, simplify the workflow, and rerun observed usability trials |
| Migration fidelity cannot reconcile | Perforce/Git source and target have unexplained root, history, or LFS/archive differences | Remain in shadow/read-only mode; do not authorize cutover |
| Recovery exists only in theory | Scheduled clean restore, cache-loss, failover, or export/import drill misses RPO/RTO or needs private engineering intervention | Block the next production gate and repair tooling/runbooks |
| Ecosystem remains vendor-controlled | No independent verifier/operator/integration, or one actor retains unilateral signing/specification control | Do not call the system 1.0 or the governance neutral |

## Program-level success measures

- Zero acknowledged snapshots with missing or corrupt referenced content.
- Zero successful unauthorized path enumeration or object retrieval in the conformance suite.
- Zero dual successful submits for the same valid hard-lock conflict domain.
- Verified restore and export on every supported release train.
- Warm status p95 under 2 seconds at one million tracked paths on the reference workstation.
- Same-region lock acquisition p95 under 250 ms and 200 ms RTT acquisition p95 under one second, excluding interactive authentication.
- Artist task completion without CLI for setup, sync, start edit/lock, view conflict owner, revert, review, and submit.
- Published logical bytes, unique stored bytes, transfer bytes, and deduplication ratio by representative asset format.
- At least two production design partners and one independent operator before 1.0.

## Explicitly deferred

The roadmap does not include arbitrary binary merge, offline exclusive-lock guarantees, peer-to-peer or multi-master metadata, a full DAM, or a P4 wire-compatible server. Adding any of these requires a new PRD and a new reliability/security review.
