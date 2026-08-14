# OGVCS-005 — Benchmark, conformance corpus, and fault harness

**Status:** Todo  
**Release:** R0 — Engineering Foundation  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-001, OGVCS-002, OGVCS-003, OGVCS-004, OGVCS-041  
**Blocks:** OGVCS-006, OGVCS-007, OGVCS-012, OGVCS-028  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Developers and release engineers have an executable benchmark/fault harness that reproduces every performance, correctness, durability, security, and compatibility claim under a declared dataset, topology, cache state, fault schedule, and hardware profile. Regressions block the relevant release gate.

## Problem

VCS benchmarks are easy to game by changing file mix, history, warm caches, hardware, or operation definition. Ordinary tests also miss failures between upload, metadata commit, branch publication, index update, cache fill, and backup boundaries.

## Scope

### In scope

- Versioned workload runner for all OGVCS-001 fixture bundles and scenarios.
- Reference hardware/topology profiles and controlled network conditions.
- Task definitions and measurement schema for setup, status, sync, submit, lock, merge, CI, verify, backup, restore, and export.
- Deterministic service/client fault injection and crash-point orchestration.
- Security and path-conformance suites from OGVCS-003/004.
- Result comparison, uncertainty, regression budgets, and publication format.

### Out of scope

- Optimizing product code.
- Declaring final SLOs before representative results exist.
- Vendor benchmarking without permission or license compliance.

## Users and journeys

- **Feature engineer:** runs a focused profile locally and the required full matrix in CI.
- **Release manager:** sees whether a candidate satisfies its release gate and exactly which regression blocks it.
- **Studio evaluator:** reproduces a published result on documented infrastructure.
- **Reliability engineer:** injects a named crash at each transaction boundary and verifies invariants after restart.

## Requirements

### Functional

- **OGVCS-005-FR-01:** Each run SHALL record corpus/format/implementation version, configuration, hardware, OS/filesystem, topology, RTT/loss/bandwidth, cache state, concurrency, seed, wall clock, CPU, memory, disk, and network bytes.
- **OGVCS-005-FR-02:** Workload tasks SHALL have normative start/end conditions and correctness assertions; timing a failed or incomplete operation SHALL not count as success.
- **OGVCS-005-FR-03:** The harness SHALL support cold, warm-local-cache, warm-regional-cache, and mixed-cache runs without hidden state between repetitions.
- **OGVCS-005-FR-04:** Network control SHALL support 20–200 ms RTT, bandwidth caps, packet loss, interruption, duplication, and reorder where the platform permits.
- **OGVCS-005-FR-05:** Fault schedules SHALL target every durable write, object finalize, policy decision, branch compare-and-swap, lock mutation, event publication, index cursor, backup generation, and GC mark/sweep boundary exposed by later PRDs.
- **OGVCS-005-FR-06:** Post-fault verification SHALL assert no missing referenced content, unauthorized access, dual hard-lock submit, invisible committed state, or unverifiable backup/export.
- **OGVCS-005-FR-07:** Results SHALL report sample count, p50/p95/p99 where meaningful, dispersion, failures/retries, bytes, and logical/unique content ratios.
- **OGVCS-005-FR-08:** A machine-readable threshold file SHALL let each PRD own explicit regression and release criteria without changing harness code.
- **OGVCS-005-FR-09:** Public result bundles SHALL include enough configuration and raw non-sensitive samples to reproduce calculations.
- **OGVCS-005-FR-10:** Harness lifecycle/task/fault adapters exposed over a process boundary SHALL use an OGVCS-041 registered test profile with bounded messages, negotiation, typed errors and deterministic trace capture.

### Quality attributes

- **OGVCS-005-NFR-01:** Repeating a deterministic correctness/fault scenario with the same seed MUST inject the same ordered logical faults.
- **OGVCS-005-NFR-02:** Harness measurement overhead SHALL be measured and kept below 5% for throughput tasks or reported/corrected explicitly.
- **OGVCS-005-NFR-03:** The harness MUST run without privileged host access for normal profiles; privileged fault/network profiles SHALL be isolated and documented.

## Interfaces and data

Provide an OGVCS-041-profiled test-driver protocol for server/client lifecycle, fault points, task operations, metrics, invariant checks, and result bundles. Product components publish named fault points only in test builds or authenticated test mode. Thresholds reference stable PRD requirement IDs.

## Development plan

1. Implement runner/task/result schemas, lifecycle adapters, environment capture, threshold files, and smoke execution against fake components and OGVCS-001 bundles.
2. Add deterministic cache-state control, network-shaping adapters, resource measurement, repeat/variance calculations, and reproducible result packaging.
3. Add named fault-point orchestration, crash/restart scheduling, invariant plug-ins, and intentionally broken fake services that prove each checker detects its target defect.
4. Integrate tiered local/presubmit/nightly/release profiles, dashboards and regression comparison, publish the driver SDK, and complete an independent result reproduction.

## Acceptance criteria

- **OGVCS-005-AC-01:** All five reference corpora complete smoke runs on the reference environment and produce schema-valid bundles.
- **OGVCS-005-AC-02:** Cold/warm state controls are independently inspected and demonstrate expected cache-byte differences.
- **OGVCS-005-AC-03:** A deliberately broken atomic-submit prototype is caught at every injected missing-content/publication defect.
- **OGVCS-005-AC-04:** The authorization/path negative corpus detects seeded enumeration and workspace-escape defects.
- **OGVCS-005-AC-05:** A second operator reproduces one published result within the declared tolerance.
- **OGVCS-005-AC-06:** CI can run a bounded presubmit suite and schedule the complete matrix without modifying product code.
- **OGVCS-005-AC-07:** The driver passes OGVCS-041 negotiation/malformed/retry/bounds traces, and an incompatible harness/product pair fails before enabling a fault hook or mutation.

## Verification plan

- Golden result-schema and calculation tests.
- Harness self-tests using intentionally faulty fake services.
- Repeated-run variance and overhead study.
- Independent reproduction and review of network/cache isolation.

## Telemetry and operations

The harness emits only test metrics and bundles. It must scrub credentials and partner identifiers, cap artifact retention, and label synthetic versus partner-derived runs. A dashboard links regressions to PRD requirement IDs.

## Rollout and rollback

Start with local smoke profiles, add nightly scale runs, then release-gate matrices. Harness schema changes are versioned; release thresholds pin a version. A faulty harness version is withdrawn and affected claims are marked invalid until rerun.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Benchmark becomes too expensive for contributors | Tiered smoke, nightly, weekly, and release profiles |
| Fault hooks change production behavior | Compile/test-mode isolation and review of every hook |
| Results appear precise but are not comparable | Mandatory environment/cache/topology metadata and uncertainty reporting |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
