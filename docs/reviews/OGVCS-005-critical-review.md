# OGVCS-005 critical review

- **Review date:** 2026-08-25
- **Reviewer:** Independent Codex critical-review pass
- **Initial verdict:** Not definition-of-ready
- **Final verdict:** Done; no live P0, P1, or P2

## Scope and method

The review challenged the PRD, ADR-0014, generated authority and independent
validator, all schemas/registries/profiles/thresholds/vectors, the JavaScript
runtime and TypeScript API, fake service, deterministic scheduler, cache and
network controls, fault/security checkers, OGVCS-041 process driver, CLI,
publisher/verifier, offline packer, comparator, release planner, workflow,
runbook, evidence packet, and lifecycle records.

Dynamic review covered 35 conformance scenarios, 25 runtime/type tests, 36
fault rows, seven deliberately broken service modes, both predecessor negative
suites, 110 smoke samples, a 1,320-sample presubmit, ten-package offline
installation, three hosted operating systems, and an independent comparison
replay. Hostile review included Proxy/accessor inputs, post-timeout mutation,
pre-cancellation, non-settling processes, malformed frames, retries, resource
ceilings, package/report tamper, path replacement, credential canaries, forged
summaries, partial publication, and privileged-adapter misuse.

The review did not rerun OGVCS-002's exact one-million-entry tree or logical
1 TiB manifest cases. That work is deliberately monthly/major-release only and
already passed independently for JavaScript and Rust in
[run 32714126083](https://github.com/n3r/OpenGameVCS/actions/runs/32714126083).

## Findings and remediation

| Area | Initial or discovered gap | Settled remediation |
|---|---|---|
| Architecture | Task/fault/driver/result choices lacked an accepted cross-cutting decision. | ADR-0014 freezes authority, compatibility, security, resource, evidence, and rollback boundaries. |
| Authority | The first model did not bind every predecessor or independently check fixture profiles. | Manifest generation and a separate validator recompute every fixture, repository, authorization, path, and protocol pin. |
| Derived claims | A schema-valid bundle could carry forged summaries, thresholds, or status. | Publisher and verifier recompute all summaries, thresholds, schedules, counts, digests, status, and expiry from retained raw authority. |
| Aggregate memory | Matrix and cache lanes could each consume the full limit. | The runner reserves retained matrix memory first and partitions the remainder across active cache lanes. |
| Timeout transaction | An in-process task could time out, return control, then continue mutating shared state in the background. | Cancellation now aborts and drains the cooperative task before the lane is released or the public call returns; regression tests prove no post-return mutation. |
| Adapter trust | The public API did not state whether in-process cancellation was cooperative. | Trusted in-process adapters must honor `AbortSignal`; noncooperative/untrusted adapters use the externally killable process driver. |
| Host input trust | Caller arrays/objects could be trapped or mutated during semantic use; publication could freeze caller-owned data. | Public options and inventories are copied from exact inert own-data records, pre-cancelled calls stop before side effects, and output owns its immutable snapshots. |
| Parser working memory | Encoding/parsing could allocate nested/transient values before admission. | Canonical JSON, streams, bundles, caches, and reports conservatively charge live/transient working capacity before allocation. |
| Operation transaction | Cache, network, fault, and retry failures could partially advance simulated state. | Effects commit only after checks; failures roll back; post-mutation retries reuse one cached semantic result with monotonic evidence. |
| Comparison authority | Callers could weaken PRD thresholds or compare duplicate platforms. | Threshold authority caps tolerance; comparison requires distinct OS/architecture rows and exact contract, package-set, and semantic identities. |
| Driver security | Fault hooks could become reachable before negotiation or through malformed/unbounded output. | The OGVCS-041 test profile requires compatible authenticated test mode and lifecycle start; framing, stream, trace, deadline, retry, stderr, and process-tree failures precede mutation. |
| Publication | Partial/tampered directories could be mistaken for evidence. | Create-only staging, synchronization, one rename, no-follow regular-file checks, exact inventory, and semantic verification make publication transactional. |
| Workflow provenance | Path filters and package proof were initially incomplete. | Commit-pinned workflow triggers cover every predecessor/tool/package input and install ten archives offline on Linux, macOS, and Windows. |
| Scale honesty | Ordinary plans could be read as exact object-model proof. | CLI, schemas, runbook, workflow, and reports state ordinary runs never dispatch exact scale and retain `exactScaleExecuted: false`. |

## Requirement and acceptance matrix

| Requirement | Verdict | Evidence basis |
|---|---|---|
| OGVCS-005-FR-01 | Pass | Authenticated environment rows retain corpus, implementation, configuration, hardware, OS/filesystem, topology, network, cache, concurrency, seed, clock/CPU/memory, disk, and wire bytes. |
| OGVCS-005-FR-02 | Pass | Eleven tasks define start/completion/assertion boundaries; failed or incomplete samples never count as successful latency. |
| OGVCS-005-FR-03 | Pass | Four cache states use fresh controllers, exact prepare/inspect/reset semantics, and one aggregate memory budget. |
| OGVCS-005-FR-04 | Pass | Deterministic profiles cover 20–200 ms RTT, bandwidth, loss, interruption, duplication, and reorder; privileged shaping is isolated. |
| OGVCS-005-FR-05 | Pass | Twelve registered test-only boundaries cover every listed durable operation and execute all three fault actions. |
| OGVCS-005-FR-06 | Pass | Post-fault and deliberately broken-service checks enforce content, authorization, lock, visibility, backup/export, workspace, and reference invariants. |
| OGVCS-005-FR-07 | Pass | Raw samples and summaries retain count, nearest-rank p50/p95/p99, MAD, failure/incomplete/retry counts, bytes, and logical/unique ratios. |
| OGVCS-005-FR-08 | Pass | Versioned thresholds bind requirement IDs, metrics, gates, warnings, and maximum tolerance independently of runtime code. |
| OGVCS-005-FR-09 | Pass | Authenticated bundles contain bounded raw samples, environment, configuration, threshold authority, and recomputable derived values. |
| OGVCS-005-FR-10 | Pass | The process driver uses the registered OGVCS-041 test profile, bounded canonical JSONL, typed errors, negotiation, retry, deadlines, cancellation, and deterministic traces. |
| OGVCS-005-NFR-01 | Pass | Domain-separated PRNG and fixed seeds reproduce the ordered fault schedule and one semantic digest on all hosts. |
| OGVCS-005-NFR-02 | Pass | Overhead is measured and corrected only above 5%, retaining the raw measurement and method. |
| OGVCS-005-NFR-03 | Pass | Local/presubmit/nightly are unprivileged; privileged release execution is an explicit isolated operator action. |
| OGVCS-005-AC-01 | Pass | Five reference corpora produce authenticated smoke bundles across 110 samples. |
| OGVCS-005-AC-02 | Pass | Four cache states are independently prepared/inspected and exhibit their required local/regional byte behavior. |
| OGVCS-005-AC-03 | Pass | The 36-row matrix preserves invariants and all seven deliberately seeded defects are detected. |
| OGVCS-005-AC-04 | Pass | Exact OGVCS-003/004 negative suites detect enumeration and workspace escape with zero misses. |
| OGVCS-005-AC-05 | Pass | Hosted Linux/macOS/Windows runners reproduce one package/semantic authority; retained envelopes independently derive the same comparison. |
| OGVCS-005-AC-06 | Pass | Presubmit executes 1,320 bounded samples; nightly is scheduled; release CI authenticates the 33,000-sample privileged plan without running it on ordinary pushes. |
| OGVCS-005-AC-07 | Pass | Negotiation, malformed input, retries, bounds, lifecycle, traces, cancellation, and incompatible-before-mutation cases pass through the public driver. |

## Security and reliability assessment

No public API invokes Proxy/accessor host code before typed validation. Inputs
are bounded snapshots, package/report reads are no-follow and size-limited,
publication is transactional, public output is credential/partner-canary
scanned, authorization/path negative corpora are pinned, and the process driver
cannot enable faults before compatible authenticated test mode. Resource and
deadline failures are typed and transactional. The final timeout regression
proves shared cache/network authority cannot be reused while cancelled work is
still alive. No live security, reliability, portability, or recovery P0/P1/P2
remains.

## Final evidence

Implementation revision
[`2cd9b76`](https://github.com/n3r/OpenGameVCS/commit/2cd9b767349be1ed7f5bd9ffae87333fc3d9e9ad)
passes the local 3/3 contract, 25/25 runtime/type, 35/35 conformance, 36
fault-row, seven broken-mode, 110-smoke, 1,320-presubmit, and ten-package
offline gates. Hosted
[run 32850158064](https://github.com/n3r/OpenGameVCS/actions/runs/32850158064)
passed Linux, macOS, Windows, release-plan validation, and comparison. The
three platforms agree on manifest `e8e1396a…6612`, package set
`49f67a2f…81ac`, semantic results `abfc5fcd…ce66`, and comparison identity
`eb4ba481…7708`. The durable [completion packet](../evidence/OGVCS-005/README.md)
binds all raw bytes and hosted artifact metadata.

## Final verdict

OGVCS-005 is complete at the public `1.0.0-rc.1` compatibility boundary and
may move to Done. Keeping the packages at `rc.1` matches the completed
OGVCS-041 candidate consumed by the harness; it is not an open implementation
gate. All predecessors are Done. The expensive OGVCS-002 exact campaign is
already complete and must remain monthly/major-release work rather than an
ordinary OGVCS-005 or pull-request gate.
