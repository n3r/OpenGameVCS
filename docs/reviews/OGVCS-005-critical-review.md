# OGVCS-005 critical review

- **Review date:** 2026-08-21
- **Reviewer:** Independent Codex critical-review pass
- **Initial verdict:** Not definition-of-ready
- **Current verdict:** Local and hosted acceptance-ready; final R0 dependency gates pending

## Scope and method

The review challenged the PRD before and during implementation, then examined
ADR-0014, the generated contract model and validator, all schemas/registries/
profiles/thresholds/vectors, the runtime and TypeScript API, fake service,
fault/security checkers, process driver, CLI, result publisher/verifier,
comparison logic, resource accounting, ten-package offline runner, workflow,
runbook, and roadmap evidence.

Dynamic review covered all 35 conformance scenarios, 19 runtime tests, 36
fault rows, seven deliberately broken service modes, both predecessor negative
suites, a 1,320-sample presubmit, source and installed-package smoke reports,
and the full bounded repository suite. Hostile cases included malformed driver
frames, incompatibility before mutation, retries, non-settling processes,
credential/partner canaries, accessors and proxies, bundle tamper, forged
summaries and threshold rows, partial publication, resource ceilings,
cancellation, cache reuse, privileged-adapter misuse, and combined retained
matrix/cache memory.

The review did not execute the OGVCS-002 one-million-entry tree or logical-1-TiB
manifest cases. Their omission is deliberate, recorded in every report, and
reserved for the final R0 campaign.

## Findings and remediation

| Area | Initial gap | Settled remediation |
|---|---|---|
| Architecture | The task/fault/driver/result choices were not an accepted cross-cutting decision. | ADR-0014 freezes authority, compatibility, security, resource, evidence, and rollback boundaries; architecture section 18 and the decision table now point to it. |
| Authority | The first model did not bind every predecessor and had no independently checked fixture profile set. | The manifest pins OGVCS-001 profile values and exact OGVCS-002/003/004/041 manifests; both generator and independent validator recompute them. |
| Derived claims | A schema-valid bundle could carry forged summaries, threshold evaluations, or overall status. | Publisher and verifier reproduce summaries and thresholds from raw JSONL plus the embedded threshold authority and compare every derived field exactly. |
| Evidence claims | Raw fault/checker/security/conformance rows could disagree with their published counters, schedules, or authority while the writer still committed the bundle. | Authorization rows are now retained; writer and verifier recompute every evidence aggregate, schedule digest, conformance digest/count, matrix inventory, run ID, expiry, and contract/workload binding before success. |
| Task evidence | Registered task assertions could default to success without a concrete state witness, and status/error retryability could disagree. | Every registered assertion now resolves from task output, service state, mutation count, or an explicit global invariant; unknown assertions fail closed, and the runner enforces the error registry's status/retryability mapping. |
| Comparison authority | A producer or comparator caller could declare a tolerance as large as 100%, weakening PRD-owned regression criteria. | The threshold file now authenticates the maximum comparison tolerance; result bundles must reproduce it exactly and operators may request only a stricter comparison. |
| Aggregate memory | The matrix and each cache lane could each consume the full configured ceiling. | The runner reserves the complete retained matrix, validates the cache authority, and partitions only the remaining capacity across active cache lanes; a reduced 800,000-byte regression proves the combined bound. |
| Parser working memory | Canonical encoding/parsing could allocate output or nested retained values before aggregate admission. | Canonical JSON, parsed values, driver streams, bundle files, caches, and retained reports now charge conservative live/transient working capacity before allocation and return typed resource failures. |
| Input trust and TOCTOU | Caller arrays/objects, fixture sources, and publication paths could be mutated, trapped, or swapped during use. | Public inputs are snapshotted as exact inert data, fixture input digest/count is rechecked, corpus destinations are no-follow bounded paths, and publication verification admits only regular files under create-only staging. |
| Operation transactions | Cache, network, fault, and post-mutation retry failures could leave counters or simulated service state partially advanced. | Network effects commit only after all checks, cache failures roll back, fault schedules are replay-observed in order, and post-mutation retries return the one cached semantic result with monotonic retry evidence. |
| Reproduction data | A caller-supplied command could enter a public result and leak shell text or secrets. | Publication emits a fixed harness-owned command template containing the recorded profile and a seed placeholder; a token canary proves arbitrary input is absent. |
| Fault proof | A checker could appear correct without ever detecting a defect. | Seven independent broken-service modes seed missing content, publication, authorization, lock, backup, export, workspace, and reference defects; every expected detector must fire. |
| Cache/network honesty | Warm/cold labels and simulated network outcomes could be asserted without observing state. | Fresh controllers prepare and inspect local/regional bytes per repetition; network effects, wire bytes, retries, and rollback are deterministic and recorded. |
| Driver security | Fault hooks could become reachable before negotiation or through malformed/unbounded process output. | The OGVCS-041-profiled test driver requires compatible authenticated test mode and lifecycle start; framing, message/stream/trace limits, deadline, stderr, retry, and process-tree checks fail before mutation. |
| Publication | Partial or tampered directories could be mistaken for evidence. | Publication is staged and synchronized before one rename; verification rejects links/extras/tamper and authenticates exact lengths/digests before semantic use. |
| Privacy | Metadata could retain credentials or stable partner/operator identities, while unverifiable redaction counters could be presented as public claims. | Exact inert-data normalization removes credential-like fields, hashes declared identities, bounds retention, scans derived/public output, and keeps removal/hash counts only as immediate local diagnostics. |
| CI provenance | Initial path filters omitted predecessor roots and the tarball normalizer, so relevant changes could bypass the harness workflow. | Pull/push filters now include fixture, object manifest, authorization, path, protocol, normalizer, contract, runtime, tools, docs, ADR, and PRD paths; all actions are commit-pinned. |
| Package executability | The two declared package CLI sources initially inherited non-executable file modes. | Both `bin` entrypoints are committed as `0755`; package dry-run reports mode 493 and the offline installed-package proof executes the CLI. |
| Cross-platform evidence | A comparison could accept repeated evidence from one platform and mistake it for portability. | Packed reports authenticate ten exact archives and retained semantics; the comparator requires distinct OS/architecture rows and exact contract, profile, package-set, and semantic digests. |
| Scale honesty | Ordinary plans could be read as proof of the two expensive OGVCS-002 criteria. | CLI/help/runbook/workflow/report schemas state that ordinary commands never dispatch exact scale; retained reports require `exactScaleExecuted: false`. |

## Requirements verdict

| Requirement | Verdict | Basis |
|---|---|---|
| FR-01 | Pass | Authenticated environment rows capture corpus, implementation, configuration, hardware, OS/filesystem, topology, network, cache, concurrency, seed, time/CPU/memory, disk, and network bytes. |
| FR-02 | Pass | Eleven normative tasks have start/completion/assertion definitions; failed and incomplete samples remain raw and never count as successful latency. |
| FR-03 | Pass | Four cache states use fresh controllers, exact preparation/inspection, counter reset, and aggregate retained-memory accounting. |
| FR-04 | Pass | Four deterministic simulations span 0–200 ms plus bandwidth/loss/interruption/duplicate/reorder; privileged netem is isolated release-only. |
| FR-05 | Pass | Twelve named test-only boundaries cover every PRD-listed durability class and execute three failure actions each. |
| FR-06 | Pass | Post-fault and broken-service checkers enforce content, authorization, lock, visibility, backup/export, workspace, and reference invariants. |
| FR-07 | Pass | Raw samples and summaries retain sample counts, nearest-rank p50/p95/p99, MAD, failures, incompletes, retries, bytes, and logical/unique ratios. |
| FR-08 | Pass | Versioned threshold files bind stable requirement IDs, metrics, and the maximum comparison tolerance without changing runtime code; publisher, verifier, and comparator enforce that authority. |
| FR-09 | Pass | Manifest-authenticated bundles include raw bounded inputs, threshold authority, environment, reproduction template, and recomputable derived values. |
| FR-10 | Pass | The process driver uses the registered test-only OGVCS-041 profile, canonical JSONL, typed errors, negotiation, retries, deadlines, and bounded traces. |
| NFR-01 | Pass | Domain-separated PRNG and fixed seed reproduce the exact ordered schedule; retained source and packed results have one semantic digest. |
| NFR-02 | Pass | Overhead is measured and corrected only above 5%, with raw value and method retained. |
| NFR-03 | Pass | Local/presubmit/nightly are unprivileged; privileged release execution is a documented isolated operator action. |

## Acceptance verdict

| Criterion | Verdict | Basis |
|---|---|---|
| AC-01 | Pass | All five corpora emitted valid authenticated smoke bundles across 110 samples. |
| AC-02 | Pass | Four independently observable cache states produce their required byte/hit state and reset between repetitions. |
| AC-03 | Pass | The 36-row fault matrix preserves invariants and all seven deliberately broken modes are detected. |
| AC-04 | Pass | Exact OGVCS-003 authorization and OGVCS-004 path negatives detect enumeration and workspace escape with zero misses. |
| AC-05 | Pass | Hosted Linux/macOS/Windows runners reproduced the exact package/semantic authorities, and a local redownload independently reproduced their comparison. |
| AC-06 | Pass | Presubmit executes 1,320 samples; nightly executes the full unprivileged matrix; release CI validates a 33,000-sample plan without privileged execution. |
| AC-07 | Pass | Negotiation, malformed, retry, lifecycle, bounds, trace, and incompatibility-before-mutation driver tests pass. |

## Current evidence

The frozen local manifest is
`11c3038d6456e690664e705dcab55f2d8f8c8690b66e542a496a8e8a067ea7c3`.
Contract tests passed 3/3, runtime tests 19/19, report tools 3/3, the
presubmit executed 1,320 samples, and the local-smoke report passed 35/35
conformance rows, 36/36 fault rows, seven/seven checker modes, and both security
suites. Its semantic-results SHA-256 is
`8e14fb0797faae7e9202b2d708029dadcac411365974e8ccb657940cbac80a12`.

Ten exact package archives installed and ran with npm offline. Their package-set
SHA-256 is
`4c609f2ecb8eb8c9ad51e6b37e40611f93957b74309439456c34c1718dc01fe9`.
The full ordinary repository suite passed. Its fixture scale test remained
explicitly skipped behind `OGVCS_RUN_SCALE`, and the Windows-only junction test
was skipped on macOS.

Hosted run
[32441625231](https://github.com/n3r/OpenGameVCS/actions/runs/32441625231)
passed the packed proof on Linux, macOS, and Windows at source
`327d843f6fcc2fc45616ca9e17feb1e79c7ae7ed`. The redownloaded three-report
comparison is `matched`, with SHA-256
`dcf7a133dfbc539cce2f92ab0671016d05d6fdd89f15aa9c2f5f0b9b3a8dbeb3`.

## Residual boundary

No live local P0 or P1 implementation, specification, runner, package, or
workflow defect remains in the reviewed candidate. The remaining gates are
evidence/lifecycle dependencies, not hidden passes:

- OGVCS-002, OGVCS-004, and OGVCS-041 must complete their predecessor gates;
  and
- the final R0 campaign must run the two maintainer-deferred OGVCS-002 exact
  scale cases and settle durable publication.

## Recommendation

Keep the contract and runtime at `1.0.0-rc.1` and keep OGVCS-005 in Validation.
The hosted run/job/archive/comparison record is retained. Do not ratify, move
the PRD to `prd/done`, or claim R0 completion until predecessor closure, the
final-R0 exact-scale campaign, and durable publication are complete.
