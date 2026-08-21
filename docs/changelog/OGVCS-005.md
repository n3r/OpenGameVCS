# OGVCS-005 — Benchmark, conformance corpus, and fault harness

**Validation candidate:** 2026-08-21

**Release:** R0 — Engineering Foundation

**Packages:** `@opengamevcs/benchmark-fault-contract-v1` and
`@opengamevcs/benchmark-fault-harness` 1.0.0-rc.1

## Delivered candidate

OpenGameVCS now has one MIT-licensed reproducible benchmark and fault authority
for the R0 contracts. ADR-0014 freezes eleven normative tasks, all five
OGVCS-001 profile-v2 corpora, four independently inspected cache states,
simulated network conditions from loopback through 200 ms RTT, a separately
isolated privileged network profile, twelve test-only durability boundaries,
measurement/statistics rules, threshold ownership, raw result publication, and
the OGVCS-041-profiled process-driver boundary.

The generated contract contains 28 authenticated artifacts: 17 schemas, eight
registries, one driver profile, eight threshold rows, and 35 conformance cases.
Its manifest pins the complete fixture profile set plus the exact repository,
authorization, path, and protocol authorities. The generator and independent
validator both reject predecessor drift, duplicate task/fault/scenario IDs, and
incomplete task/fault coverage. The final contract-manifest SHA-256 is
`11c3038d6456e690664e705dcab55f2d8f8c8690b66e542a496a8e8a067ea7c3`.

The reference runtime provides:

- deterministic PRNG/fault schedules and a fake repository service exposing
  all registered boundaries;
- five-corpus materialization and all task adapters;
- fresh cache and network controllers per repetition with observable counters;
- wall/CPU/memory/disk/network/logical/unique/retry/correctness measurement;
- nearest-rank p50/p95/p99, median absolute deviation, and measured overhead;
- machine-readable threshold evaluation by stable PRD requirement ID;
- bounded canonical JSONL process negotiation, lifecycle, retry, trace, and
  deadline handling;
- atomic manifest-authenticated result publication, two-pass verification, raw
  calculation replay, redaction, and comparison; and
- a CLI for matrix planning, smoke, fault proof, bundle verification, and
  result comparison, with public TypeScript declarations.

## Correctness, security, and fault proof

All twelve fault points execute crash-before, crash-after, and error outcomes.
The affected task must remain failed/incomplete and post-restart checks require
content reachability, authorization isolation, hard-lock exclusivity,
publication visibility, backup/export verification, workspace confinement, and
reference integrity. Seven deliberately broken service modes prove every
checker detects its target defect.

The exact OGVCS-003 and OGVCS-004 negative suites are integrated rather than
reimplemented. Driver hooks remain disabled until compatible authenticated
test-mode negotiation and lifecycle start. Malformed, oversized, stalled,
incompatible, stderr-producing, or contradictory processes fail before trusted
mutation and are terminated as a process tree.

Public bundles accept only inert bounded data, remove credential-like fields,
hash partner/operator identities, and publish a harness-generated reproduction
template rather than caller shell text. Publisher and verifier recompute
summaries, threshold rows, and overall status from authenticated raw evidence;
a schema-valid forged success claim is rejected.

## Profiles and CI

The fixed profile inventory is:

| Profile | Timed samples | Cache/network coverage | Privilege |
|---|---:|---|---|
| Local smoke | 110 | Two cache states, loopback | None |
| Presubmit | 1,320 | Four cache states, loopback/20 ms | None |
| Nightly | 8,800 | Four cache states, all simulation | None |
| Release | 33,000 | Full simulation plus netem | Isolated adapter |

A commit-pinned GitHub Actions workflow runs contract/runtime and bounded
presubmit gates, packs the complete ten-package dependency closure, installs and
runs it offline on Linux, macOS, and Windows, and compares exact package-set and
semantic-result authorities. The scheduled nightly job runs the full
unprivileged matrix. Release CI emits and validates the complete privileged
plan but does not mutate host networking automatically.

## Critical-review remediation

The independent review found and closed aggregate matrix/cache memory
double-budgeting, uncharged canonical working allocations, trusted derived
bundle claims, unauthenticated redaction counters, caller-weakened comparison
tolerance, arbitrary reproduction-command publication, permissive task
assertions, partial cache/network/fault transitions, fixture/path TOCTOU,
missing independent fixture-pin validation, duplicate-platform comparison, and
incomplete CI path provenance. The settled implementation now:

- reserves aggregate matrix/cache and canonical live/transient working memory
  before allocation, with reduced-ceiling regressions;
- recomputes result summaries, threshold rows, evidence claims, run identity,
  expiry, and status from authenticated raw inputs;
- derives every task assertion from a concrete task/service witness and checks
  status against the error registry's retryability contract;
- keeps cache, network, fault, and post-mutation retry behavior transactional
  and replay-observed;
- snapshots inert inputs, rechecks fixture digest/count, rejects no-follow path
  substitutions, and verifies only regular published files;
- takes comparison tolerance only from authenticated threshold authority and
  requires distinct OS/architecture reports for platform evidence;
- commits both declared CLI entrypoints as executable package files and proves
  the installed command through the offline package run;
- emits a fixed reproduction template and keeps irreversible redaction counts
  as local diagnostics rather than public recomputation claims; and
- independently authenticates all predecessor inputs and triggers CI for every
  direct authority/tool path.

No live local P0 or P1 remains. The complete finding and requirement matrix is
in the [critical review](../reviews/OGVCS-005-critical-review.md).

## Bounded evidence

On macOS 26.6.1 arm64 with Node.js 24.9.0 and npm 11.6.0:

- the contract passed 3/3 tests and reproduced 28 artifacts/35 scenarios;
- the runtime and public TypeScript surface passed 19/19 tests;
- presubmit passed 1,320 samples with semantic digest
  `64df6eec5143ce21ba21d5375399417f859e0d195b902ffe3b21a18133bfa84c`;
- local smoke passed five corpora, 110 samples, 35/35 conformance cases, 36
  fault rows, seven broken modes, and both security suites, with semantic digest
  `8e14fb0797faae7e9202b2d708029dadcac411365974e8ccb657940cbac80a12`;
- ten exact packages installed and executed offline with package-set SHA-256
  `4c609f2ecb8eb8c9ad51e6b37e40611f93957b74309439456c34c1718dc01fe9`;
  and
- the full bounded repository suite passed.

The detailed [evidence packet](../evidence/OGVCS-005/README.md) records exact
authorities and archive hashes.

## Rollout and deferred work

The candidate remains `1.0.0-rc.1` and OGVCS-005 remains in Validation. The
commit-pinned Linux/macOS/Windows workflow and a distinct operator reproduction
must still be retained for AC-05 and hosted portability. OGVCS-002, OGVCS-004,
and OGVCS-041 also remain predecessor validation candidates.

Per maintainer direction, neither the OGVCS-002 one-million-entry tree nor the
logical-1-TiB manifest campaign ran here. Ordinary OGVCS-005 commands and CI do
not dispatch them; they remain final-R0 work. Rollback removes the candidate
from release gates and invalidates affected reports for promotion without
rewriting retained evidence or repository data.
