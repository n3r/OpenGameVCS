# `@opengamevcs/benchmark-fault-harness`

This MIT-licensed Node.js 22 package is the OGVCS-005 reference benchmark,
conformance, cache/network-control, process-driver, publication, and fault
harness. It consumes all five OGVCS-001 fixture profiles and the authenticated
`@opengamevcs/benchmark-fault-contract-v1` authority.

The harness performs no telemetry or service discovery. Ordinary profiles are
unprivileged. The only privileged network profile requires an explicit
isolated adapter and is never selected by `local-smoke`, `presubmit`, or
`nightly`.

## Source usage

```sh
npm test --workspace @opengamevcs/benchmark-fault-harness
node foundation/benchmark-fault-harness/bin/ogvcs-benchmark.mjs plan \
  --contract spec/benchmark-fault/v1
node foundation/benchmark-fault-harness/bin/ogvcs-benchmark.mjs smoke \
  --contract spec/benchmark-fault/v1 \
  --output artifacts/benchmark-fault-result
```

`smoke` creates five small, synthetic, index-only fixtures and executes every
task. It does not run the separately controlled million-entry or logical-1-TiB
campaigns.

## Packed offline usage

The package has no install scripts. Pack this runtime together with its exact
local contract/runtime dependencies, install all archives in one offline npm
command, then run:

```sh
./node_modules/.bin/ogvcs-benchmark plan
./node_modules/.bin/ogvcs-benchmark smoke --output benchmark-result
./node_modules/.bin/ogvcs-benchmark verify --bundle benchmark-result
```

The repository-owned `tools/run-packed-benchmark-fault-conformance.mjs`
performs that complete offline pack/install/run proof.

## Profiles and controls

| Profile | Repetitions | Cache states | Network states | Privilege |
|---|---:|---|---|---|
| `local-smoke` | 1 | cold, warm local | loopback | none |
| `presubmit` | 3 | all four | loopback, 20 ms | none |
| `nightly` | 10 | all four | all simulated | none |
| `release` | 30 | all four | simulated plus netem | isolated adapter required |

Every repetition gets a new repository service, cache controller, and network
controller. Cache state is independently inspected. Simulated profiles model
RTT, bandwidth, loss, interruption, duplication, and reorder and can either
wait in real time or skip delay while retaining identical byte/effect
accounting. A privileged adapter must expose synchronous `apply(profile)` and
`reset()` methods and `isolated: true`; it is trusted host policy and must run
inside an isolated CI job.

## Process driver

`startExternalDriver` layers the test-only
`ogvcs.benchmark-fault-driver.test@1` profile over OGVCS-041
`ogvcs.control.https-json@1`. The adapter descriptor is inert data: an argv
array or `{command,args,env,cwd}` record, with an absolute `cwd` when present.
The runtime enforces canonical JSONL, negotiated per-message and aggregate
stream bounds, an overall deadline, closed result/error consistency,
idempotent retry, ordered trace limits, no stderr on success, and process-tree
termination on a protocol failure. Fault hooks start disabled and can be armed
only after successful authenticated test-mode negotiation and lifecycle start.

`runBenchmarkMatrix` also accepts an in-process `serviceFactory`, but that is a
trusted, cooperative adapter boundary. Every `executeTask` call receives the
task's `AbortSignal`; after cancellation or deadline expiry the task must
observe that signal and settle before the harness can release its cache/network
lane or return. The harness deliberately drains the task promise so no timed-out
operation can keep mutating repository state after a result has been reported.
An adapter that can ignore cancellation, block indefinitely, or execute
untrusted implementation code must instead use `startExternalDriver`, whose
process tree is terminated at the deadline boundary.

## Publication and comparison

`writeResultBundle` stages and synchronizes a publication before one directory
rename. A successful bundle contains:

- `result.json`, with authority digests, thresholds, retention, redacted public metadata,
  overhead, and reproduction settings;
- `environments.jsonl`, `samples.jsonl`, and `summaries.jsonl` as bounded raw
  calculation inputs;
- `evidence.json`, with all 36 fault-boundary outcomes, intentionally broken
  service detections, and authorization/path negative-suite evidence;
- optional `conformance.json`; and
- `manifest.json`, authenticating every artifact by exact length and SHA-256.

Once the final rename succeeds, an unsupported staging-directory sync or a
later parent-directory sync problem is returned as a stable
`postCommitWarnings` entry and never changes committed success into an error.

Verification is two-pass, rejects links/unexpected files/tamper, enforces one
aggregate working-memory ceiling, and checks semantic identities and envelope
digests. Public metadata accepts only inert JSON data, removes credential-like
fields, hashes partner/studio/customer/operator identifiers, and records a
bounded expiry.

`compareResultBundles` requires each result together with its authenticated raw
summaries and environments. It checks contract, workload, threshold, reference
environment, inventory, fault/security/conformance authorities,
success/failure/retry/byte semantics, and p50/p95/p99/dispersion tolerance. The
selected threshold file owns the maximum tolerance; callers may request a
stricter comparison but cannot loosen the authenticated limit.
Operator identity and capture time may differ; implementation,
corpus, hardware, platform, topology, network, cache, and configuration may
not.

## Fault and measurement semantics

The fake service exposes all 12 registered durable boundaries. The fault
matrix injects `crash-before`, `crash-after`, and `error` at each boundary,
requires the injection to be observed, requires an incomplete task rather than
success, and validates content, authorization, lock, visibility, backup,
export, workspace, and reference invariants afterward. Seven intentionally
broken service modes prove the checkers are not vacuous.

Only successful samples enter latency percentiles. Failed and incomplete
samples remain raw evidence. Summaries use nearest-rank p50/p95/p99 and median
absolute deviation, and retain failure, retry, disk/network, logical/unique,
and correctness totals. Measurement overhead is measured; above 5% it is
explicitly corrected and recorded, otherwise the uncorrected measured value is
retained.

See the normative contract docs, the OGVCS-005 runbook, ADR-0014, and the
generated TypeScript declarations for the full interface.
