# ADR-0014: Benchmark and fault-harness contract v1

**Status:** Accepted
**Date:** 2026-08-21
**Owners:** OGVCS-005

## Context

OpenGameVCS needs one reproducible way to test performance, correctness,
durability, authorization, path confinement, cache behavior, and recovery. A
number reported without an authenticated workload, cache state, network model,
fault schedule, environment, threshold authority, and raw samples is not useful
release evidence. Likewise, a fault hook that can be enabled through a normal
production protocol is a security defect rather than a test facility.

OGVCS-001 defines five deterministic synthetic workload families. OGVCS-002,
OGVCS-003, and OGVCS-004 define object, authorization, and path behavior, while
OGVCS-041 defines the public control-profile and process-boundary rules. The R0
harness must consume those authorities without redefining them, remain useful
before R1 services exist, and let later PRDs add thresholds and adapters without
editing the harness engine.

The ordinary contributor and presubmit paths must be bounded and
unprivileged. Expensive exact-scale evidence and host network control require
separate, explicit scheduling. In particular, the OGVCS-002 one-million-entry
tree and logical-1-TiB manifest campaigns are not ordinary OGVCS-005 tests and
remain deferred to the final R0 campaign by maintainer direction.

## Decision

### Versioned authority and implementation

R0 selects two MIT-licensed candidate packages at version `1.0.0-rc.1`:

- `@opengamevcs/benchmark-fault-contract-v1` contains closed JSON Schemas,
  registries, harness profiles, thresholds, driver profile, conformance vectors,
  and a manifest that pins every artifact and predecessor authority; and
- `@opengamevcs/benchmark-fault-harness` contains the reference Node.js 22
  runtime, CLI, process driver, deterministic fake service, fault/security
  checkers, result publisher/verifier, comparator, and retained-report tools.

The contract fixes eleven task IDs: setup, status, sync, submit, lock, merge,
CI, verify, backup, restore, and export. It consumes the five OGVCS-001 profile
v2 corpora by exact profile digest. Each task defines start state, completion,
correctness assertions, byte accounting, and the fault boundaries it exposes.
A failed or incomplete task is retained as evidence and never contributes a
successful latency sample.

The contract manifest pins the current fixture profile set and the exact
OGVCS-002/003/004/041 authorities. Generation and an independent validator both
recompute those pins. A changed predecessor requires regeneration and review;
it is never silently accepted as equivalent.

### Cache, network, and profile matrix

Every repetition receives a fresh service plus fresh cache and network
controllers. The four observable cache states are cold, warm local, warm
regional, and mixed. Cache preparation and post-run inspection record local,
regional, hit, and origin-byte counters; hidden state between repetitions is a
failure.

The deterministic simulator covers loopback, 20 ms studio-near, 80 ms regional,
and 200 ms intercontinental profiles, including bandwidth, loss, interruption,
duplication, and reorder controls. Simulation records the same effects whether
or not wall-time delay is enabled. The privileged `netem` profile is a separate
release-only option. It requires an explicitly isolated synchronous adapter,
never appears in local, presubmit, or nightly profiles, and must be reset after
use.

The fixed tiers are:

| Profile | Repetitions | Cache states | Network states | Timed samples | Privilege |
|---|---:|---:|---:|---:|---|
| `local-smoke` | 1 | 2 | 1 | 110 | None |
| `presubmit` | 3 | 4 | 2 | 1,320 | None |
| `nightly` | 10 | 4 | 4 | 8,800 | None |
| `release` | 30 | 4 | 5 | 33,000 | Isolated adapter required |

Planning the release matrix is safe and unprivileged. Executing privileged or
exact-scale work always requires a distinct operator action and environment.

### Deterministic faults and invariant checking

Twelve named test-only fault points cover durable writes, object finalization,
policy decisions, branch compare-and-swap, lock mutation, metadata commit,
event publication, index cursor advancement, backup generation, export
finalization, and GC mark/sweep. A domain-separated deterministic PRNG maps a
seed to an ordered schedule. Each boundary supports crash-before, crash-after,
and error outcomes.

The harness requires the scheduled injection to be observed, the affected task
not to claim success, and post-restart invariants to hold. The reference checker
asserts content reachability, authorization isolation, hard-lock exclusivity,
publication visibility, backup/export verification, workspace confinement, and
reference integrity. Seven deliberately broken fake-service modes prove those
checks are not vacuous.

Production fault hooks are forbidden. An implementation exposes them only in
an authenticated isolated test mode or a test build. Normal service protocols
do not gain a hidden fault-control surface.

### Process-driver boundary

`ogvcs.benchmark-fault-driver.test@1` layers a test-only profile over OGVCS-041
`ogvcs.control.https-json@1`. It uses bounded canonical JSON Lines, closed
messages, explicit negotiation, typed errors, deterministic traces, idempotent
retries, aggregate stream limits, deadlines, and process-tree termination.
Fault hooks remain disabled until negotiation and lifecycle start succeed.
Malformed or incompatible peers fail before any task or mutation.

The public adapter descriptor is inert data. The harness never invokes caller
accessors or arbitrary configuration callbacks during validation. A child
process may receive only explicit argv, environment, and working-directory
data within the documented trust boundary.

### Measurements and thresholds

Every sample records corpus and implementation authorities, environment,
filesystem/topology/network/cache configuration, concurrency, seed, wall and
CPU time, peak memory, disk/network bytes, logical/unique bytes, retries,
completion state, assertions, and fault schedule digest. Successful samples
produce nearest-rank p50, p95, and p99 plus median absolute deviation. Counts,
bytes, retries, failure/incomplete states, and correctness results remain
available independently of percentiles.

Measurement overhead is measured. If it exceeds five percent for a throughput
task, the harness records and applies the declared correction; otherwise it
retains the uncorrected measurement. It never hides the overhead value.

Threshold files are machine-readable, versioned, and keyed by stable PRD
requirement IDs. The harness evaluates the selected file without embedding
product-specific SLOs. A later PRD may publish a new threshold authority but
cannot change result calculation or weaken correctness gates through adapter
code.

### Result publication and comparison

A successful public bundle is staged, synchronized, and committed by one
directory rename. Its manifest authenticates every exact byte. The bundle
retains the selected threshold file, bounded raw environments, samples,
summaries, fault results, negative-suite results, and optional conformance
report. Publisher and verifier independently recompute summaries, threshold
rows, and final status from raw inputs; schema-valid derived success claims are
not trusted.

Public metadata is inert bounded JSON. Credential-like fields are removed,
partner/studio/customer/operator identifiers are hashed, retention has a
bounded expiry, and arbitrary caller reproduction commands are not published.
The published command is a harness-generated template containing the recorded
profile and an explicit seed placeholder.

Comparison first verifies both bundles. Contract, workload, threshold,
reference environment, inventory, correctness, retry, byte, and percentile
semantics must match within the tolerance capped by the authenticated threshold
authority. An operator may request a stricter comparison but cannot loosen that
cap. Capture time and operator identity may differ; inputs that could change
the result may not.

### Resource, CI, and scale boundaries

All public parsers, matrices, caches, traces, samples, schedules, output files,
and process streams have configured and hard bounds. Retained matrix state and
active cache lanes share one aggregate memory ceiling. Resource or deadline
failure is typed, leaves no trusted partial publication, and does not turn an
incomplete operation into success.

An in-process matrix task is a trusted cooperative adapter. It receives the
task deadline's `AbortSignal` and must settle after cancellation; the harness
drains it before releasing retained resources or returning, preventing a timed
out task from mutating after publication. Implementations that may ignore the
signal, block, or run untrusted code use the external-driver process boundary,
where deadline enforcement includes process-tree termination. The API does not
claim that arbitrary in-process JavaScript can be forcibly stopped.

Presubmit runs the bounded unprivileged profile. A commit-pinned GitHub Actions
workflow installs exact dependencies, executes the contract/runtime, packages
the ten-package dependency closure, installs and runs it offline on Linux,
macOS, and Windows, and compares semantic and package-set digests. Nightly runs
the complete simulated unprivileged matrix. Release CI only proves the
privileged matrix is schedulable; an authorized isolated operator must execute
it.

The OGVCS-002 exact one-million-entry tree and logical-1-TiB manifest cases are
inventory-only in this phase. OGVCS-005 does not dispatch or claim them. They
remain final-R0 evidence.

## Alternatives rejected

- **Ad hoc benchmark scripts and prose-only environments:** allow cache,
  workload, hardware, and success definitions to drift between reports.
- **A single latency number:** hides failures, retries, dispersion, bytes,
  correctness, and insufficient sample counts.
- **Trusting bundle summary/status fields:** lets a producer publish forged
  derived success even when raw samples fail a gate.
- **Production debug endpoints for fault injection:** expands the attack
  surface and risks enabling destructive behavior outside isolation.
- **Privileged network shaping in ordinary CI:** is not portable, cannot run in
  a normal contributor environment, and weakens least privilege.
- **One shared mutable cache between repetitions:** makes results
  order-dependent and prevents independent cold/warm inspection.
- **Treating simulated delay as real-host performance evidence:** simulation is
  deterministic correctness/accounting evidence; reference performance still
  requires the declared host and topology.
- **Automatically running the OGVCS-002 exact-scale jobs:** conflicts with the
  explicit maintainer deferral and turns routine validation into an
  unexpectedly destructive/expensive workload.

## Compatibility and data consequences

Version 1 freezes task, cache, network, fault, error, driver-operation,
measurement, bundle, and threshold semantics. An additive candidate release may
add a registered optional field or task only with a new manifest and executable
compatibility evidence. Reassigning an identifier, changing a metric meaning,
removing raw evidence, weakening a correctness gate, or making a test hook
production-reachable requires a new major contract.

Result bundles are evidence artifacts rather than repository state. Consumers
must verify the manifest and recompute derived claims before use. Candidate
bundles may be withdrawn without migrating repositories, but published reports
remain labeled with their exact contract and package digests.

## Threat and failure analysis

- A malicious driver may emit oversized, malformed, contradictory, delayed, or
  endless output. Framing, schema, aggregate-byte, trace, deadline, stderr, and
  process-lifecycle checks fail closed.
- A malicious result producer may forge summaries, thresholds, or status.
  Verification recomputes them from authenticated raw evidence.
- A caller may provide accessors, proxies, credentials, partner names, absolute
  paths, or shell text. Public-data normalization accepts inert data only,
  redacts sensitive keys, hashes partner identities, and emits a fixed
  reproduction template.
- A fault may occur after durable mutation but before acknowledgement. The
  task remains incomplete and the invariant checker inspects recovered state;
  timing never converts it into success.
- Cache or network adapters may leak state after cancellation. Each repetition
  owns fresh controllers and reset/rollback is required at the boundary.
- A host may lack privileged capabilities. Normal profiles continue to work;
  the privileged profile fails with `HARNESS_PRIVILEGE_REQUIRED` before use.
- Publication may fail during staging, synchronization, or rename. No bundle is
  trusted until the authenticated manifest and final directory commit exist.

## Verification and evidence

The contract includes 35 executable conformance cases binding all FR/NFR/AC
requirements. Runtime unit/integration tests cover deterministic schedules,
cache/network controls, resource accounting, driver negotiation/retry/bounds,
fault recovery, security/path negatives, statistics, threshold reproduction,
tamper rejection, and atomic publication.

The bounded local candidate executes all five corpora, 110 smoke samples, 36
fault rows, seven broken-service modes, and 35 conformance rows. Presubmit runs
1,320 samples. Ten exact MIT package archives install and execute with npm in
offline mode. The hosted workflow owns the three-OS package/semantic comparison
and remains required before promotion beyond Validation.

## Rollback and migration

The contract and runtime remain `1.0.0-rc.1`. Rollback removes the harness from
release gates and marks reports from the withdrawn manifest invalid for
promotion; it does not reinterpret or delete retained evidence. Fault adapters
remain disabled and are removed from test deployments. Threshold owners pin
the prior accepted contract until a corrected candidate is published.

No repository migration is required. A future major harness contract reads old
bundles only through an explicit versioned verifier and never silently upgrades
their measurements or gate decisions.
