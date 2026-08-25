# OGVCS-005 — Benchmark, conformance corpus, and fault harness

**Completed:** 2026-08-25
**Public compatibility boundary:** `1.0.0-rc.1`
**License:** MIT

## Delivered baseline

OGVCS-005 delivers `@opengamevcs/benchmark-fault-contract-v1` and
`@opengamevcs/benchmark-fault-harness`: a generated/independently validated
benchmark authority, five reference corpora, eleven task definitions, four
cache states, five network profiles, twelve deterministic fault points, eight
thresholds, an OGVCS-041 process driver, transactional result publication,
offline package verification, comparison tooling, and tiered CI plans.

The frozen contract contains 28 artifacts, 17 schemas, eight registries, and
35 conformance scenarios. Its manifest file SHA-256 is
`e8e1396ad31407d16b269258be2f55909ed7fed6ca8e7d14af52582db15d6612`.
It binds the completed fixture, object-model, authorization, path, and protocol
authorities and rejects drift independently during generation and validation.

## Final-review hardening

Implementation revision
[`2cd9b76`](https://github.com/n3r/OpenGameVCS/commit/2cd9b767349be1ed7f5bd9ffae87333fc3d9e9ad)
closed the final critical-review findings:

- timed-out cooperative in-process work is aborted and fully drained before
  the public matrix call returns or releases a shared cache/network lane;
- trusted in-process adapters must honor `AbortSignal`, while untrusted or
  noncooperative adapters use the killable process driver;
- public option, inventory, schedule, cache, network, publication, and driver
  inputs are snapshotted from exact inert own-data records without running
  Proxy/accessor traps;
- pre-cancelled calls fail before adapter, workspace, or spawn boundaries;
- published results own their frozen matrix snapshots and never freeze
  caller-owned arrays;
- aggregate matrix/cache/parser memory is admitted under one configured bound,
  and cache/network/fault/retry failures preserve transactional state;
- package/report publication is no-follow, exact-inventory, staged, synced,
  atomically renamed, and semantically reverified;
- comparison requires distinct platforms and exact contract, package-set, and
  semantic-result authorities.

## Completion evidence

Local bounded gates pass 3/3 contract tests, 25/25 runtime/type tests, 35/35
conformance rows, all 36 fault rows, seven deliberately broken modes, 110 smoke
samples, 1,320 presubmit samples, and the ten-package offline consumer.

[GitHub Actions run 32850158064](https://github.com/n3r/OpenGameVCS/actions/runs/32850158064)
passed the same source on Linux, macOS, and Windows, validated the release plan,
and produced a strict matched comparison. All hosts agree on package set
`49f67a2f…81ac` and semantic results `abfc5fcd…ce66`; comparison identity is
`eb4ba481…7708`. The version-controlled
[completion packet](../evidence/OGVCS-005/README.md) retains all three packed
envelopes, three raw reports, the comparison, release plan, artifact metadata,
archive hashes, and the independent final review.

## Scale and scheduling policy

OGVCS-005 ordinary workflows never dispatch the one-million-entry tree or
logical 1 TiB manifest workloads. They are owned by OGVCS-002, reserved for a
monthly or major-release campaign, and already completed for JavaScript and
Rust in
[run 32714126083](https://github.com/n3r/OpenGameVCS/actions/runs/32714126083).
Every OGVCS-005 report therefore correctly records
`exactScaleExecuted: false`; no bounded result is relabelled exact-scale.

## Rollout and rollback

The public baseline remains `1.0.0-rc.1`, matching its completed protocol
predecessor. OGVCS-005 is Done; a future compatible ratification may publish
`1.0.0` without changing frozen schema, task, profile, threshold, or fault
identities. If a package or evidence artifact is withdrawn or its authority
changes, dependent claims are invalid until a new source-bound run and durable
comparison replace it.
