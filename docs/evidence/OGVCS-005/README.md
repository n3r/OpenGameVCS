# OGVCS-005 completion evidence

**Evidence date:** 2026-08-25
**Status:** Completed
**Implementation:** [`2cd9b76`](https://github.com/n3r/OpenGameVCS/commit/2cd9b767349be1ed7f5bd9ffae87333fc3d9e9ad)

## Evidence boundary

This packet authenticates the MIT-licensed `1.0.0-rc.1` benchmark/fault
contract and harness, its five reference corpora, four cache states, network
controllers, deterministic fault schedules, process driver, result publisher,
offline ten-package closure, release plan, and Linux/macOS/Windows comparison.
The machine-readable completion record is
[`completion-2026-08-25.json`](completion-2026-08-25.json); hosted run metadata
is retained in
[`github-actions-run-32850158064.json`](github-actions-run-32850158064.json).
The earlier [`candidate-2026-08-21.json`](candidate-2026-08-21.json) and its run
record remain historical evidence and are not rewritten.

The final implementation closed a cancellation-transaction defect: an
in-process task could previously outlive a timeout and mutate shared state
after the public runner returned. The runner now aborts and drains cooperative
work before releasing its cache/network lane or returning. Public host inputs
are snapshotted as inert owned data, pre-cancelled calls fail before adapter,
workspace, and spawn boundaries, and result bundles do not freeze caller-owned
arrays. Trusted in-process adapters must honor `AbortSignal`; untrusted or
noncooperative adapters use the killable external process driver.

## Frozen authority

| Authority | Value |
|---|---:|
| Contract/runtime version | `1.0.0-rc.1` |
| Manifest file SHA-256 | `e8e1396ad31407d16b269258be2f55909ed7fed6ca8e7d14af52582db15d6612` |
| Artifact set | `ba59c8dc9db4c0678fc630357396d9981934ac065b0dd2c8bbbb5c82dccad6d7` |
| Schema set | `f186e1cfe4d8905b0fe36acfa641b3a97eed3f8bcb9d245c7a96055d9cd6f706` |
| Registry set | `bbe8230b1a115b5c0862537d7dde6e97db61c283b552dad61d2020165b75d532` |
| Vector set | `7ab9d07b3f88e94be05f3d48bcd0b8e7bfac79ade49dad3e87f3f1d859a501b7` |
| Threshold set | `13a1cf5e4d20dadced0b04bdc3cc8b3d01a5c3b2a42ca04e163b08e147dac7ff` |
| Fixture profile set | `6b53f4274d8b2374224728d0cebd499e58ab990c4e6409fa5403bf8f38934b36` |
| Repository predecessor | `2d0acb01a01b64c23d883d855d2802d939a8dc99622f2774de07af1c8af8d2b9` |

The authority contains 28 artifacts, 17 schemas, eight registries, 35
conformance scenarios, eleven tasks, twelve fault points, and eight thresholds.
It pins the completed authorization, path, repository, protocol, and fixture
authorities; generation and the independent validator reproduce every pin.

## Local and hosted gates

| Gate | Result |
|---|---|
| Contract generation/validation/tamper | Passed 3/3; all 28 artifacts and 35 scenarios reproduced. |
| Runtime, TypeScript, unit, and integration | Passed 25/25. |
| Harness conformance | Passed 35/35. |
| Fault/security proof | Passed 36 fault rows, seven deliberately broken modes, and both predecessor negative suites. |
| Local smoke | Passed 110 samples and 110 summaries across ten environment lanes. |
| Bounded presubmit | Passed 1,320 samples. |
| Packed public surface | Ten exact archives installed and ran offline with lifecycle scripts disabled. |
| Hosted portability | [Run 32850158064](https://github.com/n3r/OpenGameVCS/actions/runs/32850158064) passed Linux, macOS, Windows, release-plan validation, and strict comparison. |

The hosted run used source revision
[`2cd9b76`](https://github.com/n3r/OpenGameVCS/commit/2cd9b767349be1ed7f5bd9ffae87333fc3d9e9ad).
All three retained envelopes share contract manifest
`e8e1396a…6612`, package set `49f67a2f…81ac`, and semantic results
`abfc5fcd…ce66`. The independently replayed comparison is `matched`, with
comparison identity `eb4ba481…7708`.

## Durable reports

| File | Bytes | SHA-256 |
|---|---:|---|
| [Linux packed evidence](packed-evidence-linux-2026-08-25.json) | 2,731 | `084aea5a40a0d87703b84c984a79cfae2aa2854f994f7a1299aba85a448f5c77` |
| [macOS packed evidence](packed-evidence-macos-2026-08-25.json) | 2,734 | `605f1f7b8f7d93eb5d6ce9da4a433ae0acfff36cf5debf654a5bf3cfbfe37e3f` |
| [Windows packed evidence](packed-evidence-windows-2026-08-25.json) | 2,731 | `a14ad7f40d8eee60ba0a14a84e88312826fbe5f26f8395cef2d5d59ffb2a68fb` |
| [Linux retained report](retained-report-linux-2026-08-25.json) | 1,303 | `c94456d6a7e242f4fcb58bf199374ae99bc74009136995b2d9aec65889824920` |
| [macOS retained report](retained-report-macos-2026-08-25.json) | 1,306 | `11e5c1b3573d7df72901843bfacc54ef96270ea8ff1282212aa2aa3f384fc494` |
| [Windows retained report](retained-report-windows-2026-08-25.json) | 1,303 | `e0fbcc82c83e7304553eb31cd3b5fa204b50605c58d1d14fd3339c12778d2039` |
| [Strict comparison](cross-platform-comparison-2026-08-25.json) | 524 | `a1f30d08a57e7e2f0be990ae2f3369e5b804ec575312c1938a2f61229c755925` |
| [Release plan](release-plan-2026-08-25.json) | 774 | `d451c02bc31d30de2169e7a4c300b3b9265051ed18be59317f112dbc96a9c5ff` |

The completion policy test authenticates every file and independently derives
the cross-platform comparison fields from the three retained envelopes. The
hosted comparator additionally authenticated the actual archives and installed
them offline before accepting the evidence.

## Offline package authority

| Package | Version | Bytes | SHA-256 |
|---|---:|---:|---|
| `@opengamevcs/authorization-contract` | 1.0.0 | 107,041 | `e28a0da4…43c7` |
| `@opengamevcs/authorization-contract-v1` | 1.0.0 | 262,197 | `766078f8…0770` |
| `@opengamevcs/benchmark-fault-contract-v1` | 1.0.0-rc.1 | 109,089 | `bc67dfd3…244c` |
| `@opengamevcs/benchmark-fault-harness` | 1.0.0-rc.1 | 312,895 | `f5567891…46fe` |
| `@opengamevcs/fixture-generator` | 1.0.0 | 713,851 | `1a4846a9…e2f7` |
| `@opengamevcs/path-contract-v1` | 1.0.0 | 185,899 | `432f0f59…2b8e` |
| `@opengamevcs/path-filesystem` | 1.0.0 | 188,459 | `82a9b953…e627` |
| `@opengamevcs/protocol-baseline` | 1.0.0-rc.1 | 358,468 | `07354434…539e4` |
| `@opengamevcs/protocol-contract-v1` | 1.0.0-rc.1 | 3,450,911 | `0be9148e…3407` |
| `@opengamevcs/protocol-types-v1` | 1.0.0-rc.1 | 126,497 | `d95cd47e…a989` |

## Exact-scale boundary

OGVCS-005 did **not** dispatch the one-million-entry/1 TiB workloads. Those are
owned by OGVCS-002 and are intentionally monthly/major-release work, not a PR
gate. OGVCS-002 already completed the exact JavaScript/Rust campaign in
[run 32714126083](https://github.com/n3r/OpenGameVCS/actions/runs/32714126083),
including strict byte/resource comparison. Every OGVCS-005 retained report
honestly records `exactScaleExecuted: false`; bounded smoke/presubmit evidence
is not presented as exact-scale proof.

## Acceptance map

| Criterion | Completion evidence | Status |
|---|---|---|
| OGVCS-005-AC-01 | Five profile-v2 corpora produced authenticated bundles across 110 smoke samples on every retained host. | Pass |
| OGVCS-005-AC-02 | Four cache states are reset and inspected; expected local/regional byte differences and the aggregate memory ceiling are enforced. | Pass |
| OGVCS-005-AC-03 | All 36 injected boundary/action rows preserve invariants and all seven intentionally broken modes are detected. | Pass |
| OGVCS-005-AC-04 | Exact authorization/path negative suites detect enumeration and workspace escape with zero misses. | Pass |
| OGVCS-005-AC-05 | Independent hosted Linux/macOS/Windows jobs reproduce one package/semantic authority and the retained comparison was independently derived. | Pass |
| OGVCS-005-AC-06 | Presubmit executes 1,320 bounded samples; nightly remains scheduled; release CI validates the authenticated 33,000-sample privileged plan without executing it on ordinary pushes. | Pass |
| OGVCS-005-AC-07 | The OGVCS-041 driver passes negotiation, malformed, retry, bounds, lifecycle, trace, cancellation, and fail-before-mutation tests. | Pass |

## Completion and rollback

The final [critical review](../../reviews/OGVCS-005-critical-review.md) records
no live P0, P1, or P2. All predecessors are Done, the public `1.0.0-rc.1`
candidate is usable offline, and OGVCS-005 is complete. A later compatible
release may ratify `1.0.0`; it must preserve the frozen schema, threshold,
profile, task, and fault identities. If any authenticated package, report, or
comparison is withdrawn, its claims are invalid until a replacement run binds
the new source and authority. Exact scale remains a monthly/major-release
object-model campaign and must not be added to ordinary PR workflows.
