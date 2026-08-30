# OGVCS-046 implementation evidence

**Evidence date:** 2026-08-30

**Status:** Implementation proof complete; lifecycle ratification pending

**Implementation and package source:**
[`a4e59519ea25bf7d53785268024f2e261f4e0646`](https://github.com/n3r/OpenGameVCS/commit/a4e59519ea25bf7d53785268024f2e261f4e0646)

**Hosted bounded proof:**
[GitHub Actions run 33322266963](https://github.com/n3r/OpenGameVCS/actions/runs/33322266963)

## Proven boundary

This packet binds the additive `atomicWriteStream` API in
`@opengamevcs/path-filesystem` 1.1.0 to its branded complete-set preflight
authority, bounded async source handling, mandatory byte-length and SHA-256
verification, private same-filesystem staging, exact rollback links, atomic
publication, directory durability barriers, versioned `write-stream` journal,
restart-idempotent recovery, package-root export, offline packed consumer, and
the shared three-host native conformance row.

The final source closes every reviewed durability window: capability is
reprobed after the last caller hook; newly created ancestors are synchronized;
rollback links are revalidated; record transitions preserve ambiguous
rename/sync outcomes; exact `.json.next` successors are reconciled after a
pre-rename crash; recovery tolerates an interruption after restoring the prior
target; cancellation cannot override a durable commit; and deadline timers
remain referenced while they are the only authority able to stop a hung source.

The machine record is
[`github-actions-run-33322266963.json`](github-actions-run-33322266963.json).
Raw reports, packed-package records, the independently replayed comparison, and
the Linux confinement trace are retained beside this README. Invalid run
33322087536 is intentionally not retained or cited: its Ubuntu job exposed the
deadline-timer defect fixed by source `a4e5951`.

OGVCS-046 has no exact-scale acceptance row. The million-entry, 100-GiB, and
logical-1-TiB campaigns are not part of this bounded API PRD and were not run.

## Frozen authorities

| Authority | Value |
|---|---:|
| Path contract/package version | `1.0.0` |
| Runtime package version | `1.1.0` |
| License | MIT; root, contract, and runtime texts are byte-identical |
| MIT text SHA-256 | `6f0f22f485ae8614870468a48f2c084eaf800fe02c5a2c4d9a91d34bc7f58eb4` |
| Contract manifest SHA-256 | `2f343e1dac238da527fbd36160419ec6fb53b780ac7e33c01e11acabbdd4782b` |
| Registry-set SHA-256 | `bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42` |
| Unicode case-fold source SHA-256 | `6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb` |
| Cross-platform result SHA-256 | `cb7f48edcf6e5951fddae3f489e33a0fa3e40a4220365104f2941fb2bf2cc68e` |
| Pure cross-platform rows | 63 |
| Bounded native filesystem rows | 16 |
| Total rows per host | 79 |

## Local and hosted gates

| Gate | Result |
|---|---|
| Language-neutral path contract | Generator, independent validator, closed-schema vectors, and mutation checks passed. |
| Runtime/package | Full package suite passed 74/74; the focused staged-publication suite passed 20/20. |
| Fresh-root example | `streaming-publication.mjs` created nested parents, published 1,081 bytes, reproduced SHA-256 `6f0f22…8eb4`, and left no transaction remnant. |
| Offline packed consumer | Imported and executed `atomicWriteStream` from the normalized 1.1.0 archive without network access. |
| Three-host conformance | Linux, macOS, and Windows each passed 79/79; strict comparison accepted one exact result set and identical normalized package bytes. |
| Inherited confinement trace | The OGVCS-004 `atomicWriteFile` trace fixture retained symlink-ancestor, target-race, and ancestor-race syscalls; independent replay reports zero outside-root references. It is a package-boundary regression, not direct `atomicWriteStream` syscall proof. |

The exact normalized packages retained by every host are:

| Package | Bytes | SHA-256 |
|---|---:|---|
| `@opengamevcs/path-contract-v1` 1.0.0 | 185,899 | `432f0f59a498186ff826f73e8c1e8c74e9cf836d22a0f57b463822624c962b8e` |
| `@opengamevcs/path-filesystem` 1.1.0 | 227,376 | `6932e0fc6a17c0b546d291aec10eaebbf57ef596186ec667d3b0994b996cd161` |

The retained runtime archive contains the authoritative deadline timer and no
`timer.unref()` call in `package/src/resource.mjs`.

## Hosted jobs and artifacts

Run [33322266963](https://github.com/n3r/OpenGameVCS/actions/runs/33322266963)
completed successfully at source `a4e59519ea25bf7d53785268024f2e261f4e0646`.

| Job | ID | Result |
|---|---:|---|
| Packed conformance (macOS) | `99286198017` | Passed 79/79 |
| Packed conformance (Windows) | `99286198146` | Passed 79/79 |
| Packed conformance (Ubuntu) | `99286198127` | Passed 79/79 and retained trace |
| Cross-platform comparison | `99286327607` | Passed |

| GitHub artifact | ID | Bytes | Archive digest | Expiry |
|---|---:|---:|---|---|
| `path-filesystem-Linux` | `9735225864` | 90,268 | `sha256:a5367d8dde040323789190ad40442a979f799b84e2977f6b5f02fe0fcf4067ec` | 2026-09-29 |
| `path-filesystem-macOS` | `9735222314` | 85,911 | `sha256:7bcf61d3a9fab0f5612a0069f56152e3950f5fbd20da7bf402154e5035a4d042` | 2026-09-29 |
| `path-filesystem-Windows` | `9735228956` | 85,918 | `sha256:84033b5ce1ea3e8bda88c41b68e9681a74da09c3826ac099a8b5305372230a09` | 2026-09-29 |

GitHub artifact retention is only a convenience. The raw, source-bound machine
outputs below remain version-controlled after those archives expire.

## Durable reports

| Evidence | Bytes | SHA-256 |
|---|---:|---|
| [Linux report](conformance-linux-2026-08-30.json) | 19,372 | `61422b15df3940395b6315b7c073bbf35fbe733f5d332a9d4fb7f69e2d880ed0` |
| [macOS report](conformance-macos-2026-08-30.json) | 19,374 | `66f021ecd89beb5270babbe3254608052505136e67313b964fac6fd9e568eb0c` |
| [Windows report](conformance-windows-2026-08-30.json) | 19,377 | `9f723e49605754c07ae8384947208409112968d5b15874636954ee22224ab943` |
| [Cross-host comparison](conformance-comparison-2026-08-30.json) | 781 | `998980c4703d7fdd8e788a02fbcdead6fa2ef02e2c469dfde1380f17e20b242b` |
| [Linux syscall trace](filesystem-trace-linux-2026-08-30.log) | 78,489 | `2811c43dcb935f70fa8ba974690063e9daeaf249fc8a8765daa3ccdb9397bfe4` |
| [Trace audit](filesystem-trace-audit-2026-08-30.json) | 181 | `522c27eb4ebc8af1bc3c20392f4dfc635fe3cd6586934c784d1a63e5439b33ed` |
| [Trace fixture result](filesystem-trace-fixture-2026-08-30.json) | 165 | `1d06badc9c9d1e1835bc1642efa93bfd419a609e9833f1dcd94d916a9f3b7b76` |
| [Linux packed record](packed-evidence-linux-2026-08-30.json) | 952 | `f35112537442d54f0c3acab38b95e52f719b26f1ac121c268c103df655d9a223` |
| [macOS packed record](packed-evidence-macos-2026-08-30.json) | 952 | `c946a0ba897d5fdabc2fdd75df5483d09e24f2590e9388593fc997b8c4ad65ed` |
| [Windows packed record](packed-evidence-windows-2026-08-30.json) | 954 | `5a1ade13a2f49d8d06c11947db13bb146ee4651276578f92818f3946614c7677` |

The Linux trace contains 588 lines. Its exact audit reports
`outsideReferences: 0`; the fixture records `UNSAFE_TARGET` for the symlink
ancestor and `TARGET_CHANGED` for target and ancestor races.

## Acceptance map

| Criterion | Implementation evidence | Status |
|---|---|---|
| OGVCS-046-AC-01 | Focused and native rows stream multiple chunks, compare exact bytes/identity, and prove at most one copied configured chunk is retained at a time. | Pass |
| OGVCS-046-AC-02 | Source/cancellation/resource/integrity/race/sync/rename/record-transition regressions preserve the prior target or a valid recoverable record; the three-host native row passed. | Pass |
| OGVCS-046-AC-03 | Child crashes cover partial source, rollback link, every durable record, immediate post-rename, and every pre-record-rename temporary; repeated recovery leaves no owned artifact. | Pass |
| OGVCS-046-AC-04 | Every host installed the normalized archives offline and invoked the package-root public API. | Pass |
| OGVCS-046-AC-05 | Linux, macOS, and Windows passed the same 79-row suite; replacement requires hardlink rollback support and fails closed when absent. | Pass |

## Security and reliability boundary

Every call requires a module-branded workspace and owner-bound closed plan for
the exact canonical file entry. The implementation copies one bounded chunk,
verifies declared length and SHA-256 before replacement, revalidates capability
and namespace authority at destructive boundaries, synchronizes each created
ancestor and the private stage, and retains the prior inode until the new target
and journal are durable.

Portable Node pathname calls cannot exclude an actor with the same operating-
system authority continuously swapping trusted ancestors. The supported
boundary requires an owner-private workspace root; detected identity, link,
device, or reparse changes fail closed. Windows exposes no supported directory
`fsync` through Node; only `win32` `EPERM` from syncing an already opened and
identity-verified directory is treated as unavailable. This is not a claim of
hardware power-loss durability on Windows.

## Remaining lifecycle gate

The implementation and package proof is complete, but OGVCS-046 remains in
`prd/todo` until this retained packet and its independent policy reconstruction
pass the same hosted workflow. That evidence-policy run will be recorded before
the PRD, roadmap, done index, and root status are moved to `Done`.
