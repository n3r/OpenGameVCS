# OGVCS-004 completion evidence

**Evidence date:** 2026-08-25

**Status:** Completed

**Implementation and package source:**
[`4f8a5a0f836ef51b4ac56cab9d795d7f5515926d`](https://github.com/n3r/OpenGameVCS/commit/4f8a5a0f836ef51b4ac56cab9d795d7f5515926d)

**Durable evidence-policy revision:**
[`94f68c80f9166ef3deb7aa65b9cb268453af714f`](https://github.com/n3r/OpenGameVCS/commit/94f68c80f9166ef3deb7aa65b9cb268453af714f)

**Hosted implementation proof:**
[GitHub Actions run 32831999325](https://github.com/n3r/OpenGameVCS/actions/runs/32831999325)

**Hosted evidence-integrity proof:**
[GitHub Actions run 32833243994](https://github.com/n3r/OpenGameVCS/actions/runs/32833243994)

## Completed evidence boundary

This packet binds path/workspace contract v1, its pinned Unicode case-fold
authority, four platform profiles, closed schemas and stable errors, the public
JavaScript library and CLI, OGVCS-002 object-model integration, complete-set
materialization authority, bounded watcher/recovery behavior, offline package
installation, native filesystem proofs, and strict three-host comparison.

The implementation run's machine record is
[`github-actions-run-32831999325.json`](github-actions-run-32831999325.json).
The evidence-policy run's machine record is
[`github-actions-run-32833243994.json`](github-actions-run-32833243994.json).
The latter reruns all three operating systems and independently checks every
retained report, package identity, comparison, and syscall-trace claim. The
[critical review](../../reviews/OGVCS-004-critical-review.md) found no live P0,
P1, or P2 after those proofs passed.

OGVCS-004 has no exact-scale acceptance row. The million-entry tree and logical
1-TiB campaign belongs to OGVCS-002 and is already completed there; duplicating
it in this bounded path/materialization PRD would add cost without proving a
new path contract property.

## Frozen authorities

| Authority | Value |
|---|---:|
| Contract/package version | `1.0.0` |
| License | MIT; root, contract, and runtime texts are byte-identical |
| MIT text SHA-256 | `6f0f22f485ae8614870468a48f2c084eaf800fe02c5a2c4d9a91d34bc7f58eb4` |
| Contract manifest SHA-256 | `2f343e1dac238da527fbd36160419ec6fb53b780ac7e33c01e11acabbdd4782b` |
| Registry-set SHA-256 | `bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42` |
| Unicode case-fold source SHA-256 | `6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb` |
| Cross-platform result SHA-256 | `a21941590359b85c6a45cdab432bfec636c66b13d524746c0dadbaf97da41616` |
| Pure cross-platform rows | 63 |
| Bounded native filesystem rows | 15 |
| Total rows per host | 78 |

The independent validator does not import the reference evaluator. It hashes
every manifest artifact, checks the profile registry and Unicode source,
validates closed schemas and all 63 pure outcomes, and mutation-tests authority
drift. The runtime adds fifteen bounded native proofs on every host.

## Local and hosted gates

| Gate | Result |
|---|---|
| Language-neutral contract | Passed all generator, independent-validator, schema, vector, and mutation checks for 63 decisions. |
| JavaScript runtime | Passed 54/54 path, package, OGVCS-002 integration, workspace, watcher, recovery, telemetry, property, and report tests. |
| Offline packed consumer | Imported every public API, ran all seven CLI commands, and passed the complete 78-row report using only retained archives. |
| Three-host conformance | Linux, macOS, and Windows each passed 78/78; strict comparison accepted one exact pure result set and identical package bytes. |
| Confinement trace | Linux retained symlink-ancestor, target-race, and ancestor-race syscalls; independent replay reports zero outside-root references. |
| Dependent authority | Path → protocol → benchmark predecessor generation and checks passed with exact pins. |
| Evidence governance | Checked-in byte lengths/hashes, report decisions, packed identities, comparison, and trace replay are enforced by `path-filesystem-workflow-policy.test.mjs`. |

The exact normalized packages retained by every host are:

| Package | Bytes | SHA-256 |
|---|---:|---|
| `@opengamevcs/path-contract-v1` 1.0.0 | 185,899 | `432f0f59a498186ff826f73e8c1e8c74e9cf836d22a0f57b463822624c962b8e` |
| `@opengamevcs/path-filesystem` 1.0.0 | 188,459 | `82a9b9533df0e9b3e9dfecac1e8dc12e146dc1ddb6ec972dfcde86bea21de627` |

## Hosted implementation jobs and artifacts

Run [32831999325](https://github.com/n3r/OpenGameVCS/actions/runs/32831999325)
completed at source `4f8a5a0`.

| Job | ID | Result |
|---|---:|---|
| Packed conformance (macOS) | `97752560093` | Passed 78/78 |
| Packed conformance (Windows) | `97752560367` | Passed 78/78 |
| Packed conformance (Ubuntu) | `97752560391` | Passed 78/78 and retained trace |
| Cross-platform comparison | `97753040245` | Passed |

| GitHub artifact | ID | Archive digest | Expiry |
|---|---:|---|---|
| `path-filesystem-Linux` | `9557120878` | `sha256:e8a27ef9f64ffd9f90fa9a393faf1e6579e366bc376eb02b536c323afa17f559` | 2026-09-24 |
| `path-filesystem-macOS` | `9557116715` | `sha256:c537ec6cc042d7b35754fd2b08a7ef3be73b60744b1ca9c1018d9f36d88cd5d8` | 2026-09-24 |
| `path-filesystem-Windows` | `9557161255` | `sha256:438fdbab619af684bbbea116f4964434c12d40b4f6c38d920bb589160b8f43d8` | 2026-09-24 |

Run [32833243994](https://github.com/n3r/OpenGameVCS/actions/runs/32833243994)
then passed the same four jobs at evidence revision `94f68c8`, including the new
durable evidence-integrity policy. Its machine record retains all job and
artifact metadata.

## Durable reports

| Evidence | Bytes | SHA-256 |
|---|---:|---|
| [Linux report](conformance-linux-2026-08-25.json) | 19,111 | `2a4c15657dba0865365d2d361be54657ccca8b9d3ae05142bd921e7d63517ca7` |
| [macOS report](conformance-macos-2026-08-25.json) | 19,113 | `ec7e381f346bf5753b34c117278f611a5c0245bc72778b42a6714a5107d413b0` |
| [Windows report](conformance-windows-2026-08-25.json) | 19,116 | `3cdfabdf3256ab8ad09a50e067389ae8ef6a465d4359e519a0ac082729566098` |
| [Cross-host comparison](conformance-comparison-2026-08-25.json) | 781 | `d756461173ba68883d48c22f45183b5d6de64f2fda106cd9c509326bc54800f1` |
| [Linux syscall trace](filesystem-trace-linux-2026-08-25.log) | 77,935 | `42679b72183e427bbea91c9689c03ef8e4a6f3fdaf8e66244813d54bccb4ad30` |
| [Trace audit](filesystem-trace-audit-2026-08-25.json) | 181 | `bd9a49f0ca3a90b40b7e5fd0c249684a1e0d6fd9a69f8e3adc6adfd18c09c875` |
| [Trace fixture result](filesystem-trace-fixture-2026-08-25.json) | 165 | `1d06badc9c9d1e1835bc1642efa93bfd419a609e9833f1dcd94d916a9f3b7b76` |

The three [Linux](packed-evidence-linux-2026-08-25.json),
[macOS](packed-evidence-macos-2026-08-25.json), and
[Windows](packed-evidence-windows-2026-08-25.json) packed records bind each
report to both exact archives. The raw Linux trace contains 586 lines; replay
proves `outsideReferences: 0`. Its fixture result records `UNSAFE_TARGET` for
the symlink ancestor and `TARGET_CHANGED` for both target and ancestor races.

## Acceptance map

| Criterion | Completion evidence | Status |
|---|---|---|
| OGVCS-004-AC-01 | All 63 pure rows are independently reproduced; the three-host comparator requires exact decisions and package bytes. | Pass |
| OGVCS-004-AC-02 | Linux tracing covers the symlink ancestor plus target and ancestor replacement with zero outside-root references; the Windows native row executes the junction fixture. | Pass |
| OGVCS-004-AC-03 | OGVCS-002 integration pins exact before/after tree and logical-bundle identities, preserves `FileID`, and rejects decomposed input before encoding. | Pass |
| OGVCS-004-AC-04 | Overflow, gaps, unsupported resume, corrupt/unclean state, first-open ordering, and queued-event regressions never let portable notifications falsely publish clean. | Pass |
| OGVCS-004-AC-05 | Unreal and Unity fixtures are actually materialized through one bound plan and produce exact inventory digests; a 257-segment peer returns the stable depth-limit diagnostic. | Pass |

## Security and reliability boundary

Every public mutator requires a module-branded workspace and complete-set plan.
The plan binds canonical entries, case/profile, platform, measured
capabilities, and workspace identity; capabilities are re-probed before the
first mutation. Existing components are inspected without following links,
staged bytes and identities are rechecked, directory descendants are bounded
and fingerprinted, and recoverable transaction records precede publication.

Portable Node pathname calls cannot exclude a continuously hostile actor with
the same operating-system authority. The supported boundary therefore requires
an owner-private workspace root; stronger adapters may use handle-relative
native calls. Detected changes always fail. Likewise, `fs.watch` has no
authenticated queue-drained cursor, so its notifications only accelerate the
index; a bounded reconciliation is the only operation that grants clean state.

## Historical candidate retained for audit

The 2026-08-16 candidate remains available as
[`candidate-2026-08-16.json`](candidate-2026-08-16.json) and
[`github-actions-run-31939458256.json`](github-actions-run-31939458256.json).
It proved the earlier 62-pure/10-native, 72-row boundary and exposed useful
platform packaging issues, but it is superseded by the source-bound 2026-08-25
completion evidence above. Historical records are not rewritten as current
proof.
