# OGVCS-001 critical review

- **Review date:** 2026-08-15
- **Reviewer:** Independent Codex subagent (`ogvcs001_critical_review`)
- **Initial verdict:** Not acceptance-ready
- **Remediation status:** Source remediated and frozen; required Windows evidence pending

## Scope and method

The reviewer independently read the PRD, package, schemas, examples, and tests; ran the presubmit and reference-scale suites; compared the implementation with every functional and non-functional requirement; and performed adversarial recovery mutations. The review was intentionally performed before any PRD completion claim.

## Initial findings

| Severity | Finding | Required resolution | Status |
|---|---|---|---|
| P0 | Named profiles were mostly labels: ordinary content was uniformly pseudorandom, Unreal source/config was absent, Unity negatives did not model duplicate GUIDs, large-file versions were recipes without version bytes/digests, operations lacked coherent state, identity/ACL fixtures were absent, and nearly all feature flags were inert. | Ship a version-bumped, profile-specific semantic contract with structured content, coherent history/lock/ACL state, real Unity/Unreal relationships, materializable large-file versions, and behaviorally effective flags. | Resolved in profile/schema v2 |
| P1 | Resume could publish an owned stage containing an unrelated file, and completed `--resume` accepted a fixture after a materialized file was removed. Atomic-write failures could also leave tool temporary files. | Enforce an exact stage allowlist before publication, fully verify completed resume, clean only positively identified tool temporaries, and make publication durability explicit. | Resolved and fault-tested |
| P1 | Public JSON Schemas and runtime bounds/required fields diverged; generated documents were not runtime-validated against the public contract; manifest-controlled artifact paths were not containment-checked. | Make schemas and runtime one closed contract, add bidirectional contract tests, validate public artifacts, and use a single containment-checked resolver. | Resolved and contract-tested |
| P1 | Unreal and Unity path records referenced groups beyond the 10,000 embedded-group cap. Verification regenerated and accepted the same dangling references. | Remove the cap inconsistency or stream group definitions, then test referential integrity above the former boundary. | Resolved with bounded, non-dangling group coverage |
| P1 | Symlink checks and filesystem mutations had time-of-check/time-of-use windows; stale-lock takeover was non-atomic; concurrency and disk-full tests were simulations rather than adversarial process/persistence tests. | Strengthen no-follow/ancestor checks and lock takeover, race real processes, and inject failures at each durable-write boundary. | Resolved within the documented workspace-safety boundary |
| P2 | Scenario verification skipped semantic parsing above 100,000 operations; executable mode was not verified; examples were shallow and not exercised end-to-end from the installed package. | Stream-validate all supported scenario sizes, verify portable modes, and run semantically meaningful consumers against the packed offline installation. | Resolved and package-tested |

## Initial acceptance verdicts

| Criterion | Initial verdict | Reason |
|---|---|---|
| AC-01 | Partial | Small source-tree runs and offline installation passed, but installed generation/verification of every semantic profile was not proven. |
| AC-02 | Failed | macOS and Linux evidence existed; Windows had not run. |
| AC-03 | Partial | One million logical records and a 100-GiB sparse apparent file stayed below 1 GiB RSS, but this did not prove full-byte/full-inode materialization. |
| AC-04 | Failed | Only an early checkpoint was killed; completed corruption and later-phase damage were not safely handled. |
| AC-05 | Failed | Common input/path checks passed, but publication, real concurrency, stale-lock, directory-swap, and persistence-fault cases were incomplete. |
| AC-06 | Partial | Source examples used public interfaces, but installed-package execution and profile-specific semantic consumption were incomplete. |

## Reproduced release blockers

1. Interrupt after a checkpoint, add `unrelated.txt` to the owned stage, then run `generate --resume`: generation reported success and published a manifest; `verify` subsequently failed workspace safety.
2. Generate a full fixture, remove a materialized file, then run identical `generate --resume`: generation reported success after checking only manifest/request identity.
3. Generate records above the old group cap: Unreal inventory record 40,000 referenced an undeclared group, as did Unity record 20,000.

## Resolution and re-review

The remediated candidate was frozen only after repeated independent source review found no residual P0, P1, or P2 implementation defect. The final implementation adds profile-specific v2 semantics, exact public schema/runtime closure, streaming semantic verification, replayable FileID/revision/branch/lock/ACL state, conservative resource planning, bounded parsers, complete-write handling, request-derived sparse verification, and black-box installed consumers.

Recovery/publication now uses atomic lock candidates, closed stale-guard recovery epochs, request-bound stage/publication receipts, manifest-last hard-link publication, exact artifact and nested materialization proofs, deterministic deep verification before publication/reuse, and corruption/resource error classification that preserves unrelated or valid resumable state. Deterministic tests cover interruption before the first owner, every checkpoint, both stale-guard handoff windows, physical-large partial writes, corrupted controls/modes/descriptors, nested unknown content, persistence boundaries, post-commit warnings, and real competing processes.

Frozen-candidate evidence is recorded in [`docs/evidence/OGVCS-001/README.md`](../evidence/OGVCS-001/README.md):

- macOS arm64/Node 24: 127 passed, 0 failed, 2 intentional skips;
- network-disabled Linux arm64/Node 22 with a read-only source mount: 127 passed, 0 failed, 2 intentional skips;
- byte-identical macOS/Linux golden summary SHA-256 `ca0949b76f9dcfb409148a41b588d4911af4c5b2135bc65a73821c193c61adb0`;
- reference scale: 1,000,000 logical paths, three 100-GiB versions fully hashed in three passes, 911.922 s total, and 705,937,408-byte OS high-water RSS.

The `/usr/bin/time -l` wrapper's final sandboxed `sysctl kern.clockrate` probe failed after its child passed; this is not represented as a second high-water measurement. The acceptance test's operating-system `process.resourceUsage().maxRSS` assertion is the authoritative measurement.

## Final acceptance verdicts

| Criterion | Final verdict | Independent-review basis |
|---|---|---|
| AC-01 | Pass | Complete small-profile CLI matrix on macOS and network-disabled/read-only Linux, plus offline packed installation and installed consumers. |
| AC-02 | Not passed—Windows pending | macOS and Linux golden summaries match, but workflow configuration is not an actual Windows execution. |
| AC-03 | Pass under the documented logical/streaming contract | One million logical inventory paths; zero ordinary materialization; 100 GiB × 3 streamed during initial generation, again in the mandatory gate, and again in explicit verification; 705,937,408-byte RSS; no physical large file claimed. |
| AC-04 | Pass | Initialization/publication interruption, every durable checkpoint, corruption, replay, and deterministic baseline recovery are covered. |
| AC-05 | Partial—Windows junction execution pending | Tested-host safety, persistence, concurrency, containment, and mutation checks pass; the actual Windows junction case has not run. |
| AC-06 | Pass | Both black-box examples use only the installed CLI/public artifacts for all five profiles. |

FR-01 through FR-12 are source-satisfied. NFR-02 and NFR-03 pass. NFR-01 and the Windows portion of NFR-04 remain evidence-pending because no Windows runtime was available.

## Done recommendation

No source blocker remains; the frozen implementation is merge-ready. OGVCS-001 is **not Done** and remains in `prd/todo` solely because required actual Windows golden and junction execution evidence is absent. Once that configured Windows job runs and matches, update the evidence/criterion links and only then move the PRD to `prd/done`.
