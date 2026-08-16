# OGVCS-004 validation evidence

**Evidence date:** 2026-08-16

**Status:** Local validation candidate; hosted Linux/macOS/Windows proof pending

## Evidence boundary

This packet covers path/workspace contract v1, the pinned Unicode case-fold
authority, four ratified platform profiles, closed schemas and stable errors,
the JavaScript runtime and CLI, OGVCS-002 profile integration, offline package
installation, bounded native filesystem proofs, and the cross-platform report
comparator. The machine-readable local record is
[`candidate-2026-08-16.json`](candidate-2026-08-16.json), and the independent
assessment is
[`docs/reviews/OGVCS-004-critical-review.md`](../../reviews/OGVCS-004-critical-review.md).

This is intentionally not final release evidence. The three hosted operating
systems and elevated Linux syscall trace must pass from the committed source.
In addition, the roadmap does not permit OGVCS-004 to move to `prd/done` while
its OGVCS-002 predecessor remains in development.

The maintainer directed that OGVCS-002's exact one-million-entry tree and
logical-1-TiB manifest tests not run now. They remain deferred to the final R0
campaign. OGVCS-004 does not duplicate those format-scale tests: its
materializer has a documented 100,000-record convenience bound, and FR-04
explicitly leaves the one-million-entry tree ceiling with OGVCS-002.

## Frozen candidate authorities

| Authority | Value |
|---|---:|
| Contract/package version | `1.0.0` |
| License | MIT; root, OGVCS-002, contract, and runtime texts are byte-identical |
| MIT text SHA-256 | `6f0f22f485ae8614870468a48f2c084eaf800fe02c5a2c4d9a91d34bc7f58eb4` |
| Contract manifest SHA-256 | `15251e63487e442f46ea689850f8d4d8db9ef65f1f1eeb961d9594686531b000` |
| Registry-set SHA-256 | `bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42` |
| Unicode case-fold source SHA-256 | `6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb` |
| Local result SHA-256 | `baffdd9ec60e53865a39048c6f995086f4e5d102351d6bc514337f1b1fa3260a` |
| Pure cross-platform rows | 62 |
| Bounded native filesystem rows | 10 |

The independent validator does not import the reference evaluator. It verifies
every manifest artifact, exact registry assignments and documents, Unicode
source and license hashes, generator provenance, closed schema bounds, and all
62 path/fold/collision/preflight/rename/watcher outcomes. It mutation-tests
self-consistent registry, vector, Unicode, license, and canonical-JSON drift.

## Local bounded presubmit

Local environment: macOS 26.6.1 arm64, Node.js 24.9.0, npm 11.6.0.

| Gate | Result |
|---|---|
| Language-neutral contract | Passed 6/6 tests and all 62 independent decisions. |
| JavaScript runtime | Passed 30/30 path, package, object-model integration, workspace, watcher, crash/recovery, and report tests. |
| Packed offline report | Passed 72/72 rows from a clean consumer using only the two retained npm archives. |
| Report tooling | Passed source, packed, comparator, and syscall-trace-auditor tests. |
| OGVCS-002 JavaScript regression | Passed 164/164 tests, 58,520 mutation executions, all 235 ordinary scenarios, and 1,236-artifact independent audit. |
| Hygiene | Generated checks and `git diff --check` passed. |

The local packed artifacts were:

| Package | SHA-256 |
|---|---|
| `@opengamevcs/path-contract-v1` 1.0.0 | `c376cd1d29d42295f4842491b2fdf76322bd0537198d202f288f788d4271662e` |
| `@opengamevcs/path-filesystem` 1.0.0 | `b115450fdd758e2b403a4469bc429c0267d3b3635233601a9c65582bba0fac6e` |

The normalized report SHA-256 was
`de1921e62673ee349e0fe106261ca8285c85aadd6512694d2eff365311c9beee`.
Hosted comparison will require the same package bytes and all pure outcomes on
Linux, macOS, and Windows. Native rows may expose different measured
capabilities but must all pass.

## Acceptance map

| Criterion | Candidate evidence | Status |
|---|---|---|
| OGVCS-004-AC-01 | All 62 pure rows are independently reproduced and the comparator requires exact results and package hashes from Linux, macOS, and Windows. | Local pass; hosted pending |
| OGVCS-004-AC-02 | Symlink/junction ancestors, target replacement, restored-mtime rewrites, forged handles, and unowned remnants fail closed. The Linux workflow retains and audits a `strace` proof with a disjoint outside fixture. | Local pass; hosted trace pending |
| OGVCS-004-AC-03 | The OGVCS-002 integration test re-encodes canonical trees/bundles, preserves `FileID`, rejects non-NFC input, and observes the expected changed tree/object/bundle identities for a case/Unicode rename. | Pass |
| OGVCS-004-AC-04 | Gap, overflow, adapter failure, corrupt state, and unclean restart durably require reconciliation; only completed reconciliation restores clean. | Pass |
| OGVCS-004-AC-05 | Long/deep Unreal/Unity-style bounded preflight passes on the local profile; limit and platform failures use stable codes. | Pass |

## Security and reliability boundary

Every public mutator requires a module-branded workspace handle. Existing
components are inspected without following links; regular targets are hashed
through one no-follow handle and rechecked before and after caller-owned
boundaries. A durable plan precedes staging. Atomic files, symlinks,
file/directory replacement, and multi-step rename cycles either commit exact
state or leave an owner-bound record that can be verified and recovered.
Unknown transaction artifacts are preserved and reported.

The Node implementation cannot make separate path-based system calls atomic
against continuously hostile code with the same operating-system authority.
The supported boundary therefore requires a private workspace root (account,
container, or equivalent); a stronger native adapter may use directory-handle
relative operations. A detected race never becomes success, and no top-level
operation result becomes trusted before commit.

## Pending release evidence

1. Push the frozen candidate and retain the path-filesystem workflow's exact
   Linux, macOS, and Windows package/report artifacts.
2. Require the comparison job to accept exact package hashes and all pure rows.
3. Retain and audit the Linux syscall trace for the unsafe-target fixture.
4. At the final R0 campaign, complete OGVCS-002's maintainer-deferred exact
   scale evidence; only then can the roadmap dependency permit OGVCS-004 Done.
