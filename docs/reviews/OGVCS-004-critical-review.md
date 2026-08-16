# OGVCS-004 critical review

- **Review date:** 2026-08-16
- **Reviewer:** Independent Codex critical-review pass
- **Initial verdict:** Not acceptance-ready
- **Current verdict:** Locally accepted as a validation candidate; hosted and predecessor evidence pending

## Scope and method

The review examined the PRD and architectural ownership split, ADR-0012, all
language-neutral registries/schemas/vectors, the independent validator, pinned
Unicode data and license, generated runtime bindings, every public path,
preflight, rename, capability, workspace, recovery, watcher, report, CLI, and
object-model adapter API, offline packages, comparator, and pinned workflow.

Hostile inputs included invalid Unicode scalars and normalization, Windows
device/trailing/ADS forms, enormous path containers, invalid diagnostic IDs,
child-before-parent trees, repository/platform collisions, absolute and
escaping symlinks, junction requests, forged workspace handles, same-size
target rewrites with restored timestamps, target replacement, crash at each
durable boundary, injected transaction artifacts, watcher overflow/gap/corrupt
state, hung promise callbacks, and package path/hash substitution.

## Findings and remediation

| Area | Initial gap | Settled remediation |
|---|---|---|
| Independent corpus | Preflight vector metadata was passed into a newly closed request, making generated expectations reject for the wrong reason. | Generator strips vector metadata before reference execution; all 62 results are independently recomputed. |
| Path bounds | Array/string splitting and UTF-8 conversion could allocate before depth/UTF-16 limits. | Depth, joined UTF-16, and segment UTF-16 limits run before copying, splitting, normalization, or encoding; proxy regressions prove unread over-limit elements. |
| Hierarchy and collisions | Input order affected parent validation; rename sources were not compared under repository/platform keys. | Preflight validates all entries before a second hierarchy pass; source and destination collisions are both rejected, and reversed cycles produce the same plan. |
| Symlink safety | Lexical `..` handling ignored the link parent's depth, drive-absolute and non-scalar targets were ambiguous, and a caller could request a Windows junction. | Resolution begins at the parent depth, root escapes/drive paths/backslashes/non-scalar text fail, and only explicit `file`/`dir` symlink types are accepted. |
| Workspace authority | Visible workspace fields could be forged and ordinary path checks did not bind the complete observed file state. | Module-private handle branding, no-follow same-handle hashing, identity/digest rechecks, private control directories, and closed records fail forged or changed targets. |
| Crash windows | Staging could precede durable intent; kind replacement and multi-step rename lacked exact resumable state. | A durable planned record precedes staging. File, symlink, kind-replacement, and rename transitions bind exact state, support rollback/finalize/resume, and reject unknown remnants. |
| Memory and timing | Write buffers and plan hashes could copy aggregate caller data before configured bounds. | Byte lengths are checked before copying; plan hashes stream item canonical forms; public promise hooks use one cooperative deadline and abort signal. |
| Watcher durability | Notifications could be mistaken for authority and state rename lacked a parent-directory durability attempt. | Cursors are hints only; gap/overflow/failure/corruption persist dirty state. State files are handle-synced, atomically renamed, and parent-synced where supported. |
| Package authority | Runtime loading initially trusted package-relative files without complete manifest confinement. | Only declared bounded JSON is loadable, and exact bytes/hash must match the packed manifest. Both MIT packages install and execute offline. |
| Cross-OS comparison | The comparator still required the superseded 63-row report shape after the runtime report grew to 72 rows. | The comparator and its package-evidence regression now require all 72 passing rows before comparing exact decisions and archive bytes. |
| AC-02 proof | Native assertions alone did not literally provide elevated filesystem tracing. | Linux hosted conformance now runs the unsafe-target fixture under `strace`, rejects any outside-root syscall reference, and retains the trace/audit with the package reports. |
| OGVCS-002 integration | Ratified path profile names could be recognized without proving complete composed-path semantics. | JavaScript requires the OGVCS-004 adapter for every composed path and full-set collisions; Rust explicitly fails closed until supplied with an equivalent adapter boundary. |

## Residual boundary and release gaps

No live P0 or P1 local implementation defect remains in the reviewed scope.
One explicit environmental boundary remains: separate pathname syscalls cannot
exclude a continuously hostile same-authority namespace actor. The package and
ADR require a private root or stronger native adapter, preserve staged output
as untrusted until success, and fail every detected race closed. This is an
accepted deployment boundary, not an authorization claim.

The release is not yet acceptance-complete for two evidence reasons:

1. the candidate has not yet passed and retained the Linux/macOS/Windows hosted
   package/report comparison and Linux syscall trace; and
2. OGVCS-002 remains In development because the maintainer deferred its exact
   one-million-tree and logical-1-TiB runs to the final R0 campaign. The roadmap
   correctly forbids marking dependent OGVCS-004 Done before that predecessor.

Neither missing item is hidden or replaced by a smaller-scale claim.

## Acceptance verdict

| Criterion | Verdict | Basis |
|---|---|---|
| OGVCS-004-AC-01 | Pending hosted proof | The pure implementation, independent evaluator, and strict comparator are green locally; all three hosted reports are still required. |
| OGVCS-004-AC-02 | Pending hosted trace | Local adversarial fixtures pass and the exact elevated trace gate exists; its retained Linux artifact is pending. |
| OGVCS-004-AC-03 | Pass | Canonical tree/bundle re-encoding changes the expected identities while preserving `FileID`; non-NFC input is rejected, never repaired. |
| OGVCS-004-AC-04 | Pass | Every gap, overflow, failure, corruption, and unclean restart forces durable reconciliation. |
| OGVCS-004-AC-05 | Pass | Long/deep game-project paths either pass within profile bounds or fail with stable preflight diagnostics. |

## Recommendation

Commit and push this candidate, run the ordinary three-OS workflows without
enabling OGVCS-002 scale, and update this review with exact run/job/artifact
identities. Keep OGVCS-004 in `Validation` and ADR-0012 Proposed until hosted
proof is accepted. At the final R0 campaign, run the two deferred OGVCS-002
scale cases and close the dependency before moving OGVCS-004 to `prd/done`.
