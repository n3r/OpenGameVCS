# OGVCS-046 critical review

- **Review date:** 2026-08-30
- **Reviewer:** Independent Codex requirement, filesystem-boundary, package, and evidence passes
- **Current verdict:** Implementation acceptance-ready; lifecycle ratification pending

## Scope and method

The review traced every OGVCS-046 functional requirement, quality attribute,
acceptance criterion, interface, rollout statement, recovery claim, and
operational boundary through the public package export, closed materialization
plan, workspace authority, streaming source adapter, publication journal,
inspection/recovery API, package consumer, conformance report, three-host
workflow, comparator, and Linux syscall trace.

Adversarial checks covered forged workspaces and copied plans, plan/path/kind
substitution, early and late capability drift, missing rollback-link support,
oversized bytes/scratch/chunks/operations/time, source failure, cancellation,
length and digest mismatch, source buffer mutation, stage mutation, symlink or
junction ancestors, target and ancestor replacement, multiply-linked targets,
sync and rename failure, busy targets, every durable crash boundary, malformed
remnants, cleanup failure, and a post-commit observer failure. No exact-scale
workload was run or required.

## Findings and remediation

| Area | Confirmed gap | Settled remediation |
|---|---|---|
| Complete-set authority | A streaming writer could otherwise bypass OGVCS-004's collision and capability plan. | `atomicWriteStream` requires the exact module-branded workspace and owner-bound closed plan for the canonical file entry, with capability revalidation before staging and immediately before publication. |
| Retained memory | A producer-controlled source could yield oversized or mutable views. | Every input is copied into one bounded chunk, charged before retention, hashed/written incrementally, and released before the next source value. |
| Integrity | Publication could expose an incomplete or substituted stream. | Expected byte length and lowercase SHA-256 are mandatory and checked against the synced private stage before any target replacement. |
| Replacement rollback | Removing or renaming an old target before durable publication could lose the prior file. | Replacement requires hardlink capability and retains an exact owner-bound rollback link through target and journal durability; inability to create it fails before publication. |
| Namespace races | A target or ancestor could change while a long source is consumed. | Workspace/control identities, path component bindings, target, stage, and rollback inode are revalidated around the destructive boundary; detected races fail closed. |
| Created ancestors | A successful nested publication could acknowledge before newly created ancestor entries were durable. | Each created directory is identity-bound and its containing directory is synchronized before traversal continues. |
| Crash states | Partial source, linked rollback, journal replacement, publication, recovery, or commit could leave ambiguous artifacts. | The closed `write-stream` record has planned/staged/published/committed states; exact `.json.next` successors cover pre-record-rename crashes, ambiguous record-directory sync preserves restart authority, and recovery is repeatable after its own interruption. |
| Filesystem promise timing | Racing a timeout against an unresolved filesystem promise could mutate after rollback. | Deadlines/cancellation race only cooperative source and hook work; filesystem promises settle before cleanup or transition. |
| Event-loop deadline authority | The only timer able to reject a hung source was unreferenced, so fast Linux could exit with the test pending. | The deadline timer remains referenced until the raced operation settles and is cleared immediately when the operation wins. The hanging-source regression and all three hosts now pass. |
| Commit cleanup | Backup/journal removal lacked a final transaction-directory barrier, and a post-commit hook error could report failure after durable publication. | Cleanup removals are directory-synced. Once a `committed` record is durable, cleanup/observer failure returns the durable result and leaves a valid remnant for finalization instead of reporting ambiguous failure. |
| Windows directory sync | Node reports unsupported directory sync as `EPERM` on Windows. | Only `win32` `EPERM` from `FileHandle.sync()` on an already opened and identity-verified directory is treated as unavailable; open, ACL, identity, and non-Windows failures remain terminal. |
| Package evidence | Local tests alone would not prove the public archive or host behavior. | All three hosts install normalized archives offline, execute the public API/native row, and feed exact reports/package hashes to a strict comparator. Raw evidence is checked in and policy-tested. |

## Requirement and acceptance matrix

| Requirement | Verdict | Evidence |
|---|---|---|
| FR-01 branded workspace and closed plan | Pass | Forged/cross-workspace/wrong-path plans reject; early and late capability drift tests fail before publication. |
| FR-02 bounded async source | Pass | AsyncIterable and Web stream tests process one copied configured chunk at a time; the 1-MiB multi-chunk test observes a 4-KiB source peak. |
| FR-03 integrity before replacement | Pass | Wrong length, short source, and digest mismatch preserve the prior target and remove ordinary-failure artifacts. |
| FR-04 capability revalidation | Pass | Tests change atomic-replace authority before stage creation, after source consumption, and in the final caller hook; all reject typed. |
| FR-05 private synced atomic stage | Pass within the inherited owner-private-root boundary | No-follow identity checks, same-device private stages, exact staged state, every newly created ancestor barrier, file sync, target-parent barrier, and atomic rename precede success. |
| FR-06 rollback link | Pass | Existing targets require hardlink capability; exact prior inode/link state is retained until committed cleanup is durable. |
| FR-07 failure cleanup/rollback | Pass | Source, cancellation, resource, integrity, race, sync, rename, busy, and hook tests preserve/restore prior bytes or expose an honest recoverable record. |
| FR-08 versioned crash ownership | Pass | Partial-source, rollback, all four durable-record, post-rename, pre-record-rename temporary, and interrupted-recovery boundaries are inspected and recovered without pathname guessing. |
| NFR-01 bounded retained source memory | Pass | Source retention is independent of total length and bounded by `maxChunkBytes`; scratch and total byte ceilings are separately enforced. |
| NFR-02 stable public failures | Pass | Public boundaries normalize to privacy-safe `PathFilesystemError` codes; native and package tests assert exact results. |
| NFR-03 settled filesystem operations | Pass | Host operations are awaited; cancellation/deadline behavior is confined to cooperative source/hook calls, and the authoritative timer remains referenced until the race settles. |
| AC-01 bounded exact multi-chunk output | Pass | Focused test streams 256×4-KiB chunks, observes 4-KiB peak source retention, and verifies the exact 1-MiB target and digest. |
| AC-02 fault/race/resource safety | Pass | Focused hostile/fault tests plus the common three-host native row preserve old bytes or durable recovery state. |
| AC-03 restart recovery | Pass | Child-process crashes cover partial source, rollback link, every durable record, post-rename/pre-parent-sync, and every `.json.next` state; rollback/finalization and repeated recovery leave the transaction directory empty. |
| AC-04 packed public API | Pass | Offline packed consumers import and execute `atomicWriteStream` on all three hosts. |
| AC-05 Linux/macOS/Windows | Pass | Retained reports are 79/79 on each host with exact shared decisions and package identities; hardlink-unavailable replacement rejects before mutation. |

## Accepted boundary

OGVCS-046 inherits OGVCS-004's portable filesystem boundary: the workspace and
reserved control roots are owner-private, and a stronger handle-relative native
adapter is required against an actor with the same operating-system authority
that can continuously replace trusted ancestors. Portable Node code detects
observable identity, link, device, and reparse changes and fails closed; it does
not claim stronger namespace continuity.

The package can make file and supported-directory barriers durable, but Node on
Windows does not expose a successful directory `fsync`. The implementation
records this as an unavailable host capability by accepting only the documented
Windows directory-sync `EPERM` after successful open and identity verification.

## Final proof

- The full runtime/package suite passes 74/74; twenty focused stream tests cover
  public API, resource, hostile, crash, cleanup, and durability behavior.
- The contract generator, independent validator, schema/vector mutation checks,
  packed consumer, report tooling, comparator, trace audit, workflow policy, and
  roadmap policy pass.
- [Run 33322266963](https://github.com/n3r/OpenGameVCS/actions/runs/33322266963)
  passed Linux, macOS, and Windows at source `a4e5951`, 79/79 on each host.
- The retained [comparison](../evidence/OGVCS-046/conformance-comparison-2026-08-30.json)
  proves exact shared decisions and normalized package identities.
- The retained [Linux trace and audit](../evidence/OGVCS-046/README.md#durable-reports)
  preserve the inherited `atomicWriteFile` confinement regression with zero
  outside-root references; they are not presented as direct stream syscall proof.

## Final verdict

No live P0, P1, or P2 remains in the bounded staged-publication implementation,
public API, package, or journal/recovery path. The retained implementation run
is complete. OGVCS-046 remains in `prd/todo` until the evidence-policy commit
itself passes hosted validation; only then may the lifecycle files move to
`Done`. The downstream OGVCS-007 100-GiB campaign and production chunk profile
ratification remain separately owned gates and are not claimed here.
