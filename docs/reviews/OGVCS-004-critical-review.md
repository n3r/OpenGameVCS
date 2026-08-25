# OGVCS-004 critical review

- **Initial review:** 2026-08-16
- **Final implementation review:** 2026-08-25
- **Reviewer:** Independent Codex requirement, filesystem-boundary, and evidence passes
- **Initial verdict:** Not acceptance-ready
- **Current verdict:** Acceptance-ready; no live P0, P1, or P2

## Scope and method

The review traced every OGVCS-004 FR, NFR, acceptance criterion, interface,
development-plan step, verification claim, and operational signal through the
language-neutral authority, independent validator, JavaScript package, public
CLI, OGVCS-002 adapter, packed consumer, comparator, and workflow. It also
reviewed the downstream path-manifest pins in the protocol baseline and
benchmark/fault contract.

Adversarial cases included invalid scalar/NFC input, case-folded reserved
control names, Windows device/trailing/ADS forms, over-limit containers,
complete-set collisions, missing plan authority, capability drift, copied
handles/plans, permissive roots, symlink/junction ancestors, ancestor and
target replacement, same-size content rewrite with restored timestamp, stage
rewrite, multiply linked files, directory descendant races, busy publication,
crash boundaries, unknown remnants, watcher stop/reopen, first-open ordering,
queued events, overflow/gaps, corrupt state, callback failure, forged telemetry,
package substitution, and stale generated predecessor pins.

No exact-scale workload belongs to OGVCS-004 and none was run. The million-tree
and logical-1-TiB format campaign is completed OGVCS-002 evidence, not a path
materializer requirement.

## Findings and remediation

| Area | Confirmed gap | Settled remediation |
|---|---|---|
| Reserved namespace | Only lowercase `.ogvcs` was rejected, allowing case variants on case-sensitive hosts. | All segments and watcher control events use the frozen Unicode fold; `.OGVCS` and every fold-equivalent spelling are reserved. |
| Materialization authority | Public mutators accepted caller convention after an unbound pure preflight. | A module-branded plan binds one workspace, complete entries, case/profile, platform, and measured capabilities; every mutation re-probes it before creating parents or stages. |
| Plan resource behavior | Binding all plan context through one aggregate serialization could exceed the convenience materializer's intended working set. | The canonical digest streams the bounded entry array while still binding capabilities, case mode, profile, and platform. |
| Workspace authority | Root/control identities and permissions were not all retained; control replacement could redirect later operations. | Absolute owner-private roots and every reserved directory are identity/mode bound and rechecked around each operation. Invalid profile/case configuration rejects before control creation. |
| Publication state | Target checks did not cover exact staged content, hard links, directory descendants, or every durable sync failure. | Stage identity/length/digest, single-link state, bounded directory fingerprints, component bindings, and directory-sync outcomes are verified before success. |
| Windows directory durability | Treating every `EPERM` as a permission failure also rejected Windows' documented unsupported directory-`fsync` result after otherwise successful atomic publication. | The runtime ignores only Windows `EPERM` from `FileHandle.sync()` on an already opened and verified directory; open/ACL failures and POSIX permission errors remain terminal. |
| Busy/interference behavior | Locked-file and scanner interference had a normative result but no deterministic retry proof. | Declared publish-attempt fault boundaries prove bounded retry, exact `TARGET_BUSY`, recoverable staging, and no copy fallback. |
| Sparse behavior | Sparse allocation was described but not exercised. | A native row materializes a sparse source and verifies exact logical length and digest; allocation layout remains nonidentity. |
| Sidecar scope | Group semantics were named but the ownership boundary was ambiguous. | OGVCS-002 owns group membership/cardinality; OGVCS-004 receives every resolved member in one complete-set plan, whose digest changes if a sidecar is omitted. |
| Watch stop/resume | A normal `fs.watch` stop preserved a clean-looking cursor even though Node cannot resume across the stopped interval. | Close records `unsupported-resume`; reopen cannot reuse the generation and performs a new post-subscription reconciliation. |
| Watch first-open gap | Reconciliation completed before the native subscription, so a change in between could be lost and a later event could restore clean. | Open persists dirty state, subscribes first, then invokes the required bounded reconciliation callback and installs its new generation only on success. |
| Watch queued events | One acknowledged notification restored clean while another native event could already be queued. | Portable Node batches advance only a synthetic acceleration cursor and always remain nonauthoritative; `fs.watch` has no queue-drained proof. Only bounded reconciliation grants clean. |
| Watch state safety | Case-variant control events, hard-linked state, control replacement, and some directory-sync failures were not closed. | Control filtering is fold-based; state/control files are single-link, no-follow, identity-bound, atomically replaced, and sync permission failures propagate. |
| Engine fixtures | Acceptance was inferred from preflight rather than actual Unreal/Unity output. | Both fixtures materialize through one plan and compare exact canonical inventory digests; a 257-segment peer returns the exact depth-limit detail. |
| Case/NFC identity | The integration proof asserted only unequal identities and did not pin all outputs. | Exact before/after tree ObjectRefs and logical-bundle hashes are pinned while `FileID` is preserved; decomposed input rejects before encoding. |
| Property verification | The planned canonicalization/path-bound fuzz proof was absent. | A deterministic 2,000-sample property suite covers canonical round trips, fold idempotence, and hard/profile boundaries. |
| Telemetry | Required operational signals existed only as errors/prose. | A branded, callback-free collector exposes privacy-safe profile, failure, watcher, duration, retry, fallback-refusal, and denial counters. |
| CLI/package | The write CLI bypassed the closed plan; relative roots were resolved into authority; packed testing omitted advertised surfaces. | The CLI binds a complete plan, rejects relative roots, and the offline consumer imports public adapters/telemetry and runs all seven commands plus the full report. |
| AC-02 tracing | One symlink trace did not prove target and ancestor race fixtures; Windows could silently skip its junction. | Linux traces all three attacks with a disjoint outside root and retained fixture JSON; Windows must execute the host-native junction row. |
| Generated closure | Late normative edits left path, protocol, and benchmark predecessor hashes stale. | Generation is performed in path → runtime binding → protocol → benchmark order, and every generator check is part of the candidate gate. |

## Requirement and acceptance matrix

| Requirement | Verdict | Evidence |
|---|---|---|
| FR-01 canonical relative NFC paths | Pass | `path.mjs` and all path vectors reject noncanonical/forbidden encodings without rewriting bytes. |
| FR-02 immutable case mode/fold | Pass | ADR-0012 and the pinned Unicode-16 fold produce host-locale-independent keys. |
| FR-03 repository/platform collisions | Pass | Complete-set collision keys and vectors cover repository and selected-platform equivalence. |
| FR-04 explicit profile limits | Pass | Four ratified profiles have bounded limits and exact actionable errors. |
| FR-05 distinct symlink entries | Pass | Plan-bound internal-relative link materialization never follows the link while writing. |
| FR-06 portable executable intent | Pass | Portable intent is authoritative and the native bit is capability-gated. |
| FR-07 confined atomic writes/recovery | Pass within the documented private-root boundary | Owner-bound stages/records, exact state, crash recovery, and fault tests fail detected races closed. |
| FR-08 read-only is a hint | Pass | The API reports `authoritative:false`, rejects hard links, and never changes versioned mode. |
| FR-09 watcher reconciliation | Pass | Stop/open/queue/overflow/gap/corruption tests never let portable notifications establish clean authority. |
| FR-10 platform outcomes | Pass | All ten outcomes are registered; case/kind/cycle/delete/junction/sparse/busy/symlink/executable paths have executable proof. |
| NFR-01 cross-host identities/digests | Pass | All 63 pure rows, pinned engine/OGVCS-002 identities, and both normalized archives agree on Linux, macOS, and Windows. |
| NFR-02 no outside-root writes | Pass | Link, target, and ancestor attacks fail before outside access; retained Linux syscall replay reports zero outside-root references. |
| NFR-03 capability failure before mutation | Pass | Branded plans revalidate the complete measured capability record before output creation. |
| AC-01 golden cross-host decisions | Pass | 63 pure decisions and exact package/result comparator passed in the retained three-host run. |
| AC-02 symlink/junction/race confinement | Pass | Three retained Linux trace attacks plus the required Windows junction row passed. |
| AC-03 case/NFC rename identity | Pass | Exact pinned tree/bundle identities and preserved FileID; NFD rejection. |
| AC-04 watcher never falsely clean | Pass | Subscription precedes reconciliation and portable batches never claim queue completeness. |
| AC-05 engine materialization | Pass | Exact Unreal/Unity inventory hashes and paired over-limit result passed on all three hosts. |

## Accepted boundary

Portable Node pathname calls cannot exclude code with the same operating-system
authority continuously swapping trusted ancestors between every host call, nor
can `fs.watch` prove a native queue-drained cursor. The supported deployment
therefore uses an owner-private root (account/container or equivalent), treats
notification batches only as acceleration, and supplies a stronger native
directory/journal adapter when those properties are required. Detected change
always fails; no output or clean state becomes trusted merely because the
portable API cannot observe a stronger primitive.

## Final proof

- Language-neutral path authority: 63 vectors, 23 errors, four profiles; six
  independent contract tests pass.
- Runtime/package: the final complete path suite passed 54/54, including the
  queued-event, stopped-interval, subscription-order, materialization,
  property, offline-package, and CLI regressions.
- Retained report shape: 78/78 on Linux, macOS, and Windows (63 pure plus
  fifteen native rows), with exact shared result and package identities.
- Protocol baseline: generated closure, 14 spec tests, 102 runtime tests, and
  independent adapter check pass against the current path predecessor.
- Benchmark/fault contract and runtime: three spec and nineteen runtime tests
  pass against the current path/protocol predecessors.
- Generator checks, roadmap validation, offline package/report tooling, and
  `git diff --check` pass.
- Implementation run
  [32831999325](https://github.com/n3r/OpenGameVCS/actions/runs/32831999325)
  passed all three hosts and the strict comparator at source `4f8a5a0`; its raw
  reports, packed records, comparison, and Linux trace are checked in.
- Evidence-policy run
  [32833243994](https://github.com/n3r/OpenGameVCS/actions/runs/32833243994)
  passed at revision `94f68c8`, including independent byte/hash validation and
  syscall-trace replay of the durable packet.

## Final verdict

No live P0, P1, or P2 remains in the implementation, contract, package, CLI,
workflow, evidence, or lifecycle boundary. The historical August 16 packet is
preserved as history; the 2026-08-25 packet binds current implementation bytes,
jobs, artifacts, packages, reports, exact decisions, and the expanded trace.
OGVCS-004 satisfies its acceptance criteria and may move to `prd/done`.
