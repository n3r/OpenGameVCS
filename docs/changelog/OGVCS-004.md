# OGVCS-004 — Cross-platform path and workspace filesystem library

**Completed implementation:** 2026-08-25

**Historical validation candidate:** 2026-08-16

**Release:** R0 — Engineering Foundation

**Packages:** `@opengamevcs/path-contract-v1` 1.0.0 and
`@opengamevcs/path-filesystem` 1.0.0

## 2026-08-25 final-review hardening

The final review replaced caller-convention safety with enforceable authority
at every public materialization boundary and expanded the retained report from
the historical 72 rows to 78 rows: 63 language-neutral decisions and fifteen
bounded native filesystem proofs. The earlier 1.0.0 archives were unpublished
validation candidates; the source-bound final archives and three-host report
will be recorded after the current candidate completes hosted validation.

### Closed materialization authority

- `preflightWorkspaceMaterialization` now returns a module-branded plan bound
  to one workspace handle, the complete canonical entry set, immutable case
  mode/profile, actual host platform, and the complete measured capability
  record. The plan digest streams canonical entries and binds all of those
  inputs without retaining one aggregate serialization.
- Every file, kind replacement, symlink, and rename mutation requires that
  plan. Each operation re-probes capabilities before creating parents,
  transaction records, or stages; missing, foreign, incomplete, or changed
  authority fails before destructive work.
- OGVCS-002 remains authoritative for asset/sidecar group membership. Once it
  resolves a group, all members enter one complete-set plan; omitting a
  sidecar changes the plan digest and requires preflight again.
- The public CLI and safe-write example use the same measured, workspace-bound
  plan as the library rather than bypassing the complete-set contract.

### Workspace and recovery hardening

- Workspace roots must be absolute and owner-private. POSIX roots and reserved
  control directories reject group/other access; root, `.ogvcs`, transaction,
  and rename directories are identity-bound and rechecked around operations.
- Existing ancestors, targets, stages, and control files reject symlink,
  junction-shaped, multiply linked, wrong-kind, or replaced state. Staged bytes
  are re-hashed and identity-checked immediately before publication.
- Directory replacement and rename use bounded recursive state fingerprints,
  so descendant delete/modify races and over-limit subtrees fail without
  speculative cleanup. Directory rename is supported by the same durable
  staged transaction model as files.
- Directory-sync permission failures remain errors; they are no longer
  suppressed as durable success. Windows' measured lack of directory `fsync`
  remains an explicit unsupported capability: only the `EPERM` returned by
  `FileHandle.sync()` after a successful directory open is ignored there;
  path-open and ACL failures still propagate. Read-only hints reject
  hard-linked inodes.
- Locked-file and scanner/antivirus-style interference is retried only within
  the declared bound, then returns `TARGET_BUSY` with recoverable staging and
  never falls back to an unsafe copy. Sparse allocation remains nonidentity;
  the native proof verifies exact logical length and digest after materializing
  a sparse source.

### Watcher correctness

- The portable Node adapter never treats a stopped `fs.watch` cursor as
  resumable. Normal close records `unsupported-resume`; reopen requires a new
  generation and cannot reuse the previous synthetic cursor.
- Opening now persists a dirty boundary, establishes the native subscription,
  and only then invokes the required bounded full-reconciliation callback.
  The callback must update the index and return `true` before the adapter may
  install a new generation and start the live session. This closes both the
  stopped-interval gap and the former reconcile-to-subscribe gap.
- Node exposes no authenticated queue-drained barrier. Delivered notifications
  therefore advance the synthetic cursor and accelerate indexing but never
  promote the live state to authoritative clean while another native event may
  already be queued; a later bounded reconciliation owns that decision.
- Control events are filtered with the frozen case fold, including `.OGVCS`
  variants. Watcher state files and their control ancestors are no-follow,
  single-link, identity-bound, atomically replaced, and durably synchronized.
- Regressions cover overflow, cursor gaps, corrupt and unclean state,
  unsupported resume, offline mutation, subscription ordering, cursor
  generation, and failed reconciliation.

### Contract, portability, and observability

- The reserved `.ogvcs` namespace is rejected case-insensitively by the frozen
  Unicode 16 fold. The contract now contains 63 exact decisions, including the
  new reserved-name and unsupported-resume cases, all independently validated.
- The case/NFC rename integration pins exact before/after OGVCS-002 tree and
  logical-bundle identities while preserving `FileID`; decomposed spelling is
  rejected before encoding.
- Unreal and Unity fixtures are actually materialized through one bound plan
  and compared by exact canonical inventory digest. The paired 257-segment
  fixture returns the exact depth-limit diagnostic.
- A deterministic 2,000-sample property suite exercises canonical path, fold
  idempotence, and core/profile boundaries. Native rows additionally cover the
  watcher open boundary, sparse logical bytes, and bounded busy interference.
- `createPathTelemetry`/`snapshotPathTelemetry` expose a module-branded,
  callback-free collector for profile IDs, stable preflight failure classes,
  watcher gaps/reconciliation duration, busy retries, refused atomic
  fallbacks, and unsafe-path denials. Snapshots never contain paths, link
  targets, content digests, or temporary names.

### Packaging, tracing, and generated authority

- The offline package test imports every public API—including object-model
  adapter, workspace preflight, and telemetry—runs all seven documented CLI
  commands, rejects relative workspace roots, and executes the full 78-row
  report from packed archives only.
- Linux tracing now retains one fixture result plus symlink-ancestor,
  target-rewrite, and ancestor-replacement attacks under `strace`; the audit
  still requires zero references to the disjoint outside root. Windows must
  execute the junction fixture rather than silently skip it.
- The workflow uses current Node-24-based action releases (`checkout@v7`,
  `setup-node@v7`, `upload-artifact@v7`, and `download-artifact@v8`), runs hosted
  JavaScript payloads on Node 24, and retains Node 22 as the package minimum.
- Regeneration rebounded the final path manifest through the protocol baseline
  and benchmark/fault predecessor chain. Generated checks, independent path
  validation, runtime/package tests, protocol generation/runtime tests,
  benchmark generation/runtime tests, roadmap validation, and diff hygiene are
  green. The final three-OS retained evidence and its independent integrity
  replay are also green.

### Hosted completion evidence

- Implementation/package source
  [`4f8a5a0`](https://github.com/n3r/OpenGameVCS/commit/4f8a5a0f836ef51b4ac56cab9d795d7f5515926d)
  passed [run 32831999325](https://github.com/n3r/OpenGameVCS/actions/runs/32831999325):
  78/78 on Linux, macOS, and Windows plus strict cross-host comparison.
- Evidence-policy revision
  [`94f68c8`](https://github.com/n3r/OpenGameVCS/commit/94f68c80f9166ef3deb7aa65b9cb268453af714f)
  passed [run 32833243994](https://github.com/n3r/OpenGameVCS/actions/runs/32833243994),
  including independent validation of all checked-in byte lengths, SHA-256
  identities, decisions, packed records, comparison, and syscall trace.
- The normalized archives are source-bound and identical across hosts:
  `@opengamevcs/path-contract-v1` is 185,899 bytes with SHA-256
  `432f0f59a498186ff826f73e8c1e8c74e9cf836d22a0f57b463822624c962b8e`;
  `@opengamevcs/path-filesystem` is 188,459 bytes with SHA-256
  `82a9b9533df0e9b3e9dfecac1e8dc12e146dc1ddb6ec972dfcde86bea21de627`.
- The shared 63-row result digest is
  `a21941590359b85c6a45cdab432bfec636c66b13d524746c0dadbaf97da41616`.
  Each host also passed fifteen native rows. The 586-line Linux trace replayed
  with zero outside-root references.
- Raw reports, packed records, comparison, trace, fixture result, machine run
  records, and the complete acceptance map are retained in the
  [completion evidence packet](../evidence/OGVCS-004/README.md).
- No million-entry or logical-1-TiB run was executed for OGVCS-004. Those are
  completed OGVCS-002 format proofs and are deliberately not repeated by this
  bounded path/materialization PRD.

## Historical candidate (2026-08-16)

## Delivered candidate

OpenGameVCS now has a versioned, language-neutral path/workspace contract and a
public Node implementation instead of host-locale/path behavior spread across
future clients and services. The contract consumes OGVCS-002 canonical NFC
segments and entry/mode identities without changing object preimages.

The contract package contains:

- immutable `case-sensitive` and `case-folded` assignments;
- Unicode 16.0.0 full default case folding from the pinned `C` and `F`
  mappings, source digest, Unicode license, and third-party notice;
- ratified portable, Windows, macOS, and Linux profiles with explicit segment,
  joined-path, depth, UTF-16, reserved-name, case, normalization, and symlink
  rules;
- 23 stable errors, ten operation outcomes, seven closed JSON Schemas, and 62
  exact path/fold/collision/preflight/rename/watcher vectors;
- normative workspace, watcher, versioning, and threat-boundary documents; and
- an independent validator that re-hashes every artifact and rejects semantic,
  assignment, Unicode, license, vector, schema, and canonical-JSON drift.

The runtime package provides deterministic path/collision keys, complete-set
preflight, two-phase rename planning, capability probing, transactional file
publication, symlink materialization, file/directory kind replacement,
multi-step rename execution/resume, crash-remnant inspection/recovery,
read-only hints, durable watcher state, bounded `fs.watch`, OGVCS-002 path
profile integration, the `ogvcs-path` CLI, and a 72-row conformance report.

## Path and profile behavior

- Repository paths are nonempty relative `/` joins of already-NFC scalar
  segments. Empty, dot, dot-dot, slash/backslash, NUL, unpaired surrogate,
  decomposed, reserved control-root, and over-limit values are rejected rather
  than normalized.
- Case-folded repositories use the pinned Unicode mapping rather than locale or
  host lowercase. Display/canonical bytes stay unchanged.
- Both repository and selected-platform keys are compared. A case-sensitive
  repository therefore still rejects names its declared Windows or default
  macOS target cannot distinguish.
- Windows profiles reject control characters, separators, ADS colons,
  trailing dot/space, classic and superscript COM/LPT device aliases. macOS
  profiles model colon and case/normalization behavior; Linux remains the
  explicit least-restrictive host profile.
- Complete materialization preflight validates closed entry shapes,
  kind/mode relationships, host capabilities, collisions, symlink targets, and
  parent directories independent of enumeration order.

## Workspace safety and recovery

- Every mutation requires a module-branded handle for an absolute, existing,
  private workspace root. Visible handle fields cannot be copied into authority.
- Existing ancestors and targets are inspected without following symlinks.
  Regular files are read and hashed through one no-follow handle, and exact
  identity/digest/size state is rechecked around publication boundaries.
- A durable, canonical owner-bound planned record is published before staging.
  Exclusive same-filesystem stages are synced before rename; directory parents
  are synced when the host supports it.
- Atomic file replacement, symlinks, regular/directory kind replacement, and
  case-only/cyclic renames have explicit commit states and exact rollback,
  finalize, or resume behavior. Unknown or changed artifacts are never cleaned
  speculatively.
- Link targets must be internal relative scalar text. Root escapes,
  absolute/drive paths, backslashes, unpaired surrogates, empty/dot components,
  and junction requests fail closed.
- Read-only state is explicitly nonauthoritative and never changes versioned
  portable mode.

## Watcher and reconciliation behavior

Watcher events accelerate indexing but never establish authority by themselves.
State persists adapter, cursor, generation, live session, clean/reconciliation
flags, and a closed reason. Overflow, cursor gap, invalid filename, callback
failure, queue exhaustion, corrupt state, unexpected iterator completion, or
unclean restart durably removes authoritative-clean status. Only a complete
reconciliation at the next generation restores it.

The promise-based Node adapter uses one operation deadline and AbortSignal for
watch creation, iteration, caller index updates, and iterator cleanup. It
filters `.ogvcs`, bounds queue/event work, and persists each acknowledged
cursor before returning it.

## OGVCS-002 integration

Four additive `path.opengamevcs/*@1` assignments were added to all OGVCS-002
registry snapshots, regenerated vectors, package bindings, Rust indexes, and
evidence. JavaScript repository expansion calls the OGVCS-004 adapter for every
composed path and rejects full-set repository/platform collisions. Recognizing
the profile family alone is not considered a proof. Both OGVCS-002 core
implementations expose the same pinned path-profile/case-mode validation hook
and fail closed when it is absent or mismatched. OGVCS-004 currently ships the
owner adapter as a JavaScript package; it does not claim a separate Rust
filesystem implementation.

Case/Unicode integration tests decode normative OGVCS-002 objects, build
renamed canonical trees, preserve the entry `FileID`, verify changed tree bytes
and ObjectRefs, construct logical bundles, and reverify supplied closure.

## Packaging and validation

Both packages carry the byte-identical MIT license. The contract archive ships
the complete public authority but excludes generation/test internals. The
runtime archive ships public source, examples, and executable CLI but no tests
or private repository paths. A clean temporary consumer installs the exact
archives offline and runs the public CLI/report. Windows validates the declared
`bin` without pretending npm's host file-mode metadata is POSIX; retained
archives normalize that member to mode `0755` before exact cross-OS comparison.

Local validation passed all 62 pure rows, ten bounded native rows, six contract
tests, runtime/package/integration tests, report/comparator/trace-auditor tests,
and the OGVCS-002 164-test/58,520-mutation ordinary regression suite. Hosted run
[31939458256](https://github.com/n3r/OpenGameVCS/actions/runs/31939458256)
then passed 72/72 rows on Linux, macOS, and Windows, accepted byte-identical
packages and pure decisions, and retained a Linux trace with zero
outside-workspace references. Exact hashes and the acceptance map are recorded
in the [evidence packet](../evidence/OGVCS-004/README.md).

The three-OS workflow uses commit-pinned actions, retains both normalized npm
archives and the report from every host, and compares exact package/pure result
hashes across the complete 72-row report. Linux additionally executes the
outside-root symlink attack under `strace`, verifies no syscall reaches the
disjoint outside fixture, and retains the raw trace and audit.

## Historical rollout status

At the time of the August 16 candidate, OGVCS-004 remained in validation because
its OGVCS-002 predecessor was incomplete. That dependency is now closed and the
current 2026-08-25 completion evidence supersedes this historical boundary.
Repositories still pin case mode, profile, and contract major at creation; an
incompatible fold/profile change requires a new version and migration preview.
A defective release can be withdrawn, but rollback cannot reinterpret existing
keys or mark an unreconciled workspace clean.

The historical candidate intentionally did not run one-million-tree or
logical-1-TiB work. Those OGVCS-002 gates later completed in their owning PRD;
they remain outside OGVCS-004 rather than being duplicated here.
