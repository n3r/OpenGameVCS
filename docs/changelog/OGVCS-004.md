# OGVCS-004 — Cross-platform path and workspace filesystem library

**Validation candidate:** 2026-08-16

**Release:** R0 — Engineering Foundation

**Packages:** `@opengamevcs/path-contract-v1` 1.0.0 and
`@opengamevcs/path-filesystem` 1.0.0

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
the profile family alone is not considered a proof. The Rust object library
fails these production profiles closed until an equivalent external path
adapter is supplied; it does not silently apply incomplete rules.

Case/Unicode integration tests decode normative OGVCS-002 objects, build
renamed canonical trees, preserve the entry `FileID`, verify changed tree bytes
and ObjectRefs, construct logical bundles, and reverify supplied closure.

## Packaging and validation

Both packages carry the byte-identical MIT license. The contract archive ships
the complete public authority but excludes generation/test internals. The
runtime archive ships public source, examples, and executable CLI but no tests
or private repository paths. A clean temporary consumer installs the exact
archives offline and runs the public CLI/report.

Local validation passed all 62 pure rows, ten bounded native rows, six contract
tests, runtime/package/integration tests, report/comparator/trace-auditor tests,
and the OGVCS-002 164-test/58,520-mutation ordinary regression suite. Exact
hashes and the acceptance map are recorded in the
[candidate evidence packet](../evidence/OGVCS-004/README.md).

The three-OS workflow uses commit-pinned actions, retains both normalized npm
archives and the report from every host, and compares exact package/pure result
hashes across the complete 72-row report. Linux additionally executes the
outside-root symlink attack under `strace`, verifies no syscall reaches the
disjoint outside fixture, and retains the raw trace and audit.

## Rollout and remaining work

This is a validation candidate, not a completed roadmap item. Hosted
Linux/macOS/Windows evidence is pending the first candidate push. Repositories
must pin case mode, profile, and contract major at creation; an incompatible
fold/profile change requires a new version and migration preview. A defective
candidate can be withdrawn, but rollback cannot reinterpret existing keys or
mark an unreconciled workspace clean.

Per maintainer direction, no one-million-tree or logical-1-TiB test ran during
this delivery. Those are OGVCS-002 exact-scale gates deferred to the final R0
campaign, not smaller OGVCS-004 claims. Because OGVCS-004 depends on OGVCS-002,
the PRD remains in `Validation` until the hosted path proof passes and the final
R0 campaign closes the predecessor.
