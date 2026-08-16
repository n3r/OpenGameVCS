# Workspace materialization and safety contract

## Preflight

Materialization receives a closed set of path, kind, portable-mode, and
symlink-target records plus measured host capabilities. Before destructive
mutation it validates every path and hierarchy, repository/platform collision,
kind/mode pair, internal-relative symlink target, platform selection, atomic
replacement support, configured bounds, and required symlink capability.
Executable intent remains authoritative even on a host without a native
executable bit; callers may separately require native application.

Preflight success is bound to the canonical plan digest. A changed plan or
capability result requires preflight again. Unsupported behavior never silently
falls back to following links, copying through a target, or stripping mode.

## Mutation protocol

The reference protocol uses a private `.ogvcs` control directory and an
owner/plan-bound transaction record. Content is written to exclusively created
temporaries, fully written and flushed, identity-checked, then atomically
renamed. Existing root/ancestors/target are inspected without following the
final link; root and target identity are checked before and after each boundary.
Directory entries are flushed where the host API supports it. The transaction
record is removed only after the committed targets and parent metadata are
durable enough for the host contract.

Case-only renames and every rename cycle stage all sources first beneath an
owner-bound reserved namespace, then publish in deterministic destination
order. FileIDs remain unchanged. Directory/file replacement fully stages the
new object before removing the verified old kind. A source digest/identity
change converts delete/modify into `TARGET_CHANGED`. Locked handles and
antivirus interference receive bounded retry and then `TARGET_BUSY`; unsafe
copy fallback is forbidden. Sparse allocation is nonidentity: logical bytes and
digest are authoritative.

A symlink is created as a link object only after capability preflight. The v1
default permits only relative targets whose lexical resolution from the link's
parent never leaves the workspace; a nested `../sibling` may therefore be safe,
while a top-level `../outside`, drive-qualified target, backslash target, or
absolute target is forbidden. The writer never opens through a newly created
or pre-existing link. Any existing symlink, junction, mount-like name
surrogate, or reparse point in an output chain is `UNSAFE_TARGET`.

## Crash recovery and threat boundary

Incomplete transactions remain owner- and plan-bound crash remnants. A durable
plan record precedes every stage, and rename-cycle progress records distinguish
"source still present" from "destination already published" after a crash.
Recovery
may remove only an exact exclusive temporary or finish/roll back an exact
record whose identities still match. Unknown files, unowned records, changed
targets, or ambiguous state are preserved and reported; recursive best-effort
cleanup is not a recovery proof.

The Node reference protects hostile repository data, pre-existing link/junction
chains, ordinary competing creators, and changes injected at its declared
boundaries. The supported root and its ancestors must be private from
continuously hostile same-authority namespace mutation. Node does not expose a
portable Windows/macOS/Linux directory-handle-relative rename family capable of
preempting such an actor between all host calls. Deployments with same-authority
hostile code isolate the workspace or provide a stronger native adapter. A
detected race always fails; this boundary is never an authorization claim.

Read-only mode is a best-effort hard-lock usability hint only. It is not
authorization, does not stop same-authority writes, and never changes the
versioned portable mode.
