# `@opengamevcs/path-filesystem`

Dependency-minimal Node ESM implementation of OpenGameVCS path/workspace
contract v1. The package exposes deterministic joined-path validation,
Unicode-16 full default case folding, repository and platform collision keys,
bounded collision/materialization preflight, rename planning, transactional
workspace writes/recovery, capability probes, read-only hints, and a persisted
watcher reconciliation state machine.

The API consumes OGVCS-002 NFC path segments and entry/mode values without
rewriting canonical bytes or identities. It never uses host locale as a
repository authority. All public failures are `PathFilesystemError` values with
a stable contract code and privacy-safe details.

Filesystem mutation requires a private workspace root. The reference Node
adapter rejects pre-existing symlinks/junctions, checks root and target identity
around each mutation, stages content before replacement, and fails closed on a
detected race. It cannot defend against untrusted code running with the same OS
authority continuously swapping trusted ancestors between host system calls;
such deployments use an isolated account/container or a stronger native
directory-handle adapter. No bytes or status become trusted until the top-level
operation succeeds.

Watch notifications are hints. Restart, cursor mismatch, overflow, adapter
error, state corruption, or unclean shutdown requires reconciliation. Only
`completeReconciliation` can restore authoritative clean state.

## Public API

```js
import {
  pathCollisionKeys,
  findPathCollisions,
  preflightMaterialization,
  probeFilesystemCapabilities,
  openWorkspaceRoot,
  atomicWriteFile,
} from '@opengamevcs/path-filesystem';

const keys = pathCollisionKeys('Content/Characters/Hero.uasset', {
  caseMode: 'case-folded',
  profile: 'path.opengamevcs/portable@1',
});

const capabilities = await probeFilesystemCapabilities('/absolute/private/root');
const workspace = await openWorkspaceRoot('/absolute/private/root');
await atomicWriteFile(workspace, keys.canonical, bytes, { createParents: true });
```

The deterministic APIs are `caseFold`, `validateRepositoryPath`,
`pathCollisionKeys`, `findPathCollisions`, `preflightMaterialization`, and
`planRenames`. Their `evaluate*` counterparts return the frozen decision shape
instead of throwing. `objectModelPathProfileValidator` is the synchronous
adapter passed to OGVCS-002 repository expansion when the descriptor selects
one of the four `path.opengamevcs/*@1` profiles. OGVCS-002 registry/family
validation alone is not a materialization proof: callers validate each
composed path with this adapter and run `preflightMaterialization` over the
complete expanded set so repository/platform collisions are also detected.

The host APIs are `probeFilesystemCapabilities`, `openWorkspaceRoot`,
`atomicWriteFile`, `replaceWorkspaceEntry`, `materializeSymlink`,
`executeRenamePlan`, `resumeRenamePlan`, `inspectCrashRemnants`,
`rollbackCrashRemnant`, and `applyReadOnlyHint`. Workspace handles are
module-branded; copying their visible fields does not confer mutation access.
Caller inputs are bounded before retention: collision, preflight, and rename
operations default to 100,000 records; writes default to 64 MiB; transaction
enumeration defaults to 1,024 records; filesystem operations default to a
30-second cooperative deadline and 100,000 checkpoints. Smaller limits may be
passed. These in-memory operational bounds do not change the OGVCS-002
one-million-entry format maximum; its exact scale proof belongs to the bounded
streaming codec, not this convenience materializer.

Watcher state is managed with `initialWatcherState`,
`completeReconciliation`, `beginWatcherSession`, `applyWatcherBatch`,
`stopWatcherSession`, and `markWatcherRestart`. `applyWatcherEvent` durably
persists a transition under the workspace control directory. Overflow, a
cursor gap, or restart with a live session persists the dirty state before
returning the stable error. `openWorkspaceWatcher` is the bounded Node
`fs.watch` adapter: it filters the private control namespace, races every
promise boundary, requires the caller's index callback to acknowledge each
batch, and cannot report clean after an ambiguous filename, queue overflow, or
failed index update.

## CLI and packages

The installed `ogvcs-path` binary provides `validate`, `collisions`,
`preflight`, `renames`, `capabilities`, `write`, and `conformance` commands.
`write` accepts only an absolute private workspace root and publishes bytes
only after the transaction succeeds. Errors contain a stable code and never
include a full protected path by default.

The npm archive contains this MIT license, source, CLI, and examples. Its exact
language-neutral dependency includes the Unicode source/license, normative
documents, registries, schemas, vectors, and manifest. The three-OS workflow
installs both archives offline, runs all 62 pure decisions plus ten bounded
native proofs, retains the exact archives and report, and compares package
hashes and pure outcomes across Windows, macOS, and Linux.

## Filesystem boundary

The Node adapter inspects every existing component with `lstat`, refuses
links/reparse-like entries, captures root and target identity, hashes regular
files through the same no-follow handle, rechecks after caller-owned fault
hooks, and publishes an exclusive same-filesystem stage with rename. A durable
planned record exists before staging. File/directory kind replacement and
multi-step rename cycles record every durable transition; exact remnants are
rolled back or resumed, while unknown artifacts are preserved and reported.
Recovery removes recursively only an exact owner-bound backup directory whose
identity still matches the transaction.

Node path APIs are not a substitute for directory-handle-relative syscalls.
The root and its ancestors must therefore be private from continuously hostile
same-authority namespace mutation. Use account/container isolation or a native
adapter for that stronger threat model. A detected race always fails closed;
read-only mode remains a usability hint rather than authorization.
