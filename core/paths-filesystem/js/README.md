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
adapter rejects pre-existing symlinks and junction-shaped entries, checks root,
control-directory, ancestor, staged-content, and target identity
around each mutation, stages content before replacement, and fails closed on a
detected race. It cannot defend against untrusted code running with the same OS
authority continuously swapping trusted ancestors between host system calls;
such deployments use an isolated account/container or a stronger native
directory-handle adapter. No bytes or status become trusted until the top-level
operation succeeds.
On POSIX the root and reserved control directories must have no group/other
permission bits; the adapter rejects a permissive root instead of treating the
documented private-authority boundary as caller convention.

Watch notifications are hints. Restart, cursor mismatch, overflow, adapter
error, state corruption, unclean shutdown, or a stop by any non-resumable
adapter requires reconciliation. Node `fs.watch` never claims cursor resume.
Only a completed reconciliation can restore authoritative clean state. The
portable `openWorkspaceWatcher` first establishes its native subscription and
then invokes its required bounded `reconcile` callback, so the scan that grants
clean authority covers the subscription-start boundary.

## Public API

```js
import {
  pathCollisionKeys,
  findPathCollisions,
  preflightWorkspaceMaterialization,
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
const plan = await preflightWorkspaceMaterialization(workspace, {
  schemaVersion: 'ogvcs.path/preflight-request/v1',
  caseMode: workspace.caseMode,
  profile: workspace.profile,
  platform: capabilities.platform,
  capabilities: {
    atomicReplace: capabilities.atomicReplace,
    executableBit: capabilities.executableBit,
    symlink: capabilities.symlink,
  },
  entries: [
    { id: 'content', path: 'Content', kind: 'directory', mode: 'directory' },
    { id: 'hero', path: keys.canonical, kind: 'regular', mode: 'regular-file' },
  ],
});
await atomicWriteFile(workspace, keys.canonical, bytes, { createParents: true, plan });
```

The deterministic APIs are `caseFold`, `validateRepositoryPath`,
`pathCollisionKeys`, `findPathCollisions`, `preflightMaterialization`, and
`planRenames`. Their `evaluate*` counterparts return the frozen decision shape
instead of throwing. `createObjectModelPathProfileAdapter({profile,caseMode})`
returns the exact-version/case-mode OGVCS-002 adapter object when the descriptor
selects one of the four `path.opengamevcs/*@1` profiles. It projects the richer
OGVCS-004 result to the closed object-model decision `{accepted,
repositoryKey, platformKey}` (or `{accepted:false}`). OGVCS-002 registry/family
validation alone is not a materialization proof: callers validate each
composed path with this adapter; the object-model core consumes both collision
keys across the complete expanded set.

The host APIs are `probeFilesystemCapabilities`, `openWorkspaceRoot`,
`preflightWorkspaceMaterialization`,
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

Every materializing mutation requires a module-branded workspace preflight
plan in `options.plan`; rename execution receives the same authority as
`options.materializationPlan`. The plan binds the complete canonical entry set,
repository case mode/profile, host platform, and measured capabilities to one
workspace handle. The adapter remeasures capabilities before mutation and
rejects a missing, foreign, changed, or stale plan before staging or creating
output parents. Crash recovery is separately authorized by its exact durable,
owner-bound transaction record.
Asset/sidecar membership remains an OGVCS-002 semantic decision. The resolved
complete group is supplied here as one preflight entry set; removing a sidecar
changes the plan digest instead of being silently treated as the same snapshot.

`createPathTelemetry` returns a module-branded, in-process collector and
`snapshotPathTelemetry` returns its frozen privacy-safe counters. Operations
accept the collector as `options.telemetry`. It records only profile IDs,
stable preflight failure classes, watcher gap/reconciliation counts and total
duration, busy retries, refused atomic fallbacks, and unsafe-path denials. It
never stores protected paths, link targets, content digests, or temporary names
and invokes no caller callback.

Watcher state is managed with `initialWatcherState`,
`completeReconciliation`, `beginWatcherSession`, `applyWatcherBatch`,
`stopWatcherSession`, and `markWatcherRestart`. `applyWatcherEvent` durably
persists a transition under the workspace control directory. Overflow, a
cursor gap, or restart with a live session persists the dirty state before
returning the stable error. `openWorkspaceWatcher` is the bounded Node
`fs.watch` adapter: it filters the private control namespace, races every
promise boundary, requires the caller's index callback to acknowledge each
batch, and cannot report clean after an ambiguous filename, queue overflow, or
failed index update. Its `options.reconcile(context, signal)` callback is
mandatory and must return `true` only after a bounded full scan has updated the
index. The native subscription exists before this callback runs, and a failed
or omitted reconciliation leaves durable reconciliation-required state. Node's
iterator has no authenticated queue-drained barrier, so ordinary notifications
advance the synthetic cursor but never promote the live index to authoritative
clean; they remain acceleration hints until the next bounded reconciliation.

## CLI and packages

The installed `ogvcs-path` binary provides `validate`, `collisions`,
`preflight`, `renames`, `capabilities`, `write`, and `conformance` commands.
`write` accepts only an absolute private workspace root and publishes bytes
only after the transaction succeeds. Errors contain a stable code and never
include a full protected path by default.

The npm archive contains this MIT license, source, CLI, and examples. Its exact
language-neutral dependency includes the Unicode source/license, normative
documents, registries, schemas, vectors, and manifest. The three-OS workflow
installs both archives offline, runs all 63 pure decisions plus fifteen bounded
native proofs, retains the exact archives and report, and compares package
hashes and pure outcomes across Windows, macOS, and Linux.

## Filesystem boundary

The Node adapter inspects every existing component with `lstat`, refuses
links and junction-shaped entries, captures root, control, ancestor, staged,
and target identity, hashes regular
files through the same no-follow handle, rechecks after caller-owned fault
hooks, and publishes an exclusive same-filesystem stage with rename. A durable
planned record exists before staging. File/directory kind replacement and
multi-step rename cycles record every durable transition; exact remnants are
rolled back or resumed, while unknown artifacts are preserved and reported.
Recovery removes recursively only an exact owner-bound backup directory whose
identity still matches the transaction.

Portable Node APIs cannot inspect arbitrary Windows reparse tags; those
workspaces require a native adapter. Node path APIs are not a substitute for directory-handle-relative syscalls.
The root and its ancestors must therefore be private from continuously hostile
same-authority namespace mutation. Use account/container isolation or a native
adapter for that stronger threat model. A detected race always fails closed;
read-only mode remains a usability hint rather than authorization.
