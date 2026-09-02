# OGVCS-014 — Local checkpoints and offline recovery

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-007, OGVCS-011, OGVCS-012, OGVCS-013  
**Blocks:** OGVCS-015, OGVCS-022  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-09-02

## Outcome

Users can save, inspect, chain, restore, squash, and later publish immutable local checkpoints while disconnected, without implying that a hard-lockable edit remains globally exclusive offline.

## Problem

Centralized systems make local experimentation and recovery dependent on a server. Game contributors need safe work-in-progress history, but local state must not be confused with shared branches or valid online locks.

## Scope

### In scope

- Local checkpoint DAG rooted at server snapshot, using canonical manifests/chunks in shared cache.
- Create/list/show/diff/restore/delete/squash and crash recovery.
- Pinning, local metadata integrity, optional at-rest integration with OS protection, and publish handoff.
- Lock-receipt snapshot and offline exclusivity warning state.

### Out of scope

- Server shelves/reviews, shared local checkpoints, branch merge algorithm, or offline hard-lock guarantee.

## Users and journeys

- **Developer:** checkpoints an experiment on a flight, creates another checkpoint, then merges/rebases and publishes later.
- **Artist:** saves a recoverable local checkpoint before a risky DCC conversion.
- **Support engineer:** recovers the last complete checkpoint after client crash without deleting newer working files.

## Requirements

### Functional

- **OGVCS-014-FR-01:** A checkpoint SHALL record parent, base server snapshot, ordered local operations, manifests/chunks, message, time, workspace/spec identity, and lock receipts/status.
- **OGVCS-014-FR-02:** Creation SHALL be atomic: an interrupted checkpoint is either absent or discoverable as incomplete/recoverable and never replaces the last valid checkpoint.
- **OGVCS-014-FR-03:** Restore SHALL preview affected paths, preserve uncheckpointed changes by default, and require explicit action to overwrite/discard them.
- **OGVCS-014-FR-04:** Diff/list/show SHALL work without network for all locally available content and clearly mark unavailable baseline bytes.
- **OGVCS-014-FR-05:** Checkpoint chunks SHALL use the OGVCS-013 shared-cache pin contract until checkpoint deletion plus recovery grace; cache eviction, selection change and workspace removal SHALL respect pins.
- **OGVCS-014-FR-06:** Publish handoff SHALL identify the checkpoint/base and invoke normal current authorization, ancestry, content, policy, and lock validation.
- **OGVCS-014-FR-07:** When connectivity or lock lease cannot be verified, hard-lockable changes SHALL display `exclusivity unverified`; the client SHALL not claim a valid exclusive reservation.
- **OGVCS-014-FR-08:** Delete/squash SHALL be recoverable for a grace period and SHALL verify that no descendant/workspace pin is orphaned.

### Quality attributes

- **OGVCS-014-NFR-01:** Checkpoint operations MUST work with the server unreachable after the base and required bytes are local.
- **OGVCS-014-NFR-02:** Power loss at every metadata/chunk/index update MUST preserve all previously complete checkpoints.
- **OGVCS-014-NFR-03:** Local checkpoint metadata MUST be integrity-checked and must not cause writes outside the workspace/cache roots when restored.

## Interfaces and data

Define local checkpoint object/index, OGVCS-013 cache pin/eviction transition, operation list, availability marker, lock receipt state, and publish request. Reuse OGVCS-002/007 canonical identities so publish does not re-encode content.

## Development plan

1. Implement the local checkpoint object/index format, content capture through OGVCS-007, OGVCS-013 cache pin integration, atomic creation, verification, listing, and retention accounting.
2. Implement diff/inspect/restore/open-copy operations with exact local-change preflight and crash-safe workspace application.
3. Add checkpoint chains, metadata/message updates, squash, expiry/pin, later publish conversion, and explicit offline/lock-state semantics.
4. Complete corruption/disk-full/kill/restart/three-OS tests, add recovery diagnostics and documentation, and roll out creation/inspect before restore/destructive actions.

## Acceptance criteria

- **OGVCS-014-AC-01:** Create/diff/restore/squash works offline across all supported platforms and reconstructs exact bytes.
- **OGVCS-014-AC-02:** Every injected crash leaves prior checkpoints valid and recovery reports, rather than hides, incomplete state.
- **OGVCS-014-AC-03:** Restore never overwrites newer uncheckpointed work without explicit confirmed action.
- **OGVCS-014-AC-04:** OGVCS-013 cache pressure, selection change, workspace removal and eviction races cannot remove pinned checkpoint chunks; corrupt chunks are detected before restore.
- **OGVCS-014-AC-05:** Restore or publish-request generation never treats a stored lock receipt as authority; it remains explicitly untrusted metadata for later server validation.

## Verification plan

Offline integration, checkpoint DAG properties, crash/corruption tests, cache pin/eviction tests, restore obstruction matrix, and stale lock receipt tests.

## Telemetry and operations

Local-only metrics: checkpoint count/bytes, creation/restore duration, cache pins, incomplete recovery, and unverified lock warnings. Nothing is sent remotely without explicit telemetry consent.

## Rollout and rollback

Enable after local format recovery tests. Workspace clients retain read support for the previous checkpoint format; downgrade exports or restores checkpoints before rebuilding local metadata.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Users mistake checkpoint for backup/shared work | Clear local-only labels and publish/share actions |
| Checkpoints consume disk indefinitely | Quotas, visibility, graceful delete, never evict silently |
| Offline binary edits conflict | Explicit unverified state and server reconciliation |

## Completion evidence

- **Implementation changes:** an unpublished, unwired Rust 1.82 candidate now
  records a bounded immutable local checkpoint with a content-derived ID,
  complete local parent, exact caller-supplied repository/base/workspace/spec/
  path bindings, contiguous add/modify/copy/move/delete operations, OGVCS-002
  FileID/manifest/chunk references, consistent same-identity projections and
  the OGVCS-007 2 MiB chunk maximum,
  message/time, and a digest-only historical lock-receipt snapshot whose only
  state is `historical-untrusted-exclusivity-unverified`. Fixed workspace-
  confined create-new files publish intent, record, and completion manifest
  last with file sync barriers and directory sync barriers where the platform
  implements them. The exact Windows post-identity `ERROR_ACCESS_DENIED`
  capability classification establishes no directory-entry power-loss
  guarantee. Complete-only list/show/verify and deterministic incomplete
  recovery are local-library surfaces; recovery seals only an exact reread
  intent+record or reports incomplete/corrupt state without intentionally
  addressing ordinary workspace paths. Recovery re-syncs surviving exact
  files and attempts the platform-scoped directory barrier before trusting or
  sealing them. A second private surface now verifies the selected complete
  record and its bounded ancestor chain, requires exact caller-supplied
  repository/base/workspace/spec/path bindings, and folds only that record's
  final touched-path effects into a deterministic read-only application
  preview. Exact current-path observations and final content facts bind path
  collision keys, ordinals, FileIDs, manifest/whole-file/chunk projections and
  availability. Availability remains `AvailableUnverified` or `Unavailable`;
  the crate reads no ordinary workspace/cache byte. The default preserves
  differing current work. Explicit replacement intent affects only preview
  classification and cannot bypass unknown/inaccessible/link/directory/
  collision/unavailable blockers or perform a write.
- **Test and benchmark results:** bounded Rust tests cover deterministic
  identity, list/show/verify, all seven create publication boundaries,
  preservation of a prior complete checkpoint and a newer workspace sentinel,
  corruption, unknown artifacts, substituted intent-only metadata, corrupt
  complete ancestry, missing/binding-mismatched parents, store/depth/path/
  object/count/byte/chunk/logical exact and max+1 bounds, same-identity
  manifest/chunk conflicts, safe arbitrary-name reporting, abstract self/
  cycle/missing/duplicate-ID/over-depth graphs, and Unix symlinks/hard links.
  Five preview groups cover the domain-separated digest known answer and
  reordered-input determinism, immutable-binding and path/FileID/content/
  disposition substitution, missing/extra facts and case collision,
  copy/move/repeated-touch folding, newer-work preservation, all supplied
  obstruction states, unavailable bytes, exact plus-one count/path/chain-byte/
  chain-operation/work/retained-memory bounds, and cancellation before retained
  projection. The test sentinel remains unchanged under both replacement
  intents.
  Rustfmt, warning-denied Clippy, exact offline packed-crate, Node source-policy,
  Windows cross-compilation, and roadmap gates are the local candidate boundary.
  Exact revision `fa61786b272a019b82f4e96eaaa47dbef60c5b6c` also passed the
  bounded source/package gates on hosted Linux, macOS, and Windows in
  [run 33664922225](https://github.com/n3r/OpenGameVCS/actions/runs/33664922225).
  This is source portability only; no scale, three-OS crash/corruption, or real
  power-cut result is claimed.
- **Security/reliability review:**
  [private local-checkpoint boundary review](../../docs/reviews/OGVCS-014-local-checkpoint-boundary-review.md).
  The unkeyed intent integrity frame binds expected record ID/digest/length
  without authenticating its local producer; recovery repeats that
  verification immediately before create-new manifest publication and rejects
  extraneous artifacts. Prospective-child depth and store-count admission occur
  before sealing/entry creation; regular artifact handles must be single-link.
  Manifest/chunk/cache and current-workspace facts remain untrusted caller
  observations. Historical lock receipts are ignored by preview, whose only
  lock result is the fixed unverified warning. Pathnames are reopened between
  checks, so malicious same-authority namespace replacement remains an
  explicit residual.
- **Documentation/runbooks:** the private crate README defines the exact
  identity domain, namespace, seven publication points, platform-scoped
  directory-durability nonclaim, recovery dispositions, preview digest/
  observation/replacement-intent boundary, limits, lock warning, gates, and
  nonclaims. There is no restore/publish/cache runbook because none of those
  operations exists in this tranche.
- **Rollout result:** none. There is no public CLI/JSON command, route,
  authorization/permission/grant check, lock authority, cache pin/eviction
  mutation, telemetry upload, restore, delete/squash, or publish handoff.
  OGVCS-014 remains **Todo** and no acceptance criterion is claimed.

### Candidate residuals blocking completion

- Full base-tree/checkpoint diff, restore/open-copy, executable filesystem
  obstruction preflight, overwrite confirmation/action, delete, squash,
  retention/grace, mutable messages, broader DAG operations, and publish
  conversion are absent. The selected-record application preview cannot
  account for untouched/newer paths or reconstruct a target tree.
- Shared-cache pins, eviction/selection/workspace-removal races, cache-byte
  availability and corruption verification, transfer/refetch, and recovery
  grace are absent; this candidate neither reads nor re-encodes content.
- The operation/manifest/chunk projection is not authenticated by a server or
  cache producer. The operation shapes omit entry kind/mode/policy, group and
  restore data, are not replayed against the base tree, and stored FileIDs are
  not allocation/lifetime authority. The supplied workspace/spec digest is not
  loaded from authenticated workspace metadata.
- Same-authority path replacement, full Unix ACL/ownership policy, Windows
  inherited-ACL/owner verification, real reparse/hard-link fault execution,
  actual power loss, three-OS crash/corruption, scale, real
  filesystem/cache observation, complete restore obstruction, lock
  reconciliation, and cache-race campaigns remain unproved.
- Public CLI/JSON/GUI integration, auth/permission/grant and request-root
  checks, lock validation, telemetry consent/upload, support diagnostics,
  rollout/rollback, and every OGVCS-014 acceptance criterion remain open.
