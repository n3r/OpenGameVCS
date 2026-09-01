# OGVCS-012 — Workspace index and scalable status

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-004, OGVCS-005, OGVCS-011  
**Blocks:** OGVCS-013, OGVCS-014, OGVCS-016, OGVCS-022, OGVCS-037, OGVCS-042, OGVCS-043  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-09-01

## Outcome

`status` accurately reports local adds, edits, deletes, moves, type changes, conflicts, and materialization state on million-path workspaces without routinely scanning or hashing the full tree.

## Problem

Game workspaces can contain millions of paths. A full filesystem walk/hash on every status makes the client unusable, while trusting file notifications without gap recovery can silently omit changes.

## Scope

### In scope

- Durable local baseline/materialization index and workspace generation.
- OS change-journal/watch adapters with cursor persistence and gap detection.
- Fast metadata fingerprint followed by content hashing only when required.
- Versioned ignore rules, untracked discovery boundaries, move hints, and reconciliation.
- Status API/CLI result and recovery/repair.

### Out of scope

- Sync planning/execution, file upload, virtual placeholders, or semantic diff.

## Users and journeys

- **Contributor:** receives an accurate status in seconds after changing a small working set in a million-path workspace.
- **Client:** detects missed watcher events after sleep/crash and reconciles before reporting clean.
- **Support engineer:** explains why a path is dirty, ignored, unmaterialized, conflicted, or requires hash verification.

## Requirements

### Functional

- **OGVCS-012-FR-01:** The index SHALL record baseline snapshot/tree/FileID/manifest, materialization state, portable mode, local fingerprint, watcher cursor, and pending/conflict state without storing plaintext credentials.
- **OGVCS-012-FR-02:** Windows USN, macOS FSEvents, and Linux inotify adapters SHALL persist progress and emit a mandatory reconciliation condition on overflow, unsupported filesystem, cursor loss, or unclean shutdown.
- **OGVCS-012-FR-03:** Clean status SHALL never be reported while a required reconciliation is incomplete or a watched root cannot be trusted.
- **OGVCS-012-FR-04:** Candidate changes SHALL use safe metadata fingerprints and compute full manifest/hash before submit or when ambiguity exists; timestamps alone SHALL not establish content equality.
- **OGVCS-012-FR-05:** Status SHALL distinguish modified, added, deleted, moved/renamed hint, type/mode change, untracked, ignored, conflicted, metadata-only, absent-by-spec, and inaccessible/error.
- **OGVCS-012-FR-06:** Ignore rules SHALL be versioned repository policy plus workspace-local nonshareable rules, with deterministic precedence and an explain command.
- **OGVCS-012-FR-07:** Index transactions SHALL be crash-safe and tied to workspace generation so an interrupted sync cannot mix old baseline with new files.
- **OGVCS-012-FR-08:** Repair SHALL rebuild from an immutable baseline and filesystem without discarding local files; uncertain identity becomes an explicit status.

### Quality attributes

- **OGVCS-012-NFR-01:** Warm no-change status at one million tracked paths SHALL achieve p95 under 2 seconds on the reference workstation without full-tree walk/hash.
- **OGVCS-012-NFR-02:** Status with 1,000 journaled changes SHALL target p95 under 5 seconds after required reconciliation.
- **OGVCS-012-NFR-03:** Index corruption, watcher loss, or timestamp spoofing MUST not cause a changed file to be submitted as unchanged or a dirty workspace to be declared authoritatively clean.

## Interfaces and data

Publish local index schema/version, watcher adapter contract, status entry/reason, reconciliation state/progress, ignore evaluation, and repair API. OGVCS-013/014/016 consume transactional index updates.

## Development plan

1. Implement the versioned local index/journal schema, baseline import, atomic updates, integrity checks, and safe rebuild command.
2. Implement platform watcher adapters, cursor persistence, overflow/unclean-shutdown detection, event coalescing, and bounded reconciliation.
3. Implement status classification, lazy hashing, move/FileID inference, ignore/materialization/conflict states, paging, and CLI/JSON integration.
4. Run crash/corruption/adversarial and million-path performance suites, tune bounded memory/I/O, add diagnostics, and roll out watcher acceleration behind full-scan comparison.

## Acceptance criteria

- **OGVCS-012-AC-01:** Reference performance targets pass on all supported OS profiles or a documented platform exception blocks R1.
- **OGVCS-012-AC-02:** Every OGVCS-004 file operation and watcher fault produces correct status after recovery.
- **OGVCS-012-AC-03:** Crash at every index transaction point leaves prior generation valid or triggers repair; no false clean result occurs.
- **OGVCS-012-AC-04:** Timestamp-preserving edits, rename cycles, case-only rename, locked-open files, and ignored/untracked transitions are detected correctly.
- **OGVCS-012-AC-05:** Rebuilding a corrupt index preserves local content and yields the same status as a clean authoritative scan.

## Verification plan

Cross-OS watcher matrix, state-machine/property tests, timestamp/case adversarial fixtures, index corruption/crash injection, million-path benchmarks, and repair equivalence.

## Telemetry and operations

Expose status duration, candidates/hashed paths, journal events/gaps, reconciliation reason/duration, index size/generation, repair count, and filesystem capability. Path labels are excluded.

## Rollout and rollback

Begin with watcher plus mandatory verification mode; enable optimized paths after parity measurement. Index schema supports rebuild, so downgrade discards/rebuilds index rather than rewriting user files.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Watch APIs miss changes | Gap tracking, conservative reconciliation, hash before submit |
| Reconciliation still scans too much | Sparse materialization boundaries and directory summaries with correctness tests |
| Index DB becomes corrupt/hot | WAL/atomic generations, repair, bounded transactions, profiling |

## Completion evidence

This section records an incomplete private candidate. It is not completion
evidence sufficient to move this PRD out of Todo.

- **Implementation changes:** the Rust local CLI has a bounded authenticated
  baseline sink, sealed create-new generations, fixed-width collision-safe
  lookup, strict hash-chained watcher journal, an opening/final native-watcher
  status fence, deterministic status paging, a v2 HMAC cursor, and Applied
  Add/Move/Delete staging visibility. Per-page authenticated/kernel-locked
  reader leases, a durable logical epoch, and bounded physical generation
  compaction protect active readers. Repair subscribes before its scan and
  holds one mutation lock through verification, its final barrier, and
  publication. Compaction preserves the current generation, its authenticated
  numeric predecessor, and every locked or unexpired reader generation; it
  deletes no workspace content. A bounded test-only full-scan oracle now reads
  the immutable baseline and workspace independently of the index classifier;
  healthy repair and authenticated rebuild of corrupt watcher-state/event-chain
  artifacts match its complete deterministic paged stream. Rebuild capacity
  preflight authenticates existing reader leases before transition
  publication, and distinct status candidates are rejected at the exact
  in-memory bound before map insertion while preserving existing duplicate-key
  precedence. Same-path coalescing now preserves creation, conflict, and rename
  lineage across later events; watcher-only transient destinations collapse
  only when no Applied staged intent owns them, and watcher rename destinations inherit
  a source-baseline FileID when one exists and the destination has no distinct
  baseline identity. A rename onto such a baselined destination is Conflicted
  without a guessed FileID and requires reconciliation for changed,
  equal-content, and absent outcomes. A post-deletion create at a rename
  destination clears stale lineage and is Added without the source FileID;
  conflict remains sticky. Staging records bind no watcher cursor or sequence,
  so every Applied Add/Move/Delete path-role intersection with delete→create
  reset is instead Conflicted without FileID/prior and requires reconciliation.
  Only the exact same staged Move source→destination watcher edge is compatible;
  differing incoming lineage or rename-out from any staged role conflicts the
  complete staged intent and watcher destination. Move/Delete staged
  FileIDs are lent only after any immutable source-baseline ID matches and the
  source is observed absent; staged Add on a baseline path conflicts. Persisted
  staging paths are structurally validated,
  their repository keys are re-derived and matched, and duplicate intent IDs or
  repository/platform path identities fail on every load. Candidate intent-ID
  or path-identity overlap fails again before another staging or filesystem
  mutation. Definitive post-stage reset semantics require a future durable
  watcher-order binding. This does not establish FileID semantics or
  repository-lifetime uniqueness where no immutable local source baseline is
  authoritative. Its
  private candidate contract is
  `client/native-cli/rust/contracts/workspace-index/v1` version
  `0.1.0-rc.4`, while committed generation bytes remain readable as
  `0.1.0-rc.1`.
- **Test and benchmark results:** Rust 1.82 focused tests cover crash boundaries,
  a synced journal tail without state publication, withheld final-barrier
  events, session/authority substitution, closed-but-continuous watcher state,
  idle-cursor pagination, concurrent transition/status races, staging changes,
  active/settings/profile/case/cursor staleness, digest collisions, case
  collisions/order, symlink/reparse rejection, timestamp-preserving edits,
  same-length index corruption, deleted-directory uncertainty, transient
  untracked create/delete, and repair preserving workspace files. Five focused
  repair-equivalence tests additionally cover healthy and degraded-continuity
  oracle parity across complete bounded pages, reconstructible watcher/event
  corruption, fail-closed active/seal/entry/lookup/finding/ignore/history/key/
  lease/control corruption before publication, exact pre-insertion candidate
  admission, and preservation of captured workspace bytes, node types,
  modification times, read-only states, and portable modes. Retention
  tests cover the independent HMAC known answer and hostile variants,
  cross-workspace/repository leases, exact 127/128/129 lease admission,
  prepublication history capacity, locked-reader pinning, abandoned-reader
  expiry, current/predecessor retention, malformed/unknown controls before
  intent, deterministic mutation races, one-call paging leases, and idempotent
  recovery at epoch, lease, intent, unlink, directory-sync, state, and intent-
  removal boundaries. Table-driven local tests additionally cover
  create→modify, create→delete, delete→create, modify→delete,
  conflict→modify, rename→modify/delete, rename→delete→create identity reset,
  baseline-destination rename ambiguity for changed/equal/absent outcomes,
  Applied Add/Move/Delete watcher overlap, all staged path-role identity resets,
  incompatible incoming/outgoing watcher lineage for every staged role, direct source reoccupation, immutable-source
  FileID mismatch, and staged-Add/baseline ambiguity,
  healthy staged repository/platform collisions, persisted-key corruption, and
  duplicate loaded identities plus duplicate candidate intent-ID admission that
  fail before workspace mutation. This isolated source passed 72
  Rust 1.82 library tests with 2 exact bounded-release tests ignored, 2 binary
  unit tests, 3 CLI contract tests, 2 contract-vector tests, and 12
  production-foundation tests; Rustfmt, warning-denied Clippy, packed-crate,
  installed-artifact hermetic, Node 24 contract/spec, and roadmap gates also
  passed locally. The prior default suite passed
  from its exact integrated source on hosted Linux, macOS, and Windows in
  [run 33513695931](https://github.com/n3r/OpenGameVCS/actions/runs/33513695931);
  the [retained record](../../docs/evidence/OGVCS-012/README.md) binds all three
  jobs. A local
  exact 1,000 changed-file candidate run classified and content-verified every
  item in 210 ms. A local exact 100,000-event run used 100 chunks of 1,000,
  completed in 11.619 s, rejected event 100,001 before append, verified the
  complete chain, and proved a new generation resets the bound. These are
  single-host scale measurements, not p95 or hosted exact-scale evidence.
- **Security/reliability review:** status fails closed during an in-progress
  generation and brackets every filesystem probe with opening/final native
  barriers. An event or authority/transcript change rejects the in-flight page;
  only a bound cursor-only idle advance can continue pagination. Lookup digest
  hits never substitute a different full path. A portable or safe third-party
  watcher implementation cannot mint native continuity. Cursor MACs bind both
  repository and local ignore digests, exact staging state, watcher authority
  and transcript, and the generation/settings/filter/path key. A status lease
  is created, synced, authenticated, and shared-locked before releasing the
  mutation lock; compaction authenticates the complete bounded control/lease/
  generation namespace before publishing intent. Forged, malformed, cross-
  boundary, or overflowing metadata fails before deletion. Rebuild likewise
  rejects corrupt sealed/history/control authority rather than silently
  replacing it; only the reconstructible watcher-state/event-chain class is
  replaced through authenticated baseline acquisition. Owner HMACs and
  kernel locks do not solve malicious same-authority lock-namespace replacement
  or promise Unix unlink-by-open-handle semantics.
- **Documentation/runbooks:** the Rust README and
  `docs/reviews/OGVCS-012-workspace-index-boundary-review.md` describe the
  runnable gates and exact residuals.
- **Rollout result:** none. The first-party CLI still installs unavailable
  public routes, and optimized status/compaction has not been enabled. Mixed
  old/new processes are unsupported for the private candidate; restart before
  compaction, and rebuild the private index before downgrade.

### Candidate residuals blocking completion

- No authenticated public workspace-baseline/status route or public CLI/JSON
  journey exists.
- No built-in Windows USN, macOS FSEvents, or Linux inotify authority can issue
  the private continuity proof; every production-callable implementation is
  degraded.
- The exact one-million-path warm p95 target, three-OS watcher matrix, complete
  OGVCS-004 operation/fault matrix, rename cycles, multi-hop rename/source
  reoccupation, case-only rename, FileID semantic binding and repository-
  lifetime uniqueness beyond locally immutable sources,
  directory/file replacement, locked-open files, and repair
  equivalence for a safe public discard/reseed of non-reconstructible sealed
  authority remain unproven. The bounded test-only oracle is not that public
  recovery operation and has no exact-candidate hosted cross-OS record.
- Staging records have no watcher cursor/sequence binding. The covered
  non-commutative intersections fail closed; definitive post-stage identity
  reset semantics remain unimplemented.
- Telemetry, support-facing explain/repair/compaction commands, rollout
  comparison, and downgrade behavior are not wired into a public product
  surface.
