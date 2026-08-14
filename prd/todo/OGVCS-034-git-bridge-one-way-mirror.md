# OGVCS-034 — Git bridge and one-way mirror

**Status:** Todo  
**Release:** R3 — Production Beta  
**Priority:** P1  
**Owner:** Unassigned  
**Depends on:** OGVCS-015, OGVCS-019, OGVCS-020, OGVCS-025, OGVCS-033  
**Blocks:** None  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

A studio can expose a deterministic, authorized code-oriented view of native snapshots as a one-way Git/Git LFS mirror, preserve existing read-only build/review consumers during adoption, and trace every mirrored commit back to the authoritative combined code-and-asset snapshot.

## Problem

Git ecosystem compatibility lowers migration risk, but pretending Git can represent the complete native model invites two authorities and fidelity loss. A safe bridge needs an immutable projection policy, explicit transformations, content-before-ref publication, durable identity mappings, and a hard stop if the destination diverges.

## Scope

### In scope

- Initial history projection and incremental OpenGameVCS→Git one-way mirror for selected branches/path views.
- Deterministic commit/tree/blob/LFS pointer generation, author/time/message mapping, merge-parent policy, tags where configured, and native snapshot↔Git commit mapping.
- Dedicated destination namespace, event-driven updates with reconciliation, status/provenance links, and operator controls.

### Out of scope

- Git→OpenGameVCS writes, bidirectional sync, Git server emulation, native asset locking through Git, or representing hidden/excluded native state in Git metadata.

## Users and journeys

- **Programmer:** clones the mirror with familiar Git tooling and can map a commit to the immutable native snapshot used by the full game build.
- **CI/review owner:** keeps a code-only consumer running while authoritative combined submits and reviews live in OpenGameVCS.
- **Operator:** sees mirror lag/divergence, retries destination outages, and never force-pushes over an unexpected external write.

## Requirements

### Functional

- **OGVCS-034-FR-01:** A mirror SHALL bind one source repository/authorized service identity, selected source branches/tags, include/exclude path view, transformation rules, identity mapping, LFS policy, destination/namespace, and history policy in an immutable versioned configuration generation.
- **OGVCS-034-FR-02:** Preflight SHALL report hidden/excluded paths, path/case incompatibilities, modes/symlinks, large files/LFS, parent gaps, tags, identities, signatures, messages, and any native operation/metadata not representable in Git.
- **OGVCS-034-FR-03:** Projection SHALL use only data currently authorized to the mirror identity; trees, blobs, commits, messages, counts, tags, LFS objects, and errors SHALL not encode excluded-path or hidden-parent information.
- **OGVCS-034-FR-04:** Identical source snapshot/configuration/tool version SHALL deterministically produce the same Git tree and commit identity under documented timestamp/author/message/parent rules.
- **OGVCS-034-FR-05:** Configuration SHALL choose and record whether asset-only/no-visible-change snapshots produce empty mapping commits or collapse onto a prior commit; every native source snapshot SHALL retain an unambiguous mapping disposition.
- **OGVCS-034-FR-06:** Merge parent projection SHALL include only mapped authorized parents under the declared policy and SHALL never invent ancestry silently; parent loss/collapse SHALL be reported.
- **OGVCS-034-FR-07:** Files selected for LFS SHALL generate canonical pointer blobs; verified LFS content SHALL be uploaded and confirmed before any Git ref that references it advances.
- **OGVCS-034-FR-08:** Incremental operation SHALL consume durable OGVCS-019 events with idempotent checkpoints and periodically reconcile source roots, mapping records, destination commits/trees, LFS objects, and refs.
- **OGVCS-034-FR-09:** Destination ref updates SHALL use compare-and-swap/fast-forward inside a dedicated namespace. Unexpected modification, deletion, or non-fast-forward state SHALL halt that ref and alert; the bridge SHALL not force overwrite automatically.
- **OGVCS-034-FR-10:** Initial publish and every incremental ref advance SHALL occur only after all reachable Git/LFS objects verify at the destination and the snapshot↔commit mapping is durable.
- **OGVCS-034-FR-11:** Mirror commits SHALL include a documented non-secret provenance marker for source repository/export namespace, native snapshot ID, and projection-policy generation, with safe lookup in both directions.

### Quality attributes

- **OGVCS-034-NFR-01:** Rebuilding a mirror from the same source/configuration MUST reproduce all Git object IDs/refs and mapping disposition except explicitly documented destination-side signatures.
- **OGVCS-034-NFR-02:** Destination outage, throttling, duplicate/reordered event, and process crash MUST not create partial refs, missing LFS dependencies, or skipped source checkpoints.
- **OGVCS-034-NFR-03:** Mirror lag under the design-partner peak source rate MUST stay within the approved SLO and expose a bounded catch-up estimate.

## Interfaces and data

Define projection policy/generation, preflight fidelity report, source snapshot disposition, native↔Git mapping, LFS publish receipt, destination ref precondition, event checkpoint, reconciliation result, and mirror health/lag. Import and export identity rules reuse OGVCS-020/033 where compatible.

## Development plan

1. Implement immutable projection policy/preflight and deterministic native snapshot/tree/identity/history to Git commit/tree/blob/LFS mapping with durable dispositions.
2. Implement initial history projection, verified Git/LFS object publication, dedicated-ref compare-and-swap and source↔destination provenance lookup.
3. Implement event-driven incremental checkpoints, retry/backoff, periodic reconciliation, authorization filtering and divergence halt without force push.
4. Complete golden/rebuild/fault/non-disclosure/large-bootstrap tests, publish operator tooling, and expose the mirror read-only after isolated reconciliation.

## Acceptance criteria

- **OGVCS-034-AC-01:** Golden native DAGs with branches, merges, moves, deletes, executable/symlink files, Unicode/case cases, hidden paths, asset-only commits, tags, and LFS produce expected Git objects/mappings.
- **OGVCS-034-AC-02:** Independent rebuild yields identical commits/trees/refs and a clean source/destination reconciliation report.
- **OGVCS-034-AC-03:** Kill, duplicate/reorder, Git outage, and LFS partial-upload tests eventually converge without a ref exposing missing content or an unrecorded snapshot gap.
- **OGVCS-034-AC-04:** External destination mutation halts safely and preserves both states/evidence; no automatic force push or reverse native mutation occurs.
- **OGVCS-034-AC-05:** A mirror identity excluded from an asset/path cannot leak its name, bytes, hash, size, parent effect, message, or existence through the Git/LFS repository or service telemetry.

## Verification plan

Golden projection corpus, deterministic rebuild, Git object/fsck and LFS verification, event/reconciliation fault matrix, destination mutation tests, authorization/non-disclosure review, large-history bootstrap, sustained incremental load, and consumer clone/build smoke tests.

## Telemetry and operations

Expose safe mirror/config generation, source/destination checkpoint, lag, objects/bytes, LFS status, retries, divergence, reconciliation age/result, and ref update. Sensitive paths/messages/authors remain in destination according to its approved view, not shared monitoring.

## Rollout and rollback

Build into an isolated destination namespace, reconcile, expose read-only to pilot consumers, then adopt incrementally. Rollback stops source consumption and freezes the last consistent mirror; it never changes native history or deletes/rewrites destination data automatically.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Teams treat Git as a second write authority | Read-only/dedicated refs, divergence halt, documented native authority |
| Partial projection leaks protected assets | Authorization-bound service view and end-to-end leak tests |
| Git ref advances before LFS bytes exist | Upload/verify all dependencies before compare-and-swap |
| Mapping loses native combined-snapshot meaning | Explicit every-snapshot disposition and provenance lookup |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
