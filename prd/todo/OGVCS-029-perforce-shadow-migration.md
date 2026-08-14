# OGVCS-029 — Perforce importer and shadow migration

**Status:** Todo  
**Release:** R2 — Studio Alpha  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-002, OGVCS-007, OGVCS-010, OGVCS-015, OGVCS-016, OGVCS-017, OGVCS-020, OGVCS-045  
**Blocks:** OGVCS-033  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

A studio can inventory and deterministically import selected Perforce history, run a one-way shadow until differences are explained, execute a rehearsed cutover, and retain an auditable path back without requiring a flag-day blind migration.

## Problem

Perforce repositories encode semantics across depot paths, file types, changelists, branches/streams, integration records, lazy copies, labels, protections, and large archives. A bulk file copy loses history and trust; an indefinite dual-write system creates two authorities. Migration needs staged evidence and one explicit authority transition.

## Scope

### In scope

- Read-only inventory/preflight, deterministic import of selected depots/streams/history, path/type/identity policy, source-to-target mappings, and fidelity report.
- Resumable one-way Perforce-to-OpenGameVCS shadow ingestion, periodic tree/content comparison, cutover readiness, final delta/freeze procedure, and rollback window.
- Optional selected labels and shelves where source APIs provide stable complete data; unsupported semantics remain explicit.

### Out of scope

- P4 wire compatibility, permanent bidirectional synchronization, automated multi-master conflict resolution, or changing/deleting the source server.

## Users and journeys

- **Migration lead:** inventories a real depot, chooses history/path/type/stream policies, imports, tails new changes, resolves discrepancies, and receives a go/no-go report.
- **Studio administrator:** performs an externally coordinated source freeze, final sync/verification, user switch, and documented rollback if acceptance fails.
- **Developer/artist:** looks up an OpenGameVCS snapshot/change/FileID from an original depot path, revision, or changelist.

## Requirements

### Functional

- **OGVCS-029-FR-01:** Preflight SHALL inventory selected depot/stream graph, changelists, revisions, integrations, lazy copies, labels, shelves, file types/modifiers, symlinks, path collisions, protections/mappings, archive availability, bytes, and source server capabilities.
- **OGVCS-029-FR-02:** The operator SHALL approve an immutable migration policy covering included scope/time, branch/stream mapping, path/case transformation, file-type/lock policy, identity, timestamps, descriptions/jobs metadata, labels, shelves, obliterated/missing archives, and unsupported records.
- **OGVCS-029-FR-03:** Import SHALL preserve selected submitted change ordering, atomic change boundaries, file bytes/digests, delete/move/branch relations where representable, author/time/description provenance, and parent/integration mappings under documented deterministic rules.
- **OGVCS-029-FR-04:** Perforce exclusive/binary/filetype/typemap semantics SHALL map to explicit OpenGameVCS content and lock policies; lossy or ambiguous mappings SHALL block or require recorded operator disposition.
- **OGVCS-029-FR-05:** Every source server/depot/path/revision/changelist/stream/label and imported archive SHALL have a durable target ID/status mapping and safe lookup interface.
- **OGVCS-029-FR-06:** Import/shadow data SHALL remain isolated until its reachable graph passes OGVCS-017 and selected branch roots reconcile to source content under the migration policy.
- **OGVCS-029-FR-07:** Shadow ingestion SHALL be one-way, ordered from a durable source watermark, resumable/idempotent, lag-visible, and unable to overwrite target-native history.
- **OGVCS-029-FR-08:** Comparison SHALL report tree/content identity plus classified metadata/integration/policy differences for each checkpoint; unexplained differences SHALL block cutover readiness.
- **OGVCS-029-FR-09:** Cutover SHALL require a rehearsed plan, verified backup, externally confirmed source write freeze, final watermark/delta, zero unexplained P0 differences, target verification, identity/access validation, client communication, and named rollback decision window.
- **OGVCS-029-FR-10:** The tool SHALL never mutate, freeze, or disable the Perforce source unless the operator performs a separate explicitly documented source-administration action outside importer credentials.
- **OGVCS-029-FR-11:** Final evidence SHALL include source fingerprint/capabilities, policy hash, mappings, watermarks, counts/bytes, exceptions, reconciliation, verification, sign-offs, cutover time, and rollback state.
- **OGVCS-029-FR-12:** Credentialed Perforce API/archive acquisition SHALL run only in the OGVCS-045 broker; metadata/archive parsing and conversion SHALL run as credential-free, no-network, immutable-input sandbox jobs with declared limits and validated outputs.
- **OGVCS-029-FR-13:** Source file/revision/integration mapping SHALL allocate each target FileID once and persist it across historical import and shadow retry; moves/integrations/copies SHALL follow the explicit identity policy and path text SHALL not become identity.

### Quality attributes

- **OGVCS-029-NFR-01:** Identical source snapshot and migration policy MUST produce identical target roots and mapping/report digests.
- **OGVCS-029-NFR-02:** Import credentials MUST be read-only and least privilege; source content and credentials MUST not enter shared telemetry.
- **OGVCS-029-NFR-03:** The shadow pipeline MUST handle the design-partner peak change/archive rate with measured headroom and a bounded final-cutover catch-up estimate.
- **OGVCS-029-NFR-04:** Parser escape, credential/network access, malicious archive, traversal, bomb, hang, fork and output-flood cases MUST fail the OGVCS-045 profile without source mutation or partial target publication.

## Interfaces and data

Define Perforce capability/inventory report, broker acquisition/staged-input request, sandbox parser job/output policy, migration policy, source identity tuple, type/path/stream/FileID mapping, watermark/checkpoint, difference classification, exception disposition, cutover-readiness report, and final evidence bundle. Extend the generic import mappings from OGVCS-020.

## Development plan

1. Implement brokered read-only Perforce capability/archive acquisition and inventory/preflight, immutable migration-policy schemas, OGVCS-045 jobs, and deterministic path/type/FileID/stream mapping reports.
2. Implement credential-free sandboxed historical changelist/archive/integration conversion, durable source/FileID mappings, isolated staging, target graph verification and tip reconciliation.
3. Implement resumable ordered shadow tailing from a durable watermark, continuous classified comparison, lag/readiness reporting, and target-native-history isolation.
4. Complete golden/source-version/load/kill-resume tests and two full backup/freeze/final-delta/switch/rollback rehearsals before exposing the cutover command/runbook.

## Acceptance criteria

- **OGVCS-029-AC-01:** A golden Perforce fixture covering streams/branches, merges/copies, moves, deletes, lazy copies, filetype modifiers, Unicode/case, labels, selected shelves, and missing archives yields expected target history or explicit dispositions.
- **OGVCS-029-AC-02:** Kill/retry/source-timeout tests across inventory, archive copy, conversion, verification, shadow tail, and publish yield the same roots/watermark without duplicates or partial visibility.
- **OGVCS-029-AC-03:** Reconstructed tip trees/bytes for every selected cutover branch match the source under declared transformations; every non-match has a reviewed classification.
- **OGVCS-029-AC-04:** The shadow sustains partner peak load, reports accurate lag, catches up within the cutover budget, and never treats target-native writes as source input.
- **OGVCS-029-AC-05:** A full rehearsal performs backup, freeze coordination, final delta, verification, client switch, smoke build, and rollback within agreed time using only published runbooks.
- **OGVCS-029-AC-06:** OGVCS-045 canaries prove parsers cannot access credentials, network, host/control-plane state, or direct publication; malicious archive/resource cases leave source and target authority unchanged.
- **OGVCS-029-AC-07:** Move/branch/copy/delete/recreate, historical retry, shadow retry and malicious duplicate-ID cases preserve the declared FileID mapping or block publication with an explained conflict.

## Verification plan

Golden Perforce server/depot corpus, OGVCS-045 sandbox/canary/malicious archive cases, FileID mapping properties, deterministic reruns, source-version capability matrix, archive corruption/missing cases, type/path edge cases, shadow load/lag tests, kill/resume fault matrix, permission review, tree reconciliation, and two cutover rehearsals before production.

## Telemetry and operations

Expose phase, source watermark/lag, scanned/imported/reused objects and bytes, mapping exceptions, classified differences, verifier state, estimated catch-up, and readiness gates. Detailed depot paths/descriptions/users stay inside the access-controlled migration evidence store.

## Rollout and rollback

Run inventory and import without target publication, publish an isolated mirror, enable read-only shadow comparison, rehearse, then coordinate a single authority cutover. During the declared rollback window, preserve/freeze target writes per plan and keep source recoverable; no automated reverse synchronization is implied.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Hidden Perforce semantics cause fidelity loss | Capability inventory, golden fixtures, explicit exception dispositions |
| Dual authority corrupts history | One-way shadow and explicit freeze/cutover boundary |
| Migration never catches up | Peak-rate benchmark, lag SLO, bounded final-delta estimate |
| Rollback exists only on paper | Two rehearsals, named decision maker/window, preserved source/backup |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
