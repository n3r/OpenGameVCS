# OGVCS-035 — Authorization-safe search and review scale

**Status:** Todo  
**Release:** R3 — Production Beta  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-009, OGVCS-025, OGVCS-026, OGVCS-028  
**Blocks:** None  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Users can search authorized files, history, shelves, reviews, comments, and derived metadata and can navigate very large changes without result counts, facets, snippets, cache behavior, or index lag revealing protected work.

## Problem

Search engines are derived, eventually consistent stores optimized for broad candidate retrieval—the opposite of path non-disclosure. Filtering unauthorized hits only after search can leak existence through totals, ranking, timing, suggestions, or stale ACLs. Large reviews also need indexed pagination without becoming a bypass around repository authorization.

## Scope

### In scope

- Scaled indexes for path/name/type and authorized snapshot/change/shelf/review/comment/preview metadata.
- Authorization-safe query planning, totals/facets/suggestions/snippets, ACL/policy change handling, rebuild/reconciliation, staleness display, and large-review navigation.
- Content-text indexing disabled by default and enabled only for explicitly classified fields/formats under the same security model.

### Out of scope

- Public/global search, ML semantic search, image/audio similarity, general DAM/catalog taxonomies, or weakening non-disclosure for approximate results.

## Users and journeys

- **Contributor:** locates an authorized file across rename-aware history and jumps to its current path/change/review.
- **Reviewer:** filters a 100,000-file review by status/type/owner-safe metadata and loads deterministic pages without losing comments or approval context.
- **Security admin:** removes path access and verifies search, suggestions, counts, cache, and direct-document retrieval stop exposing it within a declared bound.

## Requirements

### Functional

- **OGVCS-035-FR-01:** Define a versioned indexable-field registry with source, classification, analyzer, retention, authorization scope, cardinality, snippet rule, and whether content indexing is permitted.
- **OGVCS-035-FR-02:** Every indexed document SHALL bind tenant/repository, source object/version, stable FileID where applicable, source generation, security-label/policy generation, and index-schema generation.
- **OGVCS-035-FR-03:** Query authorization SHALL be applied before a result contributes to hits, rank, total, facet, aggregation, suggestion, spelling correction, snippet, highlight, cache entry, timing class, or related-item response.
- **OGVCS-035-FR-04:** Direct document/result IDs SHALL be reauthorized against OGVCS-009; possession of an index ID or previously returned URL SHALL not preserve access.
- **OGVCS-035-FR-05:** ACL/policy/identity changes SHALL produce a durable invalidation/relabel event with a measured revocation bound; until safe application, affected results SHALL be suppressed/fail closed rather than served under stale grants.
- **OGVCS-035-FR-06:** Index ingestion SHALL be at-least-once/idempotent, detect cursor gaps, reconcile against authoritative generations, and support full online rebuild with atomic alias/generation switch.
- **OGVCS-035-FR-07:** Search results SHALL display indexed-at/source generation and an explicit pending/unknown state when freshness is outside policy; search SHALL never be authoritative for submit, lock, or branch state.
- **OGVCS-035-FR-08:** Large review change lists SHALL use stable cursor pagination over immutable shelf revision, support filter/sort/group summaries computed from authorized rows, and preserve FileID-bound comment threads.
- **OGVCS-035-FR-09:** Preview/derived metadata SHALL be searchable only while source authorization and converter/review artifact validity remain current; revoked artifacts SHALL disappear under the same bound.
- **OGVCS-035-FR-10:** Query syntax, regex/wildcard/fuzzy expansion, page size, aggregation, export, and rate SHALL be bounded per tenant/user to resist enumeration and resource exhaustion.
- **OGVCS-035-FR-11:** Operators SHALL be able to pause, drain, rebuild, compare generations, inspect safe lag/failures, delete a tenant/repository index, and reconstruct it entirely from authoritative state.

### Quality attributes

- **OGVCS-035-NFR-01:** Permission removal MUST suppress affected search/review surfaces within a declared maximum of 60 seconds; high-risk policies MAY require immediate query-time denial with zero stale window.
- **OGVCS-035-NFR-02:** On the reference million-path/history corpus, authorized simple search p95 MUST be under one second and a 100,000-file immutable review page/filter p95 under two seconds under declared load.
- **OGVCS-035-NFR-03:** Index loss or corruption MUST affect discovery/performance only; authoritative repository/review data remains intact and rebuildable.

## Interfaces and data

Define field/index schema, security label/policy generation, index document, ingestion/invalidation event, authoritative reconciliation cursor, safe query/response and count semantics, review-page cursor, rebuild comparison, staleness, and purge receipt.

## Development plan

1. Implement the classified field/schema registry, security-label/generation model and authoritative idempotent ingestion/invalidation pipeline.
2. Implement authorization-first exact search/direct lookup, then safe ranking/paging/snippets/counts/facets with bounded query syntax, caches and revocation checks.
3. Implement immutable large-review cursors/filter/group views, preview validity, online rebuild/atomic generation switch, reconciliation and full purge/recreate operations.
4. Complete leakage/timing/ACL-race/fault and million-path/100,000-change load tests, then stage exact lookup → metadata search → reviewed aggregate features.

## Acceptance criteria

- **OGVCS-035-AC-01:** A red-team query corpus cannot infer hidden documents/terms/users/reviews through hits, totals, facets, ordering, suggestions, snippets, direct IDs, errors, cache, pagination, timing buckets, or export.
- **OGVCS-035-AC-02:** Grant/revoke/move/rename/delete/policy/group changes during indexing/query meet the revocation bound and never return a result forbidden at response authorization time.
- **OGVCS-035-AC-03:** Duplicate/reordered/missing events, index outage, partial rebuild, corrupt document, and atomic generation switch reconcile to authoritative expected results.
- **OGVCS-035-AC-04:** Reference search and 100,000-file review workloads meet latency, throughput, memory, cardinality, and storage budgets with reproducible benchmark metadata.
- **OGVCS-035-AC-05:** Deleting the index and rebuilding from authoritative sources restores identical logical authorized results and FileID/comment associations.

## Verification plan

Authorization differential/red-team suite, timing/count bucketing tests, ACL race/property tests, ingestion fault/reconciliation matrix, schema migration/rebuild, index deletion recovery, query resource attacks, and million-path/large-review load benchmark.

## Telemetry and operations

Expose ingest/invalidation/reconciliation lag, suppressed-stale count, query latency/result bands, rate-limit/resource rejects, generation health, rebuild progress/diff, and review paging latency. Queries, terms, paths, snippets, comments, identities, and raw results are excluded from shared telemetry.

## Rollout and rollback

Start with exact authorized path lookup, then metadata search without totals/suggestions, then reviewed facets/features. Run shadow-result comparisons before each enablement. Rollback disables query features or the whole index; users retain authoritative browse/review APIs.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Post-filter leaks totals/ranking | Authorization before all observable query computation |
| ACL revocation races stale index/cache | Durable invalidation plus query-time generation check/fail closed |
| Search becomes accidental authority | Explicit freshness and revalidation for every mutation/navigation |
| Large reviews exhaust service | Immutable cursors, bounded queries, virtualization, load gates |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
