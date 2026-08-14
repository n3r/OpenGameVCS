# OGVCS-027 — Regional content cache

**Status:** Todo  
**Release:** R2 — Studio Alpha  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-008, OGVCS-009, OGVCS-013, OGVCS-017  
**Blocks:** OGVCS-028, OGVCS-032  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Remote studios and build farms fetch authorized immutable content from a nearby verified cache, reducing repeated WAN transfer and origin load without making the cache an authorization, metadata, or durability authority.

## Problem

Large game assets make intercontinental sync expensive and fragile. Ordinary CDNs assume public or URL-authorized objects, while content-addressed IDs can become bearer secrets if a cache serves any known digest. A studio cache must preserve permission checks, detect corrupt storage, and fail safely back to the source.

## Scope

### In scope

- Regional read-through caching for immutable manifests/chunks and permitted derived transfer objects.
- Short-lived scoped transfer grants, verified cache fill/read, eviction, purge/quarantine, warmup, origin fallback, and cache fleet operations.
- Single-origin metadata authority with multiple optional cache regions.

### Out of scope

- Metadata replication/failover, lock or branch decisions, authoritative write-back, peer-to-peer clients, or active-active object ingestion.

## Users and journeys

- **Remote artist:** resolves metadata at the authority, then fetches most selected bytes from a nearby cache with the same final digests.
- **Build farm:** warms declared snapshot inputs and shares immutable chunks across ephemeral jobs without sharing credentials.
- **Operator:** drains or deletes a regional cache and observes only performance degradation, not data loss or metadata inconsistency.

## Requirements

### Functional

- **OGVCS-027-FR-01:** Only OGVCS-009 may authorize content access; a cache SHALL accept a short-lived signed grant binding tenant/repository, subject/session, allowed object IDs or bounded manifest root, verbs, expiry, audience/region, and nonce/key generation.
- **OGVCS-027-FR-02:** Knowledge of an object digest, URL, cache key, or prior successful response SHALL not authorize retrieval after grant expiry/revocation semantics apply.
- **OGVCS-027-FR-03:** Cache fill SHALL retrieve from an authenticated origin, validate framing/size/digest, write atomically, and expose an entry only after verification.
- **OGVCS-027-FR-04:** Cache read SHALL verify stored object identity before or during delivery under the OGVCS-017 policy; a mismatch SHALL quarantine the entry and refetch/fail explicitly.
- **OGVCS-027-FR-05:** Tenant isolation SHALL apply to namespace, encryption/key policy, quota, metrics, purge, and administration even when physical deduplication is enabled by explicit deployment policy.
- **OGVCS-027-FR-06:** Eviction SHALL affect only reconstructible cached copies, use configurable capacity/priority policy, and SHALL never report source content deletion or durability.
- **OGVCS-027-FR-07:** Clients SHALL discover/cache-select using an authenticated service response, retry another healthy endpoint/origin, and preserve resumable transfer and end-to-end verification.
- **OGVCS-027-FR-08:** Operators SHALL support drain, warm, targeted safe object/tenant purge, key rotation, quarantine inspection, and full disposable rebuild without database edits.
- **OGVCS-027-FR-09:** Cache logs/errors SHALL use safe object/correlation identifiers and SHALL not reveal protected paths, branch structure, credentials, or grant contents.
- **OGVCS-027-FR-10:** Origin and cache SHALL negotiate a versioned transfer protocol and reject incompatible framing, compression, or digest algorithms.

### Quality attributes

- **OGVCS-027-NFR-01:** Deleting or losing the complete cache fleet MUST preserve correctness/durability; clients either fetch verified bytes from origin or fail explicitly.
- **OGVCS-027-NFR-02:** At 200 ms origin RTT, a warm-cache representative sync MUST reduce origin egress by the declared target and deliver a material p95 wall-time improvement documented before rollout.
- **OGVCS-027-NFR-03:** Revocation, replay, confused-deputy, and cross-tenant tests MUST not yield an unauthorized byte, even for identical content IDs.

## Interfaces and data

Define cache endpoint discovery, signed transfer grant, grant-key rotation/revocation generation, cache entry health, fill lease, eviction/purge request, warm plan, and cache/origin transfer result. Object identity remains the OGVCS-002/007 canonical identity.

## Development plan

1. Implement cache discovery and signed scoped transfer grants plus a single-node immutable read-through cache with verified atomic fill/read.
2. Add concurrent fill suppression, resumable client routing/fallback, quotas, eviction, tenant isolation/encryption policy, quarantine and purge.
3. Add fleet drain/warm/rebuild, key rotation/revocation, origin/capability negotiation, capacity and origin-egress observability.
4. Complete cross-tenant/grant/corruption/stampede/WAN and destructive-rebuild tests, then deploy bypass → selected traffic → managed warmup.

## Acceptance criteria

- **OGVCS-027-AC-01:** Cold, warm, partial, evicted, corrupt, unavailable, and partitioned cache scenarios produce identical verified client bytes or explicit errors with successful safe origin fallback where reachable.
- **OGVCS-027-AC-02:** Expired, forged, replayed, wrong-audience, wrong-tenant, revoked-session, and unauthorized-object grants cannot retrieve content or reveal its presence.
- **OGVCS-027-AC-03:** Injected corruption on fill and at rest is quarantined before client acceptance; repair/refetch does not poison concurrent readers.
- **OGVCS-027-AC-04:** Destroying and rebuilding a cache from empty requires no repository repair and does not change branch, lock, audit, or backup state.
- **OGVCS-027-AC-05:** The reference intercontinental workload meets approved warm-hit, origin-egress, throughput, latency, and cost thresholds under bounded cache resources.

## Verification plan

Transfer-grant security suite, cross-tenant probes, WAN emulation, load/cache-stampede tests, corruption/race injection, origin/cache failover, key rotation/revocation, eviction/quota stress, and destructive cache rebuild drill.

## Telemetry and operations

Expose hit/miss/fill/eviction bytes, origin egress, latency, grant failures by safe category, integrity findings, capacity, queue/stampede suppression, fallback, and endpoint health. Fine-grained object identifiers remain local/access-controlled.

## Rollout and rollback

Deploy empty cache in bypass/observe mode, enable selected read traffic, then warm high-value snapshots. Rollback removes it from discovery and drains traffic; cached copies may be destroyed after confirmation because origin durability is unchanged.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Digest becomes an authorization token | Signed scoped grants and authorization at issuance |
| Cache serves corrupt bytes at high fanout | Verify fill/read, quarantine, client end-to-end digest |
| Cache stampede overloads origin | Per-object fill leases, backoff, bounded concurrency |
| Operators treat cache as a replica | Explicit disposable role, health language, rebuild drills |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
