# OGVCS-009 — Identity, path authorization, and audit

**Status:** In development
**Candidate packages:** `@opengamevcs/identity-policy-audit-contract-v1` 0.2.0 and `@opengamevcs/identity-policy-audit` 0.2.0
**Date:** 2026-09-01

## 2026-09-01 aggregate authorization and durable PostgreSQL v3

- Added append-only identity migration v3 after byte-frozen v1/v2. It makes
  durable credential reconstruction and the authority/security epoch explicit;
  appends versioned repository-metadata settings bindings; and adds sealed
  relational policy projections, external HMAC key metadata, bounded aggregate
  plan/chunk/resource facts, one aggregate decision commitment, and immutable
  one-use consumption evidence.
- Added a server-derived HMAC-authenticated aggregate plan and opaque receipt.
  Both bind the exact credential subject/scope and generation, tenant and
  repository, authority/security epoch, policy generation and digest, metadata
  tenant/repository/settings generation/descriptor, path profile and case mode,
  permission/capability/reference/snapshot, privileged reason digest, ordered
  resource count/set digest plus an ordered per-resource-digest projection,
  issuance/expiry, and signer generation/reference.
  Secrets remain behind an injected key-provider boundary and are never stored
  in PostgreSQL.
- Added streamed upload with exact limits of 100,000 total resources, 1,000
  items and 1 MiB of canonical bytes per chunk. There is no public
  100,000-element `Vec` API and no per-resource query loop: chunks use bounded
  batched `UNNEST`, seal verification uses a server-side row stream, and the
  complete set is evaluated by one deny-overrides relational query before a
  single allow/commitment can be returned.
- Sealed policy projections and initialized actor/scope/upload facts against
  later inserts or mutation. Database guards prevent plan/key deletion,
  nonmonotonic authority/policy transitions, commitment substitution, and
  post-authorization evidence changes. Currentness is rechecked on every plan
  operation and receipt consumption.
- Added bounded hostile tests for exact Unicode/profile path semantics,
  duplicate/order/shape/byte limits, subject/epoch/policy/settings/signer HMAC
  tamper boundaries, privileged reasons, early/middle/late denial without
  partial disclosure, stale authority races, restart reconstruction, sealed
  projection mutation, expiry/replay, and concurrent one-use consumption. An
  opt-in PostgreSQL test authorized exactly 100,000 resources in 100 streamed
  chunks and rejected item 100,001 before insertion; ordinary hosted CI leaves
  that exact-scale proof ignored.
- Added the minimal repository-metadata handoff:
  `AggregateAuthorizationReceipt` stays opaque, and
  `consume_receipt` must run in the same protected PostgreSQL transaction as
  the metadata mutation. The public O(1)-memory projection builder lets
  lifecycle reconstruct the receipt commitment from ordered persisted 32-byte
  resource digests. Publication submit is frozen to `submit` plus
  `submit.consume-publication`, and durable consumption exposes the composite
  `(plan_id, consumption_id, operation_digest)` key for cross-schema evidence.
  This is an internal authorization brand, not a public OGVCS-010/disaster-
  recovery receipt.

## 2026-09-01 Rust path-contract convergence prerequisite

- Added a Rust OGVCS-004 pure path binding generated from and pinned to the
  exact v1 manifest (`2f343e1d…dd4782b`), Unicode 16.0.0 C/F table
  (`6f1f9c58…59e09bb`), four-profile registry, and fold/path/collision vectors.
  Generation and `--check` reject manifest, artifact, version, mapping-count,
  profile, or derived-file drift.
- Replaced the PostgreSQL participant's `char::to_lowercase` plus post-fold NFC
  approximation with exact `ogvcs-path-key-v1` semantics. Policy, credential
  scope, request validation, and rule matching now use the selected ratified
  profile and case mode consistently, including component-bound prefixes.
- Added bounded Rust 1.82 tests for every authoritative fold/path/collision
  vector and explicit sharp-s, sigma, dotted-I, Cherokee, decomposed-input,
  no-post-fold-normalization, reserved-namespace, all-profile/mode, and prefix
  separation regressions. The identity workflow checks the generator and both
  Rust crates on Linux, macOS, and Windows without adding a scale campaign.

The v3 cut above now implements those aggregate, repository-settings, and
durable PostgreSQL prerequisites. The path-contract convergence work by itself
did not complete OGVCS-009, and neither does v3.

## Production-boundary candidate cut

- Added bounded OIDC Authorization Code with PKCE and device flows, exact HTTPS
  provider configuration, signed RS256/ES256 ID-token verification, one-use
  state/nonce/verifier records, dependency deadlines and resumable device-poll
  failures. No unintended local-authentication fallback exists.
- Added rotating bootstrap recovery, an independent-recovery prerequisite for
  local-login disablement, trusted-source rate control and fail-closed storage.
- Added authorized policy preview plus generation CAS and atomic
  `policy.changed` append, bounded revocation receipts, and atomic authority
  epoch/key promotion receipts.
- Added authority-derived transaction credential evidence, participant-owned
  transaction identities, exact batch resource checks, and a poison-on-ambiguous
  ordinary decision commitment for OGVCS-006. It does not counterfeit an
  OGVCS-003 privileged audit class or expose a raw database transaction.
- Added a 14-row executable production-boundary corpus alongside the existing
  15 security vectors. The independent validator freezes all 21 artifacts,
  17 schemas, 25 limits and 29 vector outcomes, including coordinated-drift
  mutation tests.
- Updated bounded CI to pinned Node 24 on Linux, macOS and Windows. The workflow
  contains no exact-scale or scheduled scale campaign.

## First security-core cut

- Added an authenticated candidate contract with exact OGVCS-003, OGVCS-004,
  OGVCS-041, and OGVCS-006 predecessor pins. The new schemas cover policy,
  digest-only credential records, authority state, audit-chain records, and
  externally retained audit checkpoints plus non-chain authorized audit views
  without reassigning predecessor
  permissions, resources, decisions, audit classes, grants, metadata
  operations, paths, or protocol errors.
- Added canonical path-aware, case-aware, deny-overrides evaluation. Missing or
  malformed context and evaluator failures deny with OGVCS-003 decision codes.
- Added bounded human sessions and service credentials with one-return secrets,
  digest-only stores, scope checks, revocation, and monotonic epoch fencing.
- Added policy-gated single-object transfer-grant issuance through the existing
  OGVCS-003 signing and verification contract, including nonce revocation and
  authority/key-generation invalidation. Authenticated principals are
  authority-branded, signer output must preserve the exact authorized claims,
  and single-use replay acceptance is atomically owned by an injected nonce
  ledger rather than caller-supplied verifier context.
- Added authorization-first list projection, generic OGVCS-041 denial problems,
  bounded privacy-safe rate limiting, and repository-filtered audit projections
  that verify a trusted complete-chain checkpoint before omitting all global
  chain positions, hashes, hidden counts, and gaps.
- Added append-only per-tenant audit chains and trusted tail checkpoints that
  detect removal, insertion, reordering, mutation, and complete-history rewrite.
- Added 15 executable security vectors and focused hostile-input, resource,
  stale-epoch, revocation, enumeration, callback, audit-tamper, and adapter tests.

## Deliberate remaining work

The PRD remains In development. This cut does not provide or claim a configured
studio OIDC deployment; deployment-specific secret/KMS, nonce, external audit
checkpoint/root, and all public-route adapters; trusted OGVCS-018 root-proof
authority; request-root grant issuance; production latency/revocation SLO and
fault evidence; an end-to-end rollout; or final acceptance. The aggregate
PostgreSQL participant has local restart reconstruction and exact-scale proof,
but hosted exact-scale and cross-service lifecycle evidence remain open. Hosted
bounded 0.2 conformance is green on Linux, macOS, and Windows at run
`33444182014`. No OGVCS-010/disaster-recovery receipt is claimed, and OGVCS-009
is not marked complete.
