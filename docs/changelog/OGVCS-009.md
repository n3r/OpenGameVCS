# OGVCS-009 — Identity, path authorization, and audit

**Status:** In development
**Candidate packages:** `@opengamevcs/identity-policy-audit-contract-v1` 0.2.0 and `@opengamevcs/identity-policy-audit` 0.2.0
**Date:** 2026-09-01

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

This prerequisite does not implement aggregate authorization, persist a sealed
100,000-resource plan, or complete OGVCS-009. Immutable repository metadata
settings must still be cross-checked against the selected policy profile/mode,
and a durable credential/security-epoch migration remains separate work.

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
studio OIDC deployment, production secret/key/audit/nonce/PostgreSQL adapters,
process-restart reconstruction proof, request-root or multi-object grant
issuance, latency/SLO evidence, complete public route integration, hosted
cross-platform evidence, or final acceptance.
