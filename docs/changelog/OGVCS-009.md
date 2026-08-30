# OGVCS-009 — Identity, path authorization, and audit

**Status:** In development
**Candidate packages:** `@opengamevcs/identity-policy-audit-contract-v1` 0.1.0 and `@opengamevcs/identity-policy-audit` 0.1.0
**Date:** 2026-08-30

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

The PRD remains In development. This cut does not provide or claim real OIDC,
production secret/key/audit/nonce stores, crash-atomic revocation plus audit
commits, process-restart state reconstruction, request-root or multi-object
grant issuance, latency/SLO evidence, complete API route integration, hosted
cross-platform evidence, or final acceptance.
