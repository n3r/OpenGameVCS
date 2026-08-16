# ADR-0011: Authorization contract v1

**Status:** Accepted
**Date:** 2026-08-16
**Owners:** OGVCS-003, implemented by OGVCS-009 and consumed by OGVCS-041

## Context

OpenGameVCS must freeze its authorization boundary before services and clients
invent incompatible rules. A content hash is public identity, not a secret or a
bearer credential. Path filtering performed after global counting, ranking, or
pagination leaks protected state. Caches and hostile repository-supplied tools
cross trust boundaries that cannot inherit a caller's broad service credential.

OGVCS-003 owns the versioned contract and conformance kit, while OGVCS-009 owns
production authentication, policy persistence/evaluation, grant issuance, and
audit storage. The contract therefore needs deterministic reference semantics
without becoming a production policy engine.

## Decision

- Contract version 1 uses closed permission, resource, credential, decision,
  audit, threat, abuse, revocation, sandbox, and roadmap-surface registries.
  Existing assignments are immutable; incompatible behavior requires v2.
- An authorization request binds actor/session class, tenant, repository,
  reference or snapshot context, canonical path and/or `FileID` when relevant,
  resource state, permission, policy generation, and authority/security epoch.
  Missing required context and evaluator failure deny.
- Policy composition is deny-overrides. Every matching deny defeats every allow;
  an allow requires an explicit matching rule; no match denies. Decisions expose
  only a stable privacy-safe code, policy generation, and deterministic request
  fingerprint. They never echo protected paths, hashes, policy text, or claims.
- Lists, history, search, reviews, events, facets, suggestions, and caches are
  constructed from an authorized input view before counting, ordering, ranking,
  pagination, aggregation, or serialization. Mixed-visibility views expose only
  authorized items and authorized-set cursors; hidden counts and positions are
  not represented. Timing is bounded and padded by response class where
  practical; residual aggregate timing risk is tracked explicitly.
- Content transfer requires an Ed25519-signed, canonical, short-lived grant that
  binds issuer, key generation, authority epoch, subject, tenant, repository,
  permission/transfer operation, explicit object set or bounded request root,
  audience, issued/expiry times, nonce, and replay mode. Possessing an object ID
  never grants access. A request root is the domain-separated SHA-256 commitment
  to the canonical sorted unique object-ID plan; the verifier recomputes it from
  trusted local plan state and checks current-object membership. A root string
  supplied by the holder is not membership evidence. A verifier checks current
  epoch/key ID/generation, scope, audience, expiry, and replay state offline and
  fails closed. Verification material is selected from trusted issuer state,
  never from holder-provided key material.
- Deduplication, encryption, quotas, purge, and metrics are tenant scoped.
  Cross-tenant equality probes and content-derived encryption keys are forbidden.
- Privileged operations require a bounded reason and a separate permission, and
  emit append-only redacted audit classes. Audit access is itself separately
  authorized; default telemetry uses bounded low-cardinality reason classes.
- Sessions, service tokens, transfer grants, authorization caches, and offline
  lock receipts have frozen maximum validity and revocation ceilings. A newer
  authority epoch rejects all prior-epoch authority claims.
- Hooks, merge drivers, import parsers, and preview converters receive no
  credential, no network by default, read-only declared inputs, isolated scratch,
  pinned tooling, and explicit CPU, memory, elapsed-time, output, and fanout caps.
- The public runner executes language-neutral vectors against its reference
  fixture evaluator or a bounded NDJSON adapter process. It is conformance
  tooling, not a reusable production authorization implementation.

## Alternatives rejected

- **Repository-wide roles only:** cannot express restricted subtrees, snapshots,
  FileIDs, reviews, grants, or privileged action separation.
- **Hash-as-capability:** leaks through guessing, logs, deduplication probes, and
  stale URLs; revocation and audience restriction are absent.
- **Post-filtering responses:** leaks counts, ranking, parents, cursors, timing,
  and cache state created from hidden rows.
- **Allow-overrides composition:** one stale or broad allow can defeat an
  intentional deny and makes local review of restricted policies unsafe.
- **JWT as an unconstrained implementation choice:** optional algorithms and
  claim interpretation would make the R0 fixture non-deterministic. Protocol
  envelopes may transport the frozen claims later without changing semantics.

## Compatibility and data consequences

The package and schema major version are 1. A consumer advertises the exact
contract version and registry digest. Additive registry entries require a new
minor package only when old readers fail closed on the unknown assignment;
reassignment, semantic widening, or a changed signing preimage requires v2.
Policy and audit persistence layouts remain owned by OGVCS-009.

## Threat and failure analysis

The machine-readable threat registry covers external attackers, compromised
users, administrators, automation, cache operators, hostile imports/plugins,
hooks/preview parsers, stolen devices, and confused-deputy services. Critical and
high threats must have executable mitigations. Accepted medium residuals name an
owner and roadmap PRD. Evaluator outage, malformed input, stale epoch, wrong
audience, missing context, invalid signature, expiry, and replay all deny with a
non-disclosing code.

## Proof

OGVCS-003 provides schema, registry, digest, policy, authorization-view,
grant/revocation, sandbox, abuse-catalog, external-adapter, package, and
cross-platform vectors. OGVCS-005 consumes the negative corpus; OGVCS-009 must
pass it before enforcing policy; OGVCS-041 binds the same grant claims.

## Rollback

Before downstream adoption, withdraw the package version and keep protected
surfaces disabled. After adoption, readers may retain v1 only in deny-only mode
while a replacement version dual-evaluates. Rollback never restores a revoked
credential, old authority epoch, broad grant, or removed audit record.
