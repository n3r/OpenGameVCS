# `@opengamevcs/identity-policy-audit`

This `0.2.0` candidate is the bounded OGVCS-009 developer-preview runtime. It composes
the existing public authorities instead of inventing replacement assignments:

- OGVCS-003 authorization requests, decisions, permissions, resources, audit
  events, transfer claims, signing, and verification;
- OGVCS-004 canonical path profiles and case folding;
- OGVCS-041 safe `AUTHORIZATION_DENIED` protocol problems when a caller
  supplies its frozen `ProtocolProblemCatalog`;
- OGVCS-006 metadata operation-to-permission/resource assignments.

The runtime provides deny-overrides path policy evaluation, single-return
hashed session/service credentials, shared epoch fencing, audited revocation,
post-policy transfer-grant issuance, authorized views, bounded rate limiting,
and per-tenant append-only audit hash chains with externally retained tail
checkpoints that detect complete-history rewrites. The 0.2 surface adds:

- OIDC Authorization Code with PKCE and device flow, with exact HTTPS endpoints,
  signed ID-token verification, bounded network responses and one-use state;
- a rotating local bootstrap recovery authority that cannot disable local login
  before an independent recovery path is configured;
- authorized, previewable policy generation CAS with an atomic
  `policy.changed` audit append;
- bounded credential-revocation and authority-promotion receipts; and
- same-transaction credential, policy, resource-view and decision-commitment
  boundaries for the PostgreSQL metadata adapter.

Malformed context and dependency failure deny; list filtering occurs before
returned items and exposes no hidden count.

Authorized audit reads require a trusted checkpoint, verify the complete tenant
chain, and then return an event-class-redacted projection. The projection has no
tenant-global sequence, previous/tail hash, total, hidden count, or gap marker.

## Adapter boundary

Credential storage, secret generation, clocks, OIDC HTTP, authentication
transactions, transport-derived rate identity, grant signing/key resolution,
atomic grant-nonce state, policy/security transactions, audit persistence,
trusted checkpoints, and protocol problems are explicit, injected interfaces.
The nonce adapter's synchronous `accept`
operation must atomically reject revoked or consumed nonces and consume a new
single-use nonce. `./testing` exports deterministic secrets, a fake identity
provider, and in-memory stores. They are not production persistence or
secret-management implementations. No OIDC network call, production key, or
retrievable stored secret is included.

OIDC public transaction records contain digests only. A production transaction
adapter must atomically retain the corresponding bounded private verifier,
state, nonce, or device-code compartment until the one-use claim finishes.
Production rate-source adapters must derive their key from trusted transport
state; request bodies and caller-selected strings are not trusted rate sources.

Production stores must make credential/audit updates durable and serialize an
audit append with the corresponding revocation, policy change, or epoch
transition. The same-transaction participant owns the transaction identity and
must poison an ambiguous or malformed decision-commitment attempt. No public
API exposes a raw database transaction.
The runtime itself makes no process-restart durability claim: callers must
restore authority state, credential and grant-nonce stores, audit records,
and trusted audit checkpoints through production adapters before serving
requests. The `./testing` stores retain state only while their JavaScript
objects remain alive.

## Lifecycle limits

Sessions are limited to eight hours, service credentials to one hour, and
transfer grants to five minutes, matching or narrowing OGVCS-003. Every one is
bound to the shared authority epoch. Promotion advances both epoch and signing
key generation; old sessions, service credentials, and grants then fail closed.

The package includes a real protocol-level OIDC adapter but no specific studio
provider configuration, production secret/database implementation, or public
HTTP route assignment. See the
[identity and policy operations runbook](../../../docs/runbooks/identity-policy-operations.md)
for bootstrap, provider, policy, revocation, checkpoint, outage and promotion
procedures.

This package remains a developer-preview core. It does not claim production
storage deployment, latency targets, complete metadata/transfer route
integration, hosted conformance, or final OGVCS-009 acceptance.
