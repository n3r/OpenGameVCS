# `@opengamevcs/identity-policy-audit`

This `0.1.0` candidate is the first bounded OGVCS-009 runtime cut. It composes
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
checkpoints that detect complete-history rewrites. Malformed context and dependency
failure deny; list filtering occurs before returned items and exposes no
hidden count.

Authorized audit reads require a trusted checkpoint, verify the complete tenant
chain, and then return an event-class-redacted projection. The projection has no
tenant-global sequence, previous/tail hash, total, hidden count, or gap marker.

## Adapter boundary

Credential storage, secret generation, clocks, OIDC flows, grant signing/key
resolution, atomic grant-nonce state, audit persistence, and protocol problems
are explicit, injected interfaces. The nonce adapter's synchronous `accept`
operation must atomically reject revoked or consumed nonces and consume a new
single-use nonce. `./testing` exports deterministic secrets, a fake identity
provider, and in-memory stores. They are not production persistence or
secret-management implementations. No OIDC network call, production key, or
retrievable stored secret is included.

Production stores must make credential/audit updates durable and serialize an
audit append with the corresponding revocation or epoch transition. This cut
orders the required audit callback before the in-memory state change and fails
closed if it fails; a later persistent service cut owns crash-atomic storage.
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

This package remains a developer-preview core. It does not claim real OIDC,
production secrets/storage, latency targets, complete metadata/transfer route
integration, hosted conformance, or final OGVCS-009 acceptance.
