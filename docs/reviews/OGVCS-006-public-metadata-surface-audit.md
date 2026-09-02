# OGVCS-006 public metadata surface audit

**Audit base:** `3563167763a54b97eb8166ded1db895aa3a5b7cd`

**Date:** 2026-09-02

**Disposition:** safe carrier tranche landed; every network route remains closed

## Boundary decision

The authenticated OGVCS-041 assignment fixes 22 `POST` tuples, their success
status/media, stream class, required capabilities, and request-envelope shape.
It does not by itself authorize a network handler. The v0.3 registry therefore
continues to contain `networkRoutes: []`, and every entry continues to declare
`networkRegistered: false`.

This tranche adds only a framework-neutral response carrier. It emits the exact
RFC 8785 canonical `ResponseEnvelope`, binds success status/media and operation
carrier to the selected static descriptor, derives failure status from the
closed OGVCS-041 problem entry, and enforces the full one-MiB control limit
before the sealed read dispatcher commits its decision. The carrier's debug
view exposes only status, media type, and byte count, not control bytes. It
does not create a trusted authentication principal, install HTTP, reinterpret
OGVCS-009, map any unassigned metadata domain error, or enable request-root
authorization.

## Exact route matrix

| # | Operation | Assigned result | Current implementation | Network blocker / fail-closed owner |
|---:|---|---|---|---|
| 1 | `repository.create` | 201 JSON | persistence primitives only | atomic create/root/reference coordinator and public domain-error mapping |
| 2 | `repository.get-settings` | 200 JSON | sealed PostgreSQL read dispatcher candidate | trusted HTTP principal/session carrier, public host, domain-error mapping |
| 3 | `repository.list` | 200 page | authorized persistence query exists | project-scoped authority and sealed page dispatcher |
| 4 | `object.put` | 201 JSON plus input byte stream | internal metadata ingestion exists | authenticated bounded stream carrier and publication coordinator |
| 5 | `object.get` | 200 canonical byte stream | internal metadata read exists | authenticated bounded stream carrier and completion semantics |
| 6 | `tree.page` | 200 page | authorized persistence query exists | sealed authorized-view/page dispatcher and public cursor error mapping |
| 7 | `reference.read` | 200 JSON | sealed PostgreSQL read dispatcher candidate | trusted HTTP principal/session carrier, public host, domain-error mapping |
| 8 | `reference.list` | 200 page | authorized persistence query exists | sealed authorized-view/page dispatcher and public cursor error mapping |
| 9 | `reference.compare-and-swap` | 200 JSON | transaction-composable CAS exists | aggregate submit/lock coordinator and ratified conflict carrier |
| 10 | `history.ancestry-page` | 200 page | bounded persistence traversal exists | sealed authorized-view/page dispatcher and incomplete/cursor carrier |
| 11 | `history.file-id-page` | 200 page | bounded persistence traversal exists | sealed authorized-view/page dispatcher and incomplete/cursor carrier |
| 12 | `history.path-page` | 200 page | bounded persistence traversal exists | sealed authorized-view/page dispatcher and incomplete/cursor carrier |
| 13 | `file-id.allocate` | 201 JSON | identity-authorized opaque receipt operation exists | sealed public idempotency dispatcher and ratified failure carrier |
| 14 | `file-id.register` | 201 JSON | native receipt consumption is internal | create/copy dispatcher; restore remains proof/coordinator closed |
| 15 | `file-id.register-import` | 201 JSON | mapping-bound transaction primitive exists | sealed import coordinator/dispatcher and ratified failure carrier |
| 16 | `file-id.tombstone` | 200 JSON | transaction-composable primitive exists | aggregate publication coordinator and exact lifetime proof/error carrier |
| 17 | `file-id.history` | 200 page | bounded persistence traversal exists | sealed authorized-view/page dispatcher and incomplete/cursor carrier |
| 18 | `idempotency.status` | 200 JSON | private scope-bound persistence logic exists | fresh OGVCS-009 scope reauthentication and public status/error carrier |
| 19 | `consistency.issue-token` | 200 JSON | transaction-bound issuance exists | sealed public dispatcher and trusted principal carrier |
| 20 | `outbox.claim` | 200 JSON | internal exact-lease operation exists | internal-only; never install as a client route |
| 21 | `outbox.acknowledge` | 200 JSON | internal exact-lease CAS exists | internal-only; never install as a client route |
| 22 | `outbox.release` | 200 JSON | internal exact-lease CAS exists | internal-only; never install as a client route |

## Cross-cutting closure gates

1. A concrete HTTP/TLS 1.3 host must derive a trusted principal/session from an
   authentication authority. `MetadataNegotiationPrincipal` is a negotiation
   input, not an authorization brand.
2. The host must preserve the existing same-transaction OGVCS-009 decision,
   exact server-derived resource, currentness recheck, decision commitment, and
   commit-before-success rules. This audit does not add or change an
   authorization decision.
3. A later protocol release must explicitly bind metadata domain errors. Until
   then `REFERENCE_CONFLICT`, `FILEID_CONFLICT`, history limits, consistency
   failures, and metadata-not-found/denied cannot impersonate an OGVCS-041
   `ProblemDetails` entry.
4. Every authorized page construction must precede counts, positions, cursors, and
   incomplete reasons. The existing persistence queries are not public route
   dispatchers by themselves.
5. CAS, tombstone, restore, and repository creation stay behind their aggregate
   coordinators. A route parser or canonical response carrier cannot reopen
   those mutations.
6. Object put/get stay closed until the separately authenticated stream carrier
   is assigned; request-root authorization is unchanged and remains outside
   this tranche.

OGVCS-006 remains in development and every acceptance criterion remains open.
