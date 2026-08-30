# Repository metadata v1 semantics

The normative artifacts are the authenticated registries, schemas, and vectors.
This prose cannot widen them.

All protected operations receive an OGVCS-003 decision before resource lookup or
response construction. List, tree, and history operations build the authorized
input view before page limits, counts, positions, and cursor state. The default
development authorizer denies; an allow fake is isolated-test-only.

`reference.compare-and-swap` always carries an expected state. Creation uses
`absent`; update and delete use the exact prior target and generation. A mismatch
returns `REFERENCE_CONFLICT` without mutation. Current state is an optional safe
parameter only after a visibility decision.

Consistency and cursor tokens are opaque handles. Server-owned state binds all
scope, position, issue/expiry, repository generation, and authorization fields.
The token text never carries those facts.

Domain errors are stable module results. They are not OGVCS-041 R0
`ProblemDetails` assignments. Transport parsing, authorization, cursor, and
semantic-idempotency errors continue to use the frozen R0 authorities where
applicable; a later negotiated protocol release must define the public mapping.

Object byte streams remain staged and untrusted until complete canonical/identity
validation and transaction commit. Exact duplicate bytes are idempotent. A
different byte sequence under the same ObjectID is a security/corruption result.
