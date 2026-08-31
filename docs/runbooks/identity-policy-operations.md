# Identity and policy operations runbook

This runbook covers the OGVCS-009 0.2 developer-preview boundary. It does not
turn the in-memory `./testing` adapters into production stores and does not
assign public HTTP routes.

## Before serving requests

1. Configure an exact HTTPS OIDC issuer, authorization endpoint, token endpoint,
   JWKS endpoint, redirect URI and optional device endpoint. Permit only the
   configured RS256/ES256 algorithms and an explicit client audience.
2. Provide an atomic authentication-transaction store. Its public record keeps
   only digests; its private compartment encrypts and atomically claims the
   bounded state, nonce, verifier or device code. Expired, complete and failed
   rows must be reclaimed without exceeding the contract ceiling.
3. Provide durable credential, nonce, policy, authority and audit stores. A
   policy change, revocation or epoch promotion and its required privileged
   audit event commit atomically.
4. Provide a transport-owned rate-source adapter. It derives the source from a
   trusted listener/proxy boundary and never accepts an address or bucket key
   from a request body.
5. Restore the externally retained audit checkpoint and verify the complete
   tenant chain before enabling audit reads.
6. For metadata operations, install the same-database transaction participant.
   It owns transaction identity, rechecks credential/policy/resource state in
   that transaction, appends one exact decision commitment and poisons any
   ambiguous attempt. Never expose its raw transaction handle to callers.
7. Bind each identity repository name to the authoritative metadata repository
   UUID and its current immutable settings generation. A settings promotion
   requires appending a new identity binding before new plans can begin; never
   rewrite an old descriptor/profile/mode binding.
8. Configure an `AggregateHmacKeyProvider` and register only its opaque key
   reference and non-secret fingerprint. Keep HMAC bytes in the process secret
   compartment, HSM, or KMS. The database must never receive them.

## Aggregate authorization operations

Use `begin_plan`, then feed canonical ordered resources to `append_chunk` in
chunks of at most 1,000 items and 1 MiB of canonical bytes. The service rejects
duplicates, reordered resources, a 100,001st item, and any cross-chunk ordering
regression before inserting that chunk. Do not collect the whole resource set
into a caller `Vec`.

`authorize_plan` locks current credential, authority/security epoch, policy,
metadata settings, and active signer facts; reconstructs every persisted chunk
and resource through a bounded database row stream; and evaluates the complete
set with deny-overrides SQL. It returns only after the whole set allows and
persists one commitment. A denial does not return item positions or partial
decisions.

Keep the resulting opaque `AggregateAuthorizationReceipt` inside the protected
server boundary. In the exact PostgreSQL transaction performing the metadata
mutation, call `consume_receipt` with a unique consumption ID and the canonical
operation digest. Continue only with the returned
`AggregateReceiptConsumption` brand and its post-verification `authorization()`
view. Compare both typed metadata tenant/repository IDs and reconstruct
`resource_digest_projection_digest` before consumption by streaming the
metadata rows' ordered 32-byte resource digests through
`AggregateResourceDigestProjection`; compare its final count and digest without
materializing the set. A publication submission must request the exact
`submit` permission and `submit.consume-publication` capability. Its canonical
operation digest must commit every lifecycle-specific publication, contract,
size, idempotency, and plan fact required by that operation. A concurrent or
replayed consumption, expired plan, revoked/replaced credential, epoch or
policy promotion, metadata settings change, profile/mode change, or signer
change fails closed.

## Bootstrap ceremony

Initialize once on a private administrative console. Deliver the returned
recovery code through a separate secure channel; the store retains only its
domain-separated digest. A successful recovery rotates the code immediately.
Configure and test an independent recovery path before disabling local login.
Repeated failures are rate-limited and reach a closed bounded-attempt state;
recovery then requires the external operational procedure, not a hidden bypass.

## OIDC outage

Do not fall back to bootstrap merely because OIDC is unavailable. Existing
unexpired sessions continue only according to their credential policy. New
code exchanges fail closed. A temporary device-poll dependency failure releases
the one-use claim with a bounded next-poll time; invalid grants and terminal
provider errors finish the transaction.

## Policy rollout and rollback

Preview the exact next generation against the retained authorized request set.
Review actor, reason and diff reference, then commit with the expected current
generation. A lost generation race is a conflict and appends no audit event.
Rollback is another monotonic policy generation; never rewrite the policy or
audit history in place.

## Revocation and authority promotion

Credential revocation returns the maximum time at which the old credential may
still authorize, bounded by the contract registry. Monitor that deadline and
alert on violation. Authority promotion must advance both epoch and key
generation, bind the verified recovery boundary, and atomically append exactly
one `authority.epoch-changed` event. After promotion, reject every old-epoch
credential, grant, cache entry and transaction view.

For aggregate HMAC rotation, advance the authority key generation first as part
of the protected promotion ceremony, make the prior active registry row
verify-only, and register exactly one new active key/fingerprint. Old plans and
receipts do not remain consumable after the current key generation changes.
Retire a verify-only key only after its operational retention window; rows and
consumption evidence are durable and cannot be deleted.

## Audit recovery and export

Retain checkpoints outside the mutable audit store. Verify linkage and the
trusted checkpoint before projection or export. Authorized projections omit
global sequence, hashes, totals, hidden counts and gap markers. Never accept a
checkpoint supplied by the audit query itself. On mismatch, stop reads, retain
the suspect store and checkpoint, and investigate as an integrity incident.

## Current developer-preview gates

Run:

```sh
npm run test:identity:spec
npm run test:identity
npm run test:identity:rust
npm run test:roadmap
```

Against a fresh disposable PostgreSQL database, also set
`OGVCS_IDENTITY_POLICY_DATABASE_URL` and run
`npm run test:identity:postgres`. The exact 100,000-resource SQL proof is an
explicit opt-in Rust test and is intentionally excluded from normal hosted CI.

The identity workflow runs those bounded gates on Node 24 across Linux, macOS
and Windows. Large repository scale campaigns are not part of this workflow;
they remain at the final scheduled release boundary.

This runbook does not activate public routes and does not describe an
OGVCS-010/disaster-recovery receipt. Production secret/KMS, nonce, external
audit/checkpoint, and trusted OGVCS-018 root-proof adapters plus latency and
revocation SLO evidence remain required before OGVCS-009 can be completed.
