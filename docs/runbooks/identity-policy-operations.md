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
npm run test:roadmap
```

The identity workflow runs those bounded gates on Node 24 across Linux, macOS
and Windows. Large repository scale campaigns are not part of this workflow;
they remain at the final scheduled release boundary.
