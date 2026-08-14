# ADR-0004: DR authority/security epochs

**Status:** Accepted  
**Date:** 2026-08-14  
**Owners:** OGVCS-009, OGVCS-010, OGVCS-016, OGVCS-032

## Context

Asynchronous cross-region DR can promote a verified point older than the former authority's last acknowledgement. Restoring sessions, grants, leases, or idempotency state without an epoch can resurrect revoked authority or silently lose a result.

## Decision

- Each write authority has a monotonic authority/security epoch bound into sessions, service tokens, transfer grants, locks, idempotency results, and commit receipts.
- Promotion fences the former authority, rotates relevant signing/credential generations, and creates a new epoch before writes reopen.
- Old locks become expired/reacquire-required. Old credentials and grants cannot authorize in the new epoch.
- Promotion publishes a signed recovery boundary and immutable recovery ledger. Clients reconcile receipts beyond the boundary as `not present after recovery` or `requires reconciliation`, never ordinary success.
- Failback reseeds from the promoted truth; histories are not merged as coequal authorities.

## Consequences and proof

Clients retain drafts/content long enough to reconcile an acknowledged operation outside the promoted point. DR drills must include revocation, lock, grant, idempotency, lost-response, and old-primary-return scenarios.

