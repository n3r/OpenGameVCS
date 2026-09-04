# OGVCS-009 transaction-authorized page boundary review

**Review base:** `fa61786b272a019b82f4e96eaaa47dbef60c5b6c`

**Date:** 2026-09-02

**Disposition:** source-only identity prerequisite; no metadata dispatcher or
public route is enabled

## Boundary decision

Authorization-safe metadata paging needs a primitive that can filter a large
server-owned candidate window without disclosing the size, identity, position,
or denial class of protected rows. The existing 1,000-resource batch API is
all-or-nothing and canonical-sorts resources, so it cannot safely serve that
role. This cut adds a distinct transaction-authorized page primitive to the
Rust PostgreSQL participant and leaves the batch contract unchanged.

The page primitive accepts a typed operation/query digest and an ordered slice
of at most 100,000 candidate contexts. Each context binds the exact resource,
reference, and snapshot. Exact duplicate contexts fail closed. Candidate order
is preserved in an incremental domain-separated digest; no canonical sort can
rewrite the ordinals.

## Evaluation and failure semantics

1. The participant verifies schema compatibility and the existing sealed
   `TransactionAuthorizedView` against the caller-owned live transaction.
2. It reconstructs current credential, authority epoch, policy generation, and
   authenticated scope exactly once. Candidate evaluation performs no database
   lookup.
3. It evaluates every candidate in stable order. `AuthenticationDenied` alone
   becomes an internal visibility bit. Candidate-local validation,
   policy/evaluator, or digest failures are retained while the remaining
   bounded candidates are still visited. Database/currentness failures happen
   at the single pre-scan reconstruction and poison the transaction without
   entering candidate evaluation.
4. At most 1,000 authorized results are retained. Result overflow is reported
   only after the complete scan. Every returned error goes through the existing
   PostgreSQL poison boundary.
5. A second participant-owned verification step rechecks the live transaction,
   view currentness, exact query/candidate commitments, ordinal structure, and
   HMAC before exposing references into the checked candidate slice. Its
   witness retains the mutable transaction borrow, and item references reborrow
   the witness rather than inheriting the longer page/candidate lifetime.

This preserves the existing authorization recheck semantics: bound
reference/snapshot values cannot be widened, unbound candidates still undergo
the full policy and credential-scope evaluation, and a page cannot be moved to
another transaction, view, query, candidate order, or participant instance.

## Disclosure and proof shape

`TransactionAuthorizedPage` has no `Serialize` implementation and no public
naked-ordinal or raw-commitment getter. Its transaction-unique opaque
HMAC-SHA-256 fingerprint binds:

- the participant secret and PostgreSQL backend/XID binding;
- every neutral authorized-view field, including transaction identity,
  credential evidence digest/generation/expiry, subject and authenticated-scope
  digests, request and decision fingerprints, tenant/repository/permission,
  authority epoch, and policy generation;
- the typed operation plus semantic-query digest;
- the complete ordered candidate resource/reference/snapshot set; and
- the authorized ordinal/decision set and a separate ordinal digest.

The raw candidate and query digests are deliberately private: serializing a
deterministic digest of a small guessable protected set would itself create an
enumeration oracle. Debug output also omits ordinals and raw commitments.

The verified witness is deliberately transaction-scoped: commit, rollback, and
other mutable transaction use are rejected by the Rust borrow checker while it
or one of its candidate references remains live. A trusted in-process consumer
can explicitly derive owned decisions, drop the witness, and continue the same
transaction. Such owned values are capability-bearing application state, not a
serializable or cross-transaction proof, and must not be accepted by a later
transaction without re-verifying the original page.

## Verification evidence

Bounded Rust tests cover denial filtering, complete visitation on non-denial
faults and result overflow, duplicate rejection, exact 100,000 acceptance and
100,001 rejection, candidate order/reference/snapshot binding, HMAC changes for
query/set/ordinal/transaction substitution, and the external read-only type
surface. External compile-fail documentation probes reject both using a witness
after commit and retaining an item reference across witness drop/commit. The
ordinary crate checks remain suitable for Rust 1.82 debug, release, formatting,
strict Clippy, and an isolated offline packed-workspace consumer run.
The exact 100,000-candidate case is a bounded unit proof, not hosted scale
evidence.

## Deliberate nonclaims

- The semantic query digest is metadata-owner supplied and is not independently
  reconstructed here; this cut does not prove that owner's canonical query
  encoding.
- The proof is not yet bound to an OGVCS-041 negotiation session. Negotiation
  `sessionId` is still not linked to credential presentation or to a
  participant-derived public authentication/session carrier.
- No cursor or repository-metadata dispatcher calls the primitive; all public
  and network routes remain closed.
- No object transfer, request-root authorization, mutation, PostgreSQL live
  page test, latency campaign, or hosted cross-platform page evidence is added.
- OGVCS-009 remains In development and all six acceptance criteria remain
  open, including timing and non-disclosure acceptance.

## Repository-metadata integration contract

A separate future `PostgresMetadataPageDispatcher` may consume this primitive
for exactly `tree.page`, `reference.list`, `history.ancestry-page`,
`history.file-id-page`, `history.path-page`, and `file-id.history`. The
project-scoped `repository.list` operation is excluded and needs its own
project authority. Every public page request retains the authenticated
`pageSize` range 0 through 10,000; this request bound does not alter the
primitive's 1,000-authorized-result ceiling.

For `pageSize = 0`, the repository dispatcher must privately scan only until
the first authorized sentinel or bounded exhaustion and return zero items. An
authorized sentinel yields `state = more` and a non-advancing cursor bound to
the current start. It issues a fresh opaque cursor bound to the same decoded
`after` position when an input cursor exists, or to the internal empty-byte
start sentinel when none was supplied; position is preserved, not token
identity. Exhaustion with no authorized item yields
`state = complete` and no cursor. A later positive-size page resumes from the
same position, so the sentinel is not skipped. No denial identity, count,
position, class, raw scan position, or unauthorized status becomes output.

That integration must retain one live PostgreSQL transaction through candidate
acquisition, `authorize_page`, witness verification, owned result derivation,
cursor/consistency-token construction, decision commitment, and commit. The
semantic query digest remains metadata-owner supplied and is not independently
reconstructed here. This source-contract addendum does not claim that the
dispatcher, a PostgreSQL live page proof, or any network route exists; OGVCS-006
and OGVCS-009 remain in `prd/todo` with every acceptance criterion open.
