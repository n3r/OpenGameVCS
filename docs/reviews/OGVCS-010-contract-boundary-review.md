# OGVCS-010 atomic-submit contract-boundary review

**Review date:** 2026-08-30

**Review scope:** bounded requirements and language-neutral contract design

**Verdict:** blocked before contract scaffolding
**Status effect:** none; OGVCS-010 remains Todo

## Executive verdict

The architectural submit invariant is clear, but the language-neutral module
boundary is not yet safe to freeze. In particular, no current versioned
predecessor contract can make object-lifecycle revival, authorization/audit,
FileID publication, branch CAS, idempotency outcome, consistency token, and
outbox insertion one authoritative transaction.

Creating `spec/atomic-submit/v1` now would force the package to invent private
behavior for unresolved predecessor-owned state. This review therefore adds no
schemas, registries, package manifest, public route, protocol assignment, or PRD
status/ownership claim. It defines the proposed boundary and the exact gaps that
must close before scaffolding is honest.

## Authorities read

This review uses prose and published language-neutral artifacts as authority.
Implementation code was inspected only to find missing ports; it does not define
submit semantics.

| Authority | Version/state used | Submit ownership consumed |
|---|---|---|
| OGVCS-002 repository format | format 1, ratified | canonical objects, snapshot/change-set/tree semantics, graph closure, FileID proof rules |
| OGVCS-003 authorization | `1.0.0` | request/decision context, non-disclosure, `submit` permission, grant and audit vocabularies |
| OGVCS-004 path/filesystem | `1.0.0` | joined-path validity, repository/platform collision keys, immutable case/profile rules |
| OGVCS-041 protocol | `1.0.0-rc.1`, candidate | envelopes, semantic idempotency, limits, safe errors, negotiation and explicit completion |
| OGVCS-006 repository metadata | `0.1.0`, candidate | metadata transaction, immutable object put, FileID registry, reference CAS, outbox and consistency tokens |
| OGVCS-009 identity/policy/audit | `0.1.0`, candidate | current epoch/credential/policy decisions and audit-chain shapes |
| OGVCS-008 object transfer | committed candidate `505bdae`, `0.1.0-rc.1`; unreviewed | informational lifecycle/receipt shape only; no implementation behavior is assumed |

The accepted ADRs read for this boundary are ADR-0001, ADR-0003, ADR-0004,
ADR-0008 through ADR-0011, ADR-0013, and ADR-0015. Architecture sections 3,
5–10, 16–18, and 24 provide the governing transaction, recovery, failure, and
acceptance invariants.

## Ownership boundary

OGVCS-010 should own only the submit workflow and its domain messages:

- immutable draft state and expiry/cancellation;
- preflight and missing-content planning;
- canonical candidate binding and ordered-operation validation orchestration;
- finalize transaction orchestration;
- submit outcome/status, conflict next action, and recovery reconciliation;
- submit-specific error, event, audit, receipt, limit, and extension assignments;
- invariant and fault vectors spanning the predecessor ports.

It must not redefine:

- deterministic CBOR, ObjectIDs, change-set replay, snapshot fields, graph or
  FileID proof semantics (OGVCS-002);
- joined-path or collision behavior (OGVCS-004);
- permission decisions, actor/session validity, policy storage, epochs, or audit
  chain storage (OGVCS-003/009);
- object availability, health, lifecycle generation, backend durability, or
  transfer grants (OGVCS-008/009);
- metadata rows, FileID uniqueness, reference CAS, commit sequencing,
  idempotency persistence, consistency tokens, or outbox persistence
  (OGVCS-006); or
- public envelopes, fingerprint algorithm, generic retry rules, or safe problem
  details (OGVCS-041 and a future protocol release).

## Proposed language-neutral interface

The following is a design target, not a frozen schema.

### Public workflow operations

```text
createDraft(authenticatedScope, protocolIdempotency, SubmitIntent)
  -> DraftCreated | SubmitProblem

inspectDraft(authenticatedScope, draftId)
  -> AuthorizedDraftView | SubmitProblem

cancelDraft(authenticatedScope, protocolIdempotency, draftId, expectedRevision)
  -> DraftCancelled | SubmitProblem

preflight(authenticatedScope, draftId, expectedRevision)
  -> PreflightResult | SubmitProblem

missingContentPlan(authenticatedScope, draftId, expectedRevision)
  -> MissingContentPlan | SubmitProblem

finalize(authenticatedScope, protocolIdempotency, draftId, expectedRevision)
  -> SubmitCommitted | SubmitConflict | SubmitProblem

lookupOutcome(authenticatedScope, operation, idempotencyKey)
  -> pending | committed | not-committed | unknown-recovering

reconcileReceipt(authenticatedScope, CommitReceipt, RecoveryBoundary)
  -> committed | not-present-after-recovery | requires-reconciliation
```

There is no public direct `advanceBranch` escape hatch in this surface. Generic
OGVCS-006 reference CAS remains a lower-level authority and must not bypass the
submit invariants for ordinary branch publication.

### Submit intent

An immutable `SubmitIntent` should contain:

- repository and target branch;
- exact expected head **and** expected branch generation;
- the repository descriptor and ordered parent snapshot references;
- one canonical OGVCS-002 change-set reference and proposed result-tree
  reference;
- optional group-set, conflict-set, and provenance references;
- author identity reference, authored time, and message;
- bounded typed lock/review/policy proof references; and
- a client closure claim used only as a missing-content hint.

The authenticated principal is server-derived. A client identity string cannot
replace authentication context. Author attribution must be separately valid and
authorized; the server derives the committer identity.

The actual operation list should live in the canonical OGVCS-002 change-set
object, not be duplicated inline in a bounded JSON control message. The server
must derive the authoritative metadata/content closure from the referenced
candidate graph. A caller-supplied object list, byte count, membership boolean,
or request-root string is never closure evidence.

The server creates the final snapshot because committer, committed time, and
the policy result are finalize-time facts. The intent therefore cannot carry a
pre-acknowledged snapshot ID.

### Preflight result

Preflight is advisory and should return:

- draft ID, immutable intent digest, and draft revision;
- the observed head/generation, policy generation, and authority epoch;
- pure validation results and required proof classes;
- a server-derived sorted missing-object plan with request-root commitment,
  object count, and logical bytes;
- bounded warnings and an expiry; and
- an explicit `mutableChecksRepeatAtFinalize: true` marker.

Preflight must not reserve a branch outcome, promise policy success, or make
staged content visible.

### Finalize result and conflict

A successful result should contain:

- snapshot ID;
- old and new head;
- branch generation;
- audit correlation reference and outbox event ID;
- opaque consistency token;
- authority epoch; and
- an authenticated durable commit receipt.

A CAS loser preserves the draft and staged content. It may return the current
head/generation only after a fresh visibility decision for that exact
reference. Otherwise it returns the same non-disclosing conflict class with a
`refresh-authorized-head` next action and no protected identifier.

### Authoritative transaction ports

All mutation ports below must share one serializable database transaction or an
equivalent single fenced transactional authority. Calling them over HTTP or
committing one before another is nonconforming.

```text
MetadataSubmitTx
  reserveOrJoinIdempotency(authenticatedScope, operation, key, fingerprint)
  lockReference(repository, branch, expectedHead, expectedGeneration)
  putCanonicalObject(repository, objectRef, exactBytes)
  applyFileIdFirstConsumptions(repository, changeSet, orderedAdditions)
  compareAndSwapReference(repository, branch, expected, snapshot)
  appendOutbox(submitEvent)
  commitOutcome(safeResult, commitReceiptRecord)
  issueConsistencyTokenForCurrentCommit()

LifecycleSubmitTx
  lockAndValidateClosure(repository, tenantScope, derivedClosure)
    -> current available generations
  reviveExactQuarantinedGeneration(object, generation, verifiedReceipt)
  recordPublicationReachability(snapshot, closure)

IdentityPolicySubmitTx
  requireCurrentCredentialAndEpoch(authenticatedScope)
  authorizeBatch(reference + every affected before/after path and FileID)
  evaluatePinnedSubmitPolicy(candidateDigest, proofSet)
    -> canonical snapshot PolicyResult
  appendSubmitAudit(submitAuditEvent)

OptionalProofSubmitTx
  validateLockReviewAndCheckProofs(repositoryRules, proofSet)
  applyCommittedLockDisposition(snapshot)
```

Every method is repository/scope bound when the transaction is created. A
method cannot accept another repository and thereby turn an earlier allow into
a confused-deputy write. Every public transaction method error poisons the
transaction; a caller cannot ignore an error and commit partial state.

### Finalize ordering

Large immutable work can be staged outside the short database transaction, but
no mutable assurance survives into commit without revalidation.

1. Validate the complete protocol envelope, semantic fingerprint, resource
   limits, and immutable draft binding.
2. Derive and purely validate the exact OGVCS-002/004 candidate graph, ordered
   operations, paths, collisions, closure, and FileID proof delta.
3. Begin one repository-scoped serializable authoritative transaction.
4. Reauthenticate the credential and current authority epoch before disclosing
   an idempotency outcome.
5. Reserve or join the finalize idempotency identity.
6. Lock/compare the exact target branch head and generation.
7. Re-evaluate authorization, policy, hidden before/after path effects, and all
   required lock/review/check proofs.
8. Rebind the prevalidated immutable candidate digest to the exact stored bytes.
9. Apply only create/copy/import FileID first-consumption rows in operation
   order. Restore adds no lifetime origin; deletion never frees an ID.
10. Lock every lifecycle row in the derived closure. Accept current healthy
    `available` generations or atomically revive an exact eligible
    `quarantined` generation. Reject staged, unhealthy, deleting, deleted,
    missing, or stale state.
11. Construct and validate the canonical snapshot; persist every new immutable
    metadata object.
12. CAS the branch and apply any committed lock disposition.
13. Append submit audit, outbox event, idempotency outcome, commit receipt,
    repository commit sequence, and consistency-token state.
14. Commit once, then return the already committed safe outcome.

No broker, webhook, cache, search service, object backend, remote policy engine,
or KMS network call occurs inside this transaction. Required policy and proof
evaluation must be deterministic, bounded, version pinned, and locally
available; unavailability fails closed.

## Required invariants

1. **Visibility:** only a committed branch reference makes a snapshot published.
   Drafts, uploaded bytes, staged metadata, and unreferenced snapshots never
   appear in branch/history reads.
2. **Atomic publication:** reference, immutable metadata, FileID first
   consumptions, lifecycle revival/reachability, lock disposition, audit,
   outbox, idempotency outcome, commit sequence, consistency token, and receipt
   are all old or all new.
3. **Content completeness:** authoritative server derivation finds the complete
   candidate closure. Every referenced manifest and chunk is current, healthy,
   verified, and available at commit.
4. **GC fencing:** a newly reachable generation cannot concurrently enter
   deleting. Exact quarantine revival and branch publication share the
   transaction.
5. **CAS:** one expected head/generation has at most one successful branch
   advance. A loser does not create an implicit side branch.
6. **Canonical history:** every stored object passes exact OGVCS-002 identity,
   known-schema, configured-profile, graph, replay, and path validation at the
   applicable layer.
7. **FileID lifetime:** create/copy/import have one permanent first consumption;
   move/rename preserve identity; restore proves and reactivates a historical
   lifetime without creating an origin; deletion never enables reuse.
8. **Current authorization:** finalize uses the current credential, epoch,
   policy generation, reference, and every affected before/after path/FileID.
   Preflight decisions cannot authorize commit.
9. **Non-disclosure:** denied and conflict responses expose no head, path,
   FileID, object, count, or position not covered by a fresh authorized view.
10. **Idempotency:** the OGVCS-041 semantic projection binds every operation
    input. Equal scope/operation/key/fingerprint returns one committed result;
    changed input rejects before mutation.
11. **Unknown result:** a lost response never triggers a second submit. Status is
    committed, not committed, or explicitly unknown/recovering until authority
    can decide.
12. **Epoch/recovery:** credentials and receipts bind the commit authority epoch.
    A later recovery boundary returns only committed, not-present-after-recovery,
    or requires-reconciliation.
13. **Audit/outbox:** a successful branch advance has exactly one authoritative
    audit correlation and one stable outbox event identity. Delivery may repeat;
    creation may not be lost.
14. **Bounded execution:** counts, bytes, graph work, database locks, retries,
    transaction duration, and scratch use have explicit limits. No whole-corpus
    materialization is required.
15. **Poisoned failure:** any transaction-port failure makes commit impossible,
    including when caller code catches or ignores the returned error.

## Verification plan

### Ordinary bounded presubmit

- Schema/registry self-validation and mutation tests for every proposed message,
  error, event, receipt, extension, limit, and predecessor pin.
- Golden semantic-fingerprint tests proving JSON member order is irrelevant and
  every intent field, canonical reference, proof, expected head, and extension
  changes the fingerprint when applicable.
- Small OGVCS-002/004 candidate graphs covering every operation kind, rename
  cycle, case/platform collision, conflicting operation, group/sidecar failure,
  hidden before/after path effect, and unresolved conflict.
- Draft state-machine tests for create, inspect, preflight, cancel, expiry,
  finalize, replay, conflict, and unknown result.
- Transaction model tests that inject failure before and after every numbered
  finalize step and assert either the complete old state or complete new state.
- An ignored-error test for every transaction port proving the transaction is
  poisoned and rolls back.
- Reduced concurrency races for branch CAS, idempotency join, FileID collision,
  audit tail, outbox identity, lifecycle revival, and GC deletion acquisition.
- Authorization races where credential, epoch, policy, path rule, lock, review,
  or check changes between preflight and finalize.
- Non-disclosure pairs for known protected branch/head/path/FileID/object inputs,
  including conflict and idempotency lookup.
- Lifecycle matrices for every state and stale generation, corrupt/unhealthy
  receipt, quarantine revival, deleting acquisition, and response loss.
- FileID create/copy/move/rename/delete/recreate/restore/import retry and
  cross-repository proof vectors.
- Lost-response/restart tests returning the exact committed snapshot, receipt,
  audit correlation, event ID, and consistency token without a second mutation.
- Outbox duplicate delivery and consumer deduplication by event ID plus explicit
  per-repository ordering/gap reconciliation.
- Old-epoch credential/receipt and recovery-boundary reconciliation vectors.
- Packed offline contract-consumer tests and Linux/macOS/Windows agreement for
  the language-neutral artifact.

### Deferred final/release evidence

The 100,000-operation latency target, one-hundred-way authoritative database
race, broad crash campaign, 100 GiB transfer, one-million-entry tree, and 1 TiB
manifest evidence are release/final-campaign work. They must not run on every PR
or ordinary presubmit. Reduced deterministic cases prove the same state-machine
branches during development.

## Blocking contract gaps

### B1 — lifecycle cannot join the metadata transaction (P0)

ADR-0003 requires shared transactional lifecycle records. The committed
OGVCS-008 candidate publishes a filesystem-profile lifecycle schema but no
transaction-bound port that can share OGVCS-006's serializable transaction.
It also has no separate current health generation. A submit could observe
`available`, then lose a race to quarantine/deleting before branch commit, and
cannot atomically revive quarantine.

**Closure required:** OGVCS-008 must publish a repository/tenant-scoped
`LifecycleSubmitTx` contract backed by the same fenced authority as reference
CAS, including batch closure locking, current health, exact-generation revival,
publication reachability, and GC race vectors.

### B2 — metadata has no complete submit/idempotency transaction (P0)

The OGVCS-006 language-neutral contract has an idempotency-status operation but
no reservation/join/committed-outcome schema. Its current transaction trait does
not expose idempotency operations, current-commit token issuance, committed
receipt storage, set-based FileID proof application, or a scope-bound repository
handle. The current metadata event registry also has no submit event.

**Closure required:** OGVCS-006 must expose the transaction methods listed
above, bind authorization scope and repository at transaction start, poison on
every operation error, reject generic restore as a first-consumption origin,
and prove crash recovery for the whole result tuple.

### B3 — submit audit and policy result are unassigned (P0)

The OGVCS-009 candidate audit chain accepts only the closed OGVCS-003 privileged
audit event schema. That registry has no submit-committed event, and the runtime
exposes no transaction-bound audit append. Separately, OGVCS-002 snapshot bytes
require one `PolicyResult`, but there is no ratified production policy profile
or exact digest aggregation from OGVCS-009 authorization plus submit proofs.

**Closure required:** assign a submit audit class/redaction and a same-transaction
append port; define the exact policy-result profile, decision mapping, and digest
preimage; and add vectors connecting those results to canonical snapshot bytes.

### B4 — public protocol binding is intentionally absent (P0)

OGVCS-006 and OGVCS-009 both declare `unassigned-future-release-required`.
OGVCS-041 cannot carry new domain errors/routes without a later release. Its R0
error registry deliberately excludes `currentGeneration`, so it cannot satisfy
the OGVCS-010 authorized-current-head conflict journey. Inline 100,000-operation
JSON would also exceed the bounded control profile.

**Closure required:** a protocol release must assign submit schemas, operation
names, capabilities, errors and safe parameters; authenticate current-head
visibility; and ratify whether canonical OGVCS-002 change-set byte streaming or
another bounded carrier supplies the operation set.

### B5 — durable commit receipt/recovery reconciliation is undefined (P0)

ADR-0004 and OGVCS-010 FR-12 require an epoch-bound durable receipt that can be
compared with a later signed recovery boundary. No predecessor defines the
receipt schema, authentication, branch-generation/position binding, storage,
or exact reconciliation outcomes. A consistency token alone promises read
freshness and is not DR acknowledgement evidence.

**Closure required:** define an authenticated commit receipt, its atomic stored
record, retention, safe client projection, epoch/branch/snapshot binding, and
the deterministic comparison with OGVCS-032's recovery boundary.

### B6 — production snapshot profile assignments are missing (P1 enablement)

The ratified format registry currently has no production-write-eligible identity
or snapshot policy profile; content/group profiles are likewise not generally
ratified. OGVCS-009 therefore cannot yet map an authenticated subject to a
production-valid OGVCS-002 `IdentityRef`, and OGVCS-010 cannot emit a
production-valid `PolicyResult`.

**Closure required:** additive profile assignments with immutable semantics and
writer eligibility. Until then, any implementation must remain explicitly
isolated/conformance-only and cannot claim production publication.

### B7 — proof extensions and submit event ordering need owners (P1)

Lock/review/check implementations are downstream, but OGVCS-010 must not freeze
an opaque proof blob or silently ignore a repository-required proof. The outbox
contract also lacks the submit event payload, repository-stream ordering, and
gap-reconciliation assignment required by OGVCS-010 NFR-03.

**Closure required:** a typed namespaced proof registry with required/optional
semantics and fail-closed fallback, plus a submit event schema with stable event
identity, commit ordering, redaction, consumer deduplication, and gap recovery.

## Scaffold gate

`spec/atomic-submit/v1` may be created only after B1–B5 have versioned candidate
contracts and the following statements can be answered without implementation
knowledge:

1. Which exact transaction handle is shared by metadata, lifecycle, audit, and
   later lock/review modules?
2. Which exact bytes define the submit fingerprint, snapshot policy result,
   submit audit event, outbox event, and commit receipt?
3. How does a conflict expose a current head without bypassing authorization?
4. How are ordered operations carried within protocol limits?
5. How does a receipt compare with a recovery boundary after authority epoch
   change?

Until that gate passes, a spec scaffold would advertise interoperability that
the current contracts cannot implement.
