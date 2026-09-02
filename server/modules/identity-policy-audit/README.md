# OGVCS-009 PostgreSQL participant

`ogvcs-identity-policy-audit-postgres` is the server-side, same-transaction
participant for the OGVCS-009 candidate. It is not an HTTP API and deliberately
does not hand a database transaction back to its caller.

The direct, at-most-1,000-resource evaluator consumes the generated
`ogvcs-path-contract` Rust binding instead of a language-native lowercase
approximation. The binding pins the exact OGVCS-004 v1 manifest and Unicode
16.0.0 C/F case-fold table, rejects non-NFC input without repair, performs no
post-fold normalization, accepts all four ratified profiles, and compares
component-bound `ogvcs-path-key-v1` repository keys.

The same participant also exposes a private bounded authorized-page primitive.
It accepts at most 100,000 server-derived candidates in stable query order,
where each candidate carries its exact resource, reference, and snapshot
context. One sealed `TransactionAuthorizedView` currentness reconstruction
feeds the complete in-memory scan: policy denials become internal visibility
bits, while malformed contexts, evaluator faults, duplicate contexts, storage
faults, and more than 1,000 authorized results fail and poison the transaction.
The scan never canonical-sorts candidates and always visits the complete
bounded set before returning a candidate-dependent result.

`TransactionAuthorizedPage` is an opaque, non-serializable in-process carrier.
Its HMAC-SHA-256 fingerprint binds the PostgreSQL transaction, every neutral
authorized-view field (including credential evidence, authenticated scope,
authority epoch, and policy generation), the typed query-context digest, the
ordered candidate-context digest, and the authorized ordinal/decision set.
Raw commitments and ordinals have no public getter. A caller receives candidate
references only from `verify_authorized_page`, which repeats view/currentness
and exact query/candidate/HMAC checks against the live transaction. The
returned witness holds the mutable transaction borrow, and item references
reborrow the witness, so commit, rollback, and other mutable use cannot occur
while either remains live. A trusted caller may explicitly derive owned
in-process decisions, drop the witness, and continue that same transaction;
those owned values are not portable authorization proof and cannot replace
reverification in a later transaction. The primitive is not wired to repository
metadata or any route.

The semantic query digest is currently supplied by the trusted metadata owner
and is not independently reconstructed here. This crate does not yet derive it
from an OGVCS-041 negotiation session, and the negotiation `sessionId` is still
not linked to credential presentation. There is no cursor, metadata dispatcher,
public route, PostgreSQL live page test, latency/timing non-disclosure evidence,
or cross-platform hosted evidence in this cut.

Migration v3 adds a separate aggregate participant with an exact 100,000-item
ceiling. `begin_plan` derives current credential, subject, scope, authority,
policy, repository-settings, and signer facts on the server. Callers then use
`append_chunk` with at most 1,000 canonical resources and at most 1 MiB of
canonical resource bytes per call. No public operation accepts a
100,000-element `Vec`; upload uses one bounded `UNNEST` insert per chunk and
authorization reconstructs its seal through one server-side row stream before
one set-based deny-overrides query. It emits one aggregate commitment, not one
decision row per resource.

Repository metadata is bound through an immutable root plus append-only exact
settings-generation records. Every plan/receipt binds both the metadata tenant
and repository identities, settings generation and descriptor digest, path
profile and case mode. Policy JSON is normalized into sealed relational
rule/subject/reference/path/type/
permission/term projections. The application cannot add to or mutate a sealed
projection or initialized plan facts, and PostgreSQL rechecks complete chunk,
item, order, byte-count, canonical-key, path-key, and digest coverage before an
allow can be returned.

Aggregate handles and receipts are HMAC-authenticated by an injected
`AggregateHmacKeyProvider`. PostgreSQL retains only an opaque key reference and
provider fingerprint; it never stores secret material. The supplied
`HmacSha256KeyRing` is suitable for a bounded in-process deployment and clears
owned 32-byte keys on drop; HSM/KMS deployments implement the same provider
trait. Currentness checks fence expiry, credential state/generation, authority
and security epoch, policy generation/digest, metadata descriptor, exact path
profile/mode, and active signer generation/fingerprint on append, authorize,
and consume.

The adapter accepts a caller-owned `postgres::Transaction` only while it is
inside the protected server boundary. It mints a transaction identity itself,
loads current credential/policy/authority state with locks, produces a sealed
authorized view, rechecks a bounded canonical resource set, emits the neutral
`AuthorizedResourceBatch` v1 carrier in canonical-resource order, and appends
an ordinary decision commitment in that same database transaction. Any error
poisons the transaction using the database fail-closed function.

Migration v1 remains byte-frozen at SHA-256
`f31def32f2dc2a5da085187e345fa91ca0defe1035426c17fdeba719bd1df583`.
Additive v2 installs and validates equivalent 1..256-byte opaque-ID checks,
then removes only the v1 PostgreSQL regular expressions whose `{1,256}` bound
cannot be evaluated by PostgreSQL 15. Append-only v3 adds durable credential
reconstruction/security-epoch fields, versioned repository settings bindings,
sealed policy projections, HMAC key metadata, aggregate plans/chunks/resources,
one aggregate decision commitment, and one-use consumption evidence. The live
tests apply and verify all nine Expand/Migrate/Contract ledger entries on a
fresh database without changing v1 or v2.

`TransactionDecisionCommitment` is an OGVCS-009 decision record. It is not
presented as an OGVCS-003 frozen `AuditEvent`; the latter remains limited to
the explicitly supported privileged policy/security event classes.

`AggregateAuthorizationReceipt` is likewise an opaque internal authorization
carrier, not an OGVCS-010 distributed-receipt or disaster-recovery claim.
Repository metadata should retain it inside the protected server boundary and
call `PostgresAggregateAuthorizationParticipant::consume_receipt` on the same
`postgres::Transaction` as the protected mutation. The returned
`AggregateReceiptConsumption` is the one-use brand; its `authorization()`
accessor returns the exact receipt only after verification/currentness/consume
succeeded. Neither type exposes raw secret material or a database handle.

The receipt carries both its canonical ordered `resource_set_digest` and the
frozen `ogvcs.identity-policy/resource-digest-projection/v1` commitment. A
metadata participant can reconstruct the latter in O(1) memory by feeding its
ordered, persisted 32-byte per-resource digests to
`AggregateResourceDigestProjection`; it must compare the one final digest and
count before consuming the receipt. Publication submit uses the exact internal
pair `permission = "submit"` and
`capability = "submit.consume-publication"`; mixed pairs fail closed. The
consumption evidence declares `(plan_id, consumption_id, operation_digest)` as
an exact composite foreign-key target for lifecycle evidence.

## Checks

The crate pins Rust 1.82 and has a checked Cargo lockfile. Run the ordinary
source gate with:

```text
node core/paths-filesystem/rust/scripts/sync-contract.mjs --check
cargo fmt --manifest-path core/paths-filesystem/rust/Cargo.toml -- --check
cargo test --manifest-path core/paths-filesystem/rust/Cargo.toml --locked
cargo clippy --manifest-path core/paths-filesystem/rust/Cargo.toml --locked --all-targets -- -D warnings
cargo fmt --manifest-path server/modules/identity-policy-audit/Cargo.toml -- --check
cargo test --manifest-path server/modules/identity-policy-audit/Cargo.toml --locked
cargo clippy --manifest-path server/modules/identity-policy-audit/Cargo.toml --locked --all-targets -- -D warnings
sh server/modules/identity-policy-audit/scripts/test-packed.sh
```

The packed check packages both Rust crates, then reconstructs the participant's
declared workspace-relative migration and neutral-vector inputs in an isolated
temporary hierarchy before running all packed targets offline. This is a
bounded package-consumer proof, not hosted scale evidence.

The root aliases are `npm run test:identity:rust` and, with
`OGVCS_IDENTITY_POLICY_DATABASE_URL` set to a disposable database,
`npm run test:identity:postgres`.

The PostgreSQL integration tests self-skip unless
`OGVCS_IDENTITY_POLICY_DATABASE_URL` names a disposable PostgreSQL 15 database.
The `identity-policy-audit.yml` Linux job supplies that value and proves the
checksummed Expand/Migrate/Contract sequence, compatibility fence, and
database-level transaction poison path for direct and aggregate participants.
The ordinary aggregate test covers hostile mutation, stale authority inputs,
deny position, Unicode folding, restart, key mismatch, expiry, and concurrent
one-use consumption. The ignored `exact_hundred_thousand_resources_stream_and_authorize`
test is the explicit opt-in database-scale proof; it streams 100 bounded chunks,
rejects item 100,001 before insertion, and authorizes the complete set. It is
not part of ordinary hosted CI.

This is still a developer-preview internal boundary. Public authentication,
policy, audit, and authorization routes; deployment-specific secret, KMS,
nonce, and external audit/checkpoint adapters; measured latency/revocation SLO
evidence; and trusted OGVCS-018 root-proof authority remain completion gates.
No OGVCS-010 or disaster-recovery receipt claim is made, and OGVCS-009 is not
marked complete.
