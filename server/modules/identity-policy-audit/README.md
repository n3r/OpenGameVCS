# OGVCS-009 PostgreSQL participant

`ogvcs-identity-policy-audit-postgres` is the server-side, same-transaction
participant for the OGVCS-009 candidate. It is not an HTTP API and deliberately
does not hand a database transaction back to its caller.

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
cannot be evaluated by PostgreSQL 15. The live test applies v1 and v2 before
the first decision insert and verifies both versions in the migration ledger.

`TransactionDecisionCommitment` is an OGVCS-009 decision record. It is not
presented as an OGVCS-003 frozen `AuditEvent`; the latter remains limited to
the explicitly supported privileged policy/security event classes.

## Checks

The crate pins Rust 1.82 and has a checked Cargo lockfile. Run the ordinary
source gate with:

```text
cargo fmt --manifest-path server/modules/identity-policy-audit/Cargo.toml -- --check
cargo test --manifest-path server/modules/identity-policy-audit/Cargo.toml --locked
cargo clippy --manifest-path server/modules/identity-policy-audit/Cargo.toml --locked --all-targets -- -D warnings
```

The `postgres_live` integration test self-skips unless
`OGVCS_IDENTITY_POLICY_DATABASE_URL` names a disposable PostgreSQL 15 database.
The `identity-policy-audit.yml` Linux job supplies that value and proves the
checksummed Expand/Migrate/Contract sequence, compatibility fence, and
database-level transaction poison path. It additionally proves authorize →
batch recheck → decision append, plus cross-transaction and duplicate-resource
failure paths. It is bounded CI; it contains no exact-scale workload.
