# OGVCS-018 private backup completeness manifest rc.1

This unpublished Rust 1.82 crate is a bounded, unwired model seam for one
narrow part of OGVCS-018. It binds an opaque metadata capture generation,
opaque branch/tag name commitments, configuration and mutable-state treatment
commitments, supplied reachability and integrity-verification commitments, a
supplied sorted OGVCS-002 typed-identity/declared-length inventory, and one
supplied designated-target copy-evidence row per inventory object into a
deterministic private manifest digest. The crate emits no raw ref names, but it
does not prove that a caller's name-commitment construction is hiding or
unlinkable.

The builder consumes two sorted `ExactSizeIterator`s in lockstep and retains no
object inventory or content bytes. Exact declared counts are checked before
either iterator is polled, then each iterator receives exactly the declared
row polls plus one end-of-stream probe. Thus a one-sided lying
`ExactSizeIterator` cannot hide an additional row. Every expected object must
have one same-identity, same-length copy-evidence row for the declared target,
storage generation, verification receipt, retention proof, and retention
deadline. Missing, additional, reordered, duplicate, mismatched, cancelled,
over-count, over-byte, over-work, or overflowed inputs return no manifest.
Branch/tag roots are strictly ordered and unique by `(kind, name_commitment)`,
and every supplied snapshot target must occur in the exact inventory.
Per-object lengths cannot exceed the frozen OGVCS-002 chunk/metadata payload
ceilings; zero bytes are allowed only for a raw chunk. Counts are stored and
hashed as `u64`, independent of host pointer width. Work is exactly one unit
per retained root plus one per expected-inventory row and one per copy-evidence
row. A conservative retained-memory charge covers the logical manifest state
plus simultaneous root-vector/root-set residency; it is deterministic, not an
allocator measurement. The builder discards root-vector spare capacity before
retaining the manifest. Allocations already made for caller-owned capture and
iterator inputs before invocation remain outside that charge.

The builder rejects a unique-root count larger than the declared inventory and
an aggregate byte declaration larger than `object_count * metadata_maximum`
before stream polling. `has_valid_binding` reconstructs capture shape, logical
work/memory charges, root digest, and the final checksum. It cannot reconstruct
the consumed inventory/copy streams, and the unkeyed manifest digest is a
deterministic binding checksum, not a signature or producer authentication.

All authority values in this crate are opaque commitments. Digest inequality
between source and target bindings is only a fail-closed consistency check; it
does not prove credential separation, independent retention, encryption,
copy durability, or source authenticity. A future authenticated backup-target
adapter and authorization boundary must produce and verify those facts. This
crate reads no object payloads, opens no storage, handles no credentials or
keys, and emits no path, ref name, actor, or secret.

Timestamp fields use the full unsigned 64-bit domain and only enforce
`captured_at < minimum_retention_until <= copy_retention_until`; no arithmetic,
wall-clock trust, freshness judgment, or calendar conversion occurs here. A
future authenticated adapter must impose its operational clock bounds.

This candidate has no durable wire/storage format, resumable cursor, scheduler,
freshness/RPO/RTO surface, public command or route, backup-target adapter,
encryption provider, restore planner or activation, graph verifier invocation,
retention/hold authority, GC mark/quarantine/sweep mutation, deletion receipt,
audit/outbox persistence, production concurrency rule, hosted portability, or
scale/SLO evidence. It does not make a backup complete in production and does
not unlock restore or garbage collection. OGVCS-018 remains Todo.

Local gates:

```text
cargo +1.82.0 fmt --manifest-path core/backup-manifest/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path core/backup-manifest/rust/Cargo.toml --locked --offline
cargo +1.82.0 test --manifest-path core/backup-manifest/rust/Cargo.toml --release --locked --offline
cargo +1.82.0 clippy --manifest-path core/backup-manifest/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo +1.82.0 package --manifest-path core/backup-manifest/rust/Cargo.toml --locked --offline --allow-dirty --no-verify
node --test tools/backup-manifest-source-policy.test.mjs
npm run test:roadmap
```
