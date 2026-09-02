# OGVCS-018 private backup completeness manifest boundary review

**Decision:** **SHIP the bounded source candidate only** as an unwired
metadata/inventory proof seam after independent audit. Do not treat it as a
production backup, restore gate, garbage-collection gate,
credential-separation proof, or completion evidence for OGVCS-018.

**Source baseline:** `a20c41f1cf4e91420085524d9f0719aaf1f3c0f1`

## Independent audit disposition — 2026-09-02

The independent pass found and corrected six material boundary defects before
issuing the bounded SHIP verdict:

1. `Iterator::zip` could accept a one-sided hidden extra row when the other
   dishonest exact-size stream ended at the declared boundary. The builder now
   consumes exactly the declared pair count and terminally probes both streams;
   short, long, one-sided, and two-sided lies have poll-count regressions.
2. Root ordering used the whole `RootBinding`, so one `(kind,
   name_commitment)` could bind two different snapshots. Validation now sorts
   and deduplicates the logical root key independently of its target.
3. Manifest counts were host-sized `usize` values cast into digest fields.
   Counts and limits are now `u64`; iterator/root lengths are checked at the
   boundary, and digest slice-length conversion has a compile-time pointer-width
   guard.
4. A non-chunk metadata object could declare an impossible zero-byte payload,
   and impossible aggregate-byte or unique-root/count declarations could force
   avoidable stream work. Zero is now chunk-only, and both impossible envelopes
   fail before row polling.
5. Caller-controlled spare capacity in the captured root vector was omitted
   from the retained-state interpretation. The builder now discards spare
   capacity before the capture becomes returned manifest state and explicitly
   excludes only allocations made before invocation from its logical ledger.
6. Source and prose called opaque names privacy-preserving, supplied target
   evidence independent, and a reconstructible checksum stronger than it is.
   The API, README, PRD, and this review now state the hiding, independence,
   authentication, signature, reachability, and stream-reconstruction
   nonclaims explicitly.

The audit also added exhaustive row/capture/ledger digest-field mutations,
canonical OGVCS-002 `ObjectRef` byte-order equivalence for all eleven v1 kinds,
zero-digest ObjectRefs including a Snapshot root, full-`u64` time ordering,
every configured hard-limit overrun, cancellation before a second callback,
and an explicit self-check non-authority regression.

Independent local gates at the final uncommitted candidate state:

- pinned Rust 1.82 debug and release: 26/26 tests in each profile;
- `cargo fmt --check` and all-target Clippy with `-D warnings`: pass;
- private `cargo package`: 6 source files, 75.7 KiB / 13.6 KiB compressed;
- OGVCS-002 upstream Rust conformance: 17/17;
- backup source policy: 2/2; roadmap validation: 8/8;
- independent Node `crypto` reconstruction reproduced known-answer digest
  `a6da23bf13f9d346ea3a865184e2907a349d52111432da4038b8ad450d9cfe0a`.

This is a local single-OS source verdict. Hosted portability, production target
behavior, reference scale, destructive restore, fault recovery, and all
OGVCS-018 acceptance evidence remain absent.

## Reviewed boundary

The unpublished `ogvcs-backup-manifest` rc.1 crate consumes one opaque,
immutable capture and two caller-supplied sorted streams:

```text
captured metadata generation + opaque root-name commitments
  + supplied sorted OGVCS-002 typed identities and declared lengths
  + one supplied designated-target copy-evidence row per object
  -> deterministic private completeness-manifest digest
```

The capture binds tenant/repository, equal metadata/inventory generations,
schema, protocol, configuration, lock treatment, audit treatment, capture
authority, reachability proof, integrity-verification proof, primary storage
and credential-scope commitments, target/policy commitments, capture and
minimum-retention times, declared object/byte totals, and ordered branch/tag
root commitments. Ref names are represented only by opaque commitments. That
representation prevents this crate from emitting raw names but does not prove
hiding or unlinkability against a caller's commitment scheme. Root targets and
inventory objects use the frozen OGVCS-002 `ObjectRef` type.

## Validation and failure order

1. Configured root/object/byte/work/retained-memory limits are capped by hard
   candidate maxima; cancellation is checked before capture validation.
2. Capture commitments, same-generation binding, retention interval, source
   versus target non-alias checks, root shape/order/uniqueness, declared count,
   declared bytes, the count-derived maximum possible byte sum, exact work, and
   deterministic peak retained charge are preflighted before either inventory
   iterator is polled. After exact-length preflight, a unique-root count larger
   than the inventory also fails without row polling.
3. Both inputs must expose the declared exact length. The implementation then
   polls each stream for exactly the declared rows plus one terminal
   end-of-stream probe. One-sided and two-sided violations of the
   `ExactSizeIterator` contract therefore fail without relying on `zip`'s
   shortest-stream behavior.
4. Expected and copy rows are consumed in strict OGVCS-002 identity order.
   Duplicate/reordered rows fail before their later semantic use. Identity and
   declared object length must match exactly. Root rows are ordered and unique
   by `(kind, name_commitment)`, so one logical ref key cannot bind two targets.
   A regression proves the native `ObjectRef` order matches the frozen complete
   deterministic-CBOR reference-byte order for all eleven v1 kinds.
5. Every row is checked against the frozen OGVCS-002 chunk or metadata payload
   maximum; only a raw chunk may declare zero payload bytes. Copy evidence must
   bind the declared target, a nonzero storage generation, verification
   receipt, retention proof, and a retention deadline no earlier than the
   capture minimum.
6. Counts, checked byte totals, exact work, inventory digest, copy-evidence
   digest, and root membership close before a manifest is returned.
   Cancellation or any defect returns no partial report or digest.

The manifest self-check reconstructs capture validity, exact work and retained
charges, root digest, and the final domain-separated digest. Regression tests
exercise every root/inventory/copy row field, capture projection, and terminal
ledger field and reject correctly resealed work/memory ledgers that disagree
with reconstructed state. It does not reconstruct either consumed stream. The
unkeyed digest is a deterministic checksum, not producer authentication or a
signature. The three-row known answer fixes the private digest byte-for-byte.

## Resource interpretation

The builder retains only the bounded root set and hashing/accounting state;
the million-object inventory is streamed and not returned. Work units are one
per retained root plus one per expected row and one per copy-evidence row. The
retained-memory ledger conservatively charges fixed state and simultaneous
root-vector/root-set residency. The builder removes caller spare root-vector
capacity before returning retained state. The charge is still a deterministic
logical reservation, not allocator/RSS evidence, and cannot retroactively bound
capture or iterator allocations a caller made before invocation. Counts and
their digest fields are `u64`; every conversion from host iterator/root length
is checked before use.

Capture and copy times use the complete `u64` domain. Validation performs only
ordered comparisons, never duration arithmetic or calendar conversion, so the
maximum boundary cannot overflow. This seam supplies no trusted wall clock,
freshness decision, or operational timestamp range.

## Security and reliability review

| Condition | Fail-closed result |
|---|---|
| Source/target storage or credential-scope commitment aliases | `BACKUP_CAPTURE_INVALID` |
| Metadata and inventory generations differ | `BACKUP_CAPTURE_INVALID` |
| Missing/additional/mismatched copy row | `BACKUP_OBJECT_MISMATCH` |
| One-sided lying exact-size iterator | Terminal probe, then `BACKUP_OBJECT_MISMATCH` |
| Duplicate or reordered expected/copy row | Stable inventory/copy order error |
| Duplicate logical root key, absent target, or non-Snapshot root | Stable root-order/missing/capture error |
| Impossible zero metadata length, kind ceiling, or total envelope | `BACKUP_BYTE_LIMIT` |
| Exact/max+1 count, work, root, or memory envelope | Stable typed limit; no manifest |
| Target/generation/verification/retention evidence malformed | `BACKUP_COPY_EVIDENCE_INVALID` |
| Cancellation before or during stream polling | `BACKUP_CANCELLED`; no manifest |
| Counter/sum overflow | `BACKUP_ACCOUNTING_OVERFLOW`; no saturated result |

Every authority and proof field is opaque supplied data. Hash inequality only
prevents an obvious binding alias; it does not prove credential separation or
that operators, storage systems, retention controls, or encryption keys are
independent. The candidate neither opens storage nor verifies object payloads,
receipts, signatures, policies, graph reachability, or ref-name commitment
privacy.

## Acceptance interpretation and residual work

- **FR-01/FR-02:** bounded data-model relevance only. The candidate binds the
  requested generation/root/configuration/treatment/inventory/copy-proof
  projections and rejects an incomplete exact set. It does not authenticate
  their producers or establish an independently retained copy.
- **AC-01 through AC-07:** open. There is no clean restore, production-storage
  removal, fault-resumable backup, GC/submit race model, quarantine/sweep,
  deletion receipt, drill, or operator evidence.

OGVCS-018 remains Todo. A production backup-target adapter, separate credential
and encryption authorities, durable/versioned manifest format, resumable copy
cursor, OGVCS-017 full-graph invocation, restore planning/isolation/activation,
pins/holds/retention authority, lifecycle/GC transactions, audit/outbox,
freshness and RPO/RTO telemetry, destructive clean-target drills, hosted
cross-OS evidence, and reference-scale/SLO evidence remain absent. No public
command, route, service, or production module imports this crate.

## Local evidence commands

```text
cargo +1.82.0 fmt --manifest-path core/backup-manifest/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path core/backup-manifest/rust/Cargo.toml --locked --offline
cargo +1.82.0 test --manifest-path core/backup-manifest/rust/Cargo.toml --release --locked --offline
cargo +1.82.0 clippy --manifest-path core/backup-manifest/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo +1.82.0 package --manifest-path core/backup-manifest/rust/Cargo.toml --locked --offline --allow-dirty --no-verify
node --test tools/backup-manifest-source-policy.test.mjs
npm run test:roadmap
```
