# OGVCS-017 private read-only verifier rc.1

This unpublished Rust 1.82 crate is a bounded, deliberately unwired integrity
verification seam. It pins one supplied immutable generation, walks the
content closure rooted at a format-v1 `Snapshot` (`Snapshot` root `Tree`,
ordered tree file/version entries, `ContentManifest`, and `Chunk` objects),
and returns only typed findings, digests, counts, and byte/work ledgers. It
never returns or publishes object payloads.

Metadata identity, canonical CBOR framing, version, known schema, and typed
references are checked by `ogvcs-object-model`. Manifest shape, chunk
identity, whole-file digest, and Gear boundary closure are checked by
`ogvcs-chunking-manifest::verify_manifest`. The source interface belongs to
this private candidate only: it has no production adapter, endpoint, command,
storage-health brand, authentication, permission, audit, quarantine, or repair
semantics.

The metadata-boundary cursor retains the captured generation, deterministic
pending closure, seen objects, expected file sizes, covered identities,
traversed edges, file/version keys, restart recovery class, terminal-overflow
state, findings, and cumulative coverage ledger. Its digest binds all of that
state. Active resume fails closed if either the source generation or an
individual read generation changes; generation drift takes precedence over
cancellation observed on the same returned read. Cancellation raised while a
read is in flight retains that metadata object or manifest as pending.
Per-page object, source-read, transferred-byte, work-unit, object-byte, cursor-count,
manifest-index, manifest-ledger, fragment, finding, and charged-memory limits
are explicit. Charged memory is a deterministic conservative accounting
contract for cursor nodes plus admitted codec/index/object reservations. The
initial root cursor is admitted before source generation is consulted. The
maximum passed to the source is capped by the remaining object, transfer, and
memory envelope before allocation. The private source contract bounds both
the returned `Vec` length and capacity by that maximum and must answer an
oversized allocation with `ByteLimit` and no payload; a violation becomes
`SourceUnavailable` / `SourceFailure`, never valid bytes. The admitted actual
capacity remains charged through metadata processing or chunk coverage.
Returned `Found` payload bytes are counted as source effort even when a later
generation, cancellation, or source-contract check rejects the read. A
manifest reservation stays charged while each chunk buffer is admitted, so
those simultaneous holdings cannot be counted separately. Cursor-growth
admission is atomic with newly admitted edge work: a rejected edge changes
neither graph coverage nor the work ledger. This is not an allocator profiler.
At completion, the report's contiguous finding buffer is admitted while the
cursor finding set remains live; a tight envelope returns `LimitReached`
without a report.
An invalid resume envelope also returns `LimitReached` with the cursor
unchanged, so a configuration mistake cannot consume the only resumable state.

Logical-file byte totals use checked accounting. An unrepresentable sum returns
terminal `CoverageOverflow` with no report. If the finding envelope fills, the
corpus retains a fail-closed `FindingsTruncated` sentinel and can never claim an
intact result merely because individual findings were dropped.

An OGVCS-007 manifest closure is one indivisible verification unit in this
candidate. A source/read/byte/work/memory limit reached inside it returns
`ManifestRestartRequired`; retry with the same or a smaller relevant envelope
returns immediately without rereading chunks. A materially expanded relevant
envelope may retry that manifest from occurrence zero. The private restart
marker names the actual recovery class, including page-transfer versus
single-object bytes, general work versus fragment work, and configured decode
working memory. A charged-memory stop requires a larger charged-memory
ceiling; OGVCS-007 `ResourceExhausted` requires a larger
manifest-index envelope; and no-scratch `ScratchExhausted` requires a larger
resident manifest-ledger envelope. Irrelevant envelope changes do not trigger
a reread. Any enlarged index or ledger reservation is then admitted again
against charged memory and can produce a charged-memory stop. OGVCS-007
unsupported profiles, `ResourceInvalid`, and `ResourceUnsupported` are
non-corruption, non-restartable source/configuration failures. Cancellation likewise keeps the
manifest pending and an uncancelled retry restarts it from occurrence zero, so
prior source/work effort can repeat. There is no sub-manifest cursor, and this
is not evidence for AC-04 full-scrub resumability.

OGVCS-007's nonrecoverable ledger-counter `CountExceeded` path is classified as
`ManifestCorrupt`, not as a restartable verifier count limit. Increasing a
candidate envelope cannot turn that overflow into valid closure evidence.

## Read-only replica assessment follow-up

The crate also contains a private, synchronous replica-assessment function. It
accepts one exact object reference, a supplied generation and serialized-byte
expectation, and at most 64 fixed-width backend observations. Count, per-copy
bytes, aggregate bytes, work, result-memory, and decode-memory limits are
preflighted before sorting, allocation, hashing, or parsing. Present chunk
bytes must reproduce the exact chunk identity. Present metadata bytes must
reproduce the domain-separated object identity and then pass canonical framing,
known-schema, and exact-kind validation. Missing, ambiguous, and unavailable
states remain supplied observations; the function has no way to establish that
the supplied replica set is a complete physical inventory.

The deterministic result is sorted by opaque backend ID. It returns only typed
copy outcomes and opaque, domain-separated observation/local-validation
commitments. Raw object bytes and raw SHA-256 values are not returned and Debug
formatting redacts backend IDs and commitments. If one or more identical copies
validate locally and the remaining supplied copies are missing or corrupt, the result may
contain non-authoritative quarantine and repair previews bound to the exact
source and destination observations. Ambiguity, unavailability, or two
different byte strings that somehow validate as the same object identity
suppress all previews. Differing corrupt copies receive a distinct replica-
disagreement disposition without exposing their content hashes. With no
locally validated source the result is `NoVerifiedSource` and no repair preview
is produced. A lone valid observation is `SingleVerifiedCopy`, not agreement.

These statuses describe only the supplied replica set. They are not a
storage-health decision, affected-root finding, read-routing decision, repair
permission, quarantine permission, or proof that a backend generation is
current. The sealed local-validation commitment is not exported as backend
provenance or freshness evidence. A future mutation boundary must independently authenticate and
authorize the operation, prove inventory completeness where required, re-read
and reverify source and destination state, compare-and-swap the exact backend
generation, audit the disposition, and verify the post-copy bytes. This
follow-up performs no storage mutation and does not satisfy AC-02 or AC-03.

This tranche does **not** traverse snapshot parents, descriptor/change-set,
asset-group, provenance, conflict, attestation, shelf, unreachable inventory,
or authoritative replica topology. It does not quarantine, repair, durably
persist degraded roots, findings, or cursors, arbitrate concurrent production mutation, expose
public commands, or claim hosted cross-OS or reference-scale evidence.
OGVCS-017 remains Todo.

Coverage is over unique content-addressed objects and unique object-graph
definitions. Graph edges use `(parent object, ordinal, child object)` and
file/version entries use `(tree object, ordinal)`. If a snapshot reuses one
subtree object at multiple paths, object bytes and that subtree's internal
entry definitions are counted once; `logical_file_bytes` is therefore not a
namespace-expanded path-multiplicity total.

Local gates:

```text
cargo +1.82.0 fmt --manifest-path core/integrity-verifier/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path core/integrity-verifier/rust/Cargo.toml --locked --offline
cargo +1.82.0 clippy --manifest-path core/integrity-verifier/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo +1.82.0 package --manifest-path core/integrity-verifier/rust/Cargo.toml --locked --offline --allow-dirty --no-verify
node --test tools/integrity-verifier-source-policy.test.mjs
npm run test:roadmap
```

The package command proves the bounded include set and archive construction.
This unpublished crate deliberately retains local OGVCS-002/007 path
dependencies, so it is not evidence of a registry-resolved standalone or
hosted hermetic install.
