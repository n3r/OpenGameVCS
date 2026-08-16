# OpenGameVCS object model — Rust

This crate is the dependency-minimal, clean-room Rust implementation of the
OpenGameVCS repository-format-v1 codec. It provides deterministic CBOR,
domain-separated identities, the packaged twelve-file registry set, known
object and logical-record schemas, repository transition/graph validation,
bounded manifest and tree streaming, and logical-bundle supplied-closure
emission and verification.

Dependencies are exactly pinned in `Cargo.lock`. Runtime verification does not
need the repository checkout or network: `Registry::bundled()` loads the exact
registry snapshot embedded in the crate.
`Registry::registry_document` and `registry_entry_count` retain immutable
discovery access to every authority, including fields, entry modes, and hash
algorithms that do not need a specialized runtime decision API.

## Validation boundaries

The low-level APIs deliberately keep format layers visible:

```rust
use ogvcs_object_model::{scan_metadata, validate_metadata_schema, Limits};

let scanned = scan_metadata(payload, Limits::METADATA)?; // canonical framing
let kind = validate_metadata_schema(&scanned)?;           // known-kind shape
let original = scanned.original_bytes();                  // lossless forwarding
# Ok::<(), ogvcs_object_model::Error>(())
```

Every rejected public operation returns an `Error` with a stable `code`,
`layer`, and `ValidationStage`; `stage.as_str()` is the exact diagnostic-site
token from `errors.json`. `ErrorCode::default_stage(layer)` is available only
when that code/layer pair has one frozen site. The five ambiguous pairs are
selected explicitly by the producing route, and `Error::is_registered_site`
can be used at integration boundaries to reject an unregistered combination.

For a direct layer-3 decision on one known metadata object, call
`validate_semantic_object(&scanned, &registry, mode)`. It always validates the
known base schema at layer 2 before checking required features and profile
availability/state at layer 3, so a mixed-invalid object reports the earlier
schema failure. `RepositoryObjectLookup::resolve` applies the same ordering
while also enforcing the caller's identity, kind, and resource context.
`ValidationMode::{Read, Conformance, Production}` selects the shared registry
lifecycle truth table for every known object kind, hash, field, extension,
profile, entry kind/mode, semantic enum, and logical-record type. Unknown
optional extensions remain losslessly forwardable; a selected known assignment
still obeys its reserved, conformance-only, ratified, or deprecated state.

`hard_limit_maximum` and `evaluate_hard_limit` expose the frozen 25-family
authority without materializing maximum-sized values. `HardLimitCeilings`
provides deployment reductions; `with_limit` always caps a requested value at
the frozen maximum. Pass it through `scan_metadata_with_hard_limits` (or
`RepositoryLimits::hard_limits`) when framing and subsequent schema validation
must share the same reduced ceilings. `MetadataObject::constrained_by` can only
tighten the ceilings retained by an already successful scan. Stream and bundle
limit structs likewise cap their individual fields at the same authority.

Repository APIs validate manifests, expanded trees, change-set replay, FileID
lifetime/import evidence, groups, conflicts, snapshots, provenance, shelves,
and the abstract reference graph against a caller-owned
`RepositoryObjectLookup`. The caller remains responsible for storage,
transactions, authorization, and choosing the repository context. Its
`RepositoryLimits::default()` values are finite (100,000 objects, 128 MiB
encoded input, one million edges, 1 GiB conservative retained-memory and
scratch ceilings, 64 MiB chunks, and ten minutes); ingestion is checked before
objects enter the lookup. Larger graph validation must use an explicitly
bounded caller-owned lookup/service rather than relying on unbounded defaults.

`visit_logical_bundle` is the small streaming framing/visitor boundary. For a
complete supplied-closure decision, use `verify_logical_bundle_stream` with any
`Read`, or `verify_logical_bundle_file` for same-handle file verification:

```rust
use ogvcs_object_model::{
    verify_logical_bundle_file, LogicalBundleVerifyOptions, Registry,
};

let registry = Registry::bundled();
let options = LogicalBundleVerifyOptions::new(scratch_directory, &registry);
let summary = verify_logical_bundle_file(bundle_path, options)?;
assert_eq!(summary.highest_layer, 2);
# Ok::<(), ogvcs_object_model::Error>(())
```

The high-level verifier requires an existing, non-symlink scratch directory.
It spools exact input and uses exclusive private files, bounded external-sort
indexes, fixed-width edge/queue records, and a disk reachability bitmap. It
retains at most one configured-size decoded item and removes all private files
on success or failure. `LogicalBundleVerifyLimits` exposes independent total,
item, count, traversal, index, memory, scratch, elapsed-time, decoded-item,
sort-run, fan-in, and read-buffer ceilings. Its summary is privacy-safe: only
counts, timings, scratch metrics, and the transcript digest are returned.

`LogicalBundleWriter` emits a deterministic RFC 8742 CBOR sequence to any
`std::io::Write` without retaining the complete bundle or object graph. The
caller freezes header counts and declaration budgets first, then supplies
already sorted objects, logical records, and roots one at a time:

```rust
use ogvcs_object_model::{
    LogicalBundleBudget, LogicalBundleWriteOptions, LogicalBundleWritePlan,
    LogicalBundleWriter, Registry,
};

let registry = Registry::bundled();
let plan = LogicalBundleWritePlan {
    object_count: 0,
    logical_record_count: 0,
    root_count: 0,
    budget: LogicalBundleBudget {
        sequence_bytes: 77,
        largest_item_bytes: 52,
        traversal_edges: 0,
        index_entries: 0,
    },
};
let mut bytes = Vec::new();
let mut writer = LogicalBundleWriter::new(
    &mut bytes,
    plan,
    LogicalBundleWriteOptions::new(&registry),
)?;
let summary = writer.finish()?;
assert_eq!(summary.items, 2);
# Ok::<(), ogvcs_object_model::Error>(())
```

Before each item is emitted, the writer validates canonical shape, object and
logical-record identity, known base schema, registry/profile context, ordering,
counts, and actual traversal/index accounting. Object payload slices are
forwarded byte-for-byte and are never re-encoded. Header and trailer bytes are
included in sequence/largest-item enforcement, and the trailer contains the
exact transcript digest. A validation failure before emission is retryable; an
I/O failure or an elapsed-time stop during emission may leave a partial item and
poisons that writer. `LogicalBundleWriteLimits` applies finite memory and
elapsed-time ceilings (64 MiB and ten minutes by default). Memory accounting
covers writer-owned decoded/encoded values and canonical-key working state;
borrowed caller-owned inputs are not charged twice. The ordered writer uses no
scratch storage.

Treat the output sink as staging and therefore untrusted until `finish`
succeeds. For a durable publication, reread that staged output through
`verify_logical_bundle_stream` or `verify_logical_bundle_file`, then publish it
with the repository's atomic publication mechanism. Never expose a sink after
an error as a logical bundle, even when it happens to end at an item boundary.

Elapsed-time limits are cooperative checkpoints between bounded compute,
read, and write chunks. A call already inside `std::io::Read` or
`std::io::Write` cannot be preempted. Callers with a strict wall-clock SLA must
provide timeout-bounded or cancellable I/O, or isolate verification/writing in
a process they can terminate. Spool files, output sinks, and other staging data
remain untrusted until the operation returns success.

The streaming writer intentionally does not build a global identity/closure
index. After writing to a durable or rereadable sink, use
`verify_logical_bundle_stream` or `verify_logical_bundle_file` when a complete
supplied-closure decision is required. In particular, successful emission alone
does not prove that a root identity was supplied or that all supplied objects
are reachable.

A successful logical-bundle result is called `logical-bundle-v1` or
`supplied-closure`. It is not fidelity, projection, export, authorization,
repository-completeness, signature, restoration, or import evidence.

`allocate_file_id` reads only the operating-system CSPRNG through `getrandom`,
rejects zero, and performs a bounded number of collision retries without a
clock/path/counter fallback. `allocate_file_id_with` accepts injected entropy
for deterministic collision and exhaustion tests.

## Development and packaging

Run the normal offline gate from this directory:

```text
cargo fmt --all -- --check
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo package --locked --offline
```

The integration tests consume the checked-in normative objects, logical
records, logical bundles, conflicts, malformed/truncation cases, registry
compatibility cases, and configured-limit fixtures directly from
`spec/repository-format/v1/vectors`. The release-only exact scale test remains
explicitly ignored during the ordinary gate. That ignored test also runs the
streaming tree verifier with a distinct FileID scratch index and records its
wall time, maximum RSS, peak scratch, and scratch-write counts; ordinary CI
never materializes the one-million-entry or logical-one-TiB constructors.

The Rust scenario/conformance exporter executes every applicable non-scale
language-neutral scenario and emits canonical JSON. It reports JavaScript-only
fixture-adapter constructors as explicitly not applicable and leaves only the
two exact-scale constructors inventory-only:

```text
cargo run --locked --offline --bin object_model_scenario_report -- \
  --conformance \
  --vectors ../../../spec/repository-format/v1/vectors \
  --registries ../../../spec/repository-format/v1/registries \
  --output <report.json>
```

`--vectors` may instead be supplied through `OGVCS_VECTOR_ROOT`. When
`--registries` is omitted, the exporter uses the sibling `registries`
directory of that vector root, which lets an installed format-v1 data artifact
drive the same report without checkout-relative assumptions. Omit
`--conformance` to emit only the embedded
`ogvcs.object-model.scenario-execution-report/v1` object.

To build a self-contained offline distribution, first create an artifact
parent directory, then run:

```text
node scripts/build-offline-distribution.mjs --output <parent>/ogvcs-object-model-offline-0.1.0
node scripts/build-offline-distribution.mjs --verify <parent>/ogvcs-object-model-offline-0.1.0
```

The builder refuses dirty source by default and every Cargo operation is
`--locked --offline`. The result contains the packaged crate, lockfile,
checksum-verified vendored dependencies and licenses, offline Cargo source
configuration, a locked smoke consumer, and a canonical manifest. Its
reproducibility/tamper/cleanup test is:

```text
node --test scripts/offline-distribution.test.mjs
```
