# OpenGameVCS format-v1 logical bundle

## 1. Boundary and non-claim

A logical bundle is a deterministic, bounded CBOR sequence containing a
caller-selected set of immutable objects, typed logical records, declared
roots, and an integrity trailer. It proves only the integrity and supplied
closure described here.

It is **not an export**. It makes no claim of authorization, non-disclosure,
consistent repository generation, repository completeness, fidelity,
projection, signature policy, volume completeness, incrementality,
restorability, or importability. Implementations MUST call the format
`logical-bundle-v1` or `supplied-closure`; they MUST NOT relabel a successful
bundle result as fidelity/projection/export evidence. OGVCS-033 owns those
claims and containers.

The public claim label is exactly `supplied-closure`. A caller or wrapper that
asks this boundary to classify the same bytes as an export, fidelity artifact,
or authorized projection MUST receive `BUNDLE_EXPORT_CLAIM_FORBIDDEN` at
layer 3. This classification is pure and does not rewrite or reinterpret the
bundle.

The sequence follows the RFC 8742 model: complete deterministic-CBOR items are
concatenated without an outer array, delimiter, or transport framing. Each item
uses the shapes in [`repository-format.cddl`](repository-format.cddl).

## 2. Record sequence

The only valid order is:

1. exactly one `bundle-header`;
2. exactly the declared number of `bundle-object` items;
3. exactly the declared number of `bundle-logical-record` items;
4. exactly the declared number of `bundle-root` items;
5. exactly one `bundle-trailer` and then EOF.

Each section has a zero-based contiguous ordinal in field 2. Objects sort
strictly by the complete deterministic-CBOR bytes of their `ObjectRef`. Logical
records sort strictly by the tuple `(numeric logical-record type code, raw
32-byte logical-record identity digest)`. Roots sort strictly by the tuple
`(numeric root kind, deterministic-CBOR bytes of field 4's typed identity,
deterministic-CBOR bytes of field 5's role ProfileRef)`. Tuple comparison is
component-by-component unsigned lexicographic comparison and never ambiguous
concatenation. A duplicate identity, sort-key tie, missing ordinal, extra item, or
bytes after the trailer is invalid.

### 2.1 Header

```text
{
  0: 1,                         // bundle format
  1: 1,                         // item type: header
  2: 1,                         // closure mode: supplied closure
  3: object-count,
  4: logical-record-count,
  5: root-count,
  6: {
    0: declared-total-sequence-bytes,
    1: declared-largest-item-bytes,
    2: declared-maximum-traversal-edges,
    3: declared-maximum-index-entries
  }
}
```

Field 2 is the `closure-mode`, not a profile reference. Value 1 is the only v1
mode and means `supplied-closure`; any other value is
`BUNDLE_MODE_UNSUPPORTED`. Counts and budgets are unsigned 64-bit values. The
actual values MUST NOT exceed the declarations. Traversal-edge and index
accounting are defined in section 5. A declaration MUST NOT exceed
a receiver's configured budget or the named bundle hard maxima in
[`registries/limits.json`](registries/limits.json). Those maxima cover sequence
bytes, largest item bytes, object/logical/root/total item counts, traversal
edges, and index entries. Limits are checked before allocation; declarations
are not requests that a receiver reserve the declared amount. Receivers SHOULD
configure lower deployment limits and MUST stream rather than allocate from a
count declaration.

The 2 TiB sequence maximum leaves deterministic framing headroom for a complete
closure containing a 1 TiB logical file. The largest-item maximum is the 512
MiB metadata-payload maximum plus 512 bytes of bundle framing headroom; an
implementation MUST still enforce the smaller payload-specific limit inside the
item.

### 2.2 Immutable object item

```text
{0:1, 1:2, 2:ordinal, 3:ObjectRef, 4:payload-bytes}
```

For kind 1, payload bytes are the raw chunk. For every metadata kind, payload
bytes contain exactly one deterministic-CBOR item. Field 3 includes the format
version, expected kind, hash algorithm, and digest. The recomputed object ID
MUST equal it.

Field 4 is a field-specific exception to the generic 16 MiB byte-value ceiling:
its maximum is 64 MiB when field 3 expects a chunk and 512 MiB when field 3
expects metadata, while the complete wrapper remains subject to the
512 MiB-plus-512-byte largest-item limit. The reader checks this outer
kind-specific length before allocation and then checks the inner payload's exact
boundary and field-specific limits. This exception does not raise the 16 MiB
generic ceiling for any byte or text value inside decoded metadata.

Wrapping bytes do not participate in ObjectID. The payload is preserved
unchanged, allowing an integrity scanner to hash and forward an object whose
required features are not semantically supported.

### 2.3 Typed logical-record item

```text
{0:1, 1:3, 2:ordinal, 3:record-identity, 4:logical-record}
```

A logical record is canonical but not an immutable repository object. Its
identity is:

```text
SHA-256(
  ASCII("OpenGameVCS logical record\0") ||
  uint16be(1) ||
  uint16be(logical-record-type) ||
  deterministic-cbor(logical-record)
)
```

The typed identity uses SHA-256. This digest supports deterministic ordering,
roots, duplicate detection, and bundle integrity; it does not turn the record
into immutable history or a content-addressed object.

Logical record type assignments are:

| Code | Record | Stable key and meaning |
|---:|---|---|
| 1 | `repository-root` | descriptor plus designated zero-parent root |
| 2 | `mutable-ref` | descriptor, branch/tag kind, name, snapshot, generation |
| 3 | `shelf-pointer` | descriptor, ShelfID, current revision, generation |
| 4 | `file-id-lifetime` | descriptor, FileID, immutable first-consumption origin/change-set/operation and optional import key |
| 5 | `import-mapping` | descriptor, importer profile, source digests, FileID, state |
| 6 | `pending-change-reference` | descriptor, pending ID, base, change set, optional conflicts |
| 7 | `lock-reference` | descriptor, FileID/GroupID target, base, generation |
| 8 | `annotation` | subject ObjectRef, annotation profile, annotation bytes |
| 9 | `fixture-event` | scenario digest, sequence, fixture-event profile, exact public-event digest, operation-kind token |

The `mutable-ref` name is nonempty NFC text and is bounded by the generic
16 MiB UTF-8 value ceiling.

The file-id-lifetime record is
`{0:1,1:4,16:descriptor,17:FileID,18:origin,19:first-change-set,
20:first-operation,?21:import-mapping-key}`. Origins are `1 native-create`, `2
native-copy`, and `3 import`; restore is not an origin. Key 21 is required only
for import. The referenced operation must be the first consumption and agree
with the origin, so this record is immutable evidence rather than a mutable
reserved/consumed status. Import-mapping state remains the separate monotonic
`reserved`, `materialized`, or `published` projection.

An annotation is deliberately a logical record. It references its subject
ObjectID, is excluded from the subject preimage, and is protected by its record
identity and the bundle transcript. Changing or removing it cannot change the
manifest or other subject ObjectID.

These records preserve typed logical state only. They do not define database
rows, service state machines, CAS authorization, lock validity, or audit truth.

### 2.4 Root item

```text
{0:1, 1:4, 2:ordinal, 3:root-kind, 4:identity, 5:role-profile}
```

Root kind 1 uses an `ObjectRef`; kind 2 uses a typed logical-record digest.
`role-profile` describes caller intent using a registered `ProfileRef`; it does
not add an authorization or completeness claim. Every logical record in the
bundle MUST have exactly one logical-record root item. Immutable object roots
are caller-selected and must have at least one root item in a nonempty object
bundle. Duplicate root identities or duplicate `(identity, role)` pairs are
invalid.

### 2.5 Integrity trailer

```text
{
  0: 1,
  1: 5,
  2: object-count,
  3: logical-record-count,
  4: root-count,
  5: total-item-count-including-header-and-trailer,
  6: transcript-digest
}
```

Counts must repeat the header and observed counts. The transcript digest is:

```text
SHA-256(
  ASCII("OpenGameVCS logical bundle\0") ||
  uint16be(1) ||
  exact concatenated CBOR bytes of every item before the trailer
)
```

The trailer is excluded from its own digest. Truncation, mutation, reordering,
insertion, deletion, or a changed header/budget therefore changes the digest or
structure.

## 3. Supplied closure

After identity checks, the verifier walks outbound references from all declared
object roots and from every logical record. It follows the object edges defined
in `object-model.md`, including parents, trees, manifests/chunks, change sets,
groups, conflicts, provenance inputs, shelf inputs, attestation subjects, and
logical-record object references.

The set of reached ObjectIDs MUST equal the supplied object set exactly:

- a missing reached object is `BUNDLE_CLOSURE_MISSING`;
- a supplied but unreachable object is `BUNDLE_CLOSURE_EXTRA`;
- a wrong expected kind is `OBJECT_REFERENCE_KIND_MISMATCH`;
- duplicate supplied identity is `BUNDLE_DUPLICATE_IDENTITY`.

Inbound attestations are not automatically reached from their subjects. To
include one, the caller declares the attestation as an object root; traversal
then reaches its subject. This preserves the no-cycle object model.

The closure is only closure of the supplied roots. The verifier MUST NOT infer
that the roots are all repository roots, all authorized roots, or a consistent
generation.

## 4. Validation layers

Results distinguish three layers; a later layer MUST NOT be reported when an
earlier one failed.

Within a layer, the normative error is selected by the `errors.json.precedence`
contract: frozen validation-stage order, error-catalogue order, smallest
absolute input offset, then the frozen subject comparator. Implementations MUST
report the selected catalogue site as the actual `(code, layer, stage)` result
and MUST complete every safely discoverable layer-1 section/order/identity and
transcript
check before entering known schema. Thus a stale transcript cannot be hidden by
a later manifest-schema failure, traversal cannot replace an established
layer-1 failure, and semantic replay cannot replace layer-2 schema/closure.

### Layer 1 — canonical scan, identity, and forwarding

The reader checks item framing/order/counts/budgets, deterministic CBOR,
payload size, ObjectRef format/kind/algorithm, object hash, logical-record
identity, and trailer digest. Metadata with an unsupported required feature may
be retained and forwarded after this layer. The result is
`integrity-valid-forwardable`, not semantically valid.

### Layer 2 — known base schema and graph shape

For known object and logical-record types, the reader checks registered base
fields, enums, nested shapes, hard maxima, typed references, and supplied
closure. A structurally intact object whose base kind/record schema is unknown
cannot pass this layer. The result is `schema-valid`.

### Layer 3 — supported semantic context

The reader checks required-feature support, profile availability/state,
descriptor binding, production-versus-conformance profile rules, manifest
reconstruction, repository root/parent graph, transition replay, FileID/group
proofs, shelf/conflict placement, and all other repository-context invariants.
The result is `semantic-valid`.

Unsupported required features or profiles are typed unsupported failures at
layer 3; they do not retroactively invalidate a successful layer-1 hash scan.
Callers requiring semantic verification MUST treat a layer-1 or layer-2-only
result as insufficient.

## 5. Streaming, accounting, and bounds

`actual traversal edges` counts each outbound `ObjectRef` field occurrence in
each unique supplied immutable object expanded once and in each supplied logical
record scanned once. Repeated references in distinct fields or array elements
count separately. It includes tree targets, chunk-part references, snapshot and
shelf edges, change-set/proof/state references, conflict-side targets,
provenance inputs, attestation subjects, and every ObjectRef field in logical
records. It excludes bundle wrapper field 3, root identity field 4, the header,
trailer, logical-record identity digest, conflict preimage re-encoding, profile
references, typed digests, and the act of looking up or re-visiting an already
expanded identity. Missing and wrong-kind references still consume the one edge
that attempted traversal before failing.

`actual index entries` is exactly one entry for every unique supplied immutable
object identity plus one for every unique supplied logical-record identity.
Roots, traversal edges, ordinals, transcript state, path/FileID semantic scratch
indexes, and duplicate attempts do not add bundle index entries. Duplicate
identity is rejected independently; it cannot inflate a valid actual count.
Actual object/logical/root/total item counts are observed section counts, and
total items includes the header and trailer. Declared maxima must be at least
these actual values and no greater than the hard or configured ceiling.

After transcript authentication, a reader compares the safely known actual
sequence bytes, largest-item bytes, and index-entry count with their declarations
before entering layer-2 closure work. It compares actual traversal edges as soon
as known-schema scanning has safely enumerated every supplied outbound edge and
before closure resolution. An under-declaration is a layer-1
`BUNDLE_BUDGET_EXCEEDED` at `declared-accounting`; it MUST NOT be hidden by a
later layer-2 closure failure or layer-3 registry failure. A schema failure that
prevents safe edge enumeration remains the selected result because the edge
accounting fact was not safely discoverable.

A reader processes the CBOR sequence incrementally and hashes exact item bytes
as read. It may spool payloads and a compact `(identity, offset, length, kind)`
index to bounded scratch. Global closure, FileID, and path validation may use a
disk-backed ordered index. No step requires loading all objects or a
million-entry tree in memory.

The 512 MiB metadata, 64 MiB chunk, nesting-32, and object-specific limits are
format maxima. Receivers may impose lower total bytes, items, edges, memory,
time, and scratch budgets. Repository path profiles may impose lower path and
depth limits than the core 4096-byte/256-segment maxima. Exceeding a configured
limit is a typed resource error and never a partial trusted result.
