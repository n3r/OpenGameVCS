# OpenGameVCS repository format v1: canonical encoding and registries

**Status:** Normative draft for OGVCS-002
**Format version:** 1
**Encoding profile:** `ogvcs-deterministic-cbor-v1`

## 1. Scope and normative precedence

This document defines the language-neutral byte encoding, object identity,
strict-decoder behavior, reference text forms, registry governance, and hard
resource limits for OpenGameVCS repository format v1. It does not define the
kind-specific object model, a production path or chunking algorithm, physical
transfer framing, or a repository-complete export.

ADR-0008, ADR-0009, and ADR-0010 are the design authority for this draft. Their
proposal or acceptance status also determines whether this format may be called
ratified; publication of this draft does not ratify them. Within this directory:

1. this document is normative for encoding mechanics, hash preimages, textual
   forms, canonicality, and decoder behavior;
2. the JSON registries in [`registries/`](registries/) are normative for assigned
   numeric values, names, states, pairings, profiles, and hard limit values; and
3. later CDDL, vectors, implementation code, package metadata, or generated
   documentation may constrain values further but cannot redefine either source.

If an ADR, this document, and a registry disagree, an implementation
MUST stop and report a specification defect. It MUST NOT select the most
permissive interpretation. For duplicated facts inside this directory, the
registry controls numeric assignments and limit values, while this document
controls encoding and validation mechanics.

`registries/semantic-enums.json` owns every semantic numeric choice that is not
already owned by an object-kind, entry, hash, feature, field, or logical-record
registry. Numeric comments in CDDL and prose names are mirrors of that registry.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and
MAY are to be interpreted as described by BCP 14 when, and only when, they appear
in all capitals.

## 2. Deterministic-CBOR profile

Except for a raw chunk, an immutable object payload is exactly one CBOR data item
using the following restricted profile of the RFC 8949 core deterministic
encoding requirements.

### 2.1 Allowed scalar values

- unsigned integers in the range `0..18446744073709551615`;
- negative integers in the range `-9223372036854775808..-1`;
- definite-length byte strings;
- definite-length text strings containing Unicode scalar values encoded as
  shortest-form UTF-8 and already normalized to NFC; and
- the simple values `false` and `true`.

All integers and string lengths MUST use the shortest CBOR additional-information
form. A schema MAY impose a smaller numeric or length range.

Text is compared and measured after UTF-8 encoding but is never modified during
decoding. A decoder MUST reject invalid UTF-8, non-shortest UTF-8, surrogate code
points, and text that is not already NFC. It MUST NOT normalize then accept the
input. Unless a kind schema says otherwise, line endings and other valid Unicode
scalar values retain their exact value.

### 2.2 Allowed containers

- definite-length arrays containing allowed values; and
- definite-length maps containing allowed values and satisfying their schema's
  key restrictions.

Schema maps use unsigned integer keys. They MUST be emitted in RFC 8949 core
deterministic order. Because schema-map keys are unsigned integers in shortest
form, this is increasing numeric order. The extension map described below uses
text keys and therefore uses the encoded-key ordering required by RFC 8949:
first by encoded key length, then by bytewise lexical order of the encoded key.
A structured extension payload uses arrays and maps with unsigned integer keys;
nested free-form text-key maps are not part of format v1.

Map keys MUST be unique. An array's order is identity-significant unless its
schema explicitly requires a canonical sort. Container counts MUST be known
before their headers are emitted.

### 2.3 Forbidden values and forms

The following are invalid in every v1 canonical payload, including inside an
unknown optional extension:

- floating-point values;
- semantic tags;
- `null`, `undefined`, and unassigned simple values;
- positive or negative bignums;
- indefinite-length byte strings, text strings, arrays, or maps;
- duplicate map keys;
- nonminimal integer, length, or simple-value encodings; and
- bytes after the single top-level CBOR item.

Optional fields are represented by absence, never by `null`. A required empty
array or map is present. An optional empty/default value is omitted only when its
kind schema says that omission is canonical.

## 3. Metadata object envelope

Every metadata payload is a schema map with these common fields. A raw chunk has
no CBOR envelope; it implicitly has format version 1, kind `chunk`, the empty
required-feature set, and no extensions.

| Key | Requirement | Meaning |
|---:|---|---|
| 0 | required | unsigned format version, exactly `1` |
| 1 | required | object-kind code from `registries/object-kinds.json` |
| 2 | required | strictly increasing, duplicate-free required-feature IDs |
| 3 | optional | namespaced optional-extension map; omit when empty |
| 4..15 | forbidden in v1 | common fields reserved for a future format |
| 16..4095 | kind-specific | registered by the kind schema |

An object with an unsupported required feature can be checked for structural
canonicality and identity and MAY be stored or forwarded as opaque bytes. It
MUST NOT be semantically interpreted, traversed, rewritten, or written to a
production repository.

Extension-map keys use the same canonical namespace/identifier/major text
grammar as `ProfileRef`, for example `org.example/asset-hints@1`. An unknown
optional extension does not change base semantics. A component promising a
lossless round trip MUST preserve every unknown extension key and value, either
as its original canonical byte slice or as an equivalent generic value that
re-encodes to the same canonical bytes. Dropping it is not a lossless round trip.
An extension whose absence would change required interpretation needs a
registered required-feature ID; key 3 alone cannot create required semantics.
An extension value may recursively contain the allowed scalar values, arrays,
and unsigned-integer-key maps from this profile. The extension count and
aggregate encoded-value bytes are bounded by the hard-limit registry.

Unknown keys outside key 3, unknown enum values, and duplicate or unsorted
feature IDs are known-schema errors. An unregistered required-feature ID is a
semantic error: the framing scan may still hash, store, and forward the opaque
payload, but semantic interpretation is forbidden. The initial v1 feature
registry intentionally has no assigned nonzero features.

## 4. Registered helper values

### 4.1 Typed digest

A typed digest is the schema map:

```text
{ 0: hash-algorithm-code, 1: digest-bytes }
```

For SHA-256 the algorithm code is `1` and the digest is exactly 32 bytes.

### 4.2 Object reference

A binary object reference is the schema map:

```text
{
  0: format-version,
  1: expected-object-kind-code,
  2: hash-algorithm-code,
  3: digest-bytes
}
```

For v1, format version is exactly `1`. The expected kind is part of the reference
and MUST match the referenced object's registered kind. A wrong-format or
wrong-kind reference is invalid even if an object with the given digest exists
under another format or kind. No field may silently substitute an algorithm,
infer it from digest length, or omit it.

### 4.3 Profile reference

The abstract `ProfileRef` fields are `{namespace, id, major}`. Its CBOR form is:

```text
{ 0: namespace, 1: id, 2: major }
```

`namespace` and `id` are ASCII lowercase tokens and therefore are already NFC.
Define `token` as `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`. `namespace` MUST match
`token(?:\.token)+` and occupy at most 253 ASCII bytes; `id` MUST match `token`
and occupy at most 63 ASCII bytes; and `major` is an independently encoded
integer in `1..4294967295`. Registry identity is the complete tuple; no
component may be inferred, defaulted, or embedded in `id`. The canonical text
rendering is `<namespace>/<id>@<major>`, where `major` is base-10 without a
leading zero, for example `path.test/opaque@1`.

The initial profiles are conformance-only. They are valid in declared normative
vectors and fixture-adapter corpora and MUST be rejected when a caller requests
a production-repository write. Their exact family-specific payload and
validation semantics—including the deliberately non-cryptographic opaque
signature profile—are normative in
[`conformance-profiles.md`](conformance-profiles.md).

### 4.4 FileID

A binary FileID is exactly 16 bytes and MUST NOT be all zero. It is opaque and
has no UUID version, variant, byte-order, or textual-case semantics. Repository
scope and lifetime validation are object-model rules rather than byte encoding.

## 5. Object identity

The object-kind assignments are frozen in
`registries/object-kinds.json`. For registered kind code `K` and canonical
payload `P`, the format-v1 SHA-256 ObjectID is:

```text
SHA-256(
  ASCII("OpenGameVCS object\0") ||
  uint16be(1) ||
  uint16be(K) ||
  P
)
```

The ASCII domain is the 19 bytes
`4f70656e47616d65564353206f626a65637400`. The format and kind integers are
unsigned, fixed-width, and big-endian. No payload length, CBOR wrapper, text ID,
transport frame, compression metadata, tenant ID, or repository ID is inserted
into this preimage.

For `chunk`, `P` is exactly the raw logical chunk bytes. For every other kind,
`P` is the one canonical metadata CBOR item. The kind at metadata key 1 MUST
equal `K`. The hash consumes exactly the payload boundary supplied by the
containing object API or logical record; it does not consume following bytes.

Hash algorithm code `1` means SHA-256 and is the only v1 ObjectID algorithm.
Future algorithms require an assigned code and explicit compatibility rules;
digest length never selects an algorithm.

## 6. Durable text forms

The full ObjectID text form is:

```text
ogvcs:v1:<kind-name>:sha256:<64-lowercase-hex-digits>
```

`<kind-name>` is exactly the entry's `textToken` in the object-kind registry
and occupies at most 63 lowercase ASCII bytes. The complete durable ObjectID
text is therefore at most 144 bytes and parsers MUST enforce that bound before
splitting or otherwise allocating proportional component storage.
Each current token equals its lower-case registry name, including its hyphens;
aliases are not valid.
The parser MUST reject upper-case hex, a missing or extra component, an alias,
an unregistered kind, an unknown algorithm, the wrong digest length, whitespace,
and trailing characters. Example shape:

```text
ogvcs:v1:tree:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The full FileID text form is:

```text
fid:<32-lowercase-hex-digits>
```

The all-zero value is invalid. Abbreviations MAY be accepted in explicitly
interactive lookup interfaces, but they MUST NOT appear in canonical payloads,
durable records, signatures, registry data, or machine output claiming the full
identity.

## 7. Validation layers

A strict implementation exposes three distinct validation results and MUST NOT
collapse them into a single ambiguous "valid" result.

### 7.1 Canonical framing scan

The framing scan enforces byte/container hard limits, parses exactly one allowed
definite CBOR item, checks deterministic encoding, validates the common envelope
shape including a nonzero `uint16` kind code, and consumes the exact payload. It
can compute identity over the original bytes because the numeric kind is in the
hash domain. A successful framing scan MAY hash, store, or forward an otherwise
opaque object whose kind or required feature is unsupported by the local
registry snapshot. It cannot render a durable kind-name text ID for an unknown
kind and does not claim that the kind schema or semantics are supported.

### 7.2 Known-kind schema validation

Schema validation requires a supported registered object kind and validates all
registered fields, enums, lengths, counts, typed references, cross-field
constraints, and extension placement for that kind. Unknown core fields and
unknown enum values fail this layer. Passing it does not claim support for every
required feature or referenced profile.

### 7.3 Semantic feature/profile validation

Semantic validation verifies that every required feature and required profile is
known, has a state allowed for the requested operation, and satisfies contextual
graph, repository, transition, and production-write rules. Unsupported required
features or profiles fail here. `conformance-only` profiles pass only in an
explicit conformance context, never a production write.

A decoder performs the applicable checks in this order without exposing a
trusted partial object:

1. enforce caller-configured aggregate byte, object, time, memory, and scratch
   budgets while enforcing the non-overridable hard ceilings;
2. parse exactly one allowed, definite CBOR item without allocating from an
   unchecked length;
3. perform the canonical framing scan and reject nonminimal encodings, forbidden values, invalid/non-NFC text,
   duplicate or incorrectly ordered map keys, excessive nesting, and trailing
   bytes;
4. compute the ObjectID over the original canonical payload bytes and, when an
   expected reference is supplied, compare format, kind, algorithm, and digest
   in constant time where the implementation's security boundary requires it;
5. perform known-kind schema validation; and
6. perform semantic feature/profile validation before semantic use.

### 7.4 Deterministic failure selection

`errors.json.precedence` is machine authority for failure selection. Validation
establishes every failure that is safely discoverable in the earliest failing
layer and never reports a later-layer error over an earlier-layer error. Within
that layer it selects the earliest applicable validation stage in the frozen
`stageOrder`, then the error whose code occurs first in the `errors` array.
Among occurrences of that code, it selects the smallest absolute input byte
offset; when no offset exists or offsets tie, it selects the smallest affected
subject under the comparator table below.

A validator does not continue through an unsafe or structurally terminal stage
merely to discover a theoretically earlier catalogue code in a later stage. For
example, canonical sequence shape is established before object identity,
object identity before transcript authentication, and every safely discoverable
layer-1 bundle fact before known-schema or semantic interpretation. A stale
transcript therefore wins over a manifest-schema defect, while a terminal
malformed section header may prevent either fact from being discovered. A
configured resource stop that prevents safe continuation is layer 1 and precedes
facts that could only be learned by exceeding the budget. A normative result
contains this one selected failure. Implementations MAY additionally return
other failures only in a clearly non-normative diagnostic list.

Every catalogue entry binds its code to one or more exact `sites`; each site
pairs one stage with its permitted validation layer or layers. A normative
rejection reports the selected `code`, `layer`, and actual `stage` as a single
triple. Implementations MUST NOT derive or substitute the stage from the
expected vector after validation. An optional byte offset and subject identify
the selected occurrence but do not change that triple. A `(code, layer, stage)`
combination absent from the catalogue is not a format-v1 failure result.

A decoder MUST reject rather than repair, normalize, reorder, truncate, infer,
or replace any input. Diagnostics SHOULD report stable non-content-bearing error
classes and offsets and MUST NOT echo payload text, paths, messages, identities,
extensions, or identifiers by default.

## 8. Streaming and deterministic order

Definite-length CBOR does not require whole-container buffering. A producer MUST
know each container count before emitting its header and then provide values in
canonical order. An ordered database cursor or replayable iterator satisfies the
contract. An unordered source uses bounded-memory external merge sort; physical
page, shard, or run boundaries never enter canonical bytes.

In particular, a one-million-entry tree is encoded as a definite array from an
iterator already ordered by NFC basename UTF-8 bytes. An encoder hashes emitted
bytes incrementally. A decoder retains the previous ordering key and current
entry only. Whole-tree FileID uniqueness and graph checks may use a bounded
disk-backed index. An implementation MUST NOT make an in-memory million-entry
object graph a correctness prerequisite.

A payload length is deliberately absent from the hash preimage, so a single pass
can hash a canonical stream once its outer API supplies the payload boundary.

### 8.1 Frozen comparator bytes

Bytewise comparison below is unsigned lexicographic comparison; a proper prefix
sorts first. Tuple comparison is component-by-component and MUST NOT be replaced
by ambiguous byte concatenation.

| Sorted value | Exact comparison key |
|---|---|
| required feature IDs | unsigned numeric value |
| extension-map keys | complete deterministic-CBOR encoded text key |
| descriptor profile arrays | complete deterministic-CBOR bytes of `ProfileRef` |
| tree entries | raw shortest-form UTF-8 bytes of NFC `basename` |
| asset groups | raw 16-byte `GroupID` |
| group members | tuple `(deterministic-CBOR ProfileRef bytes, raw 16-byte FileID)` |
| external keys | tuple `(deterministic-CBOR ProfileRef bytes, raw value bytes)` |
| conflict subject FileIDs and paths | respectively raw 16-byte FileID and deterministic-CBOR `path-value` bytes |
| conflict records | raw 32-byte conflict ID |
| provenance inputs | complete deterministic-CBOR bytes of `ObjectRef` |
| snapshot/shelf provenance arrays | complete deterministic-CBOR bytes of kind-9 `ObjectRef` |
| bundle objects | complete deterministic-CBOR bytes of `ObjectRef` |
| bundle logical records | tuple `(numeric record-type code, raw 32-byte record-identity digest)` |
| bundle roots | tuple `(numeric root-kind, deterministic-CBOR bytes of field 4's typed identity, deterministic-CBOR bytes of role ProfileRef)` |
| validation failure subjects | deterministic-CBOR bytes for a CBOR subject, otherwise shortest UTF-8 bytes of its schema identity string |

Arrays described as ordered rather than sorted—snapshot parents, change-set
operations, manifest chunks, and bundle sections/ordinals—retain semantic order
and do not use this table.

## 9. Hard limits and configured budgets

`registries/limits.json` is the normative hard parser-maximum table. Its
`errorCode` field fixes the stable error for an isolated maximum-plus-one case.
A parser or writer MUST reject a value above any applicable hard limit before
allocation or trusted output. When malformed input exceeds an outer byte bound
and a nested bound simultaneously, the first safely observable outer bound may
fail first; normative boundary vectors isolate one bound at a time. A deployment
or caller SHOULD impose smaller aggregate limits for total bytes, object count,
elapsed time, memory, and scratch storage. Such configured limits may only
reduce accepted work; they cannot make an over-limit v1 value valid.

Elapsed-time enforcement is defined at bounded processing and I/O checkpoints,
not as permission to terminate arbitrary host code. A synchronous `Read` or
`Write` call cannot be safely preempted by this format contract; Rust callers
requiring a strict wall-clock SLA MUST provide timeout-bounded/cancellable I/O
or isolate validation in a process they control. Promise-based JavaScript APIs
race each caller-owned source, sink, provider, visitor, and index hook against
one shared deadline. OGVCS callback protocols receive its `AbortSignal`;
standard stream interfaces are cancelled or aborted through their native
mechanism. A late callback remains responsible for honouring cancellation. Implementations check the deadline
immediately before and after every bounded chunk. In every language, output and
persistence remain staged and untrusted until the operation returns success.

The metadata-payload limit applies to the complete canonical CBOR payload. The
generic text/byte-value limit applies to any individual value unless a smaller
or larger field-specific limit applies. In particular, `bundle-object` key 4 is
an explicit wrapper override: its byte string may contain up to 512 MiB for a
metadata ObjectRef kind or 64 MiB for a chunk ObjectRef kind, subject also to
the largest-item and sequence limits. The reader checks the wrapper item and
declared kind-specific payload ceiling before allocation, then checks the exact
inner payload boundary, hash and schema; individual text/byte fields decoded
inside metadata retain the generic 16 MiB ceiling unless their own field says
otherwise. Raw chunks use the separate chunk-payload limit. Logical
file length is a reconstructed size and may exceed any individual object or
chunk payload. OGVCS-004 path profiles MAY select smaller joined-path byte and
depth limits than the core maxima and repositories then enforce the smaller
values. They cannot raise the core maxima. The one-million-entry limit remains a
core tree-container maximum and is not changed by a path profile.

## 10. Registry governance and stable JSON

All registries are append-only within format v1.

Registry lifecycle applies to every assignment selected by an operation, not
only to `ProfileRef` values. A reader or writer MUST apply the exhaustive state
table in `conformance-profiles.md` to each selected object kind, hash algorithm,
common or kind-specific field, required feature, optional extension key,
entry-kind, entry-mode, semantic-enum value, profile, and logical-record type.
`read` means ordinary interpretation, `conformance` means an explicitly
declared conformance-vector operation, and `production-write` means creation of
new durable bytes. Canonical framing may still retain an opaque unsupported
kind or required feature at layer 1; lifecycle selection begins when the
corresponding registered schema or semantics is requested. State failures are
layer-3 registry-semantic failures and never make noncanonical or schema-invalid
bytes acceptable.

An encoder that accepts a registry or operation mode MUST run these lifecycle
decisions before emitting bytes. A decoder MUST run them before reporting
semantic success. Convenience encoders without a registry are schema-only and
MUST report that boundary rather than implying production-write eligibility.
The following selections are exhaustive for format v1:

| Wire occurrence | Selected registry assignment |
|---|---|
| object envelope field 1 | object kind |
| any deterministic digest algorithm field | hash algorithm |
| present common or kind field | corresponding common/kind-field assignment |
| envelope field 2 member | required feature |
| envelope field 3 key | extension profile tuple |
| tree or EntryState kind/mode | entry kind and entry mode |
| operation, allocation, conflict, subject, choice, lifetime, origin, and logical enum | semantic-enum domain member |
| any `ProfileRef` | exact profile tuple |
| logical record field 1 | logical-record type |

- An assigned numeric code, text name, semantic meaning, wire shape, or profile
  tuple MUST NOT be changed or reused.
- Removal changes state to `deprecated` and leaves the assignment present.
- `reserved` entries are neither readable nor writable. `conformance-only`
  entries are readable/writable only in explicit tests and conformance
  artifacts. `ratified` entries are readable and writable by production
  implementations. `deprecated` entries remain readable according to their
  frozen semantics but MUST NOT be used by new production writes unless a
  migration specification explicitly requires it. Unassigned ranges are
  available for governed additive assignment and are not registry entries.
  A `ratified` entry does not by itself ratify format v1; production writes also
  require the governing ADRs and format release to be ratified.
- New object kinds, common fields, hash algorithms, required features, profiles,
  extensions, entry kinds/modes, semantic enums, and logical record types require owner review, collision
  checks across the applicable registry, public positive and malformed vectors,
  and compatibility review.
- Kind-specific field assignments belong in the owning kind schema and use
  keys `16..4095`; this slice registers only common fields.
- Private or experimental production code MUST NOT claim unregistered numeric
  values. Experiments use namespaced optional extensions or a non-v1 envelope.

Registry JSON is stable source data, not an object-identity encoding. Every file
MUST be UTF-8 without BOM, use LF, end in one LF, use two-space indentation, and
have object keys in lexicographic order. Registry entry arrays are ordered by
numeric code; profile arrays are ordered by `(namespace,id,major)`; reserved
ranges are ordered by lower bound. Duplicate JSON keys are invalid. Tooling MUST
parse integer fields as exact integers, not binary floating-point approximations.

A registry loader MUST reject the complete registry set, rather than partially
load it, when any of these invariants fail:

- duplicate numeric codes, names, text tokens, or profile tuples;
- an assigned code overlapping a reserved or unassigned range, overlapping
  ranges, a reversed range, or a value outside its declared integer width;
- entries not ordered by code, profiles not ordered by `(namespace,id,major)`,
  or ranges not ordered by lower bound;
- an unknown state or a state inconsistent with `productionWriteAllowed`;
- a ProfileRef component or canonical rendering that violates the exact grammar;
- an entry-kind/mode relationship that is not symmetric, or a target object kind
  that is absent from the object-kind registry;
- a common-field assignment outside `0..15`, a kind-field range other than
  `16..4095`, or any reuse of a removed assignment;
- a nonpositive/duplicate hard limit, a limit with an unknown unit, or a numeric
  value not exactly representable by the registry loader; or
- a format or registry version mismatch, duplicate JSON key, BOM, non-LF line
  ending, noncanonical key order, or noncanonical entry order.

Registry entry objects are closed shapes. A loader MUST reject missing required
members and members not listed below; this prevents an additive assignment from
silently losing the wire-shape information that compatibility review approved.

| registry | required entry members | optional entry members |
|---|---|---|
| object kinds | `code,name,payload,state,textToken` | none |
| hash algorithms | `code,digestBytes,name,state` | none |
| common fields | `code,name,required,state,type` | none |
| kind fields | `cddlRule,code,name,requirement,scope,state,type` | at most one of `objectKind,logicalRecordType,itemType` |
| entry kinds | `allowedModeCodes,code,name,state,targetKind` | none |
| entry modes | `allowedEntryKindCodes,code,name,portableMode,state` | none |
| required features | `code,name,state` | `behavior` |
| extensions | `namespace,id,major,state` | none |
| profiles | `namespace,id,major,family,owner,productionWriteAllowed,state` | none |
| logical record types | `code,name,state` | `wireShape`; mandatory for every newly assigned v1 code |
| semantic enum entries | `code,name,state` | none |
| hard limits | `errorCode,name,unit,value` | none |

`payload` is `raw-bytes` or `deterministic-cbor`; `digestBytes` is a positive
integer; `required` and `productionWriteAllowed` are booleans; relationship
arrays are nonempty, strictly increasing code arrays; `portableMode` is exactly
six octal digits; `scope` is `repository-format.cddl#<cddlRule>`; `requirement`
is `required`, `optional`, or `conditional`; and every `wireShape` is a nonempty
object from canonical unsigned-decimal field numbers to nonempty type names.
The profile and extension tuple grammar remains the ProfileRef grammar above.
Every runtime registry snapshot MUST retain an immutable, discoverable view of
all registry documents, including registries for which a codec also exposes a
specialized typed lookup.

The registry files are:

- `registries/object-kinds.json`
- `registries/common-fields.json`
- `registries/entry-kinds.json`
- `registries/entry-modes.json`
- `registries/required-features.json`
- `registries/profiles.json`
- `registries/extensions.json`
- `registries/logical-record-types.json`
- `registries/semantic-enums.json`
- `registries/limits.json`

Typed logical records are not immutable objects and therefore do not receive an
ObjectID merely because they have a registered record-type code. The annotation
record (type 8) has canonical CBOR shape
`{0: 1, 1: 8, 16: subject-ObjectRef, 17: annotation-ProfileRef, 18: payload-bytes}`.
The ProfileRef types the byte-string payload. The annotation is not an object,
its subject is an ObjectRef, and every annotation byte is excluded from the
subject object's hash preimage; adding or changing an annotation cannot change
the subject ObjectID. A logical bundle is a bounded caller-selected exchange
artifact under ADR-0010, not a
repository-complete fidelity or projection export.
