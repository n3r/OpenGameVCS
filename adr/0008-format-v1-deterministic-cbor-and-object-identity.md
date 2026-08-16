# ADR-0008: Format-v1 deterministic CBOR and object identity

**Status:** Proposed
**Date:** 2026-08-15
**Owners:** OGVCS-002

## Context

The architecture requires canonical domain-separated serialization but did not select an encoding, field registry, strict-decoder policy, object-ID text form, or hard parser limits. Canonical JSON cannot represent binary IDs and 64-bit sizes directly, while implementation-defined CBOR or protobuf output would allow clean-room codecs to disagree on bytes.

## Decision

Format v1 uses the OpenGameVCS deterministic-CBOR profile, based on the core deterministic encoding requirements in [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html):

- Metadata is one definite-length CBOR data item. Allowed values are shortest-form signed/unsigned 64-bit integers, definite byte/text strings, definite arrays/maps, and booleans.
- Floats, tags, `null`, undefined or other simple values, bignums, indefinite containers, duplicate keys, non-minimal lengths/integers, invalid UTF-8, non-NFC text, and trailing bytes are invalid.
- Schema maps use unsigned integer keys in deterministic order. Keys `0..15` are common/reserved, keys `16..4095` are kind-scoped registered fields, and removed assignments remain reserved.
- Key `0` is format version `1`; key `1` is the registered object-kind code; key `2` is a present, strictly increasing array of required feature IDs; optional key `3` is the sole namespaced extension map and is omitted when empty. Kind fields begin at key `16`.
- Validation has three explicit layers. A **canonical framing scan** checks deterministic-CBOR well-formedness, hard/configured structural bounds, the common envelope, and exact payload consumption; it may hash, store, forward, or byte-preserve an object whose required feature is unsupported, but it does not call that object semantically valid. **Known-kind schema validation** additionally validates every understood base field, enum, and cross-field shape. **Semantic validation** additionally requires support for every required feature/profile and applies graph/transition rules. A public API reports which layer completed, reports every rejection as the catalogue-bound `(code, layer, stage)` triple, and never silently promotes a framing-only result.
- Unsupported required features prevent semantic interpretation. Unknown optional extensions may be ignored for base semantics but must be preserved by any promised lossless round trip. No layer accepts then silently canonicalizes noncanonical input.

The immutable object-kind registry starts with raw chunk, content manifest, tree, change set, asset-group set, repository descriptor, snapshot, shelf revision, provenance, attestation, and conflict set. For registered kind code `K` and canonical payload bytes `P`:

```text
ObjectID = SHA-256(
  ASCII("OpenGameVCS object\0") ||
  uint16be(1) ||
  uint16be(K) ||
  P
)
```

A chunk uses its raw logical bytes as `P`; all other objects use deterministic CBOR. Hash algorithm code `1` is SHA-256. A binary object reference carries format version `1`, expected kind, algorithm, and a 32-byte digest. The durable text form is `ogvcs:v1:<kind>:sha256:<64 lowercase hex>`, where `<kind>` is the exact lowercase ASCII token in the object-kind registry. Abbreviations are display-only. FileID is an opaque nonzero 16-byte value with text form `fid:<32 lowercase hex>` and no UUID semantics.

Hard v1 parser/object maxima are: CBOR nesting 32; metadata payload 512 MiB; chunk payload 64 MiB; generic text/byte value 16 MiB; snapshot message 1 MiB; 128 extensions and 16 MiB aggregate extension bytes; 255 UTF-8 bytes per segment; 4,096 UTF-8 bytes per joined path; 256 path segments; 1,000,000 entries in one tree; eight snapshot parents; 1,000,000 operations in one change set; 10,000 groups with 64 members each; 1,048,576 chunks per manifest; and 1 TiB logical file length. The tree-entry maximum is a core object ceiling. Ratified OGVCS-004 path/platform profiles choose operational segment, joined-path, and depth limits no greater than the core maxima. Consumers also apply smaller configured total byte, object, time, memory, and scratch budgets.

Definite encoding remains streamable: producers supply exact counts and ordered iterators, or use bounded-memory external sort. Tree encoders and decoders retain only current state needed for order checks; global FileID/path validation may use bounded disk-backed indexes. Physical database pages and shards never appear in canonical bytes.

Attestation/signature objects reference a completed subject ObjectID. A snapshot does not reference an attestation that signs it, avoiding a hash cycle. Snapshot-reachable provenance is permitted only when it is created first and has no backlink.

## Consequences and proof

The language-neutral specification publishes the integer registries, CDDL, exact preimages, fixed vectors, malformed deterministic-CBOR corpus, and limit table. Independently written Rust and JavaScript implementations must encode every vector byte-identically, reject every noncanonical variant, stream a one-million-entry single directory below the acceptance memory ceiling, and prove that physical paging does not alter identity. Any change to an assigned field, kind, preimage, or semantic interpretation requires a new format version; additive registered profiles/features use new immutable IDs.
