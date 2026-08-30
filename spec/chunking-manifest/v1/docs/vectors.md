# Vector construction and interpretation

All JSON artifacts use UTF-8, no BOM or CR, canonical compact JSON with one
terminal LF. Integer arithmetic is mathematical nonnegative arithmetic bounded
as declared by the schema.

Input recipes are exact:

- `literal` decodes lowercase hexadecimal bytes.
- `repeat` emits `length` copies of the byte.
- `sha256-counter` emits consecutive 32-byte blocks. Block `i` is
  `SHA-256(ASCII("OpenGameVCS chunk vector block v1") || 0x00 ||
  UTF8(seed) || 0x00 || uint64be(i))`; the final block is truncated.
- `insert` materializes `base` and inserts the decoded hexadecimal bytes before
  the base byte at the zero-based offset. Offset equal to base length appends.

Golden boundaries are absolute end-exclusive offsets. Each chunk row contains
the exact logical length and full OGVCS-002 ChunkID. `manifestHex` is the entire
deterministic-CBOR `ContentManifestV1` payload; `manifestObjectId` is its kind-2
ObjectID. The generator and independent validator separately calculate every
field.

Fragment patterns cycle until EOF. `[1]` therefore means every update carries
one byte. Patterns containing values around minimum/target boundaries exercise
state continuity across reads; they do not authorize fragment-dependent cuts.

Malformed rows name the operation, exact mutation/input, and stable engine
error. Runtime verifier coverage for boundary/digest/manifest mutations is part
of the next reconstruction/verification cut; this candidate contract reserves
the expected outcomes now and the independent validator authenticates their
closed inventory.
