# ADR-0016: GearHash/FastCDC content-chunk profile version 1

**Status:** Proposed
**Date:** 2026-08-30
**Owners:** OGVCS-007

## Context

OGVCS-002 fixes raw-chunk and `ContentManifestV1` identity, but deliberately
provides only the non-production `chunking.test/external-boundaries@1` profile.
OGVCS-007 needs one portable production boundary algorithm whose scalar result
is independent of read fragmentation, worker scheduling, host word size, SIMD,
locale, and platform APIs. The profile must also make its table provenance and
all boundary edge cases independently reproducible.

This ADR selects a GearHash/FastCDC-style algorithm. "FastCDC-style" describes
the two-mask normalized cut search; it does not import an external table,
implementation, wire format, patent promise, or mutable upstream behavior.
The checked-in contract and vectors are the authority.

## Decision

### Profile identity and size-class selection

The candidate first profile is `chunking.opengamevcs/gear-fastcdc-1m@1`.

The caller supplies the exact logical length before reading. The profile has two
deterministically selected classes:

| Declared logical length | Class | Minimum | Target | Maximum |
|---:|---|---:|---:|---:|
| 0 | `empty` | 0 | 0 | 0 |
| 1 through 262,144 bytes | `whole` | length | length | length |
| 262,145 through 1 TiB | `cdc-1m` | 262,144 | 1,048,576 | 2,097,152 |

`empty` emits no chunks. `whole` emits the complete nonempty file as one chunk
and may skip fingerprint calculation. `cdc-1m` uses the algorithm below. No
caller parameter may change these identity-affecting values under this profile.
A different size class or parameter set requires a different immutable
`ProfileRef` assignment. A runtime memory or worker budget may only reduce
resources or reject the operation; it cannot change boundaries.

The determinism tuple is the exact logical bytes plus the canonical
repository-selected profile/policy. Under this candidate that policy selects
this one `ProfileRef`; the declared logical length is intrinsic to those exact
bytes and therefore deterministically selects `empty`, `whole`, or `cdc-1m`.
This satisfies size-class selection without a caller-tunable threshold or mask.
Changing operational budgets does not change the tuple or the manifest.

### Gear table provenance

Let `D` be the exact 26-byte sequence consisting of the 25 ASCII bytes
`OpenGameVCS Gear table v1` followed by one NUL byte. For every integer `i` in
`0..255`, append `uint16be(i)` to `D`,
calculate SHA-256, take digest bytes `0..7`, and interpret those eight bytes as
one unsigned big-endian 64-bit integer. That integer is `GEAR[i]`.

The contract publishes all 256 lowercase, zero-padded, 16-hex-digit values in
index order and authenticates their concatenated `uint64be` bytes. A runtime may
embed or derive the table, but must prove the same table digest. No random seed,
external FastCDC table, native-endian load, signed shift, or floating point is
permitted.

### Fingerprint and boundary recurrence

At the start of every `cdc-1m` chunk, set unsigned `fp = 0` and chunk length
`n = 0`. For each raw logical input byte `b`, in source order:

```text
fp = ((fp << 1) + GEAR[b]) mod 2^64
n  = n + 1
```

The byte participates in the recurrence before its boundary is tested. Bytes
before the minimum therefore affect the first eligible fingerprint. After each
byte:

1. if `n < 262144`, continue;
2. otherwise choose mask `0x00000000001fffff` while `n < 1048576`, and
   `0x000000000007ffff` while `n >= 1048576`;
3. if `(fp & mask) == 0`, cut after that byte;
4. independently, if `n == 2097152`, force a cut after that byte.

The forced maximum wins only when the fingerprint rule did not already select
the same offset; the emitted boundary is identical either way. After a cut,
reset `fp` and `n` to zero before consuming the next byte. The comparison at
exactly 1,048,576 bytes uses the second mask. End of input emits the current
nonempty suffix even when neither cut predicate matched. It never emits an
extra empty chunk.

The declared logical length must be in `0..1,099,511,627,776`. A source ending
early or producing an extra byte fails before a manifest is trusted. Chunk
count may not exceed 1,048,576. All byte, count, offset, and sum arithmetic is
checked mathematical nonnegative-integer arithmetic with explicit conversion
to the host representation.

### Chunk and manifest identity

Each emitted chunk is the exact raw byte interval. Its ObjectID remains the
OGVCS-002 preimage:

```text
SHA-256(
  ASCII("OpenGameVCS object\0") ||
  uint16be(1) || uint16be(1) || rawChunkBytes
)
```

The whole-file digest is ordinary SHA-256 of all raw logical bytes in order.
The manifest is the unchanged OGVCS-002 deterministic-CBOR map with format 1,
kind 2, no required features, declared logical length, typed whole-file digest,
the exact profile reference above, and ordered chunk ObjectRefs and lengths.
The manifest ObjectID uses OGVCS-002 kind 2. Physical packs, compression,
placement, transfer framing, and nonidentity hints do not enter this algorithm.

### Streaming and resource rules

Boundary discovery is sequential. Implementations may hash or persist completed
chunks concurrently, but use a bounded queue and restore source order before
manifest emission. Default scalar execution uses one worker. Configured workers
are `1..64`, queued completed chunks are `0..64`, an individual input fragment
is at most 64 MiB, and configured working memory is at most 1 GiB. An operation
must perform admission before reading. Define `chunkSlots = 1 + workers +
queuedChunks`: one current source chunk, every in-flight worker chunk, and every
queued completed chunk. The required working-memory budget is exactly
`65,536 + chunkSlots * 2,097,152` bytes. The 65,536-byte fixed allowance covers
the Gear table, hash state, and control state. The caller's input-fragment
buffer, sink-retained data, and ordered ledger are separately bounded and are
not charged twice to this formula. Scalar defaults (`workers = 1`,
`queuedChunks = 0`) therefore require 4,259,840 bytes.

The implementation retains at most the current 2 MiB chunk per scalar lane and
bounded queue data. Ordered `(ChunkID,length)` records may use a bounded
disk-backed ledger because the OGVCS-002 writer requires the final part count.
The complete source file is never copied to scratch. Resource admission failure,
scratch exhaustion, cancellation, or deadline expiry yields no trusted manifest
or workspace publication.

Cancellation is caller-owned and cooperative. A public operation accepts a
cancellation token and an optional nonnegative maximum elapsed duration. It
uses a monotonic clock beginning at operation admission, checks the token and
deadline before the first source read, between delivered fragments, at bounded
intervals within a fragment, around external callbacks, and before commit.
Cancellation or expiry returns `CHUNK_RESOURCE_EXHAUSTED`; the detail may name
`cancellation` or `deadline`, but it does not create another stable error code.
An implementation may race interruptible asynchronous callbacks. A synchronous
provider that blocks without observing its shared token remains cooperatively,
not forcibly, interruptible.

Once a structurally valid manifest opens a caller publication transaction,
every failure before a successful commit invokes exactly one best-effort abort.
This includes an empty-output commit failure, a missing first chunk, callback
failure before the first successful write, cancellation, and deadline expiry.
A provider cannot erase a consumer/write failure by ignoring its callback
result and returning success: the first callback failure is sticky and wins.
Abort failure never masks the primary generated error and no commit follows it.

### Verification rules

There are two distinct claims:

- OGVCS-002 structural/content verification checks manifest shape, each chunk
  ObjectID and length, and the final whole-file digest.
- OGVCS-007 profile verification additionally streams the reconstructed logical
  bytes through this recurrence and requires every declared ordered boundary to
  equal the recomputed boundary, including the final suffix.

Claiming this production profile requires both. Repeated equal chunk references
remain valid occurrences. The same ChunkID paired with a conflicting length or
different delivered bytes is rejected. Unknown profile/version, wrong declared
length, arithmetic overflow, too many chunks, invalid boundary, corrupt/truncated
chunk, or final digest mismatch fails closed without trusted partial output.

### Shared chunk-cache key

The stable shared-cache API accepts exactly one OGVCS-002 `Chunk` ObjectRef.
Let `C` be the 31 bytes `ASCII("OpenGameVCS chunk cache key v1") || NUL`, let
`P` be the ASCII profile text
`chunking.opengamevcs/gear-fastcdc-1m@1`, and let `O` be the canonical ASCII
ObjectRef text. The key is:

```text
"ogvcs:chunk-cache:v1:sha256:" || lowercase-hex(SHA-256(C || P || NUL || O))
```

The profile binding prevents a future chunk-policy namespace from accidentally
sharing operational cache decisions even though Chunk ObjectIDs remain global
content identities. A cache hit is only a lookup hint: reconstruction still
verifies length, ChunkID, whole-file digest, and Gear boundaries. Non-Chunk
ObjectRefs and malformed text are rejected through the generated error surface.

### Checkpoints and resume

A stable completed manifest is the transfer-resume inventory. Network transfer
resume remains outside OGVCS-007. An optional local chunking checkpoint must bind
the profile, declared source length and immutable source identity, completed
offset, ordered part-ledger transcript, and resource configuration. Version 1
does not standardize serialization of a live SHA-256 or Gear state. Portable
resume replays and verifies the prefix from the same source before continuing;
source drift rejects. An implementation must not accept opaque native hash state
as interoperable evidence.

## Alternatives considered

- Rabin fingerprints provide an explicit rolling window and mature
  resynchronization theory, but require more polynomial/window conventions and
  a larger clean-room interoperability surface.
- Fixed-size chunks are simpler but fail the insertion-resynchronization goal.
- Importing a commonly copied Gear table would leave provenance and accidental
  signed/native-endian behavior ambiguous.
- Caller-selected masks under one profile were rejected because identical
  identity-bearing profile references could then mean different boundaries.

## Compatibility and rollout

While this ADR is Proposed, the namespace, identifier, major, derived Gear
table, recurrence, masks, thresholds, limits, and edge behavior form one exact
benchmark candidate. Optimized readers must pass the scalar golden and
fragmentation vectors. Acceptance freezes that tuple; a later correction or
parameter change then uses a new profile assignment and never reinterprets
existing manifests.

The candidate authority may ship before repository-format integration, but the
ADR is not Accepted and production writes remain disabled until FR-08/AC-04
benchmark evidence passes, the exact profile is added as a ratified OGVCS-007
entry to the OGVCS-002 profile registry, and all generated predecessor pins are
updated. Deployment is read-before-write. Rollback disables new writes while
retaining the reader, profile document, and vectors indefinitely. Existing
content is not automatically rechunked.

Before acceptance, an authenticated OGVCS-005-compatible report must exercise
representative source-like, structured, already-compressed, encrypted/random,
insertion, replacement, and append corpora. It must justify the 256 KiB minimum,
1 MiB target, and 2 MiB maximum using observed throughput, peak memory, chunk
count/manifest cost, boundary-resynchronization distance, and exact
logical/unique/reused/new bytes. Compressed/random poor reuse is valid measured
behavior, not a failure. The maintainers either accept this exact candidate or
publish a new candidate profile/ADR revision before any registry ratification;
they do not tune these constants under the same accepted assignment.

## Verification evidence required

- Independent JavaScript and Rust scalar implementations reproduce the table,
  every exact boundary, ChunkID, manifest byte, and manifest ObjectID.
- Fragmenting every source at one-byte, prime-cycle, and boundary-adjacent read
  sizes does not change a result.
- Golden cases cover empty, whole/small, natural early/late cuts, forced maximum,
  final suffix, repeated content, insertion resynchronization, and multiple
  chunks; malformed cases cover length mismatch, unsupported profile, boundary,
  digest, count, and resource failures.
- Later integration adds bounded 100 GiB measurement, three-OS packed evidence,
  fuzz/property results, benchmark results, and critical review. Those are not
  claimed by this first authority cut.
