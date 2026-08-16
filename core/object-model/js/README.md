# `@opengamevcs/object-model`

Dependency-free Node ESM primitives for the OpenGameVCS repository-format-v1
codec. This is a clean-room implementation based only on the public format
specification, registries, and vectors.

The narrow public API currently covers:

- strict canonical CBOR encode/decode and concatenated-item scanning;
- layer-1 metadata framing scans and current layer-2 object, logical-record,
  conflict-preimage, and bundle-item shapes;
- typed digest, `ObjectRef`, `ProfileRef`, and `FileId` values;
- exact object, logical-record, conflict, and bundle-transcript SHA-256 domains;
- canonical registry loading, immutable discovery of all twelve authorities,
  plus profile/read-write state decisions;
- OS-CSPRNG nonzero FileID allocation with bounded collision retry;
- logical-bundle encoding, streaming visitation, and supplied-closure checks;
- deterministic fixture adaptation with caller-owned ledger state;
- bounded canonical writers for ordered and external-sorted one-directory trees;
- a streaming `ContentManifestV1` writer and chunk/whole-file verifier;
- typed immutable-object lookup, manifest and expanded-tree verification;
- exact change-set replay, FileID lifetime/import evidence, groups, conflicts,
  snapshot history, shelves, and provenance; and
- defense-in-depth cycle checks over the normative prevalidated abstract graph
  envelope.

`RepositoryObjectLookup` is an in-memory implementation with finite default
object, byte, edge, memory, scratch, chunk, and time guards exposed as
`REPOSITORY_VALIDATION_LIMITS`; callers may lower them. Input is accounted
before it enters the lookup, including a conservative retained-memory estimate.
It does not claim the
streaming or million-entry boundedness required of a production repository
service. Authoritative persistence, reference finalization, and atomic lifetime
registry updates remain outside this package. A framing-only result never
claims schema or semantic validity.

`encodeCanonicalChunks` and `writeCanonical` preflight the complete value, then
compare the emitted pass with a bounded SHA-256 transcript pass. They copy each
yielded body chunk, so caller mutation between sink awaits cannot return success
for different or malformed bytes. Chunks and sink output remain staged and
untrusted until iteration completes or `writeCanonical` resolves successfully.

The bounded tree, manifest, and bundle routes deadline-race promise-based
source iteration, sink writes/drains/flushes, manifest providers, and caller
FileID-index hooks against one shared `AbortSignal`. Cooperative callbacks
receive that signal in their options argument; built-in Node writers are still
deadline-raced even where their API cannot accept a signal. Cancellation cannot
undo a side effect that a caller performs after its promise settles late, so
callbacks must honor the signal and keep all output staged. Bytes, indexes, and
other side effects remain untrusted and unpublished until the top-level promise
resolves successfully. Late rejection is observed by the library, but preventing
late publication remains the caller's responsibility.

## Bounded fixture adaptation

`adaptFixture` maps each OGVCS-001 profile-v2 family through the public
fixture-generator package. It bounded-reads and preflights the public request
before invoking that package's normative deep verification, then binds every
adapted artifact to the verified manifest before retaining records or emitted
object references. The exported `FIXTURE_ADAPTER_LIMITS`
object freezes the hard maxima:

| Resource | Hard maximum |
|---|---:|
| all adapter-read fixture bytes | 64 MiB |
| inventory records | 100,000 |
| operation records | 100,000 |
| groups | 100,000 |
| ledger mappings | 300,000 |
| emitted object references | 500,000 |
| parts in one emitted content manifest | 65,536 |
| retained tree nodes | 200,000 |
| elapsed adapter time | 10 minutes |

Callers may lower any of these with `options.limits`; they cannot raise them.
`maxRetainedBytes` separately limits retained emitted payloads plus fixed
per-reference accounting and cannot exceed 256 MiB. Aggregate input overflow
returns `LIMIT_MEMORY`, count overflow returns `LIMIT_COUNT`, and elapsed-time
overflow returns `LIMIT_TIME`. The adapter reads NDJSON with a fixed 64 KiB
line buffer and preflights declared fixture counts before loading those files.
The required `isTargetFileIdConsumed({fileId, ownerKind, ownerKey})` callback
checks every retained or newly allocated target FileID against repository-scoped
lifetime state. It returns `false` only when the ID is unused or already owned by
that exact directory/import mapping. A collision or lookup failure aborts before
ledger persistence with `FILEID_IMPORT_MAPPING_CONFLICT`.

Every awaited adapter callback receives the adapter's shared `AbortSignal`
(inside its existing options/input object, or as the second argument for sink
and persistence methods). The adapter races verifier, allocation, repository
lookup, boundary/content, staged-sink, persistence, and commit waits against the
configured deadline and returns `LIMIT_TIME` if one does not settle. Callback
implementations MUST honor that signal and MUST make persistence/commit
conditional on it so an aborted late completion cannot publish staged output.

Profile-v2 operation records are workload events, not complete native snapshot
or change-set bindings. A caller that requires immutable history sets
`requireNativeHistoryBindings: true`; the current profile-v2 contract then
fails before ledger persistence with `FIXTURE_NATIVE_BINDING_MISSING`. This
guard prevents workload events from being silently promoted to repository
history. It cannot be disabled by supplying invented empty content or IDs.

This deliberately bounded conformance adapter does **not** claim support for
the OGVCS-001 one-million-path reference fixture or every valid fixture scale.
Such inputs fail with a typed limit before unbounded retention. The separate
tree, manifest, and bundle streaming APIs are the OGVCS-002 large-scale
boundary.

## Bounded logical-bundle verification

`writeOrderedLogicalBundle` is the bounded writer. The caller supplies a
frozen header plan (`objectCount`, `logicalRecordCount`, `rootCount`, and the
four declaration budgets), already ordered iterable or async-iterable
sections, and a callback, stream, or `FileHandle`-style sink. The writer
retains only the current item plus previous sort keys, handles short writes,
checks identity/schema/profile/order/count and traversal/index declarations,
and streams the exact transcript into the trailer. Its default retained-item
ceiling is 64 MiB and may be raised up to the format item ceiling for a caller
that can safely hold a larger single item.

Successful writing proves wire integrity, not supplied closure. Publish or
classify the staged bytes only after `verifyLogicalBundleStream` or
`verifyLogicalBundleFile` succeeds. `encodeLogicalBundle` remains the
explicitly small in-memory convenience encoder.

`verifyLogicalBundleStream` is the high-level bounded verifier for an
`Iterable` or `AsyncIterable` of logical-bundle-v1 bytes.
`verifyLogicalBundleFile` opens a regular file without following its final
symlink and reads it from that same handle, so replacing the pathname after
open cannot redirect verification. Both APIs require an explicit caller-owned
`scratchDirectory`; the file API does not first load the bundle into memory.

The verifier spools the exact sequence once, records item ranges in a fixed
disk index, and retains at most one decoded non-object item or metadata payload.
Object identities are externally sorted as exact `(digest, kind, ordinal)`
records, logical identities as exact `(digest, ordinal)` records, and object
edges as append-only fixed records with per-object disk ranges. Closure uses
binary identity lookup, an append-only disk queue, and one bit per supplied
object. It never builds a JavaScript `Map`, `Set`, or array containing every
bundle object or edge. Section counts/order/ordinals, canonical identity sort,
object and logical-record hashes, registry/schema/profile rules, logical-root
equality, supplied closure, wrong-kind lookup, declared budgets, and the exact
pre-trailer transcript are all checked before a result is returned.

Scratch files are owner-only, exclusively created, opened without following
the final symlink, checked against their original file identity and SHA-256
when reopened, bounded by `maxScratchBytes`, and removed after success or
failure. The public
resource options are `sequenceBytes`, `itemBytes`, `objects`,
`logicalRecords`, `roots`, `items`, `traversalEdges`, `indexEntries`,
`maxMemoryBytes`, `maxScratchBytes`, `maxTimeMs`, `maxDecodedItemBytes`,
`maxRunBytes`, `maxOpenRuns`, and `readChunkBytes`. Format maxima remain hard
ceilings. A deployment may deliberately choose lower limits.

```js
const result = await verifyLogicalBundleFile('/staging/bundle.cborseq', {
  registry,
  mode: 'conformance',
  scratchDirectory: '/staging/ogvcs-scratch',
  maxMemoryBytes: 64 * 1024 * 1024,
  maxScratchBytes: 8 * 1024 * 1024 * 1024
});
```

The result contains only counts, total bytes, traversal/index accounting, the
bundle transcript digest, and aggregate timing/scratch/run metrics; it never
returns payloads, paths, embedded names/messages, or supplied object, logical,
or root identities. Its
`highestLayer` remains 2 because the streaming API does not accept the
in-memory `semanticValidator` callback or claim repository-context replay.
Use the existing `verifyLogicalBundle` only for explicitly small in-memory
callers that need that callback.

The packaged regular-file CLI always uses this path and requires scratch:

```sh
ogvcs-object bundle verify bundle.cborseq \
  --scratch /explicit/staging/scratch \
  --max-memory-bytes 67108864 \
  --max-scratch-bytes 8589934592
```

Successful CLI output calls the artifact `logical-bundle-v1` and the claim
`supplied-closure`; it does not relabel it as export, fidelity, or projection
evidence. `maxMemoryBytes` bounds retained encoded buffers, sort runs, merge
heads, and reached bitsets. Caller-owned iterable buffers plus JavaScript
runtime/decoder/sort overhead are outside that configured accounting; only a
measured child-process RSS high-water can establish a process-level ceiling.

## Bounded tree and manifest writers

`writeOrderedTree` accepts an `Iterable` or `AsyncIterable` of exact wire
`TreeEntry` maps. `entryCount` is mandatory because deterministic CBOR arrays
have a definite length. It validates every entry, strict NFC UTF-8 basename
ordering, target kinds, FileIDs, mode, profile, and logical size while writing
directly to a callback, Node stream, or `FileHandle`-style writer. It returns
the exact Tree `ObjectRef`, a privacy-safe aggregate summary, and resource
metrics without retaining the entry array.

`writeSortedTree` accepts the same fields plus an explicit `scratchDirectory`.
It validates unsorted entries into fixed-memory sorted runs, uses a bounded
k-way merge, and produces byte-for-byte identical output and summary. Run
files are owner-only, exclusively created, opened without following symlinks,
checksummed, subject to `maxScratchBytes`, and removed after success or
failure. The supplied scratch directory itself cannot be a symlink.

Exact FileID uniqueness is part of both paths. `writeSortedTree` maintains a
FileID-sorted side index in its bounded scratch space. `writeOrderedTree` uses
a bounded in-memory index only through 100,000 entries; larger trees require a
caller-owned index created by `createDiskFileIdIndex` (or an equivalent object
implementing `add`, `finish`, and `abort`). This prevents a million-entry claim
from depending on an unbounded JavaScript `Set`.

```js
const result = await writeOrderedTree({
  descriptor,
  entryCount: 1_000_000,
  entries: orderedEntryIterator,
  sink: stagedFile,
  fileIdIndex: await createDiskFileIdIndex({ scratchDirectory }),
  maxMemoryBytes: 64 * 1024 * 1024
});
```

`verifyTreeFile` is the corresponding raw canonical file verifier. It hashes
bounded reads from one no-follow file handle, retains one entry at a time, and
uses the same FileID-index contract. The packaged CLI exposes it as:

```sh
ogvcs-object tree verify tree.cbor \
  --descriptor ogvcs:v1:repository-descriptor:sha256:<64-lowercase-hex> \
  --scratch /explicit/staging/scratch
```

`writeContentManifest` streams exact `ChunkPart` maps and requires
`partCount`. With `wholeFileDigest` and `chunkProvider`, it checks each chunk
ObjectRef and the whole-file SHA-256 while writing. If the digest is omitted,
`parts` must be a repeatable factory: the first pass verifies content and
derives the digest, while the second pass writes metadata and checks that its
structural transcript is unchanged. Repeated chunk references use a bounded
verified-byte cache, so the provider can be read once while every logical byte
still enters the whole-file hash.

A supplied digest without a provider performs schema and length validation
only; the returned `verification.contentVerified` is `false`. These writers do
not make output atomic: use a staged sink and publish only after the returned
promise succeeds. Configured `maxMemoryBytes` bounds retained encoded buffers,
run buffers, merge heads, parser values, and index estimates. Caller-owned
source iterables/writer buffers and JavaScript runtime or sorting overhead are
outside that configured accounting; only a measured child-process RSS
high-water establishes the 1 GiB acceptance ceiling.

The `inspect`, `id`, and `verify object` CLI commands accept `--max-bytes` and
`--max-memory-bytes`. Metadata input defaults to a 64 MiB total working-memory
budget; the command reserves space for the input, its immutable scan copy, and
decoded CBOR state before reading or decoding. `id` and `verify object` hash
the exact bytes validated from one open file instance, so a pathname
replacement cannot change the reported identity. Raw chunks use the bounded
streaming hash path and do not retain the complete chunk.

The opt-in exact scale runner uses the checked-in one-million-tree recurrence
and a 1 TiB manifest made from 1,048,576 repetitions of one deterministic
1 MiB chunk. It runs in a child process and reports ObjectRefs, canonical
summary hashes, wall time, output/scratch bytes, and `process.resourceUsage()`
RSS high-water. The full command hashes the complete logical 1 TiB stream; the
smoke command exercises the same algorithms at smaller cardinalities.

```sh
npm run test:scale:smoke --workspace @opengamevcs/object-model
npm run test:scale --workspace @opengamevcs/object-model
```

The packed package also ships two dependency-free public examples. They import
only the package root and run without a repository checkout or network access:

```sh
node node_modules/@opengamevcs/object-model/examples/reference-roundtrip.mjs
node node_modules/@opengamevcs/object-model/examples/registry-inspection.mjs
```

```js
import { decodeMetadata, hashObject, ObjectRef } from '@opengamevcs/object-model';

const scan = decodeMetadata(payload, { semantic: false });
const id = hashObject(scan.kind, payload);
const durable = ObjectRef.parse(id.toString());
```

Repository validation takes an explicit as-of context: the descriptor and
designated root, exact immutable-object lookup, prior lifetime/import records,
and ordered working lifetime additions. `validateRepositoryCandidate` performs
identity/schema checks, history and tree validation, replay, conflict/group
checks, complete lifetime validation, and provenance checks without mutating
that context.

Ratified `path.opengamevcs/*@1` descriptors require the OGVCS-004 adapter.
Pass its `objectModelPathProfileValidator` as `validatePathProfile` to
`expandTree`, then run OGVCS-004 whole-set materialization preflight for case
and platform collisions. The object-model core fails closed with
`PATH_PROFILE_INVALID` when a ratified external path profile is selected but
no adapter is supplied; registry-family validation alone is not a path proof.

Decoded maps are JavaScript `Map` instances, binary strings are independent
`Uint8Array` values, and integers outside the safe JavaScript number range are
`bigint`. Encoders accept only safe integer `number` values or `bigint` values.

Run `npm test` for the checked-in normative corpus. `npm pack` produces an
offline-installable tarball containing no runtime dependencies.
