# `@opengamevcs/chunking-manifest`

Independent scalar JavaScript implementation of the Proposed ADR-0016
`chunking.opengamevcs/gear-fastcdc-1m@1` candidate. It exposes deterministic
chunk generation and bounded public verification, reconstruction, comparison,
and an additive `atomicWriteStream` publication adapter that issues a one-use
private verification receipt. It does not provide a CLI, ratify the profile,
or claim the deferred 100-GiB acceptance proof.

```js
import { createChunker } from '@opengamevcs/chunking-manifest';

const chunker = createChunker({
  declaredLength: bytes.length,
  onChunk: (chunk) => storeChunk(chunk),
  manifestSink: (fragment) => storeManifestFragment(fragment),
});
chunker.update(bytes);
const result = await chunker.finish();
```

`update` accepts fragments of at most 64 MiB. The scalar implementation admits
one worker, no completed-chunk queue, and the ADR-0016 scalar budget of
4,259,840 bytes. Runtime state contains the current at-most-2-MiB chunk plus an
explicitly bounded 48-byte-per-entry ledger. The ledger spills from
`maxLedgerMemoryBytes` to owner-private `maxScratchBytes` storage and removes
scratch on finish, failure, or explicit `abort()`.

For version compatibility, generation returns part/boundary arrays by default.
Long-running bounded callers set `retainEntries: false`; `chunkBytes` always
opts in because its whole input is already resident.

```js
import { compareManifest, reconstructManifest, verifyManifest } from '@opengamevcs/chunking-manifest';

await verifyManifest({ manifest, source: chunkLookup });
const delta = await compareManifest({ manifest, knownChunks: localIndex });
await reconstructManifest({
  manifest,
  source: chunkLookup,
  publication: { write: stage, commit: publish, abort: discard },
  signal: cancellation.signal,
  maxElapsedMilliseconds: 30_000,
});
```

All readers run OGVCS-002 canonical framing and known-schema validation before
checking the exact candidate profile. Content paths then verify every ordered
occurrence, ChunkID, declared length, whole-file digest, and Gear end.
Reconstruction commits only after every check succeeds. Repeated references are
read per occurrence; comparison counts logical, unique, reused, repeated, and
newly required bytes exactly and rejects conflicting length metadata.
After manifest admission, every reconstruction failure aborts exactly once,
including missing-first-chunk and empty commit failures. External callback and
iterator exceptions are normalized to the generated 22-code authority.

`chunkCacheKey(chunkRef)` implements ADR-0016's stable, profile-bound shared
cache-key preimage. Cache hits remain untrusted until `verifyManifest` or
`reconstructManifest` completes. Generation and manifest-reader operations
accept cooperative `signal` and `maxElapsedMilliseconds` controls;
cancellation/deadline expiry is `CHUNK_RESOURCE_EXHAUSTED` and never commits
partial output.

Manifest encoding and ObjectIDs delegate to the public
`@opengamevcs/object-model` package. The bundled candidate registry view is
conformance-only; production writes still require shared registry ratification
and trust-boundary integration.
