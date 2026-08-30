# `@opengamevcs/chunking-manifest`

Independent scalar JavaScript implementation of the Proposed ADR-0016
`chunking.opengamevcs/gear-fastcdc-1m@1` candidate. It exposes deterministic
chunk generation and bounded public verification, reconstruction, and
comparison. It does not provide a CLI, bind a production repository trust
boundary, or claim the deferred 100-GiB acceptance proof.

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

Generation does not retain returned part/boundary arrays unless
`retainEntries: true`; `chunkBytes` opts in because its whole input is already
resident.

```js
import { compareManifest, reconstructManifest, verifyManifest } from '@opengamevcs/chunking-manifest';

await verifyManifest({ manifest, source: chunkLookup });
const delta = await compareManifest({ manifest, knownChunks: localIndex });
await reconstructManifest({
  manifest,
  source: chunkLookup,
  publication: { write: stage, commit: publish, abort: discard },
});
```

All readers run OGVCS-002 canonical framing and known-schema validation before
checking the exact candidate profile. Content paths then verify every ordered
occurrence, ChunkID, declared length, whole-file digest, and Gear end.
Reconstruction commits only after every check succeeds. Repeated references are
read per occurrence; comparison counts logical, unique, reused, repeated, and
newly required bytes exactly and rejects conflicting length metadata.

Manifest encoding and ObjectIDs delegate to the public
`@opengamevcs/object-model` package. The bundled candidate registry view is
conformance-only; production writes still require shared registry ratification
and trust-boundary integration.
