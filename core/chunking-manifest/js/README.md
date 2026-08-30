# `@opengamevcs/chunking-manifest`

Independent scalar JavaScript implementation of
`chunking.opengamevcs/gear-fastcdc-1m@1` from ADR-0016. This first authority
cut exposes deterministic table derivation, streaming boundary discovery,
OGVCS-002 ChunkIDs, and exact `ContentManifestV1` bytes. It intentionally does
not yet publish chunks, reconstruct workspaces, provide a CLI, or claim the
100-GiB acceptance proof.

```js
import { createChunker } from '@opengamevcs/chunking-manifest';

const stored = [];
const chunker = createChunker({
  declaredLength: bytes.length,
  onChunk: (chunk) => stored.push(chunk),
});
chunker.update(bytes);
const result = await chunker.finish();
```

`update` accepts fragments of at most 64 MiB. This scalar cut admits exactly one
worker and no completed-chunk queue, and requires the ADR-0016 scalar budget of
4,259,840 bytes. The `maxWorkingMemoryBytes` option enforces admission. The
runtime state retains only the current at-most-2-MiB chunk; caller-owned
`onChunk` decides persistence. The returned ordered part metadata is bounded by
the format-v1 chunk-count ceiling.
Manifest encoding and all ObjectIDs delegate to the installed public
`@opengamevcs/object-model` package. The bundled candidate registry view marks
the not-yet-ratified profile conformance-only; production write eligibility
still requires the later shared registry integration.
