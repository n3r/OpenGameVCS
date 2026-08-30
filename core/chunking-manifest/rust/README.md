# `ogvcs-chunking-manifest`

Independent scalar Rust implementation of the Proposed ADR-0016
`chunking.opengamevcs/gear-fastcdc-1m@1` candidate. It uses the public
`ogvcs-object-model` crate for hashing, ObjectIDs, OGVCS-002 framing and schema
validation, profile references, and canonical manifest CBOR.

The public `verify_manifest`, `reconstruct_manifest`, and `compare_manifest`
APIs perform OGVCS-002 validation before enforcing the exact candidate profile,
ordered occurrence length/ChunkID, whole-file digest, and Gear boundaries.
Reconstruction writes through `TransactionalPublication` and commits only after
complete verification. `KnownChunkIndex` comparison reports exact
logical/unique/reused/repeated/new bytes and rejects conflicting metadata.

Generation and reading use the same fixed 48-byte ordered ledger.
`LedgerOptions` bounds resident and private scratch storage; `Drop` removes
owner-private, entropy-named scratch artifacts on success and every error path.
`Chunker::new_bounded` omits
retained result arrays, while the whole-input `chunk_bytes` convenience retains
them for compatibility.

`OperationControl` provides a shared atomic cancellation flag and optional
monotonic maximum elapsed duration for generation, verification,
reconstruction, and comparison. Expiry is `CHUNK_RESOURCE_EXHAUSTED` and an
opened publication transaction aborts exactly once on every pre-commit failure.
`chunk_cache_key` implements the stable ADR-0016 profile-bound chunk-cache key;
the cached bytes remain untrusted until full reconstruction verification.

The scalar implementation admits one worker, no completed-chunk queue, and the
ADR-0016 working-memory budget of 4,259,840 bytes. The candidate remains
conformance-only: it does not claim a CLI, production repository binding,
benchmark selection, or 100-GiB evidence.
