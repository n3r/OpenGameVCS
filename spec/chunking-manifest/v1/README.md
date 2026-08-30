# OpenGameVCS chunking-manifest contract v1 candidate

This MIT-licensed package is the language-neutral authority for the Proposed
ADR-0016 profile candidate `chunking.opengamevcs/gear-fastcdc-1m@1`.
`profiles/` fixes every identity-affecting constant, `registries/` fixes local
candidate limits/errors, and `vectors/` carries exact Gear table, boundary,
ChunkID, whole-digest, manifest-byte, manifest-ID, malformed, and fragmentation
expectations.

`registries/errors.json` is generated from `scripts/model.mjs`; JavaScript and
Rust statically prove that every public stable code matches this authority.
ADR-0016 also freezes the additive shared chunk-cache key preimage and the
cooperative cancellation/deadline and transactional-abort rules. The bounded
cross-language report compares those cache keys, all identity fields, exact
error codes, and deterministic resource-admission outcomes.

`vectors/selection-benchmark-workloads.json` and
`thresholds/selection-bounded-v1.json` add the bounded seven-workload benchmark
authority required by ADR-0016 and the OGVCS-007 ratification review. They are
not an exact-scale gate and do not authorize production writes or registry
ratification on their own.

The candidate is not yet a ratified OGVCS-002 registry assignment and must not
be used for production writes. Its purpose is independent implementation and
benchmark selection. Generate and validate without network access:

```sh
node scripts/generate.mjs --check
node validate-spec.mjs
node --test test/*.test.mjs
```

The generator and validator separately implement the table, recurrence, OGVCS-002
preimages, and deterministic manifest CBOR. Neither imports a language runtime
implementation.
