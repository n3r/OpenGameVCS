# Bounded seven-workload benchmark authority

This contract adds the bounded workload definitions and documentary thresholds
used to retain narrow, provisional OGVCS-007 selection evidence for the
2026-08-30 ratification review without attempting the deferred 100 GiB
acceptance campaign. `vectors/selection-benchmark-workloads.json` declares
seven deterministic workload pairs: source-like, structured,
already-compressed, encrypted/random, insertion, replacement, and append.

The `already-compressed` pair uses the closed
`ogvcs.portable-gzip-fixed-lz77/v1` encoder. It emits a canonical gzip wrapper
and a deterministic fixed-Huffman DEFLATE stream from the recipe bytes; native
or system zlib output is not part of the authority. This keeps the workload
byte-identical across supported hosts and runtime zlib versions.

Each workload fixes both the base bytes and the edited candidate bytes through
closed recipes. The report runner materializes those bytes locally, chunks the
base and candidate, verifies the candidate manifest from its delivered chunks,
and compares the candidate manifest against the base chunk index without any
remote service.

For insertion and replacement, `resynchronizationDistanceBytes` is defined from
actual chunk reuse, not a raw common-suffix span. The runner finds the first
mutated byte offset, then scans the candidate chunk sequence for the first
reused chunk whose candidate start offset is at or after that mutation start
and whose `ChunkID` also appears in a base chunk that starts at or after the
same mutation start. The metric is that candidate chunk start offset minus the
mutation start offset. If no such post-mutation aligned reused chunk exists,
the metric is `null`.

`thresholds/selection-bounded-v1.json` is intentionally documentary rather
than promotional. It gates report completeness, successful execution,
byte-accounting integrity, and a few bounded observations that the review
explicitly named: preserved reuse for source-like and structured inputs,
honestly poor reuse for compressed and encrypted/random inputs, bounded
resynchronization for insertion and replacement, and a bounded new-tail cost
for append. It does not ratify the profile, change the OGVCS-002 registry, or
substitute for the later 100 GiB resource run.

These inputs do not by themselves close P0-2 from the ratification review.
Actual closure still requires an authenticated OGVCS-005 result bundle/verifier
for the bounded seven-class run and retained observed process peak memory. The
retained JSON report is therefore provisional bounded OGVCS-007 selection
evidence, not an authenticated OGVCS-005 closure packet.
