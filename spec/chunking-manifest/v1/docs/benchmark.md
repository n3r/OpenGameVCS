# Bounded seven-workload benchmark authority

This contract adds the smallest bounded benchmark authority required by the
2026-08-30 OGVCS-007 ratification review without attempting the deferred
100 GiB acceptance campaign. `vectors/selection-benchmark-workloads.json`
declares seven deterministic workload pairs: source-like, structured,
already-compressed, encrypted/random, insertion, replacement, and append.

Each workload fixes both the base bytes and the edited candidate bytes through
closed recipes. The report runner materializes those bytes locally, chunks the
base and candidate, verifies the candidate manifest from its delivered chunks,
and compares the candidate manifest against the base chunk index without any
remote service.

`thresholds/selection-bounded-v1.json` is intentionally documentary rather
than promotional. It gates only report completeness, successful execution,
byte-accounting integrity, and a few bounded observations that the review
explicitly named: preserved reuse for source-like and structured inputs,
honestly poor reuse for compressed and encrypted/random inputs, bounded
resynchronization for insertion and replacement, and a bounded new-tail cost
for append. It does not ratify the profile, change the OGVCS-002 registry, or
substitute for the later 100 GiB resource run.
