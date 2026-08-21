# Public result and threshold format

A public result bundle contains `result.json`, `evidence.json`, bounded
canonical `environments.jsonl`, `samples.jsonl`, and `summaries.jsonl` streams,
an optional `conformance.json`, and `manifest.json`. The result records the
exact contract digest, environment and corpus authorities, declared
cache/network state, fault schedules, the complete threshold file and its
digest, threshold evaluations, overhead method, reproduction command,
classification, retention, and already-redacted public metadata. Every artifact is length-
and SHA-256-bound by the publication manifest.

Failed and incomplete samples remain in the raw set but never enter successful
latency percentiles. Percentiles use nearest rank over successful integer
microsecond samples. Dispersion is the median absolute deviation. Byte totals
are summed with safe-integer overflow checks; the logical/unique ratio is
reported in thousandths.

Threshold entries bind a stable PRD requirement ID, metric, direction,
severity, minimum sample count, task selector, and applicable harness profiles.
The harness does not contain product SLO constants. Candidate product PRDs own
additional threshold files and can change them without changing harness code.
The threshold file also owns the maximum comparison tolerance. A comparator may
select a stricter tolerance for a particular review, but cannot enlarge that
authenticated limit.
The exact selected threshold file is embedded in `result.json`; publishers and
verifiers recompute summaries, threshold rows, and final status from raw
samples and evidence. A schema-valid claimed success is rejected when those
derived values do not reproduce.

Credentials are removed, partner identifiers are replaced by domain-separated
SHA-256 digests, raw values never enter diagnostics, and every bundle declares
synthetic or partner-derived provenance plus a capped expiry. Bundles
intentionally do not claim removal/hash counts: those counts cannot be
recomputed after the sensitive source values have been discarded. The public
redactor API may expose counts to its immediate caller as local diagnostics.
Published comparisons require compatible task/corpus/cache/network definitions, exact
fault/security/conformance authorities, and an explicit tolerance. That
authenticated tolerance applies to p50, p95, p99, and median absolute
deviation; correctness, inventory, retry, and byte semantics match exactly.

Publication stages private files, flushes each file, attempts the platform's
staging-directory sync, and makes the bundle visible with one directory rename;
unsupported directory durability is reported without retracting a completed
commit. Verification rejects
links, missing or unexpected files, changed files, duplicate identities,
digest/count drift, noncanonical framing, aggregate byte/working-memory excess,
or raw/derived semantic disagreement.
