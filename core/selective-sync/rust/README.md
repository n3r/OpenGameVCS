# OGVCS-013 private selection kernel rc.1

This dependency-small Rust 1.82 crate implements the pure bounded evaluator
from `spec/selective-sync/v1`. It consumes one metadata record at a time,
classifies with a bounded compiled rule trie, checks canonical repository order
and platform collisions, and writes one bounded binary projection fragment at
a time. The returned summary contains only digests, counts, and byte ledgers.

The sink header contains declared bindings before the input digest can be
recomputed. All sink bytes remain untrusted and must be discarded unless the
source reaches EOF, every bound and collision check passes, the recomputed
metadata projection matches, `flush` completes, and `evaluate` returns a
summary. Errors—including cancellation and sink failure—return no summary.
At the language-neutral boundary this completed emission has no application
value: Node callbacks return `undefined`, while this Rust implementation uses
`Write::write_all` and `flush` returning `Ok(())`; any lower-level partial-write
count is consumed only inside `write_all`.

This crate is intentionally unwired. It has no object-fetch/cache code,
filesystem mutation, production entry brand, authentication or permission
filter, request-root integration, public CLI, or network route. It does not
make OGVCS-013 complete and is not evidence for the one-million-path latency
target.

Run the local gates with external build output:

```text
node core/selective-sync/rust/scripts/sync-contract.mjs --check
cargo +1.82.0 fmt --manifest-path core/selective-sync/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path core/selective-sync/rust/Cargo.toml --locked --offline
cargo +1.82.0 clippy --manifest-path core/selective-sync/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
```
