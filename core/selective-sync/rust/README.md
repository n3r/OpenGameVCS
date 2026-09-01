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

## Private dry-run candidate

The Rust-only `dry_run` module adds a current-versus-target planning candidate
without changing `spec/selective-sync/v1` or defining a wire format. It consumes
canonical selected-target and retained-workspace streams, an OGVCS-002/007
required-object closure, and a separate cache-probe stream. Candidate actions
cover add, update, delete, move-or-equivalent, materialization-state, and
conflict outcomes. File IDs and object references come directly from the
OGVCS-002 Rust authority; object payload ceilings come directly from the
OGVCS-007 Rust authority; paths and collision order use OGVCS-004.

All four input streams are private, untrusted adapter claims. In particular,
the planner does not parse manifests to prove that the supplied required-object
closure is complete, does not read cached bytes, and does not turn a
`VerifiedHit` probe into evidence that verification happened. It only binds the
supplied projections, validates typed-record count/order/identity shapes,
requires a declared target manifest to appear in the supplied closure, and
calculates deterministic arithmetic. There is no authorization input or result
type and no raw framing parser.

Sources reach EOF before the first action is emitted. Source, validation,
cancellation, sink-emission, or sink-finish failure returns no summary and
makes any emitted action discard-only. Locally modified, wrong-kind, exact
untracked, and untracked ancestor/descendant obstructions become conflicts.
Current platform-key aliases are reconciled before planning: same-File-ID
case-only transitions remain move-or-equivalent actions, while modified,
wrong-kind, or untracked aliases fail closed as conflicts. Repository- and
platform-key obstruction indexes make ancestor/descendant checks bounded
ordered lookups rather than scans over unrelated current rows.
Actions are emitted in canonical target order and then residual-current order
for preview and digest stability only. That sequence is not a safe filesystem
application schedule; a future executor must independently preflight and order
source/destination dependencies.
Each full current row also has one deterministic target-order plan owner. If
the same row is both a platform-alias path match and another target's stable-ID
source, only the owner target may name it as `source_path`; the later target may
use a different unowned destination row, but otherwise becomes a conservative
staged add from absent state. Thus two preview actions never claim the same
current row as independently executable input.
Removing a metadata-only index row with an ordinary untracked obstruction is
an index-state action and never an ordinary-file deletion. Metadata-only target
rows carry no entry/content identity and request no objects or filesystem file.

The exact ledger vocabulary is deliberately narrow:

- target and current values are logical/baseline bytes, not allocated blocks;
- transfer bytes equal missing bytes in the caller-supplied unique object
  closure; cache hit/miss bytes are arithmetic over its paired probes;
- workspace stage bytes equal target full bytes not reusable from a pristine
  payload-equivalent current entry. Reuse follows the current row's one
  deterministic target-order plan owner; a second target conservatively
  stages its bytes;
- retired baseline bytes include a pristine destination displaced by a move;
- disk payload reservation is exactly workspace-stage plus cache-miss bytes
  under the documented conservative same-volume model. It excludes allocation
  overhead and does not assert actual free space.

Target and current sources are streamed into planner-owned bounded indexes;
required objects and cache probes are consumed one pair at a time. The private
limits are 100,000 target rows, 100,000 current rows, 1,148,576 unique required
objects and paired cache probes, 200,000 emitted actions, 1 GiB modeled typed
record bytes, 256 MiB conservative retained-index admission accounting, and
9,007,199,254,740,991 bytes per aggregate ledger. The input-byte value is not a
measurement of adapter framing. `retained_bytes_peak` is not an allocator
measurement and excludes source-adapter buffers, temporary working values, and
copies retained by a caller-provided action sink. The sink receives one bounded
action at a time and must impose its own retention ceiling if it stores them.
The retained-index admission model includes the obstruction and one-use current
plan-ownership indexes.

This dry-run is not an executor. It does not authorize, fetch, verify cache
content, negotiate a server closure, mutate a workspace, reserve disk, resume,
recover from a crash, expose a public CLI/route, or establish the million-path
or latency acceptance targets.

Run the local gates with external build output:

```text
node core/selective-sync/rust/scripts/sync-contract.mjs --check
cargo +1.82.0 fmt --manifest-path core/selective-sync/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path core/selective-sync/rust/Cargo.toml --locked --offline
cargo +1.82.0 clippy --manifest-path core/selective-sync/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
```
