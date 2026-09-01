# OGVCS-013 private dry-run planner boundary review

## Decision

Accept this tranche only as a bounded Rust-internal current-versus-target
planning candidate. It adds no field, artifact, error, or claim to the frozen
language-neutral selection contract in `spec/selective-sync/v1`. It has no
public CLI/route or production operation brand and cannot authorize mutation.

The planner consumes four independently supplied private projections:

1. selected target rows (`full`, `metadata-only`, or `absent-by-spec`);
2. retained current workspace/index rows with local observation state;
3. a unique ordered OGVCS-002 object-reference closure subject to OGVCS-007
   chunk/content-manifest payload ceilings; and
4. one aligned cache probe per required object (`VerifiedHit` or `Miss`).

The OGVCS-002 `FileId` and `ObjectRef` types, OGVCS-007 ceilings, and OGVCS-004
canonical path/collision keys are direct crate dependencies. This tranche does
not invent replacement identity strings or path rules.

## Candidate behavior

After all sources reach EOF and pass count/order/shape/budget checks, the
planner emits deterministic target-order actions followed by residual-current
actions. The action classes are add, update, delete, move-or-equivalent,
materialization-state, and conflict. Stable file IDs find moves; exact manifest
and whole-file identities determine payload equivalence. Each full current row
has one deterministic target-order plan owner. That owner target alone may name
the row as `source_path` and, when payload-equivalent and pristine, count it as
reusable. If one row is both a platform-alias path match and another target's
stable-ID source, the later target cannot reference that row; it may use a
different unowned current destination, but otherwise becomes a conservative
staged add from absent state. A displaced pristine tracked destination remains
visible in the retired-baseline ledger.

Target/residual order is a deterministic preview and digest order, not an
executor schedule. This candidate neither resolves action dependencies nor
authorizes applying its sequence to a filesystem.

Modified, wrong-kind, untracked exact-path, and untracked ancestor/descendant
obstructions are explicit conflicts. A modified or untracked move destination
blocks the move. No action silently overwrites or deletes those objects.
Current rows also have a platform-key lookup: a case-only alias with the same
stable file ID remains an explicit move-or-equivalent, while modified,
wrong-kind, and untracked cross-projection aliases are conflicts. Ordered
obstruction-only repository/platform indexes prevent an earlier unrelated
descendant from masking a later obstruction without turning each target lookup
into a current-row scan.
Changing a metadata-only row to absent when an ordinary untracked obstruction
exists emits an index-state-only action; its deletion predicate is false and
the ordinary path is preserved. A metadata-only target carries no entry or
content identity, requests no required object, and cannot imply a filesystem
file.

Authorization-filtered omission has no reason field. Given the same filtered
target projection, an ordinary absence and a permission-hidden absence produce
byte-identical candidate actions and summaries; no replacement identity can be
reported. This is noninterference at the supplied-projection boundary, not an
authorization or revocation-race proof.

## Arithmetic and trust boundary

Every input remains an untrusted adapter claim. The planner does not parse
content manifests to prove closure, read object/cache bytes, invoke OGVCS-007
verification, authenticate the snapshot/current generation, or prove that a
`VerifiedHit` probe was verified. It requires each target full manifest to be
present in the supplied closure and computes only deterministic arithmetic over
the bound projections. Warm-cache zero transfer is therefore a property of the
probe projection, not AC-03 evidence for real cached bytes or reproduced file
digests.

The exact arithmetic vocabulary is:

| Ledger | Meaning |
|---|---|
| target full logical bytes | Sum of supplied full target whole-file lengths |
| current tracked baseline bytes | Sum of nonmissing current tracked baseline lengths |
| reusable workspace bytes | Target bytes owned by the first target-order plan owner of a pristine payload-equivalent current source/destination |
| workspace stage bytes | Target logical minus reusable workspace bytes |
| retired tracked baseline bytes | Current baseline minus reusable workspace bytes |
| required object bytes | Sum of the unique supplied object closure |
| cache hit/miss and transfer bytes | Paired probe arithmetic; transfer equals misses |
| disk payload reservation | Workspace-stage plus cache-miss bytes under a conservative same-volume payload model |

These are logical/payload values, not allocated blocks, actual free-space
measurement, or a promise that a future executor uses this staging model.

## Boundedness and failure semantics

The planner accepts at most 100,000 target rows, 100,000 current rows,
1,148,576 required objects, 1,148,576 aligned cache probes, and 200,000 emitted
actions. Modeled typed-record bytes are capped at 1 GiB, conservative
retained-index admission accounting at 256 MiB, and each aggregate byte ledger
at 9,007,199,254,740,991. There is no raw framing parser, and neither byte value
is an adapter-buffer or allocator measurement. Required objects/probes stream
pairwise. Target/current records stream into bounded maps needed for
deterministic file-ID move matching, platform-alias reconciliation, obstruction
lookup, single-owner current/action matching, and action order.

`retained_bytes_peak` is the conservative admission model for planner-owned
retained maps/keys only. Source adapters, temporary working values, allocator
overhead outside the model, and sink-owned action copies are explicitly
excluded. The sink receives a borrowed single bounded action and at most
200,000 calls; a retaining sink must enforce its own byte limit. A counting-sink
versus retaining-sink test proves the modeled planner peak and action digest do
not depend on sink retention.

No action is emitted until every source is fully consumed. A source,
validation, cancellation, sink-emission, or sink-finish error returns no
summary; any prior sink copies are discard-only. Final ledger arithmetic is
also checked before the sink is finalized. Exact and plus-one arithmetic,
count, order, identity, cache alignment, missing-manifest, source, sink, and
cancellation failures are hostile-tested.

## Evidence and acceptance relevance

Rust 1.82 table/property/hostile suites cover all candidate action classes,
persona-like include/exclude results, exact ledger equations, warm/cold cache
probe arithmetic, permission-hidden noninterference, deterministic generated
state matrices, modified/untracked blockers, move-destination retirement,
metadata-only index-only removal, overflow, cancellation, and source/sink
failure. Windows alias/stable-ID permutations prove that one current row has
one deterministic target-order plan/source owner and that the losing target
stages from absent state. The existing 100,000-row selection test remains
selection-kernel evidence only; this dry-run tranche did not run an exact
100,000-current plus 100,000-target plan or a million-path campaign.

This is relevant implementation progress toward FR-03, FR-05, and FR-07. It
does not satisfy an acceptance criterion:

- AC-01 still requires actual authorized path materialization and zero excluded
  transferred payload, not persona-like candidate rows;
- AC-02 still requires crash/cancel recovery at real execution boundaries;
- AC-03 still requires verified warm-cache content and identical materialized
  file digests;
- AC-04 still requires authorization revocation during transfer/application;
- AC-05 still requires reference-corpus performance and measured estimate
  error bounds.

## Residuals

There is no authenticated target/current producer, request-root authority,
server closure negotiation, object transfer, cache byte verification, free
space measurement, filesystem preflight/executor, staging, atomic generation
switch, index write, resume token, crash recovery, watcher integration, public
native CLI, network host, route, hosted three-OS evidence, or scale campaign.
The internal action model must not be promoted to a public contract until those
owners settle the production boundary. OGVCS-013 remains **Todo**.
