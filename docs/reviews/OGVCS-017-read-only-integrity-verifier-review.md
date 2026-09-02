# OGVCS-017 read-only integrity verifier boundary review

**Decision:** Accept the bounded source candidate as an unwired read-only
verification seam. Do not treat it as completion of OGVCS-017 or as authority
to add storage mutation, repair, quarantine, public commands, or permission
semantics.

**Source baseline:** `643837921d423af8632d8af40a876199f9250609`

## Reviewed boundary

The private `ogvcs-integrity-verifier` rc.1 crate pins an opaque supplied
generation and traverses only the immutable content closure represented by:

```text
Snapshot field 18 -> Tree
Tree entry field 4/5 -> child Tree or ContentManifest + logical size
ContentManifest field 19 -> Chunk occurrences
```

It intentionally does not follow snapshot parents, repository descriptor,
change set, asset groups, provenance, conflicts, attestations, shelves,
unreachable inventory, or physical replica topology. Those omissions are
explicit scope boundaries, not inferred healthy state.

## Validation authority and ordering

1. The candidate source binds the run generation before creating a cursor.
2. Each object read carries the same generation; a mismatch stops the page.
3. OGVCS-002 `opaque_object_digest` checks declared object identity without
   assuming valid framing.
4. OGVCS-002 `scan_metadata` and `validate_metadata_schema` check canonical
   CBOR, format version, known kind/schema, typed references, sizes, and
   ordering before graph fields are interpreted.
5. OGVCS-007 `verify_manifest` checks manifest identity, profile, part ledger,
   each chunk identity/length, whole-file digest, and Gear boundaries. The
   verifier uses the discard-only verification entry point, never the
   reconstruction/publication entry point.
6. Only a fully successful object check enters the unique verified-object
   coverage map. No response or report type contains object payload bytes.

The source seam has explicit `Missing`, `SourceAmbiguous`,
`BackendAmbiguous`, and `ByteLimit` outcomes. The verifier never resolves
ambiguity by selecting a plausible copy.

## Cursor and coverage accounting

The metadata-boundary cursor retains the captured generation, root,
deterministic pending queue, seen identities, expected file sizes, covered
identities, edge keys, file/version keys, manifest restart recovery class,
terminal-overflow state, findings, and cumulative ledger. Its binding digest
covers all of that state. Every active resume repeats the generation check.
Generation drift wins over cancellation observed on the same returned read;
cancellation raised during a read leaves the current object pending. Source
failure, generation change, cancellation, and resource stops return no report.

There is deliberately no sub-manifest cursor. The OGVCS-007 manifest closure
is indivisible: an internal source/read/byte/work/memory limit returns
`ManifestRestartRequired`. The same or a smaller relevant envelope returns
that state immediately with an unchanged ledger and no chunk rereads; a
materially expanded relevant envelope may restart the manifest at occurrence
zero. The private marker records the exact recovery class, distinguishing page
transfer from single-object bytes, general work from fragment work, and
configured decode working memory. A charged-memory stop requires a larger
charged-memory ceiling; OGVCS-007
`ResourceExhausted` requires a larger manifest-index envelope; and no-scratch
`ScratchExhausted` requires a larger resident manifest-ledger envelope.
Changing an irrelevant envelope performs no reread. An enlarged index/ledger
reservation is admitted again against charged memory and may replace the
marker with a charged-memory stop. OGVCS-007 unsupported profiles,
`ResourceInvalid`, and `ResourceUnsupported` are source/configuration
failures, not corruption or a restart promise. Cancellation also retains the
manifest at its object boundary, so an uncancelled retry starts the manifest
at occurrence zero and exact source/work accounting can increase for repeated
chunks. This prevents
same-envelope livelock without pretending that a partial manifest is
resumable.

Coverage fields have deliberately narrow meanings:

- verified object/byte counts are unique canonical identities that completed
  their relevant validation;
- graph-edge, file/version, and manifest-part counts use stable
  `(parent, ordinal, child)` keys, so retry does not double count them;
- source reads/bytes and work units record actual effort and therefore do
  include safe retry work; returned `Found` bytes are counted before a later
  generation, cancellation, or source-contract rejection;
- work units are source reads, newly admitted graph edges, and chunk fragments;
  graph-edge work and cursor admission are atomic, so a memory-rejected edge
  changes neither graph coverage nor work;
- peak memory is the deterministic conservative cursor/codec/object/index
  charge, including actual admitted `Vec` capacity and a simultaneously live
  manifest reservation and chunk buffer. The completion report's finding
  buffer is admitted while the cursor finding set remains live. This is not an
  allocator-profile measurement;
- logical-file byte addition is checked; an unrepresentable total is terminal
  `CoverageOverflow` and produces no report.

Limits are explicit for per-page metadata objects, source reads, transferred
bytes, work units, single-object bytes, cursor identities, findings, charged
memory, decode workspace, manifest index, manifest ledger, and chunk fragment
size. Oversized fixture sources return a typed limit outcome without returning
payload bytes. The initial root cursor is admitted before source generation is
consulted. The verifier caps each source request from the remaining
transfer, object, and charged-memory capacity before allocation; the private
source trait requires both returned length and allocation capacity to stay at
or below that cap. The verifier defensively rejects a length or capacity
violation as `SourceUnavailable` / `SourceFailure` and never validates those
bytes.
Finding count or memory truncation leaves a `FindingsTruncated` sentinel whose
fail-closed classification prevents a false intact report.

## Fault review

| Fault | Expected fail-closed result |
|---|---|
| Missing required snapshot/tree/manifest reference | `INTEGRITY_METADATA_REFERENCE_MISSING` at the precise graph layer |
| Missing supplied object | `INTEGRITY_OBJECT_MISSING` |
| Supplied or tree-declared size mismatch | `INTEGRITY_SIZE_MISMATCH` |
| Snapshot/tree/manifest/chunk bit flip | `INTEGRITY_DIGEST_MISMATCH` at that layer |
| Rebound invalid format version | `INTEGRITY_FRAMING_VERSION` |
| Rebound invalid whole-file digest | `INTEGRITY_MANIFEST_CORRUPT` from the OGVCS-007 closure verifier |
| Source/backend ambiguity | Explicit ambiguity finding; no copy chosen |
| Source failure, cancellation, or generation drift | No report; the current metadata object remains pending and generation-bound |
| Limit inside a manifest | `ManifestRestartRequired`; same/lower relevant envelope performs no reread |
| OGVCS-007 index or resident-ledger exhaustion | Restart requires the corresponding index/ledger increase; its larger reservation is re-admitted against charged memory |
| OGVCS-007 unsupported profile or invalid/unsupported resource configuration | `SourceUnavailable` / `INTEGRITY_SOURCE_FAILURE`; non-corruption and non-restartable |
| Source returns `Vec` length or capacity above the admitted cap | `SourceUnavailable` / `INTEGRITY_SOURCE_FAILURE`; bytes are never treated as valid |
| OGVCS-007 ledger-counter overflow | Terminal `INTEGRITY_MANIFEST_CORRUPT`; it is not restartable by enlarging verifier limits |
| Finding capacity exhausted | `INTEGRITY_FINDINGS_TRUNCATED`; any final report is explicitly non-intact |
| Logical coverage sum overflows | Terminal `CoverageOverflow`; no report and no saturated value |

## Read-only replica assessment follow-up

The private crate now has a separate `assess_replica_set` seam. Its input is a
bounded supplied replica set, not an inventory query or trusted health record.
Before allocation or hashing it validates literal maxima for replica count,
single and total bytes, work, result memory, and metadata decode memory. It
rejects duplicate backend IDs and sorts the remaining fixed-width identifiers,
so input order cannot select a different source.

For present chunks it independently recomputes the exact OGVCS-002 chunk
identity. For present metadata it recomputes the opaque object digest, parses
canonical framing under the frozen decoder limits, validates the known schema,
and checks the exact kind. Declared/observed length mismatch, digest mismatch,
framing/schema mismatch, missing, ambiguity, and unavailability remain distinct
closed outcomes. Supplied generation and expected length are commitment inputs;
the function does not claim to have established their storage authority.

Every copy gets an opaque observation commitment. A locally valid copy additionally
gets a sealed local-validation commitment binding the supplied generation, exact
object, backend, lengths, and raw-byte digest. Raw bytes and raw SHA-256 values
are not exposed, and the local-validation commitment is not exported as
backend provenance or freshness evidence. The assessment digest binds the sorted copies, set-level
disposition, preferred verified source, and every quarantine/repair preview.
Debug output redacts all backend IDs and commitments.

`RepairCandidate` is emitted only for an unambiguous supplied set with at least
one locally validated source and at least one corrupt or missing destination.
`NoVerifiedSource` emits no repair preview. Ambiguous/unavailable observations
and a cryptographic same-identity/different-bytes conflict suppress every
preview. Differing corrupt copies receive
`ReplicaDisagreementNoVerifiedSource`; one locally valid copy receives
`SingleVerifiedCopy`, not replica agreement. A quarantine preview is still only evidence about an observed corrupt
copy. These values are not storage-health, mutation, permission, audit,
generation-fencing, read-routing, affected-root, or post-repair evidence.

The focused twelve-case suite covers deterministic source selection and replay,
good/corrupt and good/missing candidates, all-bad/no-source behavior,
ambiguity/unavailability obstruction, chunk identity, metadata framing and kind
substitution, declared/observed length precedence, duplicate backends, exact and
maximum-plus-one count/byte/work/memory limits, multi-pass work charging,
cancellation between bounded hash/compare phases, redacted Debug, corrupt-copy
disagreement, and commitment substitution across supplied
generation/object/backend/expected length. The metadata preflight also accepts
its exact four-copy-plus-decode memory reservation and rejects one byte less.

The 77-test local Rust suite passes, as do 17 focused OGVCS-002 conformance
tests and 14 focused OGVCS-007 closure/golden tests. The fixture-derived golden
closes four metadata objects and one chunk (1,132 unique verified bytes), three
file/version entries, and six exact graph edges. One-object pages produce the
same final ledger, finding order, and transcript digest as a one-shot run.

## Acceptance interpretation

- **AC-01:** bounded candidate relevance only. The local corpus covers
  snapshot, tree, manifest, and chunk bit flips plus missing/framing/declared
  storage metadata cases, precise chunk declared/observed size evidence, and
  fail-closed finding truncation. Spare-capacity source buffers are charged or
  rejected across metadata, manifest, and chunk processing; the API exposes no
  valid-read payload. It is not a production backend or full
  mutation-fuzz/replica corpus.
- **AC-04:** narrow metadata-page relevance only. One-object page boundaries,
  generation drift, exact small-fixture coverage, and fail-closed multi-chunk
  restart requirements, including a cancellation followed by a sub-closure
  limit, resource-specific index/ledger recovery, charged-memory readmission,
  and atomic edge/work admission are tested. There is no sub-manifest resume,
  durable cursor/finding store, or concurrent-commit production campaign.
  This is not evidence for AC-04 full-scrub resumability.
- **AC-02:** bounded candidate relevance only. One supplied good copy plus one
  corrupt/missing copy produces an exact read-only disposition preview. There
  is no authoritative inventory, read avoidance, quarantine/repair execution,
  generation CAS, post-copy verification, or two-copy restoration campaign.
- **AC-03:** bounded candidate relevance only. A supplied all-bad/missing set
  produces `NoVerifiedSource` and no repair preview. There is no affected-root
  query or durable degraded-snapshot state.
- **AC-05:** open. There is no production SLO coupling or scale run.

## Residual work / nonclaims

OGVCS-017 remains Todo. Authoritative replica inventory/comparison and
verified-source repair, quarantine mutation and forensic state,
all-copies-lost degraded-root persistence,
affected-root queries, durable crash-safe findings/cursors, public commands,
authentication/authorization/audit policy, scheduled sampling, full physical
inventory scrub, concurrent upload/replication/retention/read rules, hosted
cross-OS evidence, and the reference large-repository/SLO campaign remain
open. No production brand or route imports this crate.

Object, byte, graph-edge, and file/version coverage uses unique
content-addressed definitions. A reused subtree's internal entries are not
multiplied by each namespace path that points to it, so `logical_file_bytes`
is not a namespace-expanded path-multiplicity metric.

Invalid start envelopes fail before cursor creation. Invalid resume envelopes
return `LimitReached` with the supplied cursor unchanged, so ownership of the
only resumable state is not lost to a configuration error.

## Local evidence commands

```text
cargo +1.82.0 fmt --manifest-path core/integrity-verifier/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path core/integrity-verifier/rust/Cargo.toml --locked --offline
cargo +1.82.0 clippy --manifest-path core/integrity-verifier/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo +1.82.0 package --manifest-path core/integrity-verifier/rust/Cargo.toml --locked --offline --allow-dirty --no-verify
node --test tools/integrity-verifier-source-policy.test.mjs
npm run test:roadmap
```

The local package archive contains the declared bounded file set. Verification
of that archive as a standalone registry-resolved crate is not applicable to
this unpublished candidate because its two frozen authorities remain private
path dependencies; no hosted hermetic-install evidence is claimed.
