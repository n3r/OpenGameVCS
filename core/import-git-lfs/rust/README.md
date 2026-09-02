# OGVCS-020 private Git import preflight and tree-frame candidate

This unpublished Rust 1.82 crate is a pure, bounded preflight over a
caller-supplied, already-staged Git inventory projection plus a strict decoder
for one already-inflated Git tree frame. It is private and unwired. It has no
Git pack, compressed loose-object, zlib, or archive parser; filesystem access;
network client; broker; credential handling; authorization decision;
persistence; converter; checkpoint; publication path; public CLI; or service
route.

The projection contains canonical-order ref, commit, tree, proposed target
entry, and OGVCS-002 mapping-request records. Entry occurrences and Git blob
objects are intentionally separate: one immutable blob object can back several
paths, while mode `160000` is a gitlink to a commit and is never classified or
charged as blob/LFS content. Each blob occurrence also carries an explicit
`Ordinary` or `Required` LFS disposition. That supplied disposition is bound
into the inventory transcript but is not proof that `.gitattributes` was
parsed faithfully. The crate checks counts and logical bytes, Git
SHA-1/SHA-256 identifier typing, repeated-blob metadata consistency, ref-name
shape, OGVCS-004 target-path validation/collisions, explicit mode and extension
policy, source ordering, and an independent end-of-stream inventory
declaration. A successful report binds the full returned projection—including
operational limits, measured work, and conservative peak retention—with
domain-separated SHA-256 transcripts. `ready` means only that this narrow
projection produced no local preflight blockers; it is not import,
authorization, fidelity, verification, or publication approval.

## Inflated Git tree-frame boundary

`decode_git_tree_frame` identifies its private algorithm as
`ogvcs.git-tree-frame/strict@1`. It accepts borrowed bytes in Git's inflated
`tree <canonical-decimal-size> NUL <payload>` representation, a claimed staging
SHA-256, and a typed SHA-1 or SHA-256 repository object format. The staging
digest is recomputed before parsing. It binds immutable input bytes but is not
the Git object ID: this tranche deliberately does not implement SHA-1,
collision detection, pack/loose-object acquisition, or the Git object-ID
preimage association.

Each payload entry must use exactly one canonical mode spelling: `40000`,
`100644`, `100755`, `120000`, or `160000`. Names are bounded Git byte names,
not UTF-8 text. Empty names, `.`, `..`, `/`, literal `.git`, and the HFS/NTFS
aliases that Git's tree checker treats as `.git` are rejected. Child IDs are
exactly 20 or 32 nonzero bytes according to the selected object format. Entries
must be globally unique and strictly ordered by Git's tree comparator,
including the special `/` comparison byte for a tree name at a shared prefix.
The global duplicate check covers names separated by intervening prefix entries
such as file `foo`, file `foo.bar`, and tree `foo`. Unsupported modes fail
closed; this candidate defines no transform policy.

The decoder performs an allocation-free digest/header/structural shape pass.
That pass charges a conservative protected-name recognizer, computes exact
counts, and admits all remaining work plus conservative peak retention before
allocation. A second pass uses an exact-capacity, eight-byte-per-entry stack of
borrowed-name offsets to validate full Git ordering and non-consecutive
duplicates. The scratch stack is dropped before a third pass materializes only
the validated entries into exact-capacity output storage. Errors and
cancellation drop all internal state and expose no partial entry list. A final
cancellation fence follows the projection commitment. Input, effective limits,
object format, ordered entries, conservative charged work, cancellation checks,
and retained charge are bound by domain-separated SHA-256 commitments. Entry
and projection `Debug` output redacts names and object IDs; explicit accessors
remain caller-visible by design.

| Tree decoder resource | Hard maximum |
|---|---:|
| inflated frame bytes | 1,048,576 |
| entries | 4,096 |
| one name | 4,096 bytes |
| aggregate name bytes | 1,048,576 |
| charged work | 16,777,216 units |
| conservative retained bytes | 2,097,152 |

Callers may only narrow these maxima, and the effective limits are request-
commitment inputs. The retained model charges 1,024 fixed bytes and takes the
maximum of two non-overlapping states: an exact-capacity duplicate-candidate
stack charged at eight bytes per entry, or output charged at 64 bytes per entry
plus exact retained name bytes. Both entry charges have compile-time size
assertions. The model includes exact logical vector/name capacities but excludes
borrowed frame storage, allocator metadata, hashing stack state, and caller
clones; it is not an RSS measurement.

This decoder is not connected to `preflight_git_import`. It does not recurse,
join paths, discover `.gitattributes`, derive `LfsDisposition`, or prove that a
claimed `ImportRecord::Tree` names these bytes. A future OGVCS-045
credential-free worker and authenticated acquisition boundary must establish
that association before the output can replace the current adapter projection.
It also does not implement Git fsck's separate policy findings for symlinked
HFS/NTFS aliases of `.gitmodules`, `.gitattributes`, `.gitignore`, or `.mailmap`;
the authenticated importer must enforce those repository-wide rules before
conversion.

The tree-order and protected-name rules are derived from Git's official
[`fsck.c`](https://github.com/git/git/blob/master/fsck.c),
[`tree.c`](https://github.com/git/git/blob/master/tree.c),
[`path.c`](https://github.com/git/git/blob/master/path.c), and
[`utf8.c`](https://github.com/git/git/blob/master/utf8.c) sources.

## OGVCS-002 composition

`FileId`, `ImportRequest`, `ImportDecision`, `ImportMapping`, `ImportState`, and
`import_mapping_key` are used and re-exported directly from
`ogvcs-object-model`. This crate does not allocate or derive FileIDs and never
uses a path as identity. Every non-gitlink entry occurrence is explicitly bound
by `(Git object ID, validated target-path digest)` and requires exactly one
mapping record. Reused blob content at two paths therefore requires two
distinct mapping requests and two distinct FileIDs, while Git/LFS source bytes
remain object-deduplicated. `MappingAuthority::decide(&self)` is strictly a
side-effect-free lookup over an already pinned OGVCS-002 authority view; it may
not allocate, reserve, persist, publish, or mutate product state. The kernel
requires the returned FileID to equal the requested FileID on new and retry
decisions, requires new decisions to remain `Reserved`, validates mapping keys,
rejects duplicate source identities/FileID aliasing, and fails under-, over-,
or duplicate occurrence mapping.

`ImportRequest::source_identity_digest` remains an opaque caller claim. The
candidate transcript binds the exact association between that claim and the
`SourceOccurrence`, but it neither derives one from the other nor authenticates
their relationship. A future authorized integration must define and verify the
source-identity tuple before calling OGVCS-002. A locally `ready` report is not
evidence that this association is authoritative.

Tests use only `importer.test/fixture-adapter@1`, the OGVCS-002 conformance
fixture profile. The crate defines no production importer profile and makes no
claim that a production mapping authority exists.

## Git LFS boundary

The classifier implements the canonical Git LFS v1 text-pointer rules used by
the official specification and reference encoder:

- UTF-8 text, exact single-space key/value lines, LF terminators, and a file
  strictly smaller than 1024 bytes;
- the exact `https://git-lfs.github.com/spec/v1` version string;
- lowercase 64-hex SHA-256 OIDs, positive canonical decimal sizes within the
  reference implementation's signed 64-bit range, canonical field order, and
  canonical extension framing. Extension names follow the reference
  `ext-<one digit>-\w+` prefix envelope: uppercase and underscore word bytes
  are valid, and the unanchored suffix accepted and preserved by the upstream
  parser is preserved here as well;
- the empty-file pass-through rule, so empty bytes are ordinary content rather
  than a textual pointer;
- the reference decoder's blob cutoff: every input at or above 1024 bytes is
  unconditionally `NotPointer`, even if prose or binary bytes contain an LFS
  marker. The preflight adapter supplies an empty probe for those oversized
  blobs, avoiding both misclassification and unbounded inspection;
- readable legacy aliases are rejected as noncanonical;
- only regular/executable occurrences declared `Required` are eligible for
  substitution. At those occurrences, malformed bytes containing an actual
  `git-lfs`, `git-media`, or `hawser` marker fail, and a nonempty nonpointer can
  never fall back to its stored bytes. A required empty file follows the
  official pass-through rule and has no external LFS object. An `Ordinary`
  occurrence preserves the exact Git bytes even if they form a canonical
  pointer. Symlink target blobs are always `Ordinary`; declaring a symlink
  `Required` is a source-contract error because Git does not run checkout
  filters on symlink targets. Generic short text such as
  `version 1.0` has no LFS marker and remains ordinary content, matching the
  upstream matcher.

The disposition is an opaque caller commitment. This crate neither evaluates
`.gitattributes` nor authenticates which regular paths are LFS-tracked, so a
locally `ready` report does not attest correct attribute discovery. The same
Git blob may validly remain ordinary at one path and resolve through LFS at
another; pointer and LFS-object counts include only `Required` occurrences.

The content source is a no-I/O trait supplied by the caller. The verifier reads
fixed bounded chunks, checks generation before and during reads, detects
missing/ambiguous/truncated/extended sources, and requires exact size plus
SHA-256. Shared OIDs are verified once after size agreement. Extension-bearing
pointers can be inventoried, but this crate has no extension execution model;
they always remain blockers. No policy flag can turn missing extension reversal
into a successful local preflight.

Normative references used for this candidate are Git's official
[`gitattributes`](https://git-scm.com/docs/gitattributes) documentation and
checkout [`entry.c`](https://github.com/git/git/blob/master/entry.c) behavior
(working-tree conversion is confined to regular entries), plus the official Git LFS
[`docs/spec.md`](https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md),
[`lfs/pointer.go`](https://github.com/git-lfs/git-lfs/blob/main/lfs/pointer.go),
and [`docs/extensions.md`](https://github.com/git-lfs/git-lfs/blob/main/docs/extensions.md).

## Determinism, bounds, and failure

`InventorySource`, `LfsContentSource`, and `MappingAuthority` each expose a
generation. The caller supplies those generations plus exact expected counts,
logical Git/input bytes, and inventory digest. Start, external-call, and EOF
checks detect drift. Records must be in the exported canonical key order.

Before any generation/source trait call, the exact expected inventory is
pre-admitted: category totals must agree; mappings must equal non-gitlink blob
occurrences; unique blobs/pointers/LFS objects must form a valid subset chain;
declared item/relationship/mapping/Git/input totals must fit configuration; and
the checked known minimum work must fit. Zero generations, inventory digest,
repository descriptor digest, source namespace, and mapping source identity
are reserved invalid sentinels.

Default configured ceilings are 100,000 records, 1,000,000 declared graph/tree
relationships, 16 GiB modeled Git bytes, 1 GiB modeled typed input bytes,
100,000 unique LFS objects, 64 GiB per LFS object, 1 TiB cumulative verified
LFS bytes, 100,000 mappings/findings, 4,000,000 work units, 128 MiB conservative
retained admission, 16 KiB paths, 1 KiB ref names, and 64 KiB read chunks.
Smaller caller limits are supported; hard ceilings—including 64,000,000 work
units—prevent configuration from removing bounds. Raw ref/path/probe lengths
and capacities are checked before transcript hashing or ordering-key cloning.
The predecessor-owned `ProfileRef` is rebuilt from its bounded visible text so
hidden caller `String` spare capacity is not retained.
Valid record bytes are charged in bounded hashing work units with cancellation
fences. EOF missing-mapping scans, temporary collection, finding ordering, and
report hashing are also charged and fenced. All additions and multiplications
are checked.

The retained ledger is conservative admission accounting, not allocator or
RSS measurement. It covers returned-record string/vector capacity while the
kernel owns a record, retained keys/maps/reports, temporary EOF state, and the
LFS read buffer. It excludes separate buffers still owned by source adapters,
allocator metadata, and copies retained after the returned report. `git_bytes`
charges commit/tree records and each unique blob object once, not each path
occurrence. `input_bytes` is this crate's typed-record model, not Git pack size.
Neither is storage or transfer estimation.

Failure precedence is: configured limits and policy; expected-inventory
pre-admission; cancellation and initial generation binding; source call; cheap
record-shape/capacity checks; item/input/work/order checks; record semantics,
path/policy, LFS, and OGVCS-002 mapping checks; EOF generation binding; bounded
missing-mapping analysis; declaration reconciliation; finding order and full
report hashing; then a final cancellation/generation fence. Any terminal
failure drops all local state and returns only a typed error—no report, mapping
plan, entry, or cursor exists.

## Explicit residuals and nonclaims

The inventory remains an untrusted adapter projection, not evidence that Git
packs, loose objects, refs, reachability, commit parents/order, recursive trees,
messages, authors, timestamps, `.gitattributes`, submodules, symlinks, or all
history were parsed completely. The isolated tree decoder validates only bytes
passed directly to it and is not wired to inventory records. `LfsDisposition`
is a bound adapter claim, not authenticated `.gitattributes` evaluation. The
unique-object/entry-occurrence split follows Git's data model, but adapter
declarations are not proof that object types or reachability were parsed
faithfully. Commit/tree relationship counts are declared work charges, not DAG
proof. Proposed target paths are not a raw historical tree stream. Source
identity digests are opaque caller claims; this crate does not infer rename,
move, copy, delete/recreate, or original identity.

There is no remote LFS acquisition, credential classification, sandbox,
decompression, Git object hash recomputation, conversion, target object/root,
durable mapping, checkpoint/resume, isolated namespace, OGVCS-017 verification,
source-tip/target reconciliation, atomic ref update, rollback, telemetry,
hosted behavior, large-history benchmark, or scale claim. No OGVCS-020
acceptance criterion is satisfied or closed by this candidate.

Run the local gates with build output outside the worktree:

```text
cargo +1.82.0 fmt --manifest-path core/import-git-lfs/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path core/import-git-lfs/rust/Cargo.toml --locked --offline
cargo +1.82.0 test --manifest-path core/import-git-lfs/rust/Cargo.toml --locked --offline --release
cargo +1.82.0 clippy --manifest-path core/import-git-lfs/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
sh core/import-git-lfs/rust/scripts/test-packed.sh
node --test tools/git-import-preflight-policy.test.mjs
```
