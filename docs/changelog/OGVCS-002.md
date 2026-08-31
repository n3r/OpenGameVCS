# OGVCS-002 — Core object library and open repository format

**Completed:** 2026-08-24

**Exact-scale and performance update:** 2026-08-24

**Release:** R0 — Engineering Foundation

**Packages:** `@opengamevcs/repository-format-v1` 0.1.0,
`@opengamevcs/object-model` 0.1.0, and `ogvcs-object-model` 0.1.0

## Delivered format

OpenGameVCS now has a language-neutral repository-format-v1 authority and two
independently implemented object-model libraries. The format defines canonical
bytes and identities without depending on a database layout, hosted service,
private schema, or either implementation. JavaScript and Rust expose the same
typed object references, deterministic metadata codec, repository validation,
tree and manifest streaming, logical-bundle verification, registry lifecycle,
and bounded failure model.

The frozen authority contains 2,815 authenticated artifacts, 573 scenario
envelopes, 486 traceable obligations, 81 stable error codes, and ten ordered
validation stages. It independently audits 58,520 systematic bit mutations and
7,303 proper-prefix truncations. Every executable rejection is compared as the
complete `(code, layer, stage)` result rather than by message text or a
precomputed expected-value shortcut.

## Canonical bytes, identity, and durable references

- Format v1 uses a strict deterministic-CBOR subset: definite containers,
  shortest integers and lengths, NFC scalar UTF-8 text, ordered unsigned schema
  keys, and no floats, tags, bignums, null-like values, duplicate keys,
  nonminimal encodings, invalid Unicode, or trailing bytes.
- Immutable ObjectIDs use the registered object kind and domain-separated
  SHA-256 preimage. Raw chunks and canonical metadata therefore have one
  reproducible identity rule across both languages.
- Binary and durable-text ObjectRefs bind format version, object kind, hash
  algorithm, and full digest. Parser shape/length faults, unsupported versions,
  wrong kinds, and declared-identity mismatches have frozen error precedence.
- Metadata decoding and encoding are bounded independently from semantic
  registry interpretation, so unsupported features may be scanned, hashed, and
  preserved without being treated as understood.

## Repository graph and FileID semantics

- Canonical objects cover chunks, content manifests, one-directory trees,
  change sets, asset groups, repository descriptors, snapshots, shelves,
  provenance, attestations, and conflict sets.
- Snapshot validation enforces one repository root, zero-to-eight ordered unique
  parents, parent-zero replay, complete declared closure, and cycle-safe graph
  behavior. Route-specific validators follow exactly the closure they promise;
  full candidate validation additionally authenticates every supplied object.
- Change replay verifies create, modify, copy, move, rename, delete, restore,
  group transitions, and merge resolution against exact before/after state.
- FileIDs are opaque nonzero 16-byte repository-scoped values. Native allocation
  uses operating-system entropy, bounded collision retries, and no path, time,
  counter, or deterministic fallback. Move and rename preserve identity; copy
  and create allocate; delete/recreate reuse and forged or cross-repository
  proofs fail closed.
- Lifetime and import validation authenticates prior mappings, repository
  binding, derived mapping keys, importer profile family/lifecycle, lost-ack
  retry, working additions, and unchanged caller state on rejection.
- Conflict, group, shelf, provenance, and candidate validators perform complete
  lower-layer reference discovery before registry or repository semantics. They
  rank combined-invalid inputs by the normative catalogue rather than traversal
  or insertion order.

## Streaming manifests, trees, and logical bundles

- `ContentManifestV1` verifies positive chunk lengths, checked logical sums,
  whole-file identity, profile authority, and ordered source bytes. Metadata is
  preflighted across the complete repeatable source before content callbacks;
  independent chunk failures are collected so later identity corruption cannot
  be hidden by an earlier semantic mismatch.
- Tree readers and ordered/sorted writers validate complete bounded entry sets,
  canonical basename order, kinds, modes, FileIDs, descriptor binding, path
  profiles, and content policy. FileID indexes are transactional, bounded as
  part of one aggregate working set, and reusable after an aborted attempt.
- Deep tree discovery uses explicit bounded work stacks. Caller-provided path
  validators and index adapters cannot run before closure and registry phases
  have succeeded.
- The logical-bundle sequence deterministically orders immutable objects,
  logical records, and roots; authenticates transcript/accounting/trailer data;
  validates supplied closure; and never claims repository completeness,
  authorization, projection, fidelity, generation, restoration, or import.
- Streaming bundle scanners charge cumulative active and retained canonical-map
  key captures, including transient replacement allocations. Nested keys can no
  longer amplify memory beyond the caller's configured ceiling.
- Stateful and convenience writers collect safely discoverable sequence,
  identity, schema, and lifecycle faults across each bounded section before
  selecting the frozen winner. Any rejected staging attempt is terminal and
  cannot later be committed as success.

## Registries and compatibility

- Twelve packaged registries freeze object kinds, fields, features, extensions,
  entry kinds, portable modes, hash algorithms, logical records, and profile
  assignments. The language-neutral registry-set digest is
  `6ca55f10d2cd20139e77a19ae0d297757a0f05b0acd3a3b38a6ee473e2bf84c6`.
- Loaders authenticate the complete same-handle byte set, exact additive
  schemas, immutable assignments, limits, family ownership, and lifecycle.
- Reserved entries cannot appear; conformance-only entries remain test-only;
  ratified entries are readable and writable; deprecated entries remain
  readable but cannot be selected for new production writes; removed IDs stay
  reserved.
- Unknown required features block semantics while canonical bytes remain
  preservable. Unknown optional extensions do not change base semantics and are
  retained by lossless paths.
- Registry and Unicode authority sync checks run for both distributed language
  packages and in the three-platform object-model workflow.

## Public tooling and package boundary

- The JavaScript package ships the `ogvcs-object` inspector/verifier CLI and the
  public OGVCS-001 fixture adapter. The adapter consumes all five packaged
  profile-v2 fixture corpora without source-tree imports or private service
  state, binds consumed bytes and target FileID state, and publishes no partial
  trusted result after a failure.
- Both language packages ship public metadata, repository, tree, manifest, and
  logical-bundle APIs. Rust exposes a scenario reporter and the same normative
  byte validation for every representable shared carrier; JavaScript-only rows
  are limited to the PRD-assigned fixture adapter plus JavaScript host-shape or
  raw carriers that Rust's closed public types cannot represent, such as
  Proxies, accessors, arbitrary kind maps, and unchecked unknown-kind writers.
  The Rust package documentation explicitly identifies its scenario reporter
  as conformance tooling rather than a second end-user CLI.
- Format, JavaScript, fixture, Rust crate, and offline-distribution packages all
  carry byte-identical MIT license text and matching package metadata.
- Packed checks install from retained local archives without network access,
  verify distribution manifests, compare public source and package behavior,
  and exclude generator/test internals from runtime authority.
- OGVCS-041 protocol generation now pins the exact repository-format manifest
  and registry-set digest, so negotiation cannot silently select a different
  object-model corpus.

## Security and resource behavior

- All public limits are capped by hard maxima and checked before unsafe reads,
  allocations, callbacks, or publication. Memory accounting includes retained
  decoded graphs, caches, iterator state, indexes, scratch runs, capture buffers,
  transient copies, and aggregate high-level working sets.
- Deadlines use monotonic operation-scoped guards. Memory/count/scratch failures
  roll back operation counters and newly retained cache entries, leaving the
  same lookup or scratch authority reusable when the normative recovery mode
  permits it.
- External-sort scratch data lives in private workspaces, binds same-handle file
  identity and whole-run digests, and rejects replacement between write and
  merge.
- Public JavaScript data boundaries accept only inert exact records and branded
  adapters where required; accessors, Proxies, sparse arrays, hostile iterables,
  and caller-controlled configuration cannot execute during schema preflight.
- Diagnostics expose stable codes, layers, stages, counts, and non-sensitive
  resource measurements. Payloads, paths, messages, raw IDs, extensions,
  credentials, and private repository state are excluded by default.

## Bounded validation result

The frozen language-neutral manifest is
`2d0acb01a01b64c23d883d855d2802d939a8dc99622f2774de07af1c8af8d2b9`.
The bounded JavaScript report executes 571 rows with two exact-scale inventory
rows, zero failures, and result SHA-256
`7eeb9091263530ac5f8703adb58de71f536d96f9a541f914b7b9f6e50864d153`.

Rust has 550 applicable rows: 548 executable and the same two exact-scale
inventory rows; 23 JavaScript-only fixture-adapter, host-shape, and
unrepresentable raw rows are explicitly not applicable.
The
[ratified package source `45d98fe`](https://github.com/n3r/OpenGameVCS/commit/45d98fe5adfff02e10745a0501123b30e56371bb)
runs under pinned Rust 1.82 and Node 22 on Linux, macOS, and Windows. The hosted
gate compiles, formats, lints, packages, and tests Rust; installs and tests the
JavaScript package; verifies reproducible offline distributions; executes both
reporters; and requires byte-identical shared results across all six platform
reports. Linux additionally rebuilds and runs the fixture, JavaScript, format,
and Rust archives in a clean offline consumer. That revision differs from the
exact implementation source only by the checked-in exact reports and
ratification-status prose.

The first fresh three-platform attempt exposed a Windows main-thread stack
overflow in the deep-tree semantic walk. That traversal now uses a
resource-charged explicit stack while preserving depth-first error order and
edge accounting. Subsequent attempts proved that two complete offline Cargo
builds exceed both five- and ten-minute Windows allowances without a semantic
failure. The completed workflow retains a finite fifteen-minute platform allowance
under the workflow's 45-minute outer deadline. Exact run, job, report, and
archive identities are recorded in the validation evidence packet.

## Exact-scale campaign and Rust manifest optimization

The first maintainer-authorized campaign completed in GitHub Actions
[run 32648023755](https://github.com/n3r/OpenGameVCS/actions/runs/32648023755)
at source revision `4af57563025af257ecb8eb6430908c862a3c9e4b`. Both
implementations produced byte-identical one-million-entry trees and logical
1-TiB manifests under the required resource ceilings; the retained comparison
result is `byte-identical-and-bounded`.

The exact shared identities are:

- tree payload SHA-256
  `2b13fa2c05a014ecc14a2d0e3db3adee5f828f9aa7e223c45357f3ac52d36681`;
- manifest payload SHA-256
  `18fb1ac61e4c4933181dd4e001df9f8fe3069bba145e5aec44d9c7eb75349cd6`;
- whole-file SHA-256
  `4bd995a40b5b50850812ae22899070b142b52f355f96aec8230ab39034135d09`;
  and
- chunk ObjectRef
  `ogvcs:v1:chunk:sha256:8d40b35dab2f8ff4305af64230cecf10c9c7616c2ca75e606ced44114aa9224a`.

The campaign exposed a performance asymmetry rather than a format or
correctness defect. JavaScript completed its exact phase in 38m12s and its
manifest in about 16m45s. Rust completed all tree work in about 2m34s but spent
about 3h01m in the manifest. The Rust path used the in-repository scalar
SHA-256 implementation, reread and rehashed the same 1 MiB chunk for all
1,048,576 occurrences, and processed it through 64 KiB callbacks. JavaScript
used Node/OpenSSL acceleration and a bounded verified-byte cache, so it read
and authenticated that immutable chunk once while still hashing every logical
byte into the whole-file digest.

The 2026-08-24 follow-up aligns the Rust hot path without changing canonical
bytes or validation semantics:

- `Sha256Writer` now uses exactly pinned RustCrypto `sha2` 0.10.9 with
  hardware SHA instructions and a portable fallback; non-Windows targets use
  its assembly backend while Windows uses the crate's runtime SHA-NI path;
- manifest verification admits a successfully authenticated chunk into a
  deterministic cache consuming at most half of the one configured memory
  ceiling;
- repeated ObjectRefs update the whole-file hash from verified bytes without
  another provider call, while insufficient-memory and unique-chunk workloads
  retain the streaming fallback; and
- cache candidates, retained entries, record estimates, and concurrent source
  slices are admitted before allocation, and invalid bytes are never cached.

A release-mode 16 GiB diagnostic on macOS arm64 sustained 2,077 MiB/s in 7.89s
with one provider read and guided the implementation, but it was not credited
as acceptance evidence. The
[exact implementation source `9d85d6e`](https://github.com/n3r/OpenGameVCS/commit/9d85d6ee959e47f8f65bca19c4ebb35687c39029)
was exercised by
[run 32714126083](https://github.com/n3r/OpenGameVCS/actions/runs/32714126083),
which executed the complete optimized workload. JavaScript completed its exact
step in 40m46s and manifest in 15m45.5s. Rust completed its exact step in
12m17s and manifest in 10m08.2s, with one authenticated provider read, while
still hashing all 1,048,576 logical occurrences. Both produced the unchanged
identities above and the comparator returned `byte-identical-and-bounded`.

The ratification/evidence revision passed ordinary three-OS
[run 32719990180](https://github.com/n3r/OpenGameVCS/actions/runs/32719990180),
including Rust 1.82 formatting/tests/clippy/package/offline proof, JavaScript
package and CLI checks, six-report comparison, and clean offline packed
consumers. Dependent protocol
[run 32719990210](https://github.com/n3r/OpenGameVCS/actions/runs/32719990210)
also passed its packed candidate and cross-platform comparison on all three
operating systems. The exact JavaScript, Rust, comparison, and machine completion
reports are checked into `docs/evidence/OGVCS-002/`; current packed archive
hashes are bound there as well.

GitHub workflow helper actions are pinned to immutable Node 24-compatible
releases, eliminating the hosted Node 20 deprecation fallback. Hosted JavaScript
conformance payloads run on Node 24, while published package engines retain the
Node 22 minimum.

Exact scale remains isolated in the release-only
`.github/workflows/object-model-scale.yml` workflow. It has no pull-request,
branch-push, or scheduled trigger and does not repeat the ordinary three-OS
matrix. Only an explicit manual dispatch or an `ogvcs-002-scale-*` release tag
can spend the million-entry/1-TiB build minutes. Manual dispatch additionally
requires the operator to enable `confirm_exact_scale`; leaving it false creates
no runner job.

JavaScript and Rust now execute as independent Linux jobs with no dependency
between them, so both exact workloads start together. Each job installs only
its own toolchain and uploads its language report immediately. The JavaScript
job does not install the root workspaces: its runner uses Node built-ins and
packs/installs the dependency-free public tarball itself. A small third job waits
for both artifacts, runs the byte/resource comparison, and publishes the
combined evidence. Each language job has a two-hour ceiling and the comparison
has a fifteen-minute ceiling. This changes campaign wall time from approximately
the sum of both implementations to approximately the slower implementation;
GitHub still bills the sum of both runners' active minutes.

## Rollout and rollback

Repository format v1 is ratified as the encoding and object-model contract.
Readers, schemas, registries, vectors, and both codec implementations are
version-controlled and independently reproducible. This does not promote
OGVCS-002 `*.test` profiles: they remain conformance-only, and production chunk
writing remains unavailable until OGVCS-007 supplies a ratified profile. A
defective writer or selected profile can be disabled without reinterpreting
existing objects; deprecated readers and immutable assignments remain
available. Any incompatible correction requires a new format version and
explicit migration preview, never an in-place assignment or preimage change.
