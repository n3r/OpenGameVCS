# OGVCS-007 production-profile ratification review

**Date:** 2026-08-30

**Reviewed source:** `3e2da7415028ed6f444c3c7301c756ec6cdc0dd5`

**Profile:** `chunking.opengamevcs/gear-fastcdc-1m@1`

**Verdict:** Blocked; retain Proposed/candidate/conformance-only status

## Decision

The identity-affecting tuple in ADR-0016 is coherent and the current bounded
golden corpus gives useful candidate evidence. It is not safe to add the tuple
to the OGVCS-002 registry as `ratified` or enable production writes yet.

The blocking distinction is not whether the two scalar loops can reproduce the
nine checked-in manifests. A ratified registry row says that a new production
manifest carrying this `ProfileRef` has the profile's boundary semantics. The
current public production-write boundary can prove the OGVCS-002 container,
ChunkIDs, lengths, and whole-file digest, but no production route invokes the
additional OGVCS-007 boundary verifier required by ADR-0016. The candidate also
lacks the benchmark authority that ADR-0016 names as a precondition to
ratification.

This review therefore makes no registry, profile-state, ADR-status, generated
authority, predecessor-pin, package-workspace, lockfile, roadmap, or PRD-status
change. The exact tuple and its vectors remain available for read-before-write
implementation work.

The 100 GiB acceptance campaign remains intentionally deferred to the final
OGVCS-007 acceptance/release gate. It was not run for this review and is not the
reason an ordinary pull request is blocked. The findings below are all
reproducible with bounded inputs.

## Authorities inspected

- OGVCS-002 FR-12/FR-13, NFR-01/NFR-04, AC-09/AC-11 and ADR-0010's lifecycle
  split between structural format validation and owner-defined chunk semantics.
- OGVCS-005 FR-01/FR-02/FR-07/FR-09 and its authenticated, tiered result
  authority.
- OGVCS-007 FR-01 through FR-08, NFR-01 through NFR-03, AC-01 through AC-05.
- Proposed ADR-0016, the data-only contract, independent reference generator and
  validator, all golden/malformed/fragmentation vectors, both scalar sources,
  and both runtime test suites.
- The OGVCS-002 profile registry and its JavaScript/Rust packaged copies, plus
  repository, metadata, protocol, and benchmark predecessor pins.

## Positive evidence retained

- The Gear table is independently derivable and its published digest is
  `76065028f30c5ec5c038c7f0849b0e1ac863474a5cf01ecf383fd431b576da82`.
- The recurrence, reset rule, 256 KiB/1 MiB/2 MiB thresholds, early/late masks,
  exact-target mask selection, forced maximum, final suffix, whole-file digest,
  ChunkID preimage, and manifest encoding are unambiguous in ADR-0016.
- The data-only contract regenerates and independently validates all nine
  golden cases. The corpus includes empty, maximum small, natural early/late,
  forced-maximum, final-suffix, repeated-byte, multi-chunk, and insertion cases.
- JavaScript's 32-bit-half recurrence matches a separate BigInt oracle for
  200,000 deterministic steps. Its public scalar path matches every golden and
  is invariant under one-byte, prime-cycle, and boundary-adjacent fragments.
- The existing insertion pair preserves five of six chunks after a 17-byte
  insertion: 4,303,655 of 5,242,897 post-insertion bytes are represented by
  unchanged ChunkIDs. This is useful resynchronization evidence, but not the
  required multi-workload benchmark authority.
- A bounded 64 MiB deterministic exploratory source completed as 54 chunks
  (average 1,242,756.74 bytes; minimum 380,403; maximum 2,097,152). This is a
  smoke observation only, not a retained performance or resource claim.

## Blocking findings

### P0-1: a registry-only promotion authorizes false Gear manifests

ADR-0016 requires both OGVCS-002 structural/content verification and OGVCS-007
profile-boundary verification before claiming the production profile. The
candidate exposes chunk generation only. Its own vector guide explicitly says
that runtime verification of boundary, chunk-digest, and manifest mutations is
deferred to a later cut.

The gap is observable at the production-write boundary, not merely missing test
coverage. A bounded reproduction performed the following:

1. materialized 3 MiB of zero bytes;
2. cloned the bundled registry in memory and added the proposed tuple as
   `family: chunking`, `state: ratified`, and `productionWriteAllowed: true`;
3. calculated correct OGVCS-002 ChunkIDs and the correct whole-file digest, but
   declared arbitrary chunk ends at 1 MiB and 3 MiB; and
4. called the public OGVCS-002 manifest writer with `operation:
   production-write`.

The true Gear ends were `[2097152, 3145728]`. The arbitrary ends were
`[1048576, 3145728]`. The production writer accepted the latter and emitted
manifest ObjectID
`ogvcs:v1:content-manifest:sha256:41a1d8238b99cae9b6919a9543a8b1060a93a6850ea874c5176ba18965983fa5`.

That behavior is correct for the generic OGVCS-002 structural writer, which
does not own the Gear recurrence. It makes a registry-only promotion unsafe:
there is currently no owner verifier or bound verification receipt at the trust
boundary to make the additional semantic claim true.

Required closure:

- publish a bounded streaming OGVCS-007 verifier in JavaScript and Rust;
- validate the manifest through OGVCS-002 first, then stream the same ordered
  bytes through the Gear recurrence and compare every end including the suffix;
- bind server acceptance and every production emitter to an exact
  profile-verifier version/receipt, failing closed if it is absent or mismatched;
- execute boundary shift, chunk corruption, manifest corruption, short/extra
  delivery, wrong length, wrong profile/version, repeated-reference, and
  conflicting duplicate-metadata cases through that public boundary; and
- prove the arbitrary-boundary reproduction above is rejected as
  `CHUNK_BOUNDARY_MISMATCH` before any trusted publication.

### P0-2: the required authenticated selection benchmark does not exist

ADR-0016 keeps production writes disabled until OGVCS-007 FR-08/AC-04 evidence
passes. No OGVCS-007 evidence packet, benchmark profile, threshold file, or
authenticated OGVCS-005-compatible report exists in this source.

The two insertion vectors cannot substitute for the gate. The required report
must separate source-like, structured, already-compressed, encrypted/random,
insertion, replacement, and append workloads and record observed throughput,
peak memory, chunk count/manifest cost, resynchronization distance, and exact
logical/unique/reused/new bytes. It must never infer savings from a nominal
ratio. Compressed and random inputs are expected to report poor reuse honestly.

Required closure is a bounded ordinary benchmark corpus and authenticated
OGVCS-005 result bundle covering all seven workload classes. The later 100 GiB
resource run remains a scheduled final/release job, not a per-PR prerequisite
for developing this bounded report.

### P0-3: there is no read-before-write reconstruction path

The public JavaScript and Rust packages expose chunk generation, but not the
PRD's `verify`, `reconstruct`, `compare`, or cache-key interfaces. Neither can
reconstruct from shuffled delivery, accept repeated ordered references without
confusing them with duplicate delivery, reject conflicting index metadata, or
atomically publish only after chunk and final-file verification.

Consequently AC-02 is not executable and ADR-0016's required read-before-write
rollout cannot start. A production writer cannot safely be enabled before a
reader/verifier is deployed and proven against the same immutable tuple.

Required closure is a bounded reconstruction API in both implementations that
uses a caller-supplied chunk lookup/sink, verifies each delivered object against
the requested ChunkID and declared length, verifies the final digest and Gear
ends, and commits through the OGVCS-046 staged publication boundary only after
all checks succeed. Failure must leave no trusted workspace output.

## Major findings

### P1-1: the advertised scalar memory admission omits retained engine state

Both implementations admit the operation at 4,259,840 bytes, then retain every
boundary and every part in in-memory arrays/vectors until finish. JavaScript
retains `parts` and `boundaries`; Rust retains `Vec<ChunkPart>` and
`Vec<u64>`, including a heap `String` per part. Manifest construction adds
another complete part projection. This state grows with file length up to the
1,048,576-part format ceiling and is not charged to `maxWorkingMemoryBytes`.

ADR-0016 permits a separately bounded disk-backed ordered ledger; neither
implementation supplies one or exposes a ledger/scratch budget. The current
admission check therefore proves only current-chunk capacity, not FR-03 or the
declared operation budget.

Required closure is a bounded ordered ledger with explicit memory/scratch
admission, checked count and byte accounting, transactional cleanup, deadline
and cancellation handling, and tests that cross each configured bound without
returning a trusted manifest.

### P1-2: independent Rust and cross-platform proof is absent

The Rust source is plausibly independent and consumes the same language-neutral
vectors, but this checkout has no chunking workflow, retained Rust report,
packed/offline consumer, or three-OS comparison. Rust tooling was unavailable
in the review environment, so the Rust tests were inspected but not compiled.
The JavaScript path was executed only on the local macOS host.

Before ratification, a bounded Linux/macOS/Windows workflow must pin Rust 1.82
and the supported Node runtime, run format/test/clippy, run both packed offline
consumers, emit one canonical parity report per implementation, and compare
table digest, constants, boundaries, ChunkIDs, manifest bytes/IDs, stable error
codes, and bounded resource outcomes. It must not schedule 100 GiB or 1 TiB
work in ordinary pull requests.

### P1-3: malformed/error authority is descriptive rather than executable

The malformed corpus declares 11 cases, but the runtime tests do not dispatch
the corpus. In particular, all three `verify` rows are reserved outcomes for an
unimplemented API. The local error registry also omits codes the JavaScript
runtime can emit, including sink/session and invalid/unsupported resource
states. Rust exposes enum variants rather than the same stable string/result
surface.

Required closure is one generated error registry used by both implementations,
an exhaustive static parity gate from registry to public error surface, and a
black-box runner that executes every malformed row in both languages with the
same result class and no trusted partial output.

### P1-4: reuse accounting cannot substantiate NFR-03

No public comparison function consumes a known-chunk index and reports logical,
unique, reused, and newly required bytes. There is no explicit rule for counting
repeated ordered references, distinguishing unique storage from occurrence
bytes, or rejecting one ChunkID associated with conflicting length/content
metadata. Without this API the benchmark cannot prove that claimed savings are
observed.

Required closure is a language-neutral comparison contract, matching public
implementations, exact accounting vectors (including repeated references and
digest collisions represented as hostile metadata), and reconciliation between
the comparison result and every benchmark sample.

## Bounded test additions required before re-review

These tests do not change the profile tuple and do not require a large campaign:

- deterministic property seeds over empty, 1, 262143, 262144, 262145, and
  pseudorandom lengths through a bounded multi-MiB ceiling;
- exact minimum/target/maximum predicate edges, including a target-byte case
  that distinguishes the early and late masks;
- reconstruction after deterministic shuffled delivery, repeated ordered
  ChunkIDs, missing delivery, short/long delivery, bit flips at first/middle/
  last bytes, and conflicting duplicate index metadata;
- fragmentation equivalence across empty updates, one-byte updates, primes,
  every cut minus/at/plus one, and one maximum-sized input fragment;
- deterministic mutation/property loops proving that changed bytes either fail
  or change authenticated identity and never publish partial output;
- configured memory, scratch, count, cancellation, deadline, and sink-failure
  boundaries with post-failure session poisoning/cleanup; and
- one generated cross-language parity record so constant, error, result, and
  vector drift cannot hide behind two separately green suites.

## Requirement status at this revision

| Requirement | Status | Review result |
|---|---|---|
| FR-01 | Candidate pass | Tuple and ChunkID preimage are exact, but not ratified. |
| FR-02 | Candidate pass | Golden manifest bytes match; emitters are conformance-only/bypass lifecycle. |
| FR-03 | Fail | No reconstruction path or bounded ledger; memory admission omits retained parts. |
| FR-04 | Partial | Whole-file threshold exists; common verification contract does not. |
| FR-05 | Fail | No reconstruction or verified atomic publication. |
| FR-06 | Fail | No compare/known-index API. |
| FR-07 | Fail | Verifier, duplicate-delivery, overflow, count, and complete error execution are absent. |
| FR-08 | Fail | No seven-class authenticated benchmark report. |
| NFR-01 | Partial | Oracle/JavaScript pass locally; Rust and platform comparison are not retained. |
| NFR-02 | Fail/deferred | Ledger is unbudgeted; the scheduled 100 GiB measurement remains final-gate work. |
| NFR-03 | Fail | No observed-savings comparison boundary. |
| AC-01 | Partial | Shared goldens exist; independent compiled/packed retained comparison does not. |
| AC-02 | Fail | No shuffled reconstruction or corruption/truncation rejection path. |
| AC-03 | Deferred | Correctly excluded from ordinary PR work; must run at the final/release gate. |
| AC-04 | Partial | One insertion pair resynchronizes; required workload/report authority is absent. |
| AC-05 | Fail | No runtime verifier or deterministic fuzz/property suite. |

## Safe ratification sequence after closure

1. Land the verifier/reconstruction/compare APIs, bounded ledger, generated
   error surface, hostile/property corpus, and bounded cross-language workflow
   while the profile remains candidate/conformance-only.
2. Publish and authenticate the bounded seven-class OGVCS-005 report. Perform an
   independent review of its measurements and the production trust boundary.
3. Deploy/read-test the exact profile verifier before enabling any writer.
4. Accept ADR-0016 without changing its tuple; update the data-only profile
   lifecycle and add exactly one OGVCS-007 `chunking` registry entry with
   production-write eligibility.
5. Regenerate the OGVCS-002 vector authority and synchronize both packaged
   registries. Then refresh repository pins in OGVCS-006 metadata, OGVCS-041
   protocol, and OGVCS-005 benchmark authorities in dependency order. Re-run
   ordinary packed/offline and three-OS comparisons after each generated
   boundary.
6. Roll out the writer behind a reversible production-write switch. Rollback
   disables new writes but retains the registry assignment, verifier, vectors,
   and readers permanently.
7. Run the separate 100 GiB resource campaign only at the agreed final/major-
   release gate before OGVCS-007 can be considered Done.

## Review commands and outcomes

From the isolated review worktree:

```text
npm run test:chunking:spec
  pass: 2/2 contract tests; 9 golden cases; generated authority current

npm run test:chunking:js
  pass: 4/4 runtime tests; all current goldens and fragmentation rows

bounded 3 MiB simulated-ratification reproduction
  true Gear ends:       [2097152, 3145728]
  accepted false ends:  [1048576, 3145728]
  production accepted:  true

bounded 64 MiB deterministic smoke
  chunks: 54; average: 1242756.74; min: 380403; max: 2097152

Rust compile/test
  not run: cargo/rustc unavailable in the review environment
```

No exact-scale, 100 GiB, or 1 TiB campaign was run.

## First bounded closure tranche (2026-08-30)

The additive implementation following this review closes the code-level parts
of P0-1, P0-3, P1-1, P1-3, and P1-4 without changing the verdict or lifecycle:

- JavaScript and Rust now expose public verify, reconstruct, and compare APIs.
  Both perform OGVCS-002 framing and known-schema validation before checking the
  exact Gear candidate. They validate ordered occurrence length/ChunkID,
  whole-file digest, and every derived boundary; Gear mismatch is reported only
  after generic content checks succeed.
- Reconstruction is caller-transactional: fragments are staged, commit occurs
  only after all checks, and every post-write failure calls abort. Deterministic
  corruption tests assert zero commits and cleared staged output.
- Repeated references are read once per occurrence. A bounded exact index
  rejects one ChunkID paired with conflicting lengths and reports logical,
  unique, repeated, reused, and newly required bytes without estimates.
- Generation and reading use a fixed 48-byte record ledger with separately
  capped memory/scratch tiers and private scratch cleanup. JavaScript exposes
  explicit abandonment cleanup; Rust owns cleanup through `Drop`.
- The complete malformed inventory is executed in both language test runners.
  `registries/errors.json` is generated from the contract model, and exhaustive
  static gates compare it with both public runtime surfaces.
- Deterministic golden, property, fragmentation, reconstruction, mutation,
  repeated-reference, conflicting-metadata, spill, exhaustion, and cleanup
  tests were added. No large campaign was run.
- A path-scoped bounded workflow runs JavaScript and Rust as parallel
  Linux/macOS/Windows matrices, emits canonical nine-case reports, and compares
  them per platform. It pins Node 24 and Rust 1.82 and contains no scale trigger.

Local JavaScript/spec verification passes. The local host still has no Rust
toolchain, so the Rust source remains compile-plausible pending the added CI
matrix; workflow success is required before treating Rust/cross-platform proof
as closed.

At that checkpoint the profile remained Proposed/candidate/conformance-only.
Bounded ratification still required the authenticated seven-class OGVCS-005
selection report, compiled three-OS/packed proof, and production trust-boundary
receipt/version binding. The separately scheduled final resource campaign is an
OGVCS-007 completion/release gate, not a prerequisite for bounded profile
ratification.

## No-cherry follow-up to the first tranche (2026-08-30)

Independent review correctly rejected the first tranche for integration. A
Rust `ChunkSource` could ignore a failed consumer callback, return success, and
allow reconstruction to continue toward commit. Reconstruction in both
languages also aborted only after a successful write, leaving missing-first-
chunk and empty commit failures outside the transaction cleanup rule.

The follow-up makes consumer failure sticky in Rust and adds a provider that
deliberately swallows a failed publication write. The regression proves one
write attempt, zero commits, and exactly one abort. Both languages now open the
publication transaction after manifest admission and abort exactly once on
every subsequent pre-commit failure, including missing first chunk and empty
commit failure. Abort failure cannot mask the primary generated result.

JavaScript callback, provider, known-index, iterator-factory, iterator-next,
hash/writer, and publication failures are normalized through the exact
generated 22-code authority; objects that merely spoof a `CHUNK_*` property are
not trusted. Public cancellation/deadline controls and the ADR-frozen shared
chunk-cache key are implemented in both languages. The JavaScript
`createChunker` result default is restored to retained boundary/part arrays for
version compatibility; bounded callers opt out explicitly.

Rust scratch now uses 128 bits of OS entropy, an owner-private directory and
file mode on Unix, symlink-rejecting root admission, and cleanup assertions.
The signed negative malformed row now enters the public `Chunker::new_checked`
API rather than being synthesized in its test adapter. A package-local
`Cargo.lock` is present.

The bounded parity record now compares the Gear-table digest, profile and
limits, all 22 error codes, every boundary, ChunkID/length/cache key, manifest
bytes/ObjectID, whole digest, provider reads, exact repeated/unique accounting,
and deterministic resource-admission outcomes. JavaScript proves an offline
install from both packed tarballs. Rust's workflow runs `cargo fmt`, locked
test/clippy, and offline `cargo package` verification for both packed crates;
the unpublished local object-model dependency is supplied through an explicit
package-only Cargo patch.

Local bounded results after the follow-up are JavaScript 19/19 tests, Rust
12/12 tests plus doc tests, matching nine-case reports, successful offline npm
packed-consumer execution, and successful offline Cargo package verification.
The Linux and Windows legs remain CI evidence, not a local claim. No 100 GiB,
1 TiB, or exact-scale campaign was run. This closes the no-cherry code/package
findings but does not change the original ratification verdict or any lifecycle
state.

## Bounded publication-receipt follow-up (2026-08-30)

The JavaScript package now composes reconstruction with the completed OGVCS-046
bounded publication boundary. Full content and Gear verification issues a
private one-use receipt bound to the registered verifier version, profile,
manifest ObjectID and SHA-256, logical length, and whole-file SHA-256.
`reconstructManifestToWorkspace` streams verified bytes through a one-slot
rendezvous into `atomicWriteStream`; the filesystem adapter consumes the receipt
before publication and returns the bound workspace publication receipt.

Independent hostile review rejected two intermediate implementations. The
landed follow-ups close unbounded buffering, dropped terminal errors, eager
writer startup, duplicate manifest parsing, caller-supplied verifier binding,
post-commit cancellation ambiguity, unhandled writer rejection, and reentrant
receipt consumption. Deterministic regressions prove that pre-commit
cancellation rolls back, post-durable-commit cancellation returns success,
wrong/reused receipts cannot publish, writer errors remain sticky, and temporary
workspace roots are removed.

This closes P0-1 and P0-3 at the bounded source/API boundary without ratifying
the profile. The retained seven-workload report remains provisional: P0-2 still
requires an authenticated OGVCS-005 result bundle/verifier with observed
whole-process peak memory. Bounded current-source JavaScript/Rust proof is
retained from all three hosted operating systems; registry/predecessor-pin
regeneration and the separately scheduled final 100-GiB campaign remain outside
this source-level follow-up.

## Current bounded status (2026-08-30)

The current bounded contract passes 3/3 tests, the JavaScript package passes
32/32 tests, and the report/evidence tools pass 6/6 tests. Rust retains 12
source tests and passed the Node 24/Rust 1.82 Linux, macOS, and Windows workflow
in [run 33328072458](https://github.com/n3r/OpenGameVCS/actions/runs/33328072458),
whose six reports matched all nine bounded cases.

P0-1 and P0-3 are closed at the package/API boundary. P0-1 still requires a
production acceptor/emitter to consume the private verification receipt before
writes can be enabled. P0-2 remains open until the seven workloads are published
and verified through OGVCS-005 with same-run observed whole-process peak memory.
The 100-GiB campaign remains deferred to final OGVCS-007 completion/release and
is not part of the bounded profile-ratification cut.
