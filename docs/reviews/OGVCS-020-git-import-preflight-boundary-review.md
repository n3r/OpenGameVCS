# OGVCS-020 private Git import preflight boundary review

**Review date:** 2026-09-02
**Reviewed slice:** `core/import-git-lfs/rust` private `0.1.0-rc.1` candidate
**PRD state:** Todo; OGVCS-020-AC-01 through OGVCS-020-AC-07 remain open

## Decision

The bounded candidate is suitable to retain as private, unpublished,
read-only preflight work. It is not suitable to wire into an import command,
service, broker, sandbox profile, persistence layer, or publication path.
`ImportPreflightReport::ready` is deliberately local to the supplied
projection and must not be treated as permission or proof that an import is
safe or faithful.

## Boundary and composition

The kernel accepts three caller-owned traits: a canonical ordered source
projection, a random-access staged LFS content source, and an OGVCS-002 mapping
authority. It performs no I/O. The three independently declared generations
are checked at entry, around relevant external calls, and at EOF. Exact counts,
modeled bytes, and a domain-separated inventory transcript are reconciled only
after every record reaches EOF.

The mapping seam composes OGVCS-002 types without defining another FileID or
mapping key. Every non-gitlink entry occurrence has a `(Git object ID, target
path digest)` commitment and exactly one mapping request; identical blob
content reused at two paths receives distinct FileIDs. The authority method is
an immutable, explicitly side-effect-free lookup over a pinned view. A future
production adapter would have to establish the source-identity tuple, invoke
`validate_import_request` in an authorized layer, and separately persist any
reservation. The candidate checks only a supplied decision, binds it into an
in-memory plan, and emits no mutation. Tests use the fixture-only
`importer.test/fixture-adapter@1` profile.

There is intentionally no derivation or authentication relationship between
`SourceOccurrence` and `ImportRequest::source_identity_digest`. Both are bound
into the mapping/report transcripts, so substitution changes the digest, but a
caller can supply an arbitrary nonzero association. `ready` does not attest
that association. Defining and authenticating the source identity tuple remains
future integration work.

Target path validation and repository/platform collision keys come from
OGVCS-004. The kernel hashes proposed paths before retaining findings. Its
mode booleans classify local blockers only; they are not transformation
definitions. Git LFS extensions always remain blockers because this slice has
no reversal executor. A future versioned policy format must replace this
private typed policy before any conversion integration.

## Git LFS review

Pointer classification follows the official canonical v1 encoding: exact
version string, UTF-8, LF, one space, ordered keys, lowercase SHA-256, canonical
positive signed-64-bit size, one-digit unique extension priorities, the
reference `\w+` name prefix with preserved case/underscore/unanchored suffix,
extension OIDs, and `<1024` total bytes. The global key splitter does not apply
a narrower lowercase filter before extension parsing. Empty content is
ordinary pass-through. Legacy version aliases
and other readable-but-noncanonical forms are rejected. Inputs at or above the
official 1024-byte blob cutoff are unconditionally ordinary `NotPointer`
content, including oversized prose/binary data with an interior marker;
preflight represents them with an empty bounded probe. Malformed advertised
short Git LFS content and nonempty `Required` nonpointers are terminal only at
regular/executable occurrences explicitly declared `Required`. `Ordinary`
occurrences preserve their exact Git bytes even when those bytes are a
canonical pointer. Symlinks are always ordinary and a `Required` symlink is a
source-contract violation: Git's checkout implementation reads the symlink
target blob directly and confines working-tree conversion to its regular-file
arm. The
advertisement matcher is limited to the upstream `git-lfs`, `git-media`, and
`hawser` markers; generic `version 1.0` text is ordinary content. These rules
prevent pointer-text substitution; the official empty-file pass-through
remains valid.

`LfsDisposition` is a caller-supplied, transcript-bound claim. This slice does
not parse or authenticate `.gitattributes`; therefore `ready` does not attest
that ordinary/tracked classification is faithful. A shared Git blob can be
ordinary at one path and LFS-tracked at another, and the per-occurrence result
preserves that distinction while object-byte verification remains deduplicated.

The staged content verifier issues bounded reads, checks progress and EOF,
rejects a source that overreports its buffer, verifies exact length and digest,
and deduplicates shared OIDs only after size agreement. Missing, ambiguous,
short, long, corrupt, source-failure, cancellation, and generation-drift paths
return no report. Extension objects are verified in their stored/final form,
but extension reversal is neither executed nor claimed.

## Resource and atomicity review

All configured limits are nonzero where required and capped by hard ceilings,
including a literal 64,000,000-unit work ceiling. Expected category/subset
invariants, declared totals, and known minimum work are admitted before any
source or generation call. Zero generations/digests reserved as sentinels are
rejected. Raw ref/path/probe length and capacity are validated before hashing
or key cloning; the predecessor `ProfileRef` is normalized from its bounded
visible text before retention so hidden spare capacity is discarded.
Record counts, declared graph/tree relationships, Git bytes, typed input bytes,
unique/per-object/cumulative LFS bytes, mapping/finding counts, work, path/ref
bytes, read chunks, and conservative retained memory are checked. Exact-limit
and max-plus-one regressions cover the major ledgers. Arithmetic is checked.

The kernel distinguishes unique Git blob objects from path entry occurrences,
charges blob bytes/pointer classification once per object, requires consistent
metadata on repeated OIDs, and never treats gitlinks as blob/LFS content. EOF
mapping scans, temporary collection, finding sorting, and report hashing are
work-charged with cancellation fences. The full report digest binds limits,
measured work, peak retention, entries, mappings, findings, and all three
generations. A final cancellation/generation fence runs immediately before
return. Terminal errors expose no entry plan or mapping plan. The retained
ledger includes returned-record capacities while owned by the kernel, but is
not an allocator/RSS measurement and excludes separate adapter-owned buffers
and caller copies.

The hardening review closed these candidate defects with regressions: oversized
ordinary blobs falsely classified from interior LFS markers; same-OID path
occurrences collapsed into one mapping; over/under/duplicate occurrence
mapping; null typed Git IDs; retry FileID and new-state mismatches; late raw
field validation; missing-finding allocation precedence; impossible expected
inventory declarations entering the source; uncharged EOF/report work; broad
report-digest claims; raw record debug exposure; over-narrow extension names;
generic version-text false positives; symlink pointer substitution; and
canonical pointer-looking ordinary-path substitution.

## Residual risks and required future work

- No Git pack/compressed-loose-object/archive parser or Git object hashing
  exists. A later private decoder validates one caller-supplied inflated tree
  frame and is reviewed separately in
  [OGVCS-020-git-tree-frame-boundary-review.md](OGVCS-020-git-tree-frame-boundary-review.md),
  but it is not wired to this projection. The adapter can still omit or
  misdescribe refs, reachability, parent order, tree associations,
  `.gitattributes`, identities, timestamps, encodings, or modes. The supplied
  LFS disposition is not authenticated attribute evidence.
- No selected-ref policy, commit DAG preservation, merge/empty-commit policy,
  tag/remote-ref policy, or source Git-ID lookup metadata exists.
- Proposed entries are a bounded target projection, not a complete historical
  tree model. Rename/copy/move/delete/recreate identity remains unresolved.
- Source identity digests remain opaque adapter claims. Only OGVCS-002 can
  authorize allocation/retry, and no mapping is durable in this slice.
- No broker, remote LFS fetch, credentials, OGVCS-045 sandbox/canary evidence,
  immutable staged-input format, decompression limits, or parser isolation
  exists.
- No conversion, target tree/snapshot/root, isolated staging namespace,
  OGVCS-017 pass, checkpoint/resume, atomic publish, rollback, or telemetry
  exists. There is no source-tip-to-target reconciliation.
- No golden repository conversion, kill/resume matrix, independent operator
  reproduction, malicious pack corpus, hosted deployment, large-history run,
  performance budget, or scale evidence exists.

Those residuals keep OGVCS-020 Todo and every acceptance criterion open. This
review must be repeated if the crate gains any I/O, production profile,
serialization, authorization meaning, persistence, conversion, or wiring.

Pinned GitHub Actions run
[33638102757](https://github.com/n3r/OpenGameVCS/actions/runs/33638102757)
passed the original private preflight gate on all three operating systems.
Follow-on [run 33664922211](https://github.com/n3r/OpenGameVCS/actions/runs/33664922211)
passed the expanded preflight plus strict tree-frame source/package gate on
Linux, macOS, and Windows for exact revision
`fa61786b272a019b82f4e96eaaa47dbef60c5b6c`. The retained
[machine records](../evidence/OGVCS-020/README.md) bind both results to their
exact source boundaries. This is source-portability evidence only; it is not a
converted repository, authenticated import journey, scale result, or
acceptance evidence.

Normative sources reviewed for this boundary are Git's official
[`gitdatamodel`](https://git-scm.com/docs/gitdatamodel.html) documentation
(blobs are reusable content objects; mode `160000` gitlinks name commits),
[`gitattributes`](https://git-scm.com/docs/gitattributes) documentation, and
checkout [`entry.c`](https://github.com/git/git/blob/master/entry.c)
(conversion is performed only in the regular-file arm), together with
the official Git LFS [`docs/spec.md`](https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md),
[`lfs/pointer.go`](https://github.com/git-lfs/git-lfs/blob/main/lfs/pointer.go),
and [`docs/extensions.md`](https://github.com/git-lfs/git-lfs/blob/main/docs/extensions.md).
