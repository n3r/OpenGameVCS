# OGVCS-015 private built-in text-merge kernel review

- **Review date:** 2026-09-02
- **Exact integration base:** `fc5f23509862b1c397687f6ea6d8e84613e636e3`
- **Ownership:** OGVCS-015-FR-04 and OGVCS-015-NFR-01
- **Disposition:** bounded private candidate; unpublished and unwired
- **PRD verdict:** OGVCS-015 remains Todo; AC-01 through AC-05 remain open

## Scope decision

OGVCS-015 explicitly owns a versioned three-way text algorithm, typed
clean/conflict/error outcomes, deterministic output digests, and replay
determinism. Its rollout starts with built-in text and keeps external drivers
disabled. The existing `core/history-diff/rust` crate is already the private,
`publish = false`, Rust 1.82 pure-computation owner for bounded OGVCS-015
kernels. A candidate-local built-in text module therefore has a clean owner and
does not require a public schema, route, workspace adapter, or mutation.

The tranche adds only `ogvcs.text-merge/line-diff3@1`. It does not select
repository content policy, read objects, authenticate or authorize a caller,
run an external executable, install a driver, create durable conflicts, write a
workspace, mutate a branch/reference, submit a snapshot, or implement revert.
Request-root authorization is not read, changed, or inferred.

No normative language-neutral OGVCS-015 merge vector exists yet. The algorithm
and limits below are consequently an explicitly private rc.1 candidate, not a
public contract. Any semantic change must use a new algorithm identifier.

## Input and provenance boundary

1. The caller supplies borrowed base/ours/theirs byte slices and claimed
   SHA-256 digests. All three digests are recomputed before retained line state.
2. The closed options require byte-exact whitespace and exact LF endings. Valid
   UTF-8, TAB, and LF are accepted. NUL, DEL, every other Unicode control,
   CRLF, bare CR, invalid UTF-8, and oversize input fail with typed errors.
3. Lines include their terminating LF when present. A final unterminated line
   is a distinct token, so final-newline state is preserved exactly.
4. The request commitment is domain-separated and binds algorithm tag, option
   tags, side order, exact input lengths, and the verified input digests.
5. This strict classifier prevents the candidate from synthesizing a merge for
   inputs outside its text profile. It is not evidence that a repository policy
   classified the content as text.

## Deterministic algorithm

- Each line is assigned a deterministic token from SHA-256 plus length, with
  exact byte comparison inside every matching bucket. A digest collision cannot
  silently make distinct lines equal.
- Base-to-ours and base-to-theirs use suffix LCS matrices. Equal LCS choices
  always delete from base first.
- Mixed replacement hunks are deterministically decomposed into line-aligned
  replacements followed by the remaining deletion or insertion. This freezes
  adjacent-edit and same-boundary behavior for version 1.
- Byte-identical ours/theirs, base/ours, and base/theirs shortcuts are exact.
  Disjoint and boundary-adjacent edits combine. Same-boundary insertions and
  overlapping ranges compare their complete candidate bytes: identical
  candidates apply once, while divergent candidates become typed conflicts.
- Clean output is never returned until its exact bytes, SHA-256, domain-
  separated output commitment, and final cancellation fence exist.
- Conflict output contains no file bytes or marker synthesis. It exposes only a
  bounded conflict kind, base line span, and base/ours/theirs fragment line
  counts, byte counts, and SHA-256 digests. The ordered set has its own
  domain-separated commitment bound to the request commitment.

## Literal resource closure

The implementation has no caller-inflatable resource configuration. These
literal maxima are compiled into rc.1:

| Resource | Maximum |
|---|---:|
| bytes per input | 1,048,576 |
| aggregate input bytes | 3,145,728 |
| lines per input | 4,096 |
| bytes per exact line | 65,536 |
| cells per LCS matrix | 263,169 |
| charged work units | 24,000,000 |
| clean output bytes | 3,145,728 |
| conflict spans | 128 |
| admitted peak retained memory | 12,582,912 bytes |

Input length, UTF-8/text profile, line count, exact line length, both LCS cell
products, worst script capacity, token capacity, matrix bytes, candidate-pair
bytes, output capacity, conflict capacity, and conservative retained-memory
peak are checked with overflow-safe arithmetic before the corresponding
allocation. Matrix rows, edit traversal, fragment copies/hashes, and output
hashing consume checked work and periodic cancellation fences. Failure or
cancellation drops all internal partial state and returns no outcome carrier.

The memory ledger is a conservative admission model, not allocator/RSS
measurement. It includes fixed state and capacities for retained indices,
tokens, both scripts, the larger matrix, maximum conflict vector, clean output,
and both transient conflict candidates. Borrowed input storage, allocator
metadata, caller-retained clones, and stack hashing state are documented
exclusions.

## Verification inventory

The focused suite covers:

- base-equals-ours, base-equals-theirs, and ours-equals-theirs shortcuts;
- identical overlap, identical and divergent same-boundary insertion,
  adjacent edits, and delete/modify conflict;
- exact final-newline preservation and Unicode text;
- invalid UTF-8, ASCII/Unicode controls, NUL, CRLF, and bare CR;
- input-digest substitution and input/line/line-count/LCS max and next-value
  rejection;
- cancellation during validation, indexing, tokenization, each LCS pass,
  combination, and finalization;
- deterministic generated replay and independent JSON clean/conflict golden
  commitments; and
- the existing packed fresh-consumer, format, warnings-denied Clippy, policy,
  and roadmap gates.

Frozen verification on the exact base plus this tranche is clean: Rust 1.82
passes 52/52 tests in debug, 52/52 in release, and 52/52 after extracting the
20-file packaged crate into a fresh consumer; format and warnings-denied Clippy
pass; the Node private-boundary policy passes 2/2; and roadmap validation passes
with 46 PRDs (39 Todo, 7 Done) plus 8/8 validator tests. No database, network,
external driver, dispatch, branch/workspace mutation, submit, or revert test was
run or claimed.

## Residuals and nonclaims

- OGVCS-006/009 still own authorized repository reads, hidden-path/history
  non-disclosure, and any public service view. This pure function is not an
  authorization brand.
- OGVCS-003 and later OGVCS-015 work still own external-driver manifests,
  allowlisting, signatures, sandbox execution, and driver error normalization.
  No executable or process API is present here.
- Repository text/binary/semantic policy selection and explicit binary
  choose-one behavior remain unimplemented. Passing bytes to this kernel is not
  a policy proof.
- Conflict durability, restart/checkpoint behavior, resolution records,
  submit blocking, sparse preflight, merge-base, FileID/sidecar semantics,
  branch merge submission, and revert remain unimplemented.
- This line-oriented candidate does not claim token-aware/language-aware merge,
  minimal conflict regions for every repeated-line corpus, scale, latency, or
  production rollout.
- The independent golden freezes this private version only; it is not a
  normative public vector and does not close OGVCS-015-AC-05, which also
  requires external-driver sandbox evidence.

Consequently OGVCS-015 remains Todo and every acceptance criterion remains
open.
