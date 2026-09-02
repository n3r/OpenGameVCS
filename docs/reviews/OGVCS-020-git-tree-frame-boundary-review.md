# OGVCS-020 private inflated Git tree-frame boundary review

- **Review date:** 2026-09-02
- **Exact integration base:** `9b2e4ce18b0d246ee5a84b946686e670a68a01fa`
- **Reviewed slice:** `core/import-git-lfs/rust` private tree-frame decoder
- **Disposition:** bounded candidate; unpublished, unwired, and not an import authority
- **PRD verdict:** OGVCS-020 remains Todo; AC-01 through AC-07 remain open

## Scope decision

The existing preflight consumes a caller-supplied projection and therefore
cannot establish that a projected tree matches Git bytes. Git's inflated tree
framing and entry ordering are stable source-format facts that can be decoded
without choosing target transformation, authorization, publication, or
deployment policy. A private single-frame decoder is consequently a safe
additive foundation for OGVCS-020-FR-01, OGVCS-020-FR-03, and
OGVCS-020-NFR-02.

The tranche implements only `ogvcs.git-tree-frame/strict@1`. It is not wired to
`preflight_git_import`, an OGVCS-045 worker, a broker, a public command, or a
service route. It performs no request-root authorization, credential access,
filesystem or network I/O, process execution, automatic sandbox cleanup,
mapping allocation, target conversion, persistence, or publication.

## Input and identity boundary

The input contains:

1. one borrowed already-inflated `tree <size> NUL <payload>` frame;
2. a claimed staging SHA-256 digest; and
3. an explicit SHA-1 or SHA-256 repository object format selecting child-ID
   width.

The decoder recomputes the staging digest before parsing and binds it into the
request commitment. This detects byte substitution relative to that caller
claim. It does **not** recompute a Git SHA-1 object ID, perform SHA-1 collision
detection, acquire or decompress a loose object, or establish that an external
`GitObjectId` names the frame. Adding a weak SHA-1 implementation would create
a false security claim, so Git object-ID authentication remains a deliberate
future boundary.

The request commitment binds the private algorithm version, object format,
exact frame length and verified staging digest, and every effective resource
limit. It is deterministic integrity framing, not a repository object, MAC,
signature, authorization receipt, staged-input handle, or permission to
import.

## Strict tree semantics

- Header type is exactly `tree`; size is nonempty canonical decimal with no
  leading zero and must equal the remaining payload length.
- Entry modes are exactly `40000`, `100644`, `100755`, `120000`, or `160000`.
  Unsupported modes return a typed terminal error; no transformation is
  inferred.
- Names are arbitrary byte strings rather than assumed UTF-8. Empty names,
  `.`, `..`, names containing `/`, literal `.git`, and the HFS/NTFS aliases
  Git treats as `.git` fail closed with typed errors.
- Child object IDs are exactly 20 or 32 nonzero bytes according to the selected
  repository object format and are materialized through the existing typed
  `GitObjectId` constructors.
- Entries must be globally unique and strictly increasing under Git's tree-name
  comparator. At a shared prefix the end marker is NUL for a non-tree and `/`
  for a tree, preserving the directory ordering edge that ordinary bytewise
  sorting misses. A bounded candidate stack implements Git's non-consecutive
  file/directory duplicate rule, including `foo`, `foo.bar`, then tree `foo`.

The output retains only typed modes, bounded names, typed child IDs, the
verified staging digest, commitments, and a resource ledger. Names and IDs are
redacted from `Debug`; accessors intentionally expose them to the caller. The
projection commitment binds every ordered output entry plus the final ledger.

The reviewed parity points come from Git's official
[`fsck.c`](https://github.com/git/git/blob/master/fsck.c) candidate-stack and
tree checks, [`tree.c`](https://github.com/git/git/blob/master/tree.c) name
comparator, [`path.c`](https://github.com/git/git/blob/master/path.c) NTFS
aliases, and [`utf8.c`](https://github.com/git/git/blob/master/utf8.c) HFS
aliases.

## Resource and cancellation review

Hard maxima are literal and cannot be broadened:

| Resource | Maximum |
|---|---:|
| inflated frame | 1,048,576 bytes |
| entries | 4,096 |
| one name | 4,096 bytes |
| aggregate names | 1,048,576 bytes |
| charged work | 16,777,216 units |
| retained logical state | 2,097,152 bytes |

The decoder validates limits and frame size, hashes the borrowed frame in
4 KiB cancellation-fenced chunks, validates the header, and performs a first
allocation-free structural/count pass. That pass charges three name bytes per
input name in addition to the base payload traversal, conservatively covering
the combined four-traversal ceiling of the HFS and NTFS `.git` recognizers. It
then admits all remaining comparison, materialization, commitment work, and
peak retained state before the first allocation. Literal 192-unit charges
conservatively cover each commitment's fixed transcript bytes.

The second pass allocates an exact-capacity candidate stack whose entries are
compile-time guarded at no more than eight bytes. It validates adjacent Git
ordering and ports Git's push/pop rule for non-consecutive file/directory
duplicates over borrowed payload offsets. Every entry and candidate-pop
comparison is cancellation-fenced and charged; actual comparison work is
checked against the admitted `payload + 2*name bytes + 5*entries` ceiling, and
unused allowance remains conservatively charged. The scratch stack is dropped
before the third pass fills an exact-capacity output vector and exact name
boxes. Any error or cancellation drops internal state; no partial entry carrier
exists. The final cancellation fence follows commitment construction.

The retained model uses a fixed 1,024-byte allowance and the larger of the
non-overlapping scratch state or output state. Scratch is eight bytes per entry;
output is a conservative 64 bytes per entry plus exact name bytes. Both entry
sizes have compile-time assertions. Borrowed frame storage, allocator metadata,
hashing stack state, and caller-retained clones are excluded. The ledger is
deterministic conservative admission accounting, not allocator or RSS
measurement.

## Verification inventory

The focused tests cover empty, SHA-1-width, SHA-256-width, all five modes,
non-UTF-8 names, Git directory-prefix ordering, adjacent and non-consecutive
duplicates, Git's full nested duplicate example, unsorted entries, literal and
mixed-case `.git`, NTFS short-name/trailing/ADS/backslash aliases, all 16 HFS
ignored code points at every `.git` boundary, Git's malformed-UTF-8 end-marker
case, negative alias controls, staging-
digest and object-format substitution, malformed header/type/decimal/size/mode/
name/ID cases, zero and truncated IDs, exact and next-value hard or narrowed
limits, work and retained admission boundaries, cancellation in every phase,
redacted debug output, deterministic replay, hostile deterministic byte corpora,
and independently generated JSON commitments for both object widths.

On the exact candidate worktree, Rust 1.82 debug and release runs each pass 90
tests: 47 preflight, 20 LFS, 10 typed-ID, 2 preflight known-answer, 9 tree-frame
integration, 1 tree-frame commitment golden, and 1 internal phase-cancellation
test. Formatting and strict all-target warnings-denied Clippy pass. Cargo
package verification passes for a 20-file archive using the existing local
object-model and path-contract patches, and the fresh packed-consumer gate
passes the same 90 tests. The private source policy passes 4 tests; roadmap
validation reports 46 PRDs and its regression suite passes 8 tests.

Those local gates prove deterministic private-source behavior. Exact revision
`fa61786b272a019b82f4e96eaaa47dbef60c5b6c` also passed the source/package gate
on hosted Linux, macOS, and Windows in
[run 33664922211](https://github.com/n3r/OpenGameVCS/actions/runs/33664922211),
with its exact workflow/crate bytes retained under
[`docs/evidence/OGVCS-020`](../evidence/OGVCS-020/README.md). That is source
portability only, not Git repository conversion, OGVCS-045 isolation,
performance, or acceptance evidence.

## Residuals and acceptance boundary

- No Git pack, zlib, compressed loose-object, archive, commit, tag, or ref
  parser exists. No recursive traversal or reachability proof exists.
- The staging SHA-256 is a caller-supplied association. Git object-ID
  recomputation/collision handling and authenticated OGVCS-045 staged-input
  provenance remain absent.
- The decoder is not connected to the preflight inventory. It cannot prove a
  projected `ImportRecord::Tree`, relationship count, path, mode, or source ID.
- Path joining and OGVCS-004 validation, `.gitattributes` discovery,
  `LfsDisposition`, LFS acquisition, and extension reversal remain outside this
  slice.
- Git fsck's separate HFS/NTFS policy findings for symlinked `.gitmodules`,
  `.gitattributes`, `.gitignore`, and `.mailmap` remain outside this slice; only
  the tree-local `.git` rejection is implemented here.
- FileID allocation/mapping, commit DAG preservation, identity/message/time
  fidelity, selected-ref policy, conversion, checkpoint/resume, isolated
  namespace verification, reconciliation, and atomic ref publication remain
  unimplemented.
- No public interface, operator workflow, broker/sandbox canary, kill/restart
  or conversion matrix, large-history result, or scale/latency claim is added.

Consequently AC-01 has no complete DAG/LFS conversion; AC-02 has no selected
transform policy; AC-03 has no resume or publication; AC-04 has no source-tip
to target reconciliation; AC-05 has no operator reproduction; AC-06 has no
OGVCS-045 canary execution; and AC-07 has no FileID lifecycle. OGVCS-020 remains
Todo and all seven acceptance criteria remain open.
