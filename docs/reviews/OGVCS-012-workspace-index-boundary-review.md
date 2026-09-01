# OGVCS-012 durable workspace-index candidate boundary review

- **Reviewed integration baseline:** `d660ebc92bbbca56c11769f2c5e4d98fa35faca1`
- **Private candidate contract:** `client/native-cli/rust/contracts/workspace-index/v1`
  version `0.1.0-rc.1`
- **Verdict:** useful fail-closed native implementation slice; OGVCS-012
  remains Todo.

## What this candidate establishes

The Rust participant can ingest an authenticated immutable baseline through a
bounded sink and publish a locally durable index without accepting a
million-entry caller vector. Every baseline chunk is at most 1,000 entries and
1 MiB, the full stream is canonical and duplicate/collision free, and the final
receipt binds the repository, baseline, settings, path profile/case mode,
ordered digest, count, and repository ignore digest.

Generation artifacts are create-new. The writer publishes and syncs a
transition, syncs every artifact, creates and syncs the seal, syncs the owning
directory, atomically promotes the active pointer, syncs the directory again,
and only then removes the transition. Recovery exposes the prior sealed
generation or the newly promoted sealed generation. Status does not ignore an
active transition and re-reads the active and generation-scoped watcher facts
before returning, closing both the early-clean and after-load writer races.

The lookup sidecar is fixed width and bounded. Its digest narrows the search;
it is never identity. Every digest hit is checked against the exact canonical
repository path, repository collision key, full platform collision key, and
key digest before an entry is returned.

Watcher events use strict `+1` sequence numbers and a domain-separated hash
chain. Append is limited to 1,000 events and 1 MiB per chunk and 100,000 events
per generation. The event file is synced before atomically publishing watcher
state. A crash in between is detected from the persisted byte-count/tail
mismatch and cannot yield clean status. Missing cursors, gaps, overflow,
unsupported watchers, corrupt state, and an unmatched absent delete all force
reconciliation. A same-path transient untracked create/delete is the narrow
case that can collapse to no finding.

Status hashes every event-touched regular file and never treats timestamps as
content equality. It emits the complete required status vocabulary, applies
deterministic repository/local exact/subtree ignores, and pages at most 1,000
items. The opaque paging cursor is HMAC-SHA256 authenticated by an owner-private
local key and binds the exact generation/active digest, settings, profile/mode,
both ignore digests, filter, and last full path/platform key.

## Adversarial and bounded evidence

The default focused Rust suite covers:

- every implemented transition/artifact/seal/active crash point and committed
  artifact no-overwrite behavior;
- status loaded before a writer publishes a transition, status invoked during
  a transition, and the exact new generation after promotion;
- watcher gap, oversized chunk, strict journal tail, synced-unpublished tail,
  and portable watcher degradation;
- digest collision substitution, path order/case collision, current
  profile/case/settings/generation binding, and HMAC cursor tamper/staleness;
- index-root/generation-artifact symlink or reparse rejection;
- timestamp-preserving same-size file edits and same-length sealed-artifact
  corruption; and
- deleted tracked directory uncertainty, transient untracked deletion, and
  repair that leaves local work files byte-for-byte unchanged.

Two explicit bounded release tests produced this local candidate evidence:

| Fixture | Result | Scope |
| --- | --- | --- |
| 1,000 changed files | 1,000 modified items, every content verified, 210 ms | one local debug test run; not p95 |
| 100,000 watcher events | 100 chunks × 1,000, full-chain verification, event 100,001 rejected before append, 11.619 s | one local debug test run; not a million-path benchmark |

The final default Rust run passed 28 library tests (with the two exact tests
explicitly ignored), 2 binary-contract tests, 2 contract-vector tests, and 11
production-foundation integration tests. Rustfmt and all-target clippy with
warnings denied passed on Rust 1.82; the crate also cross-checked for
`x86_64-pc-windows-gnu`. The offline packed crate repeated the same default
test set with the unpublished object-model and path crates. The existing CLI
contract gate passed 3 Node tests, the roadmap validator passed 8 tests, and
the new private-contract generator/validator passed on Node 24.

The private contract manifest authenticates five artifacts with artifact-set
SHA-256 `1e97e24e7c61d2b873d42f18ccdb8fb637495412f2face2b6c41dd59d2e253a9`.
Node 24 independently recomputes the cursor HMAC vector; the Rust test uses the
same production encoder primitive and pins the manifest artifact set.

## Exact nonclaims and completion blockers

| Residual | Candidate behavior | Completion condition |
| --- | --- | --- |
| Public baseline/status route | `UnavailablePublicRoutes` fails before index publication | Publish and authenticate the owning baseline/status adapter and CLI/JSON contract |
| Native watcher authority | No production constructor can mint continuity; portable watcher is always degraded | Implement and prove USN, FSEvents, and inotify adapters including resume/overflow/unclean shutdown |
| Generation retention | Old committed artifacts are intentionally retained | Add reader leases/epochs and crash-safe bounded generation GC; prove no active reader loses its generation |
| Million-path SLO | No exact one-million warm p95 result | Pass the reference p95 target without a full walk/hash on every supported OS profile |
| Full status state machine | Core vocabulary and hostile cases exist, not every OGVCS-004 operation/fault | Pass the complete add/move/delete/revert, rename-cycle, case-only rename, locked-open, ignore transition, and watcher matrix |
| Repair equivalence | Rebuild preserves local files and publishes a sealed generation | Compare against an independent authenticated full scan across corruption/fault fixtures |
| Product operations | No public explain, repair, telemetry, rollout, or downgrade surface | Integrate bounded public commands and operational evidence |

Retaining old generations is not physical compaction. The candidate must not
be described as scalable-status completion, public watcher authority, hosted
three-OS evidence, or OGVCS-012 Done.

## Reproduction

Run with Rust 1.82, Node 24, an external Cargo target directory, and the checked
offline lock:

```sh
node client/native-cli/rust/contracts/workspace-index/v1/scripts/generate.mjs --check
node client/native-cli/rust/contracts/workspace-index/v1/validate.mjs
cargo +1.82.0 fmt --manifest-path client/native-cli/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path client/native-cli/rust/Cargo.toml --locked --offline
cargo +1.82.0 clippy --manifest-path client/native-cli/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo +1.82.0 check --manifest-path client/native-cli/rust/Cargo.toml --locked --offline --target x86_64-pc-windows-gnu
client/native-cli/rust/scripts/test-packed.sh
```

The exact ignored-test commands are in `client/native-cli/rust/README.md`.
