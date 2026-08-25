# OGVCS-041 completion evidence

**Evidence date:** 2026-08-25

**Status:** Completed

## Completed evidence boundary

This packet closes OGVCS-041 against implementation revision
[`dfdd7ad`](https://github.com/n3r/OpenGameVCS/commit/dfdd7adcf07a3e6c964e97d21434f370c3664250).
It covers the public protocol candidate, generated consumers, reference runtime,
independent process adapter, offline package closure, bounded hostile-input and
resource behavior, three-host compilation/execution, and exact semantic/package
comparison. The machine record is
[`github-actions-run-32843391920.json`](github-actions-run-32843391920.json),
and the final assessment is the
[`OGVCS-041 critical review`](../../reviews/OGVCS-041-critical-review.md).

The protocol remains intentionally `1.0.0-rc.1`, `candidate`, and
`ratified: false`. OGVCS-041 delivers the R0 public baseline; OGVCS-005 consumes
that version before a later ratification change may publish `1.0.0`. This is a
version-lifecycle boundary, not an incomplete OGVCS-041 acceptance criterion.

The one-million-entry tree and logical-1-TiB campaign belongs to OGVCS-002. Its
current-source exact campaign is already complete, and no scale workload was
duplicated for this protocol completion.

## Frozen authorities

| Authority | Value |
|---|---:|
| Contract/package version | `1.0.0-rc.1` |
| Contract state | `candidate`; `ratified: false` |
| Contract manifest SHA-256 | `bc343842291040b6b0c2c941b183863500c4d60a4618256ffc6e36a1d6afbe72` |
| Binding manifest SHA-256 | `c8114447e71bd16b11498984a296317ce967f382c06282749e33868e167283aa` |
| Binding-set SHA-256 | `52bdaf09b83c20ca6d8858142eb3706ede11ed33806cfd6c77ef8af1e19d0135` |
| Schema-set SHA-256 | `5751fd3d06706de95c328303558a14bd4dff0fd3062f031b50cfe3810b64aae8` |
| Registry-set SHA-256 | `2a49361363cc16e743948fa3cc5e266cd1bc6e31b312cde15b5dab1ad7e5c5b0` |
| Negotiation-registry-set SHA-256 | `2b1913f9451b9f99966a24942a262846f07662b17cbb41ad6eea6474c23b4352` |
| Vector-set SHA-256 | `2a2bc52ea8299b5c8a1c7b89de98d45a2c36444fafbe1e63b5894f9480873b7c` |
| Model authority SHA-256 | `85c7f0e3332fa693a33c94b3c569830654a49cd0d05bdcaa06948295ae387fa8` |
| Generator authority SHA-256 | `effe14935a18632ad9e26f66310dbe614ebab5e6fad3a2237c13d36c77009bff` |
| Adapter execution-view SHA-256 | `cd2271dc13fa7d9c9115d39f214b6180a1e50c4fbbebf21acc10ad5c96a103a9` |
| Adapter authority-set SHA-256 | `24e960a36542e69fd70df0ade7ebd526a1ec978c68f4677cf5601e2f3d1b67f0` |
| Packed offline-source-set SHA-256 | `a7114ec3fa04b93912377396c3b96b6a0c1240dd50ca1fedef0d6a34d49e5819` |
| MIT text SHA-256 | `6f0f22f485ae8614870468a48f2c084eaf800fe02c5a2c4d9a91d34bc7f58eb4` |
| Shared semantic report digest | `7816829692bb88b2dfbb7a391e67e9e550914f5b9aedc108cbd101a473e01039` |

The generated inventory contains 90 manifested contract artifacts, 28 binding
artifacts, 46 schemas/messages, 352 numbered fields, 35 finite limits, 25
closed errors, 16 registries, and 360 scenarios: 87 accept and 273 reject.

The predecessor manifest/registry pins bind the completed OGVCS-002,
OGVCS-003, and OGVCS-004 authorities. Generation and independent validation
reproduced every checked-in contract and binding byte without drift.

## Local and hosted gates

The final local bounded run passed:

| Gate | Result |
|---|---|
| Protocol runtime | 111/111 tests passed. |
| Language-neutral contract | 14/14 tests passed; generator `--check` clean. |
| Independent adapter | All 360 public cases passed with the reference digest. |
| Report/package tooling | 3/3 tests passed, including strict synthetic comparison failures. |
| Generated bindings | Rust, C++, C#, and TypeScript retained consumers compiled/executed. |
| Roadmap and diff checks | Passed; no generated authority drift. |

Commit-pinned workflow
[`32843391920`](https://github.com/n3r/OpenGameVCS/actions/runs/32843391920)
ran on the exact implementation source and passed from 11:38:54Z through
11:53:18Z. Every host installed the packed closure offline, ran both adapters,
compiled the four generated consumers, and uploaded its authenticated evidence.

| Job | ID | Result |
|---|---:|---|
| [macOS](https://github.com/n3r/OpenGameVCS/actions/runs/32843391920/job/97787632685) | `97787632685` | Pass |
| [Ubuntu](https://github.com/n3r/OpenGameVCS/actions/runs/32843391920/job/97787632822) | `97787632822` | Pass |
| [Windows](https://github.com/n3r/OpenGameVCS/actions/runs/32843391920/job/97787632944) | `97787632944` | Pass |
| [Cross-platform comparison](https://github.com/n3r/OpenGameVCS/actions/runs/32843391920/job/97791403686) | `97791403686` | Pass |

The downstream benchmark/fault-harness scheduling and bounded packed matrix
also passed at the same source in
[`32843391941`](https://github.com/n3r/OpenGameVCS/actions/runs/32843391941).

## Packed artifacts

The normalized package bytes were identical across Linux, macOS, and Windows:

| Package | Bytes | SHA-256 |
|---|---:|---|
| `@opengamevcs/authorization-contract` 1.0.0 | 107,041 | `e28a0da4310b2bcdb12acdf6d39c55dea5221bdef451b15a601aaf63939b43c7` |
| `@opengamevcs/authorization-contract-v1` 1.0.0 | 262,197 | `766078f881bba7bd7f4e3657f506ce8270992667c425ec8054cf506e13170770` |
| `@opengamevcs/protocol-baseline` 1.0.0-rc.1 | 358,468 | `07354434b547e77e69735b02a74edfdb668f6c23d394033ccd1caefb8ba539e4` |
| `@opengamevcs/protocol-baseline-independent-adapter` 1.0.0-rc.1 | 95,772 | `2f8427f1503e1640bc131bcfabd089bf0b5a6e8895cbc4b934035480550d0f36` |
| `@opengamevcs/protocol-contract-v1` 1.0.0-rc.1 | 3,450,911 | `0be9148e0b4a1be1dafe30435fc788157d4b1cdab2124ee54263856ea17e3407` |
| `@opengamevcs/protocol-types-v1` 1.0.0-rc.1 | 126,497 | `d95cd47eef832db1e336b2732e814b58df5919550a44c2350965385ce124a989` |

GitHub retained the source/package bundles for 30 days. Their archive metadata
is preserved in the machine record; durable source, package recipes, compact
packed evidence, adapter results, and the comparator result remain in this
repository after those transient archives expire.

## Durable reports

- [`conformance-reference-2026-08-25.json`](conformance-reference-2026-08-25.json)
  is the exact 93,003-byte reference report, SHA-256
  `f7329a24ea65d8d076d58a5dea4b84727398cacc1f3fc5ac3dc6bfcab666a24a`.
- [`conformance-independent-2026-08-25.json`](conformance-independent-2026-08-25.json)
  is the exact 93,005-byte independently computed report, SHA-256
  `f1c041527a739f82aa1504c2b4d5331d49dc5391b90a5ca6de83215a4339e710`.
  Each adapter's report bytes were identical on Linux, macOS, and Windows.
- The exact host records are retained for
  [Linux](packed-evidence-linux-2026-08-25.json),
  [macOS](packed-evidence-macos-2026-08-25.json), and
  [Windows](packed-evidence-windows-2026-08-25.json).
- The hosted
  [comparison](conformance-comparison-2026-08-25.json) is 664 bytes,
  SHA-256 `17c08462fe25eb782a6c62a049863c90beab9bc1bdbb655477922556bd1625d9`.
  An independent replay over the downloaded closures reproduced it
  byte-for-byte.

## Acceptance map

| Criterion | Completion evidence | Status |
|---|---|---|
| OGVCS-041-AC-01 | Two genuinely separate engines consume only authenticated public authority, receive randomized handles/order, and produce exact equality for all 360 finite registered cases. | Pass |
| OGVCS-041-AC-02 | The 273 retained rejects cover duplicate, reorder, disconnect, expiry, incompatibility, downgrade, malformed, and reduced-resource classes with exact pre-mutation outcomes. | Pass |
| OGVCS-041-AC-03 | One numbered model reproduced 28 binding artifacts; Rust, C++, C#, and TypeScript consumers compiled/executed from retained source on every host. | Pass |
| OGVCS-041-AC-04 | Twenty-eight tagged red-team rejects plus encoded/hash canaries, safe problem schemas, empty successful stderr, and confined adapter execution found no protected output. | Pass |
| OGVCS-041-AC-05 | Twenty-four release-preflight rows reject pin, tuple, required-feature, assignment, lifecycle, and semantic drift and accept only the exact pre-reserved addition. | Pass |

The complete FR/NFR/AC assessment and remediation history are in the
[`critical review`](../../reviews/OGVCS-041-critical-review.md#requirement-and-acceptance-matrix).

## Completion and rollback

No live P0, P1, or P2 remains in the reviewed OGVCS-041 scope. Withdrawal of
the candidate prevents new sessions but does not reinterpret existing receipts,
cursors, idempotency records, assignments, or errors. Consumers must negotiate
the candidate explicitly and may not ship a private incompatible protocol.
Ratification remains a future compatible lifecycle transition after OGVCS-005
consumer evidence; it cannot silently change assigned fields or semantics.
