# OGVCS-041 validation evidence

**Evidence date:** 2026-08-17

**Status:** Local and hosted OGVCS-041 acceptance passed; predecessor completion pending

## Evidence boundary

This packet covers the public protocol v1 candidate, generated schema consumers,
reference runtime, independent process adapter, offline package closure,
conformance runner, report comparator, and bounded security/resource evidence.
The machine-readable local record is
[`candidate-2026-08-16.json`](candidate-2026-08-16.json), and the independent
assessment is
[`docs/reviews/OGVCS-041-critical-review.md`](../../reviews/OGVCS-041-critical-review.md).

The contract is intentionally `1.0.0-rc.1`, candidate, and unratified. The PRD
remains in Validation because its OGVCS-002/OGVCS-004 predecessors are not
Done.

The maintainer directed that OGVCS-002's exact one-million-entry tree and
logical-1-TiB manifest acceptance remain deferred to the final R0 campaign.
Partial diagnostic attempts do not provide the required complete retained
two-language comparison. ADR-0013 expressly excludes that separate scale
campaign from this protocol proof; no reduced case is represented as
exact-scale evidence.

## Frozen candidate authorities

| Authority | Value |
|---|---:|
| Contract/package version | `1.0.0-rc.1` |
| Contract manifest SHA-256 | `41bfebd0524458a669324e055c9849aff40f5a55bd5b8b47f1891516910ebffe` |
| Binding manifest SHA-256 | `a6905b649d593d536d8b6870654d7de319f6e228156c4eaf50720688ff01149b` |
| Binding-set SHA-256 | `de584a7e0e57a0b4ed39a24b2a85542b92268a58b3f83d44d5ca57cc6eafd6ad` |
| Schema-set SHA-256 | `5751fd3d06706de95c328303558a14bd4dff0fd3062f031b50cfe3810b64aae8` |
| Registry-set SHA-256 | `bc15d6833d2dd0daffe8d72263ee8a2e6384a314d69955f7eff1249e6aa52f14` |
| Vector-set SHA-256 | `f80da3324e3cd3c3f82035711871227db025a7eefee074891e3faa7f20e768d0` |
| Adapter execution-view SHA-256 | `accf5219fb560085fb780cc4d86fa3bd4124d555fd08b149fe90dde9bc289901` |
| Model SHA-256 | `45f4325ab0d01129e37f75610265709c4551ad09541a272d375120322346ed44` |
| Generator SHA-256 | `98dd6bef4f5a7dfc914523ac95ec6cf925de6a02223fbd25a7323861f81d570d` |
| MIT text SHA-256 | `6f0f22f485ae8614870468a48f2c084eaf800fe02c5a2c4d9a91d34bc7f58eb4` |
| Shared semantic report digest | `7816829692bb88b2dfbb7a391e67e9e550914f5b9aedc108cbd101a473e01039` |

The generated inventory contains 90 manifested contract artifacts, 28
manifested binding artifacts, 46 schemas/messages, 352 numbered fields, 35
limits, 25 errors, and 360 scenarios (87 accept, 273 reject).

## Local bounded presubmit

Local environment: macOS 26.6.1 arm64, Node.js 24.9.0, npm 11.6.0.

| Gate | Result |
|---|---|
| Contract generation and independent validation | Passed 14/14 tests; all checked-in contract and binding bytes reproduce. |
| Reference and independent adapters | Passed 360/360 each with identical result rows and report digest. |
| Runtime and isolation | Passed 102/102 tests, including permission confinement, hostile output, deadline, and package cases. |
| Differential review | A 28,889-case broad sweep plus corrected stripped-RunnerCase boundary and combined-invalid sweeps covered all nine operations; no live P0/P1 remained. |
| Generated consumers | TypeScript typecheck/smoke and C++ configure/build/CTest 1/1 passed locally; Rust, C++, C#, and TypeScript retained consumers compiled on all three hosted operating systems. |
| Offline packed proof | Six exact archives installed, regenerated, and ran both adapters from isolated offline consumers. |
| Report tooling | Passed source, packed, and synthetic three-OS comparator tests 3/3. |
| Full repository ordinary suite | Passed; the reference-scale fixture case and one Windows-only junction case were skipped on the local macOS host. |

The local packed artifacts were:

| Package | SHA-256 |
|---|---|
| `@opengamevcs/authorization-contract` 1.0.0 | `e28a0da4310b2bcdb12acdf6d39c55dea5221bdef451b15a601aaf63939b43c7` |
| `@opengamevcs/authorization-contract-v1` 1.0.0 | `766078f881bba7bd7f4e3657f506ce8270992667c425ec8054cf506e13170770` |
| `@opengamevcs/protocol-baseline` 1.0.0-rc.1 | `8b3836391046521a5672a08cdfbfb486fb7a55ac9b07e7f6c1eeb9418ac0a097` |
| `@opengamevcs/protocol-baseline-independent-adapter` 1.0.0-rc.1 | `2f8427f1503e1640bc131bcfabd089bf0b5a6e8895cbc4b934035480550d0f36` |
| `@opengamevcs/protocol-contract-v1` 1.0.0-rc.1 | `ced7e8a8b84d3ca1165b23c9c5fd0ff15709edf40eac9f6f4f4596eaeb2b4381` |
| `@opengamevcs/protocol-types-v1` 1.0.0-rc.1 | `633aee67cbbeada7c17fd95ebecea7d0d6becaa9e90145d08f451beb540beca0` |

The packed offline-source set SHA-256 is
`ac2c6da88486b4511c89bb9a968cae0a3892a190ea90e98bb41c1b0c3da6f456`.
The reference and independent report files have SHA-256
`f840ddcb89fbe42e9dfbb765a3da10df5614e420834b25ba4b076aca2ca39f0a`
and `db250a85d5d335b38fbf3a163cd054d872800c2dca89814f04edf66c5b789915`.

## Acceptance map

| Criterion | Candidate evidence | Status |
|---|---|---|
| OGVCS-041-AC-01 | Separate process implementation, oracle-free authenticated execution view, randomized handles/order, and exact 360/360 equality across every finite registered tuple and selectable extension. | Pass |
| OGVCS-041-AC-02 | 273 exact negative traces cover duplicate, reorder, disconnect, expiry, incompatibility, downgrade, malformed and bounded-resource classes with pre-mutation counts. | Pass |
| OGVCS-041-AC-03 | One numbered model reproduced four manifest-bound consumers; all four compiled from retained source on Ubuntu, macOS, and Windows. | Pass |
| OGVCS-041-AC-04 | 28 tagged red-team rejects, sensitive-carrier derivation, encoded/hash canary scanning, empty successful stderr, and permission isolation found no protected output. | Pass |
| OGVCS-041-AC-05 | 24 release-preflight rows reject pin, tuple, required-feature, assignment, lifecycle, and semantic drift while accepting only the exact pre-reserved addition. | Pass |

The full FR/NFR/AC matrix and remediation history are in the independent
[critical review](../../reviews/OGVCS-041-critical-review.md).

## Hosted validation

The commit-pinned [workflow run 31967884476](https://github.com/n3r/OpenGameVCS/actions/runs/31967884476)
passed at source revision
`f938c296759ce4a7228647221670f9160de4c77c`. Each host ran the 360-row
reference and independent reports, built the packed candidate offline, and
compiled the retained Rust/C++/C#/TypeScript consumers using only retained
source and local configuration. The platform and comparison jobs were:

| Job | ID | Result |
|---|---:|---|
| [Ubuntu](https://github.com/n3r/OpenGameVCS/actions/runs/31967884476/job/95215708587) | `95215708587` | Pass |
| [macOS](https://github.com/n3r/OpenGameVCS/actions/runs/31967884476/job/95215708603) | `95215708603` | Pass |
| [Windows](https://github.com/n3r/OpenGameVCS/actions/runs/31967884476/job/95215708506) | `95215708506` | Pass |
| [Cross-platform comparison](https://github.com/n3r/OpenGameVCS/actions/runs/31967884476/job/95217259894) | `95217259894` | Pass |

GitHub retained four archives until 2026-09-15. The archive digests reported by
the Actions API are:

| Artifact | ID | Bytes | Archive SHA-256 |
|---|---:|---:|---|
| `protocol-Linux` | `9269058422` | 1,927,354 | `3c2184dddf8fe7f30bc5691f81c02593660f43920ffcc50df2bbe168d5098601` |
| `protocol-macOS` | `9269024611` | 1,927,353 | `6182167a27c8a15baa96b7e8dfd554c0b77d02eb56125615aa83b9de5fa031ee` |
| `protocol-Windows` | `9269137328` | 1,927,356 | `973b2799b48e6698dbe71b17328a7fa14ab45a89686889665b3742a995884741` |
| `protocol-comparison` | `9269140389` | 584 | `756c9d6e63e9760c0095d8ba4023b38fd337e509a6dfb4dcd2c3d27a38d4f147` |

The downloaded comparison record has SHA-256
`77536ef06fb3c5c85e961caf28c66fb9136ec8d8c646864a00c9e9c25849af74`
and reports `equal` for all six reports, all 360 scenarios, the six package
archives, and the complete offline source set. Re-running the comparator over
the downloaded platform directories produced the same record. The exact-scale
workflow is separate and was not dispatched.

## Deferred roadmap completion

The local and hosted OGVCS-041 implementation and acceptance criteria are
satisfied. Keep the PRD in Validation until OGVCS-002/OGVCS-004 are Done. At
the final R0 campaign, run the two maintainer-deferred OGVCS-002 scale cases
before considering ratification or moving OGVCS-041 to `prd/done`.
