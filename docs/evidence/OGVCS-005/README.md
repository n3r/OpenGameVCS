# OGVCS-005 validation evidence

**Evidence date:** 2026-08-21

**Status:** Local bounded candidate passed; hosted three-OS and independent
operator evidence pending

## Evidence boundary

This packet covers the benchmark/fault contract, reference runtime, test-only
process driver, five synthetic corpora, cache/network controllers,
deterministic fault and negative suites, raw result publication and
recomputation, offline package closure, comparison tooling, and workflow plan.
The machine-readable local record is
[`candidate-2026-08-21.json`](candidate-2026-08-21.json), and the independent
assessment is
[`docs/reviews/OGVCS-005-critical-review.md`](../../reviews/OGVCS-005-critical-review.md).

The candidate packages remain `1.0.0-rc.1`. OGVCS-005 remains in Validation:
the commit-pinned Linux/macOS/Windows jobs and second-operator reproduction have
not yet run for this change, and OGVCS-002/004/041 remain predecessor validation
candidates.

The maintainer explicitly deferred OGVCS-002's exact one-million-entry tree and
logical-1-TiB manifest cases to the final R0 campaign. They were not dispatched
by this evidence pass. Every retained report records
`exactScaleExecuted: false`; no reduced case is presented as exact-scale proof.

## Frozen local candidate

| Authority | Value |
|---|---:|
| Contract/runtime version | `1.0.0-rc.1` |
| Contract manifest SHA-256 | `11c3038d6456e690664e705dcab55f2d8f8c8690b66e542a496a8e8a067ea7c3` |
| Artifact-set SHA-256 | `ba59c8dc9db4c0678fc630357396d9981934ac065b0dd2c8bbbb5c82dccad6d7` |
| Schema-set SHA-256 | `f186e1cfe4d8905b0fe36acfa641b3a97eed3f8bcb9d245c7a96055d9cd6f706` |
| Registry-set SHA-256 | `bbe8230b1a115b5c0862537d7dde6e97db61c283b552dad61d2020165b75d532` |
| Vector-set SHA-256 | `7ab9d07b3f88e94be05f3d48bcd0b8e7bfac79ade49dad3e87f3f1d859a501b7` |
| Threshold-set SHA-256 | `13a1cf5e4d20dadced0b04bdc3cc8b3d01a5c3b2a42ca04e163b08e147dac7ff` |
| Fixture profile-set SHA-256 | `6b53f4274d8b2374224728d0cebd499e58ab990c4e6409fa5403bf8f38934b36` |
| Repository predecessor SHA-256 | `2d0acb01a01b64c23d883d855d2802d939a8dc99622f2774de07af1c8af8d2b9` |
| MIT text SHA-256 | `6f0f22f485ae8614870468a48f2c084eaf800fe02c5a2c4d9a91d34bc7f58eb4` |

The authority contains 28 manifested artifacts: 17 schemas, eight registries,
one driver profile, one threshold file with eight gates/warnings, and one
35-scenario conformance corpus. It fixes eleven tasks, twelve test-only fault
points, four cache states, five network profiles, and four execution tiers.

Generation imports the five current fixture profiles and hashes their complete
semantic values. The independent validator separately recomputes the fixture
package/version/profile inventory and every other predecessor manifest pin.

## Local bounded execution

Local environment: macOS 26.6.1 build 25G76 arm64, Node.js 24.9.0, npm
11.6.0.

| Gate | Result |
|---|---|
| Contract generation, independent predecessor validation, loader, and tamper test | Passed 3/3; 28 artifacts and 35 scenarios reproduce. |
| Runtime/type/unit/integration suite | Passed 19/19. |
| Five-corpus retained smoke | Passed 110 samples and 110 summaries across ten environment lanes. |
| Fault/checker/security proof | Passed 36 boundary/action rows, seven broken modes, and both authorization/path negative suites. |
| Harness conformance | Passed 35/35 exact rows. |
| Bounded presubmit | Passed 1,320 samples; semantic digest `64df6eec5143ce21ba21d5375399417f859e0d195b902ffe3b21a18133bfa84c`. |
| Source/packed/comparator tooling | Passed 3/3, including a ten-package offline install. |
| Full ordinary repository suite | Passed; fixture 128 pass/2 explicit skips, object model 180/180 plus 58,520 mutations, and every other bounded package/report gate. |

The retained local-smoke source report has:

| Field | Value |
|---|---:|
| Overall status | `passed` |
| Bundle digest | `0d463047b6aba49854e30c67cd18712a65d9e822d93003345dfadd00001522ac` |
| Semantic-results SHA-256 | `8e14fb0797faae7e9202b2d708029dadcac411365974e8ccb657940cbac80a12` |
| Report SHA-256 | `74aaa461747e1cf63d576f0ec6f7b535149e6e24a8c56a7b9b9586310b0a4e72` |
| Conformance failures | `0` |
| Fault failures | `0` |
| Broken-checker misses | `0` |
| Security/path misses | `0` |
| Exact scale executed | `false` |

The report uses fixed clocks for portable semantic comparison. Timing fields in
that retained conformance report are harness reproducibility evidence, not a
claim about this workstation's production performance.

## Offline packed proof

Ten exact MIT archives installed together with npm offline, lifecycle scripts
disabled, and a private empty cache. The installed CLI planned the matrix and
the installed runtime emitted the same semantic-result digest as source.

| Package | Version | SHA-256 |
|---|---:|---|
| `@opengamevcs/authorization-contract` | 1.0.0 | `e28a0da4310b2bcdb12acdf6d39c55dea5221bdef451b15a601aaf63939b43c7` |
| `@opengamevcs/authorization-contract-v1` | 1.0.0 | `766078f881bba7bd7f4e3657f506ce8270992667c425ec8054cf506e13170770` |
| `@opengamevcs/benchmark-fault-contract-v1` | 1.0.0-rc.1 | `f632073283c311690a8e855056227606cdbb13e45c137e6613682fd86e88a622` |
| `@opengamevcs/benchmark-fault-harness` | 1.0.0-rc.1 | `c8355a0997941507b94a48afbb7ae353ad65349ed685e59f8062193c05031699` |
| `@opengamevcs/fixture-generator` | 1.0.0 | `1a4846a936aa466c73aaf7b722eb295eb66eadb7e98c885f17e75e2762a4e2f7` |
| `@opengamevcs/path-contract-v1` | 1.0.0 | `c376cd1d29d42295f4842491b2fdf76322bd0537198d202f288f788d4271662e` |
| `@opengamevcs/path-filesystem` | 1.0.0 | `4e726bcfdc5455ff348126ef93b1f3b2341eae92ed2bc40d0945d322a2544b6d` |
| `@opengamevcs/protocol-baseline` | 1.0.0-rc.1 | `8b3836391046521a5672a08cdfbfb486fb7a55ac9b07e7f6c1eeb9418ac0a097` |
| `@opengamevcs/protocol-contract-v1` | 1.0.0-rc.1 | `e86e12b892f5247ec8dd9c5510a48036418cc598a02797a1c2d10064f0b32f53` |
| `@opengamevcs/protocol-types-v1` | 1.0.0-rc.1 | `89e69abe4b062250ce4b16e851742de906ab92597d0f7f74f32dd36d06278e01` |

The package-set SHA-256 is
`4c609f2ecb8eb8c9ad51e6b37e40611f93957b74309439456c34c1718dc01fe9`.
The packed evidence SHA-256 is
`fa5911016272003fed6ba69a111230468e183a76afc221b8629126ff6579ad61`.

## Acceptance map

| Criterion | Candidate evidence | Status |
|---|---|---|
| OGVCS-005-AC-01 | All five profile-v2 corpora produce schema-valid authenticated bundles; local smoke passed 110 samples. | Pass |
| OGVCS-005-AC-02 | All four cache states are reset, independently inspected, and assert the declared local/regional byte differences; aggregate cache/matrix memory is bounded. | Pass |
| OGVCS-005-AC-03 | All 36 injected boundary/action rows preserve invariants and seven intentionally broken modes are detected. | Pass |
| OGVCS-005-AC-04 | The exact OGVCS-003/004 negative suites detect seeded enumeration and workspace-escape defects with no misses. | Pass |
| OGVCS-005-AC-05 | Source and offline installed runs reproduce exact semantics locally; a second operator on a commit-pinned host has not yet supplied the required independent comparison. | Pending |
| OGVCS-005-AC-06 | Presubmit executes 1,320 bounded unprivileged samples; nightly is scheduled; release CI validates a 33,000-sample privileged plan without running it. | Pass |
| OGVCS-005-AC-07 | The process driver passes negotiation, malformed, retry, bounds, lifecycle, trace, and fail-before-mutation tests. | Pass |

The complete FR/NFR assessment and remediation history are in the
[critical review](../../reviews/OGVCS-005-critical-review.md).

## Hosted and roadmap boundary

The commit-pinned workflow must still run the packed proof on Ubuntu, macOS,
and Windows and compare equal contract, package-set, and semantic-result
digests. That hosted execution supplies portability evidence and the natural
second-operator boundary for AC-05. Until its run/job/archive/comparison IDs are
retained here, the local packet does not claim those gates.

OGVCS-002, OGVCS-004, and OGVCS-041 remain in Validation. The candidate is
therefore correctly kept at `1.0.0-rc.1` and OGVCS-005 remains in
`prd/todo` with status Validation. After hosted evidence passes, the final R0
campaign must still execute the two explicitly deferred OGVCS-002 scale cases
before dependency closure can move the R0 candidates to Done.
