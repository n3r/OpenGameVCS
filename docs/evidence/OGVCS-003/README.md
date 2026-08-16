# OGVCS-003 validation evidence

**Evidence date:** 2026-08-16

**Status:** Complete

**Frozen product source:** [`dcaae7e2c3cb966e9698cf86ee52ecc81f6381d3`](https://github.com/n3r/OpenGameVCS/commit/dcaae7e2c3cb966e9698cf86ee52ecc81f6381d3)

**Hosted proof:** [GitHub Actions run 31933804281](https://github.com/n3r/OpenGameVCS/actions/runs/31933804281)

## Evidence boundary

This packet covers authorization contract v1, its generated JavaScript bindings,
reference policy/grant/view behavior, public threat runner, external-adapter
protocol, offline packages, and cross-platform reproducibility. It proves the
packaged reference and example adapter produce the same closed outcome for the
entire synthetic corpus. A future server claims conformance only when its own
adapter executes these assertions through the real public server boundary.

The contract has no million-entry acceptance requirement. Per the maintainer's
2026-08-16 instruction, neither the OGVCS-002 million-tree nor logical-1-TiB
case was run here; those remain deferred to the final R0 scale campaign.

The machine-readable record is
[`github-actions-run-31933804281.json`](github-actions-run-31933804281.json), and
the independent verdict is
[`docs/reviews/OGVCS-003-critical-review.md`](../../reviews/OGVCS-003-critical-review.md).

## Frozen authorities

| Authority | Value |
|---|---:|
| Contract/package version | `1.0.0` |
| License | MIT, byte-identical root/spec/runtime text |
| Manifest SHA-256 | `3fb4dd4a89eb914f93a589b013bda8afcf4744c0d27171ee5849ca3b7bf62447` |
| Registry-set SHA-256 | `293f9ab0be023a9ded33326d04a8314080bda56e7c70dd18d0cca38b70bed9cc` |
| Result SHA-256 | `6cf806951e198e71a616ed72362c7db5aedfb25230c3dd492fec897799d88c1f` |
| Schemas | 10 closed Draft 2020-12 documents |
| Registries | 13 complete canonical documents |
| Policies | 2 |
| Decision cases | 40 |
| Abuse cases | 30 |
| Grant cases | 16 |
| Roadmap mappings | 45 |

The independent validator does not import the generator. It re-hashes every
artifact, the manifest, registry set, assignments and complete registry
documents; independently evaluates all policy decisions and grant outcomes;
checks every authorized view, threat/abuse relation, revocation/sandbox/audit
invariant and roadmap row; and mutation-tests self-consistent tampering.

## Local bounded presubmit

Local environment: macOS 26.6.1 arm64, Node.js 24.9.0, npm 11.6.0.

| Gate | Result |
|---|---|
| `npm test` | Passed. Fixture 128 passed/0 failed/2 intentional scale skips; object model 164/164; authorization runtime 23/23; authorization spec/package 15/15; format 32/32; vector audit 1/1; roadmap 7/7; report tooling 3/3. |
| Language-neutral mutation/auditor | Passed all canonicality, reassignment, complete-registry semantic drift, threat, roadmap, schema-binding, grant, privacy-document, and MIT-license mutations. |
| Runtime hostile boundary | Passed malformed/deep JSON, Unicode, path, registry, grant scope/replay, authorized-view, sandbox, invalid UTF-8, adapter overflow, timeout, process cleanup, and typed-failure tests. |
| Offline package contract | Both exact packages installed without network/private imports; installed CLI, API, types, license, reference runner, grant verification, and external adapter passed. |
| Hygiene | Generated checks, workflow YAML parsing, package license identity, `git diff --check`, and roadmap validation passed. |

## Packed artifacts and reports

The runner first created npm tarballs, then validated and normalized their tar
headers/checksums and portable gzip framing. A clean temporary consumer installed
the two retained archives offline and ran both public report paths.

| Retained package | SHA-256 on Linux, macOS, and Windows |
|---|---|
| `@opengamevcs/authorization-contract-v1` 1.0.0 | `766078f881bba7bd7f4e3657f506ce8270992667c425ec8054cf506e13170770` |
| `@opengamevcs/authorization-contract` 1.0.0 | `e28a0da4310b2bcdb12acdf6d39c55dea5221bdef451b15a601aaf63939b43c7` |

| Report | SHA-256 |
|---|---|
| Reference fixture | `e17eae166c192b59fa371664fe5c53a575047a9a6f8ad59af770b0345827222a` |
| External adapter protocol example | `269404d5d471e242e2074b8b920982d3d39c6bcc6c928ae0960fe2bc3f958d98` |

All six reports contain 30 passed/0 failed rows and the same result digest. The
comparator verifies closed rows, expected/actual codes, manifest and registry
authorities, report hashes, archive hashes, exact package identities, both
adapter classes, and cross-platform equality.

## Hosted jobs and retained evidence

| Job | ID | Result |
|---|---:|---|
| Packed conformance (macOS) | `95132548930` | Passed |
| Packed conformance (Ubuntu) | `95132548943` | Passed |
| Packed conformance (Windows) | `95132548987` | Passed |
| Six-report/platform comparison | `95132642377` | Passed |

| GitHub artifact | ID | Archive digest | Expiry |
|---|---:|---|---|
| `authorization-contract-Linux` | `9260055908` | `sha256:70ca3b65df20d2400ef0aa7b89e2743ccd2781877b61e9002f2d9de8767aee85` | 2026-09-15 |
| `authorization-contract-macOS` | `9260057802` | `sha256:25d76245f0907a27275cbc7d0f710db682013062327c2496154dc813f55afcfd` | 2026-09-15 |
| `authorization-contract-Windows` | `9260062905` | `sha256:25ce5b4e0271394fd6e5941fa8c72759372f1e65ddb1077790ea1da9a99b21fc` | 2026-09-15 |

GitHub's outer ZIP digests differ because artifact containers carry platform
metadata. The independently checked files inside them—including both package
tarballs and both reports—are byte-identical.

## Acceptance map

| Criterion | Evidence | Status |
|---|---|---|
| OGVCS-003-AC-01 | The [critical review](../../reviews/OGVCS-003-critical-review.md) validates every trust zone/flow, all grant and redaction boundaries, and executable mitigation for each critical/high threat. | Pass |
| OGVCS-003-AC-02 | All 30 abuse vectors execute; the catalog covers every named guessed-hash, replay, visibility, discovery, export, deduplication, sandbox, preview, and revocation category. | Pass |
| OGVCS-003-AC-03 | The independent validator exactly matches all 45 roadmap IDs to frozen public/protected surfaces, resources, permissions, and audit behaviors. | Pass |
| OGVCS-003-AC-04 | Two independent evaluators reproduce all 40 decisions for both packaged policies, including deny-overrides and every permission. | Pass |
| OGVCS-003-AC-05 | The [privacy review](../../../spec/authorization/v1/docs/privacy-review.md) covers collected identity/audit data, purpose, retention, access, minimization, redaction, and subject/operator controls. | Pass |

## Rollback and downstream use

Consumers pin both packages at 1.0.0 and compare the exact registry digest. A
defective release is withdrawn; v1 may remain only in deny-only compatibility
mode while a replacement dual-evaluates. Rollback never revives a revoked key,
credential, nonce, authority epoch, cache allow, lock receipt, or audit deletion.

OGVCS-009 owns production identity, policy persistence/evaluation, grant issue,
and audit storage. It must preserve this contract and pass the public adapter
suite through its actual server surfaces; the reference evaluator and synthetic
private key are not production components.
