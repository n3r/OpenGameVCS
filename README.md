# OpenGameVCS

[![Fixture generator](https://github.com/n3r/OpenGameVCS/actions/workflows/fixture-generator.yml/badge.svg)](https://github.com/n3r/OpenGameVCS/actions/workflows/fixture-generator.yml)
[![Object model](https://github.com/n3r/OpenGameVCS/actions/workflows/object-model.yml/badge.svg)](https://github.com/n3r/OpenGameVCS/actions/workflows/object-model.yml)
[![Authorization](https://github.com/n3r/OpenGameVCS/actions/workflows/authorization-contract.yml/badge.svg)](https://github.com/n3r/OpenGameVCS/actions/workflows/authorization-contract.yml)
[![Path and filesystem](https://github.com/n3r/OpenGameVCS/actions/workflows/path-filesystem.yml/badge.svg)](https://github.com/n3r/OpenGameVCS/actions/workflows/path-filesystem.yml)
[![Protocol](https://github.com/n3r/OpenGameVCS/actions/workflows/protocol-baseline.yml/badge.svg)](https://github.com/n3r/OpenGameVCS/actions/workflows/protocol-baseline.yml)
[![Benchmark and faults](https://github.com/n3r/OpenGameVCS/actions/workflows/benchmark-fault-harness.yml/badge.svg)](https://github.com/n3r/OpenGameVCS/actions/workflows/benchmark-fault-harness.yml)

OpenGameVCS is an open-source, game-development-focused version-control system
under active development. Its target architecture is a hybrid centralized VCS
for source code and original assets, with content-addressed immutable history,
stable file identity, atomic snapshots, large-file streaming, explicit locking,
selective materialization, and open versioned formats.

> [!IMPORTANT]
> The **R0 engineering foundation is complete** and **R1 Developer Preview is
> now under active implementation**. This is not yet a complete end-user VCS:
> the production repository service, native workspace client, atomic submit,
> selective sync, and lock workflow have not passed the R1 release gate. See the
> [delivery roadmap](prd/ROADMAP.md) for the exact boundary.

## Current status

All six R0 software PRDs are complete: deterministic workload fixtures, the
repository format and independent JavaScript/Rust object codecs, authorization
and filesystem contracts, the public protocol baseline, generated bindings,
and the benchmark/fault harness. Their source-bound conformance evidence is
retained under [`docs/evidence/`](docs/evidence/).

R1 implementation is proceeding in parallel behind versioned contracts.
Bounded staged workspace publication is complete with retained three-OS
evidence; chunking/content manifests and repository metadata remain candidate
work. Object transfer and identity/policy are being security-reviewed before
integration. Incomplete R1 PRDs remain in [`prd/todo/`](prd/todo/) until their
implementation and retained evidence satisfy the PRD's completion criteria.

The broader R0 release gate also calls for external design-partner confirmation
that the synthetic Unreal- and Unity-like profiles cover material production
workflows. Completion of the repository's engineering artifacts does not claim
that external program prerequisite has occurred.

### R1 delivery

| Area | Current boundary | PRD |
|---|---|---|
| Repository metadata | Versioned metadata contract and PostgreSQL schema candidate; transactional adapter and live database evidence remain under review | [OGVCS-006](prd/todo/OGVCS-006-repository-metadata-snapshot-service.md) |
| Workspace publication | Bounded, journaled staged-stream publication is complete with exact offline package identities and retained Linux/macOS/Windows evidence | [OGVCS-046](prd/done/OGVCS-046-bounded-staged-workspace-publication.md) |
| Chunking and manifests | Candidate language-neutral contract plus JavaScript/Rust implementations; production profile ratification and final scale evidence remain open | [OGVCS-007](prd/todo/OGVCS-007-chunking-content-manifest-engine.md) |
| Object transfer | Resumable-transfer candidate is in correctness and security hardening; it is not integrated into the supported root workspace yet | [OGVCS-008](prd/todo/OGVCS-008-object-storage-transfer-service.md) |
| Identity and policy | Security-reviewed deny-overrides policy/audit candidate is integrated; production stores, real OIDC, and endpoint/API binding remain open | [OGVCS-009](prd/todo/OGVCS-009-identity-path-authorization-audit.md) |

The next integration milestone is a security-reviewed metadata, object-transfer,
and authorization service boundary. That unlocks atomic submit (OGVCS-010) and
the native workspace client (OGVCS-011). The large 1 TiB/100 GiB campaigns are
kept out of pull-request CI and run only at the scheduled final/major-release
gate.

## What is included

| Area | Delivered R0 artifact | Start here |
|---|---|---|
| Synthetic workloads | Deterministic code-heavy, Unreal-like, Unity-like, large-binary, and global-studio fixture generation | [Fixture generator](foundation/fixture-generator/README.md) |
| Repository data | Ratified format v1, registries, canonical vectors, JavaScript codec/CLI, and independent Rust codec | [Format](spec/repository-format/v1/README.md) · [JavaScript](core/object-model/js/README.md) · [Rust](core/object-model/rust/README.md) |
| Authorization | Language-neutral contract, threat corpus, JavaScript bindings, and external-adapter runner | [Contract](spec/authorization/v1/README.md) · [Runtime](core/authz-contract/js/README.md) |
| Paths and workspaces | Portable path/case rules, collision and materialization planning, transactional Node filesystem adapter, and watcher model | [Contract](spec/path-filesystem/v1/README.md) · [Runtime](core/paths-filesystem/js/README.md) |
| Public protocol | Versioned schemas and registries, bounded reference runtime, independent adapter, and generated C++, C#, Rust, and TypeScript models | [Contract](spec/protocols/v1/README.md) · [Runtime](foundation/protocol-baseline/js/README.md) · [Bindings](foundation/protocol-baseline/bindings/README.md) |
| Performance and faults | Reproducible benchmark authority, cache/network profiles, fault injection, process driver, and transactional result bundles | [Contract](spec/benchmark-fault/v1/README.md) · [Harness](foundation/benchmark-fault-harness/README.md) |

The JavaScript implementations expose the development CLIs `ogvcs-fixture`,
`ogvcs-object`, `ogvcs-authz`, `ogvcs-path`, `ogvcs-protocol`, and
`ogvcs-benchmark`. These are foundation and conformance tools, not a production
replacement for the future OpenGameVCS client.

## Requirements

- Node.js 22 or newer and npm.
- Rust 1.82 when building or testing the Rust object-model implementation.
- Linux, macOS, or Windows. The ordinary conformance matrix covers all three.

No package requires network access at runtime. The retained release evidence
also exercises packed, offline consumers.

## Quick start

```sh
git clone https://github.com/n3r/OpenGameVCS.git
cd OpenGameVCS
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

`npm test` runs the bounded workspace, contract, vector, report, package, and
roadmap suites. It does **not** run the million-entry or logical 1 TiB exact-scale
campaigns.

To inspect the synthetic workload profiles without materializing a fixture:

```sh
node foundation/fixture-generator/bin/ogvcs-fixture.mjs list
```

To test the Rust codec directly:

```sh
cargo test --manifest-path core/object-model/rust/Cargo.toml --locked
```

## Common development commands

| Command | Purpose |
|---|---|
| `npm test` | Run the complete bounded repository suite |
| `npm run test:vectors` | Independently verify repository-format vectors and tamper detection |
| `npm run test:roadmap` | Validate PRD lifecycle, dependencies, evidence links, and documentation links |
| `npm run test:object-model:js` | Test the JavaScript repository codec |
| `npm run test:authz` | Test authorization bindings and threat-runner behavior |
| `npm run test:identity` | Test the candidate identity, policy, grant, and audit runtime |
| `npm run test:path` | Test path and workspace filesystem behavior |
| `npm run test:protocol` | Test the protocol reference runtime |
| `npm run test:benchmark` | Test the benchmark and fault harness |

Exact-scale tests are deliberately isolated in
[`object-model-scale.yml`](.github/workflows/object-model-scale.yml). They are
scheduled for the monthly or major-release campaign, run JavaScript and Rust in
parallel, and are not part of pull-request CI. The latest durable exact-scale
evidence is recorded in the [OGVCS-002 evidence packet](docs/evidence/OGVCS-002/README.md).

## Repository layout

| Path | Purpose |
|---|---|
| [`architecture.md`](architecture.md) | Target system architecture and non-negotiable invariants |
| [`adr/`](adr/) | Accepted and proposed architecture decisions |
| [`spec/`](spec/) | Language-neutral contracts, registries, schemas, and vectors |
| [`core/`](core/) | Core JavaScript and Rust reference implementations |
| [`foundation/`](foundation/) | Fixture, protocol, binding, and benchmark tooling |
| [`prd/`](prd/) | Delivery roadmap, active PRDs, completed PRDs, and lifecycle rules |
| [`docs/changelog/`](docs/changelog/) | Human-readable delivery records by PRD |
| [`docs/evidence/`](docs/evidence/) | Source-bound completion and conformance evidence |
| [`tools/`](tools/) | Independent validators, report comparators, package checks, and generators |

## Architecture and change control

The [architecture baseline](architecture.md) defines the target product and
shared invariants. Normative behavior lives in versioned specifications and
registries under [`spec/`](spec/); implementations must not silently replace
those authorities with implementation behavior.

Work is planned as one independently reviewable PRD at a time. Read the
[PRD system](prd/README.md), [roadmap](prd/ROADMAP.md), and applicable
[architecture decisions](adr/README.md) before changing a public format,
identity rule, protocol, trust boundary, or compatibility guarantee.

## License

OpenGameVCS is licensed under the [MIT License](LICENSE). Individual packaged
specifications also retain applicable third-party notices and provenance files.
