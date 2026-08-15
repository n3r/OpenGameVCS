# `ogvcs-fixture`

`ogvcs-fixture` creates deterministic, wholly synthetic game-repository fixtures. It ships as the dependency-free `@opengamevcs/fixture-generator` Node package, with a command-line interface, a reusable library, and versioned public JSON Schemas.

The tool performs no network requests, telemetry, uploads, or service discovery. Generation, inspection, and verification need only Node.js 22 or newer and local filesystem access. Package acquisition is separate from runtime operation.

## Install and verify

From a released package archive:

```sh
npm install --offline --ignore-scripts --no-audit --no-fund ./opengamevcs-fixture-generator-1.0.0.tgz
./node_modules/.bin/ogvcs-fixture --help
```

In PowerShell, invoke the installed command shim as:

```powershell
.\node_modules\.bin\ogvcs-fixture.cmd --help
```

From this source directory, no dependency installation or build step is required:

```sh
node bin/ogvcs-fixture.mjs --help
npm test
npm pack --ignore-scripts
```

`npm pack` produces an installable tarball containing the executable, library, schemas, golden fixtures, examples, documentation, and license. The package has no install scripts and no runtime dependencies. To test the packed executable in a clean offline directory:

```sh
mkdir fixture-consumer
cd fixture-consumer
npm init --yes
npm install --offline --ignore-scripts --no-audit --no-fund ../opengamevcs-fixture-generator-1.0.0.tgz
./node_modules/.bin/ogvcs-fixture list
```

The equivalent final command in PowerShell is `.\node_modules\.bin\ogvcs-fixture.cmd list`.

## Quick start

All destinations—including `inspect` and `verify` positionals—are portable relative paths interpreted beneath the current working directory. Absolute, drive-qualified, and traversing paths are rejected before fixture access. Start with a destination that does not exist.

```sh
ogvcs-fixture list
ogvcs-fixture plan --profile unity-like --destination fixtures/unity-small
ogvcs-fixture generate --profile unity-like --seed ci-42 \
  --destination fixtures/unity-small
ogvcs-fixture inspect fixtures/unity-small
ogvcs-fixture verify fixtures/unity-small --deep
```

Successful commands except `--help` emit exactly one canonical JSON document on standard output. Errors emit one machine-readable JSON document on standard error and use a typed exit code. `generate --progress` additionally emits canonical NDJSON progress events on standard error; those events do not change fixture identity.

## Commands

### `list`

```sh
ogvcs-fixture list
```

Lists the built-in `code-heavy`, `unreal-like`, `unity-like`, `large-binary`, and `global-studio` profiles in stable identifier order. Each entry includes its version and public profile digest. `list --help` prints CLI help.

### `plan`

```sh
ogvcs-fixture plan --profile large-binary --seed planning-v1 \
  --destination fixtures/planned --path-count 10000 \
  --large-file-bytes 10737418240 --materialization index-only \
  --large-file-mode sparse
```

Resolves and returns the canonical request, request digest, representation warnings, and conservative logical-byte, streamed-large-byte, index-byte, physical-byte, duration, materialized-path, and peak-generator-memory estimates. The physical estimate separately exposes inventory, operations, duplicated scenario operations, groups, manifest-embedded groups, descriptors, control/checkpoint artifacts, materialized files, directory metadata, the largest atomic temporary, and publication metadata. `durationSeconds` covers the worst generation/resume invocation, including mandatory verification; separate standalone-verification phases and `acceptanceWorkflowDurationSeconds` cover the later explicit deep verification used by the acceptance workflow. Duration phases include path replay/materialization rebuild, operation replay, and the extra full-large-file validation pass. Planning does not create the destination. Estimates are planning inputs and preflight ceilings, not a filesystem reservation or a benchmark result.

### `generate`

```sh
ogvcs-fixture generate --profile code-heavy --seed ci-42 \
  --destination fixtures/code --progress
```

Generates the inventory, operation stream, scenario, group relationships, optional physical files, and final manifest. The manifest is published last. Use `--resume` only for a compatible interrupted stage or an already completed fixture produced from the identical canonical request.

### `inspect`

```sh
ogvcs-fixture inspect fixtures/code
```

Loads the ownership marker and self-digest-verified manifest, then reports identity, counts, digests, provenance, plan estimates, and representation modes. Inspection does not stream and re-derive every inventory item; use `verify` for that.

### `verify`

```sh
ogvcs-fixture verify fixtures/code
ogvcs-fixture verify fixtures/code --deep
```

Metadata verification re-derives the logical inventory, operation stream, groups, scenario contract, counts, and tree digests, validates all public artifact shapes and containment, and checks workspace structure. `--deep` additionally hashes materialized small files, verifies executable modes, re-hashes a fully materialized large file, and re-streams every version of a `stream-verified` large file. Sparse extents are checked in either mode; an index-only or virtual representation has no omitted physical bytes to hash.

## Request options

The following options are accepted by `plan` and `generate`. A `--request` document can be combined with field overrides, but cannot be combined with `--preset`.

| Option | Meaning |
|---|---|
| `--request <file>` | Read a `FixtureRequest` JSON document (maximum 2 MiB). |
| `--preset <small\|reference-scale>` | Use bounded presubmit parameters (`small`) or the one-million-path/100-GiB reference request. |
| `--profile <name>` | Select one of the five profile identifiers listed above. |
| `--profile-version <version>` | Select the profile contract version; currently `2.0.0`. |
| `--seed <text>` | Set the deterministic NFC seed. |
| `--destination <relative/path>` | Set a portable relative destination using `/` separators. |
| `--path-count <integer>` | Set the number of logical inventory paths. |
| `--history-operations <integer>` | Set the ordered operation count. |
| `--large-file-bytes <decimal>` | Set the mutable large file's logical byte length. |
| `--max-depth <integer>` | Bound logical path depth from 2 through 64 segments. |
| `--checkpoint-every <integer>` | Set the number of path/operation records between durable checkpoints. |
| `--materialization <full\|sampled\|index-only>` | Select physical representation for ordinary inventory paths. |
| `--materialized-path-limit <integer>` | Bound ordinary physical files in `sampled` mode. |
| `--large-file-mode <full\|sparse\|stream-verified\|virtual>` | Select the large-file representation independently. |
| `--negative-cases` | Enable Unity-like missing/duplicate-sidecar cases. Invalid for other profiles. |
| `--no-negative-cases` | Disable Unity-like missing/duplicate-sidecar cases. Invalid for other profiles. |
| `--help`, `-h` | Print help without running the command. |

`generate` additionally accepts `--resume` and `--progress`. `inspect` accepts one destination positional argument plus `--help`. `verify` accepts one destination positional argument plus `--deep` and `--help`. The top-level forms `ogvcs-fixture`, `ogvcs-fixture help`, `ogvcs-fixture --help`, and `ogvcs-fixture -h` print help.

Numeric command-line values use canonical non-negative decimal notation. Schema and implementation limits are enforced before generation. A request file also carries the generator version, profile version, schema-version expectations, all feature flags and generation extensions, and optional resource limits, so the stored `fixture-request.json` is the exact reproducibility contract.

## Representation semantics

Logical fixture identity comes from the canonical request, inventory, operations, group relationships, and deterministic content recipes. Physical materialization is explicit:

| Path mode | Physical result |
|---|---|
| `full` | Every eligible ordinary inventory path is written below `files/`. The large file still follows `--large-file-mode`. |
| `sampled` | A deterministic bounded subset of ordinary paths is written, up to `--materialized-path-limit`; all paths remain in `inventory.ndjson`. |
| `index-only` | Ordinary paths exist only as logical inventory records; they are not physical files. |

| Large-file mode | Physical result |
|---|---|
| `full` | Every configured version is streamed and hashed; the final version is written to a physical file. This consumes the logical file size and `verify --deep` reads the file and re-derives every version. |
| `sparse` | A file with the requested apparent length and deterministic checked extents is created. Verification re-derives the exact extent offsets, lengths, and digests from the canonical request rather than trusting the descriptor's choices. Holes do **not** represent fully materialized generated content. Because filesystem allocation varies and sparse support cannot be assumed portably, `plan` and `maximumPhysicalBytes` conservatively reserve the full logical length. The descriptor reports exact written extent payload separately from the worst-case allocation bound. |
| `stream-verified` | Every byte of every configured version is streamed and hashed into durable version digests, then re-streamed before publication. No large physical file or claimed physical bytes exist. |
| `virtual` | Only the deterministic recipe descriptor is written. No large physical file or claimed physical bytes exist. |

Therefore a one-million-path `index-only` run demonstrates a million logical path records, not a million filesystem inodes. A 100-GiB `sparse` or `virtual` run does not prove full-byte generation. `stream-verified` proves full deterministic byte generation and version digests without claiming physical storage. Choose `full` modes when a test specifically requires physical files or stored bytes.

## Determinism contract

Profile v2 uses canonical JSON, NFC portable logical paths, a domain-separated counter-based SHA-256 PRNG for identifiers and choices, an efficient random-access AES-256-CTR v2 fixture byte stream, structured semantic artifact generators, and stable ordered streams. AES-CTR is used for reproducible synthetic bytes, not secrecy. Given the same tool/profile versions and canonical request, locale, wall clock, host name, directory traversal order, scheduling, and operating-system randomness do not influence logical records or digests. The request digest includes the canonical destination; use the same relative destination when comparing complete request or manifest identities across hosts.

The manifest records separate path, content, operation, and tree digests, binds the large-file descriptor, and identifies every public schema. Consumers should compare the relevant manifest fields instead of filesystem allocation, timestamps, native separators, inode order, or sparse-file block counts. Pin both generator and profile versions: a future identity-affecting change must use a new version rather than silently changing v2 output. ADR-0007 records why the deficient pre-review profile v1 draft is unsupported.

All generator-derived paths, bytes, identities, groups, and operations carry `fully-synthetic` provenance, contain no external source identifiers, and currently use the profile license declaration `NOASSERTION`. They are not copies of Unity, Unreal Engine, or partner formats or assets. The canonical request is embedded for reproducibility, however, and its `seed` and `destination` are caller-supplied, uninspected metadata. Never place partner, customer, credential, or other sensitive identifiers in those fields. The manifest records this boundary as `requestMetadata: "caller-supplied-unattested"`; its negative external-identifier attestation applies only to generator-derived artifacts.

## Profile v2 semantics

- `code-heavy` emits valid source, script, configuration, and documentation bytes with byte-backed text versions plus coherent create/edit/branch/merge/rename/copy/delete operations and executable modes. Branch names are cycle-unique and branch/merge/delete references follow the revision actually produced when optional edits or branches are disabled.
- `unreal-like` emits synthetic package/map/sidecar magic, external-actor groups, source and configuration text, mutable versions, and linked lock acquisition/conflict/submit operations without vendor data or proprietary formats.
- `unity-like` emits text scene/prefab analogues, distinguishable binary imports, asset/`.meta` GUID relations, generated-cache exclusions, moves, an actually absent sidecar case, and one GUID shared by two distinct groups for the duplicate negative case. If `pathCount` truncates the final ordinary pair, its tail record is intentionally ungrouped and carries no GUID/negative relationship claim; Unreal package/map relationships follow the same complete-family rule.
- `large-binary` emits actual base/version byte streams, deterministic patch ranges and digests, locality, duplication, compression-class, and cross-version reuse metadata without buffering a complete file.
- `global-studio` emits linked selective-sync, lock lifecycle, submit, branch-update, review, CI, interruption, and network-condition parameters. Every scenario also carries deterministic identities, a deny-by-default synthetic ACL model, and an executable initial state declaring files, revisions, committed changes, branch heads, and locks. Operation consumers can replay FileID, revision, change-parent, branch-head, and lock transitions without private generator state.

Every named profile feature flag changes a promised path, content version, group, operation, scenario, or large-file recipe. Unity alone accepts the global `negative-cases` switch; disabling `asset-meta-pairs` also suppresses GUID and negative-sidecar relationship metadata because there is no sidecar relationship to classify. Relationship artifacts intentionally cover at most 10,000 deterministic groups; records beyond that coverage boundary have no group ID, so no inventory record can reference an undeclared group.

## Destination safety and recovery

Generation uses a sibling staging directory with a request-bound ownership marker, a durable request-bound initialization receipt that exists only until that marker is committed, and an exclusively created lock. Destination validation applies a single portable contract on every host: paths must be relative NFC `/`-separated names and cannot contain traversal, empty/dot segments, backslashes, controls, Windows-forbidden characters, alternate-data-stream colons, reserved DOS device names, or trailing dots/spaces. Each component is limited to both 255 UTF-16 code units and 255 UTF-8 bytes; the full relative path is limited to both 4096 UTF-16 code units and 4096 UTF-8 bytes. Those are lexical relative-path limits: the resolved current-directory plus destination/stage names must also fit the host filesystem's absolute-path limit. A host `ENAMETOOLONG` rejection is surfaced as typed `unsafe-destination`, never an internal error. Existing symlink or junction chains, incompatible/non-owned stages, unreceipted ownerless stages, non-empty destinations, destination races, stale-lock races, and live concurrent generators fail closed. Cleanup is limited to reserved artifact basenames or precisely formed atomic temporaries inside a verified request-owned stage; unknown names are preserved and rejected. The generator never treats arbitrary destination content as cleanup material.

Checkpoints bind the stage, request, sequence, item cursor, byte count, public checkpoint schema, and rolling digests. On explicit `--resume`, valid work is continued. Path-phase materialization is reconciled from the verified durable inventory cursor, including ordinary or physical-large files written just ahead of a crash checkpoint. Before any recursive rebuild/restart, every nested file and directory must match a canonical materialization path for the request; unknown nested or top-level content is preserved and makes recovery fail closed. Stored request/profile documents, POSIX modes, the complete large-file recipe/mode shape, and request-derived sparse extent layouts are also revalidated. Proven checkpoint/stream/control/mode/descriptor corruption causes owned derived artifacts to be restarted deterministically; resource limits, unsafe state, conflicts, and transient host I/O instead propagate without authorizing destructive restart. A rebuild interrupted by a resource limit remains checkpoint-resumable. Recovery parsers cap checkpoint/request/control documents at 2 MiB and NDJSON records at 64 KiB before parsing. A compatible completed destination is returned only after automatic deterministic deep verification; corruption fails with exit code 6.

The destination lock is installed from a fully synced candidate by a no-replace hard link, so its final pathname is never exposed with an empty or partial body. An explicit compatible resume removes precisely named stale candidates and can finish an empty stage initialization only when its durable sibling receipt exactly binds the request and derived stage name; an arbitrary empty directory is never adopted. Publication first deep-verifies the complete stage and its exact allowlist, atomically commits a request/stage/destination-bound sibling receipt, and only then reserves the destination name with an exclusive no-replace directory creation. The receipt is retired after the linked in-directory owner is durable. Verified regular files are hard-linked from the sibling stage into that new directory; directory trees are rebuilt with only verified linked files. This protocol requires the stage and destination to share a filesystem that supports regular-file hard links. Unsupported, read-only, cross-device, or hard-link-exhausted filesystems fail before commit as typed `unsafe-destination` errors. Directory entries are flushed where the host exposes that primitive. `manifest.json` is linked last and the destination is flushed again, making the manifest the commit marker. A failure before that commit leaves no completed fixture. A commit-flush failure removes the marker before returning an error; a later `--resume` removes a manifest-free reservation only when its owner and every file are proven to be links to the intact owned stage, or reclaims an exactly empty pre-owner reservation only when the durable publication receipt and intact owned stage prove it. The destination lock covers that recovery mutation as well as publication. Compatible guards left by dead processes use an atomic, monotonically generated recovery receipt keyed to the exact stale guard, so later contenders cannot reopen a closed recovery election; explicit resume also removes precisely formed dead guard candidates and superseded dead recovery epochs.

Once the commit succeeds, later cleanup cannot turn durable success into an error. A library or CLI result may include `postCommitWarnings`, containing only a stable `phase` and `code`, when stage cleanup, the caller's published-progress callback, or lock release could not be completed. The fixture is already committed in this case; automation should retain the warning. After deep-verifying the completed fixture, a later compatible `--resume` removes a leftover stage only when the entire owned stage is still the hard-linked twin of the destination. Changed or unknown content is preserved and reported as a `stage-reconciliation` warning.

Process signals have the usual acknowledgement boundary: `SIGINT` or `SIGTERM` can arrive after the manifest is durably committed but before the success document reaches stdout, so exit code 8 means the caller did not receive a success acknowledgement, not that publication is certainly absent. For an interrupted `generate`, automation SHALL retry the identical generation request with `--resume`; the completed-destination path performs deterministic deep verification and returns the committed result, while a genuinely incomplete run resumes from proven state. For `list`, `plan`, `inspect`, or `verify`, rerun the same command without adding `--resume`.

For automation, treat a missing final manifest as incomplete regardless of other files. Never manually move files into the hidden stage or remove its ownership/lock records.

The workspace-safety boundary requires that no actor with the same operating-system authority can concurrently mutate the workspace parent, stage, destination, or relevant ancestors, or preposition forged request-bound ownership/lock/receipt state. Within this boundary, exact marker/receipt and canonical-path matching is the proof that cleanup targets belong to the generator; it is not a historical attestation against a same-authority forger. A correctly timed or prepositioned actor with that capability is outside the supported boundary; no duration or repetition qualifier applies. Node's cross-platform filesystem API does not expose the directory-handle-relative `openat`/`renameat` family needed to make a stronger confinement claim consistently on Windows, macOS, and Linux. Run generation in a private workspace, container, or separate service account when local code is hostile. Within the supported boundary, untrusted request paths, pre-existing links/junctions, ordinary competing creators, concurrent generators, observed ancestor/stage replacement, incomplete publication, and injected persistence failures are rejected without overwriting unrelated data or exposing a completed manifest.

## Exit codes and error documents

| Code | Error type | Meaning |
|---:|---|---|
| `0` | success | Command completed or help was printed. |
| `2` | `usage` | Unknown command/option, missing positional argument, or malformed CLI value. |
| `3` | `invalid-request` | The resolved request violates its schema, version, feature, or resource bounds. |
| `4` | `unsafe-destination` | Destination/stage ownership, symlink, traversal, or overwrite safety failed. |
| `5` | `conflict` | A live/incompatible generator or lock conflicts with this request. |
| `6` | `integrity-failure` | A manifest, checkpoint, stream, descriptor, or generated item failed verification. |
| `7` | `resource-limit` | A configured duration/memory/physical-write limit or filesystem capacity stopped work. |
| `8` | `interrupted` | The process observed an interrupt before success acknowledgement; retry interrupted generation with the identical request plus `--resume`, or rerun the same non-generation command. |
| `70` | `internal` | An unexpected implementation or host error occurred. |

Error documents have this stable outer form:

```json
{"error":{"details":{},"exitCode":3,"message":"...","type":"invalid-request"},"ok":false,"schemaVersion":"ogvcs.fixture/cli-result/v1"}
```

Shell consumers should use the process exit code for control flow and parse the JSON for diagnostics. Human text and progress never appear on standard output during a machine-output command.

## Public schemas and artifacts

The package exports these Draft 2020-12 schemas:

- `@opengamevcs/fixture-generator/schemas/FixtureRequest.schema.json`
- `@opengamevcs/fixture-generator/schemas/WorkloadProfile.schema.json`
- `@opengamevcs/fixture-generator/schemas/OperationScenario.schema.json`
- `@opengamevcs/fixture-generator/schemas/FixtureManifest.schema.json`
- `@opengamevcs/fixture-generator/schemas/GenerationCheckpoint.schema.json`
- `@opengamevcs/fixture-generator/schemas/VerificationResult.schema.json`
- `@opengamevcs/fixture-generator/schemas/InventoryRecord.schema.json`
- `@opengamevcs/fixture-generator/schemas/GroupRelationships.schema.json`
- `@opengamevcs/fixture-generator/schemas/LargeFileDescriptor.schema.json`

The `x-ogvcs-normalization` and `x-ogvcs-portable-relative-path` keywords in these schemas are normative OpenGameVCS assertions, not informational annotations. Generic JSON Schema engines normally ignore unknown extension keywords; an independent consumer must register them with the semantics documented in the request/path contract or use the CLI at its documented ingestion/verification boundary. The portable-path assertion includes NFC, Unicode-scalar, UTF-16 and UTF-8 byte limits, Windows device/ADS, trailing-character, separator, absolute-path, and traversal rules that cannot all be expressed faithfully by a portable ECMA-262 `pattern` alone.

JSON Schema is the normative structural contract, but it cannot express every cross-record identity, reference, ordering, and uniqueness rule. `ogvcs-fixture verify --deep` (or the public `verifyFixture` function) is the normative semantic validator for group IDs/members, FileID and revision lineage, changes and branch heads, operation order, manifest bindings, and deterministic bytes. Standalone verification and inspection bootstrap from the 2 MiB-capped stored request, then construct their own deadline and separately reported `standaloneVerificationMemoryGrowthBytes` budget from that request and scale plan when the caller does not supply one; an explicit `maximumMemoryBytes` remains an absolute process-RSS limit. `peakGeneratorMemoryBytes` remains the absolute clean-process peak used by generation and scale acceptance, rather than being repurposed as a verifier-growth metric. Before whole-document parsing, these consumers cap control/profile/descriptor JSON at 2 MiB, groups and manifest JSON at 128 MiB, and reserve eight times the encoded size against the active memory budget.

A completed fixture exposes `fixture-request.json`, `workload-profile.json`, `inventory.ndjson`, `operations.ndjson`, `groups.json`, `scenario.json`, optional `large-file.json` and `files/`, the ownership marker, and final `manifest.json`. The canonical request and manifest bind all nine schema versions. Downstream tools should use those schemas, containment-checked paths referenced by the manifest, and CLI results. Hidden staging/checkpoint state and package `src/` modules are not consumer contracts.

The reusable library is available from the package root for in-process generator integrations:

```js
import {
  createRequest,
  generateFixture,
  inspectFixture,
  listProfiles,
  planFixture,
  verifyFixture,
} from '@opengamevcs/fixture-generator';
```

Black-box integrations should prefer the executable and schemas so they remain independent of generator implementation details.

## Reference scale workflow

Plan first and inspect the warnings and local quota:

```sh
ogvcs-fixture plan --preset reference-scale \
  --destination fixtures/reference-scale
```

The preset resolves to `large-binary@2.0.0`, 1,000,000 logical paths, 10,000 operations, three versions of a 100-GiB mutable file, `index-only` path representation, and `stream-verified` large-file representation. Generation streams and hashes 300 GiB of deterministic version bytes and the mandatory prepublication deep gate streams them again, while storing no large physical file. The plan reports 600 GiB of generator byte processing separately from physical disk use; the acceptance test's later explicit verification streams another 300 GiB and is budgeted separately. Its scale-dependent memory model currently gives the reference request a 970,606,592-byte (about 925.6-MiB) absolute peak-RSS ceiling while producing larger ceilings for larger path/operation requests and a fixed conservative floor for tiny requests. The acceptance test enforces separate generation and standalone-verification durations, their combined workflow ceiling, the planned memory, apparent/allocated artifact-byte ceilings, and the hard 1-GiB requirement. Peak RSS comes from the operating system's process high-water counter, so synchronous hashing loops cannot escape measurement.

Run the acceptance test portably from the repository root:

```sh
npm run test:scale --workspace @opengamevcs/fixture-generator
```

PowerShell uses the same package script (or `npm.cmd` when command shims are not resolved automatically):

```powershell
npm.cmd run test:scale --workspace @opengamevcs/fixture-generator
```

```sh
ogvcs-fixture generate --preset reference-scale \
  --destination fixtures/reference-scale --resume --progress
ogvcs-fixture verify fixtures/reference-scale --deep
```

To store the final 100-GiB version physically as well, override the large-file representation and reserve the full disk/time envelope:

```sh
ogvcs-fixture plan --preset reference-scale --large-file-mode full \
  --destination fixtures/reference-scale-full
ogvcs-fixture generate --preset reference-scale --large-file-mode full \
  --destination fixtures/reference-scale-full --resume --progress
ogvcs-fixture verify fixtures/reference-scale-full --deep
```

To require one million physical ordinary files as well, also select `--materialization full`; this is a separate, much heavier filesystem test.

## Black-box examples

Both bundled examples discover and consume every installed profile through documented flags. They invoke the executable and read only public schemas, manifests, and artifacts; neither imports `src/`.

After installing the package, choose new relative workspaces:

```sh
node node_modules/@opengamevcs/fixture-generator/examples/object-mapping.mjs \
  --workspace example-output/object-mapping
node node_modules/@opengamevcs/fixture-generator/examples/workload-driver.mjs \
  --workspace example-output/workload-driver
```

From this source directory, point them at the local executable:

```sh
node examples/object-mapping.mjs --cli ./bin/ogvcs-fixture.mjs \
  --workspace example-output/object-mapping
node examples/workload-driver.mjs --cli ./bin/ogvcs-fixture.mjs \
  --workspace example-output/workload-driver
```

Each example emits one stable JSON summary on standard output and leaves its fixtures intact for inspection. Use a new workspace for another run; the examples intentionally do not delete generated or unrelated files.
