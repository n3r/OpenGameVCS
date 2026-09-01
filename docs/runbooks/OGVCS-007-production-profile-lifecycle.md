# OGVCS-007 production-profile lifecycle cut

**State:** prepared, not executed
**Profile:** `chunking.opengamevcs/gear-fastcdc-1m@1`
**Production writes:** disabled

This runbook is the exact read-before-write, ratification, and rollback plan for
the first OGVCS-007 chunking profile. Preparing this plan does not authorize the
registry mutation. The shared OGVCS-002 registry currently has no row for the
profile, ADR-0016 remains Proposed, the packaged profile says
`proposed-not-production-write-eligible`, and
`commitProductionManifest()` therefore fails before any publication callback.

## Gates that must all be green

Do not edit the shared registry or enable a writer until one reviewed source
revision satisfies every gate below.

1. The JavaScript and Rust golden, fragmentation, malformed, reconstruction,
   compare, resource, and property suites pass on Linux, macOS, and Windows.
   The six reports must be aggregated by the bounded workflow; no scale job is
   part of that workflow.
2. The exact revision passes packed/offline installation and execution without
   npm, crates.io, or another network dependency after the package inputs have
   been assembled.
3. The OGVCS-008 production acceptor routes every kind-2
   `ContentManifestV1` transition through the package-owned
   `commitProductionManifest()` boundary. It must obtain a full OGVCS-007
   verification receipt from the stored manifest and exact chunk source,
   require the complete OGVCS-002 registry snapshot, and make the lifecycle
   `available` transition only from the boundary's commit callback. A missing,
   forged, reused, wrong-manifest, wrong-verifier, wrong-workspace, or
   arbitrary-boundary receipt must reach neither durable object publication nor
   lifecycle availability. Pre-commit failure must abort once; a settled
   durable commit remains authoritative.
4. The independently verified bounded packet remains green with seven samples,
   seven summaries, five OGVCS-005 threshold evaluations, seven successful
   retained captures, exact process-peak provenance, and
   `exactScaleExecuted: false`. Re-run both the OGVCS-005 base verifier and the
   OGVCS-007 bounded-product verifier against that separate OGVCS-005 bundle.
5. OGVCS-007-AC-03 is run as the final acceptance gate on the same source
   revision: the 100-GiB fixture completes within the declared CPU and memory
   bounds, with observed whole-process peak memory and no temporary whole-file
   duplication. The independent OGVCS-007 verifier must accept each exact-scale
   implementation bundle, then the branded comparator must accept those two
   verified inputs. The OGVCS-005 verifier does not accept this distinct schema.
   This campaign is not a PR check and is not replaced by the bounded packet. Dispatch
   `.github/workflows/chunking-manifest-scale.yml` only with the explicit
   confirmation or a reviewed `ogvcs-007-scale-*` release tag. Retain the two
   implementation reports carrying the same workflow-supplied source
   revision, both self-contained flat publication records, both independent
   validation records, and the comparator output that binds their hashes and
   proves identical result projections. A prepared or
   locally syntax-checked harness is not evidence that this gate passed.
6. Maintainers explicitly accept the immutable ADR-0016 tuple and its measured
   poor-reuse results for compressed and encrypted/random content.

The protected workflow retains its reviewed raw-report command surface. Its
comparison adapter validates both reports, publishes and verifies both
current-source-bound bundle directories, writes self-contained flat
publication and validation JSON records matched by the existing upload glob,
and compares only the resulting verified brands. The flat record embeds the
exact manifest, projection, and report bytes, so the publisher environment and
source-set projection survive artifact retention even if the floating Node 24
patch later changes. This wiring has only bounded hostile dry-run proof; it has
not been dispatched at 100 GiB. A bundle's `sourceRevision` remains explicitly
`workflow-supplied-not-git-bound` and is not producer-origin authentication.

## Exact authority mutation

After all gates pass, add exactly this new, lexicographically placed row to
`spec/repository-format/v1/registries/profiles.json`:

```json
{
  "family": "chunking",
  "id": "gear-fastcdc-1m",
  "major": 1,
  "namespace": "chunking.opengamevcs",
  "owner": "OGVCS-007",
  "productionWriteAllowed": true,
  "state": "ratified"
}
```

The row is additive and enters directly as `ratified`; no shared candidate row
exists. Do not first add a `conformance-only` row: the frozen OGVCS-002
lifecycle permits an existing assignment only to remain in its state or move
to `deprecated`, so a later `conformance-only` to `ratified` edit would be
invalid.

In the same reviewed authority cut:

- change ADR-0016 from Proposed to Accepted;
- change the packaged profile lifecycle marker and its schema/independent
  validator from `proposed-not-production-write-eligible` to
  `ratified-production-write-eligible`;
- change the chunking contract/package version from `0.1.0-rc.1` to `1.0.0`;
- update JavaScript and Rust package release versions only through their normal
  release policy; package versions do not alter the profile identity;
- retain all old-reader support, vectors, and the exact profile tuple.

## Mechanical regeneration order

Run regeneration in dependency order. Review every diff; never hand-copy a
digest from console output without its generating authority in the same change.

1. Generate the repository-format vectors with
   `node tools/reference-vector-generator/generate.mjs`. Read the new registry
   set digest from
   `spec/repository-format/v1/vectors/registries/live-snapshot.json`, update the
   generated Rust `BUNDLED_REGISTRY_SET_DIGEST`, and synchronize both packaged
   registry trees with the JavaScript and Rust `scripts/sync-registries.mjs`
   tools.
2. Regenerate the accepted chunking contract with
   `node spec/chunking-manifest/v1/scripts/generate.mjs`.
3. Refresh the protocol contract and bindings because protocol pins the
   repository-format vector manifest with
   `node foundation/protocol-baseline/codegen/generate.mjs`.
4. Regenerate `spec/benchmark-fault/v1`, which pins the chunking, protocol, and
   repository-format manifests, with
   `node spec/benchmark-fault/v1/source/generate.mjs`.
5. Regenerate `spec/repository-metadata/v1`, which pins benchmark, protocol,
   and repository-format authority, with
   `node spec/repository-metadata/v1/source/generate.mjs`.
6. Regenerate `spec/identity-policy-audit/v1`, which pins repository-metadata
   and protocol authority, with
   `node spec/identity-policy-audit/v1/source/generate.mjs`.
7. Rebuild any conformance/evidence packet whose authenticated source or
   predecessor set includes a changed file. Never reuse the pre-ratification
   source-set or bundle digest as post-ratification evidence.

At minimum, the repository-format independent validator and vector verifier,
object-model JavaScript and Rust tests, chunking JavaScript and Rust tests,
protocol tests, benchmark contract/harness tests, repository-metadata tests,
identity tests, packed/offline tests, and the six-leg bounded workflow must pass
from the resulting clean revision.

## Enablement and rollback

Deploy readers, verification receipts, and the OGVCS-008 acceptor before the
registry cut reaches any writer. Enable new writes behind a reversible switch
only after the regenerated authority is deployed everywhere required to read
the profile.

Rollback disables new profile writes and OGVCS-008 availability transitions.
It does not delete or demote the registry row, reinterpret manifests, remove
the reader, or rechunk existing content. Already durable manifests remain
readable and verifiable under the immutable profile. If a defect makes the
profile unsafe for future writes, a later authority change may deprecate the
row while retaining read support; it must never mutate the profile tuple.
