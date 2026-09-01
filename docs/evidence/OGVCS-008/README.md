# OGVCS-008 bounded candidate evidence

This packet preserves bounded hosted evidence for the object-transfer rc.6
candidate. It is not completion evidence for OGVCS-008 and does not change the
PRD's **Todo** status.

## Current integration bounded revalidation

- Product source: [`70ef689187d7d7749e33348e472d9310b4bd0828`](https://github.com/n3r/OpenGameVCS/commit/70ef689187d7d7749e33348e472d9310b4bd0828)
- Hosted proof revision: [`17f1bfb5ad5738c77546736609c40c22a4d4cee5`](https://github.com/n3r/OpenGameVCS/commit/17f1bfb5ad5738c77546736609c40c22a4d4cee5)
- Workflow: [run 33502166522](https://github.com/n3r/OpenGameVCS/actions/runs/33502166522), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33502166522.json`](github-actions-run-33502166522.json)

The current integration product tree passed the complete bounded JavaScript
contract/runtime and packed-consumer lanes on Linux, macOS, and Windows. The
same run passed the shared backend behavior suite against pinned MinIO
`RELEASE.2025-09-07T16-13-09Z` after checking the downloaded binary's exact
SHA-256. This revalidates the later kind-2 production-candidate package and its
PostgreSQL projection vectors alongside the unchanged rc.6 backend contract.

GitHub could not manually dispatch this workflow before its path exists on the
default branch. The isolated `ogvcs008-r1-hosted-70ef689-v2` alias therefore
differs from the product source only by one nonsemantic comment in
`.github/workflows/object-transfer.yml`. The `core/object-transfer`,
`core/chunking-manifest`, and `spec/object-transfer` Git trees are byte-identical
between the two revisions; the machine record preserves their exact tree IDs.

This is bounded adapter conformance, not production service composition. It
does not add the JavaScript-to-Rust subject/scope mapper, a public route,
request-root closure, authenticated submit consumption, health/GC/delete
authority, production deployment, or the release-only interrupted 100-GiB
campaign. OGVCS-008 remains **Todo**.

## PostgreSQL availability-proof update

- Integrated implementation: [`31aa82eb4877b7b1bf62870202f4b76d2dcca10c`](https://github.com/n3r/OpenGameVCS/commit/31aa82eb4877b7b1bf62870202f4b76d2dcca10c)
- Hosted source: [`3827586d9d2f0cec489149b84b20eedf9c0bc03f`](https://github.com/n3r/OpenGameVCS/commit/3827586d9d2f0cec489149b84b20eedf9c0bc03f)
- Workflow: [run 33500174865](https://github.com/n3r/OpenGameVCS/actions/runs/33500174865), completed successfully on 2026-09-01
- Machine record: [`../OGVCS-006/github-actions-run-33500174865.json`](../OGVCS-006/github-actions-run-33500174865.json)

PostgreSQL 15 passed the route-less explicit content-manifest availability
matrix at the exact hosted source. The candidate binds a separately derived
lifecycle verification receipt to the exact manifest transition, authorizes
the full sorted explicit set in fixed pages before protected lookup, commits
the lifecycle application/fact/outbox/proof/identity pages in one caller-owned
SERIALIZABLE transaction, and reconciles a lost response only from the current
typed proof. The shared JavaScript/Rust vector keeps raw manifest SHA-256,
OGVCS-002 ObjectRef identity, production-statement digest, lifecycle receipt,
and committed-proof digest distinct.

This closes only the private PostgreSQL availability-proof boundary. The
production JavaScript-to-Rust subject/scope mapper, public transfer route,
request-root closure, S3/MinIO service composition, health/GC/delete authority,
authenticated submit consumption, and release-only 100-GiB campaign remain
open. OGVCS-008 therefore remains **Todo**.

## Hosted rc.6 boundary

- Integrated source: [`a36de6d516732ecb7699284b82f0d9c836246c7c`](https://github.com/n3r/OpenGameVCS/commit/a36de6d516732ecb7699284b82f0d9c836246c7c)
- Hosted proof revision: [`658733fed8d0c9902aae0bfa13c66898d2bf9003`](https://github.com/n3r/OpenGameVCS/commit/658733fed8d0c9902aae0bfa13c66898d2bf9003)
- Workflow: [run 33452796108](https://github.com/n3r/OpenGameVCS/actions/runs/33452796108), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33452796108.json`](github-actions-run-33452796108.json)

The run passed the JavaScript contract/runtime lane on Linux, macOS, and
Windows and the shared backend suite against the pinned MinIO
`RELEASE.2025-09-07T16-13-09Z` binary after verifying its SHA-256. Contract
`0.1.0-rc.6`, manifest SHA-256
`6748334b4cbc9b155941d8382b6a67c348f0612432a9555cfa215f62681af1d3`,
and artifact-set SHA-256
`8e96a6fc57aeabb9c3bd8a363b4bbb70b2bfc4832206b20c1581e92e463bec38`
were unchanged.

The first hosted attempt, run `33452480057`, exposed a Windows lock-release
inspection race in the durable quota test. Commit `a36de6d` now retries only an
exact wrapped `ENOENT` caused when the current owner removes the lock between a
contender's `EEXIST` and pinned recovery inspection; ACL, identity, symlink,
and every other storage error still fail closed. The full local suite and the
corrected four-job hosted run passed.

## Additive kind-2 acceptor evidence

The later package-only production-acceptor candidate adds a 13-case focused
suite in `core/object-transfer/js/test/content-manifest-production.test.mjs`.
The local bounded run passed all 13 cases, including durable manifest/chunk
verification, early/middle/last missing/corrupt/wrong-length/wrong-ID and
unauthorized dependencies, lifecycle changes around reads, dependency changes
at commit, precommit abort, commit-response loss and restart, forged available
state, mismatched commit response, registry/port/handle forgery, immutable
snapshots, and hostile adapter error redaction.

That evidence is candidate-only and non-scale. It uses an in-memory fake for the
owning repository-metadata transaction and a test-only cloned registry with the
profile row enabled; it does not mutate the shared registry. Dependency
authorization is the exact explicit signed grant set only, capped at 4,096
unique objects including the manifest. The port advertises
`requestRootDependencyClosure=false`. No real OGVCS-003/006/009 adapter or
public route was exercised, and this result cannot satisfy or authorize the
OGVCS-007 100-GiB ratification gate.

## Dispatch provenance

GitHub only registers a new workflow identity after its path exists on the
default branch. For this pre-merge proof, the isolated
`r1-object-transfer-hosted-dispatch` branch placed the unchanged object-transfer
jobs at the already registered repository-metadata workflow path. The hosted
revision differs from integrated source only at
`.github/workflows/repository-metadata.yml`. The `core/object-transfer` and
`spec/object-transfer` Git tree IDs match exactly; the alias is proof
scaffolding and is not part of the integration branch.

## Deliberately unclaimed

`exactScaleExecuted` is `false`. This run did not execute the release-only exact
100-GiB interrupted transfer/reconstruction campaign. It also does not claim
public OGVCS-041 routes, the same-transaction OGVCS-009/metadata lifecycle
bridge, authenticated OGVCS-010 publication, production KMS, reachability/GC,
or hosted production deployment.
