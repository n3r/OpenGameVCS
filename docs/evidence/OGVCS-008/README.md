# OGVCS-008 bounded candidate evidence

This packet preserves bounded hosted evidence for the object-transfer rc.6
candidate. It is not completion evidence for OGVCS-008 and does not change the
PRD's **Todo** status.

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
