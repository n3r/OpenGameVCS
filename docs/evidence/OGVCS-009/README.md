# OGVCS-009 aggregate-authorization candidate evidence

This packet preserves bounded hosted and exact local PostgreSQL evidence for
aggregate authorization v3. It is not completion evidence for OGVCS-009 and
does not change the PRD's **In development** status.

## Hosted v3 boundary

- Aggregate feature commit: [`436bd02ed3e10bb8975f20c6729ed66a2dd77165`](https://github.com/n3r/OpenGameVCS/commit/436bd02ed3e10bb8975f20c6729ed66a2dd77165)
- Hosted source: [`664bc0af1c53ded3bd85a4b262e246e187948c5f`](https://github.com/n3r/OpenGameVCS/commit/664bc0af1c53ded3bd85a4b262e246e187948c5f)
- Workflow: [run 33452552924](https://github.com/n3r/OpenGameVCS/actions/runs/33452552924), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33452552924.json`](github-actions-run-33452552924.json)

Node 24 contract/runtime tests passed on Linux, macOS, and Windows. Rust 1.82
locked tests and Clippy passed on macOS and Windows; Ubuntu additionally ran the
checked v1-to-v3 migrations, the ordinary PostgreSQL participant, and aggregate
receipt sealing/currentness/one-use tests against PostgreSQL 15.

## Exact local ceiling proof

At integrated source `a36de6d516732ecb7699284b82f0d9c836246c7c`,
the opt-in Rust 1.82/PostgreSQL 16 test streamed exactly 100,000 ordered
resources in 100 batches of at most 1,000, rejected resource 100,001 before
insertion, authorized the complete relational set, reconstructed the ordered
resource-digest projection with O(1) aggregate memory, and verified exactly
100,000 stored rows. It passed in 30.81 seconds. Ordinary hosted CI deliberately
keeps that test ignored, so `hostedExactScaleExecuted` is `false`.

## Deliberately unclaimed

The same-transaction repository lifecycle bridge, configured production OIDC
and KMS providers, external checkpoint/root authority, public-route adapters,
deployment SLO/fault evidence, and an end-to-end rollout remain open. The opaque
aggregate receipt is an internal authorization handoff, not an OGVCS-010
disaster-recovery or publication receipt.
