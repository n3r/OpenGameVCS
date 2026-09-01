# OGVCS-007 exact-scale evidence authority

This OGVCS-007-owned candidate contract defines the release-only 100-GiB
corpus, verification task, profile, threshold authority, and strict raw-report
schema. It consumes the completed OGVCS-005 benchmark/fault manifest and the
candidate OGVCS-007 chunking manifest by exact digest; it does not amend either
predecessor or register an OGVCS-005 task/profile.

Bundles are content-addressed and verified against the current source
inventory; they do not attest producer identity or origin. The protected
workflow supplies its checked-out revision, but this verifier does not
independently bind that claim to Git, so `sourceRevision` remains explicitly
`workflow-supplied-not-git-bound`. The machine-readable profile and every
verified projection carry that limitation.

The task requires exact source consumption, canonical manifest emission,
chunk/whole-file accounting, cross-implementation result parity, resource
bounds, and cleanup. It does not claim a second 100-GiB manifest reread or
referenced-chunk reconstruction pass that the runners do not perform.
The `/proc/self/io` `wchar` counter remains inside the measured scope through
scratch cleanup and is capped at 512 MiB: four times the combined 64-MiB ledger
and 64-MiB manifest maxima, allowing bounded overhead while remaining
materially below a 100-GiB whole-file temporary. Unlike `write_bytes`, `wchar`
counts bytes handed to write-like syscalls even when writeback is cancelled by
deleting a temporary file; physical `write_bytes` remains separate telemetry.

The authority is pre-scale infrastructure only. Ordinary tests use tiny report
projections and must never execute either exact-scale runner. No checked-in
100-GiB evidence, release-profile ratification, workflow dispatch, or
production-write eligibility is claimed. Without changing its protected
workflow definition, the comparison command's existing raw-report flags now
publish and verify both bundle directories before comparison. It also emits
one self-contained canonical retained-publication JSON and one validation JSON
per implementation. Those four files, both raw reports, and the comparison all
match the workflow's existing `artifacts/*.json` retention rule. Each retained
publication embeds the exact manifest, projection, and report bytes, including
the publisher environment and current-source-set digest, so later verification
does not depend on reconstructing a floating Node 24 patch environment.

Regenerate and independently validate with:

```sh
node spec/chunking-scale-evidence/v1/source/generate.mjs --check
node spec/chunking-scale-evidence/v1/validate-spec.mjs
node --test spec/chunking-scale-evidence/v1/test/validate-spec.test.mjs
```
