# OGVCS-045 source-only conformance models

This directory contains deterministic, non-hosted source models bound to
revision `22a6b801b6d32283dca8a6f8ca57a4d91a91296f` and canonical source-set
SHA-256 `2baa1c704468812d689783e95e0d07113c761b11cc42a9a0ecff493d49df0c98`.
They are schema and policy fixtures, not a new hosted run, live-Docker evidence,
kernel-isolation evidence, or public conformance admission.

- `portable-linux-source-model.json`, `portable-macos-source-model.json`, and
  `portable-windows-source-model.json` run exactly the private importer and
  converter source model. Each records two `VALIDATED` results, the exact
  closed launch keys, an absent credential canary, no publication capability,
  `platformBinding: "declared-target-only"`, and `retentionStatus:
  "not-hosted"`. They do not prove host isolation on any named platform.
- `portable-source-model-comparison.json` proves those three closed reports
  have the same cases, claim boundary, revision, source inventory, and
  source-set digest.
- `linux-v2-source-only-schema-fixture.json` preserves the 43 cases, runtime
  digest, and seccomp digest from the existing retained v1 report while testing
  the v2 source/control schema. Its controller and runtime-version fields are
  explicitly synthetic `unobserved` fixture values; it records
  `runtimeBinaryBinding: "unproven"` and makes no live Docker, complete
  controller-observation, or exact OCI binary claim.
- `kill-boundary-source-model.json` freezes the expected disposition for all
  13 test-only hard-kill hooks. It is explicitly `not-executed`; represented
  resources are quarantine-only, every case expects zero destructive daemon
  calls, and no automatic daemon cleanup is claimed.

The source revision must equal checked-out `HEAD` before a generator can read
any inventory member, and every inventory path must match that revision. The
portable comparator independently closes report/case/key prototypes, requires
Node 24, and rejects empty or forged equal reports against independently read
checked-out source evidence.

The historical v1 upload channel remains unchanged. A genuine Linux v2 report
still requires a future authorized live-Docker run that observes the complete
controller set and exact sanitized runtime version/commit. A genuine restart
report requires Linux `/proc` lease recovery plus all 13 child `SIGKILL`
cases. Uploading or retaining those new reports remains unexecuted pending
explicit disclosure authorization. OGVCS-045 remains Todo and AC-01 through
AC-05 remain open.
