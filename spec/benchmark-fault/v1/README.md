# OpenGameVCS benchmark and fault contract v1

This MIT-licensed candidate contract fixes the task vocabulary, fault points,
cache and network states, bounded test-driver messages, public result bundle,
threshold format, and conformance corpus owned by OGVCS-005.

The process driver uses the registered OGVCS-041
`ogvcs.control.https-json@1` control profile with canonical JSON Lines framing.
`ogvcs.benchmark-fault-driver.test@1` is test-only: production deployments may
not enable its fault hooks. An incompatible driver is rejected from its
read-only hello before the harness sends a command or enables mutation.

The four harness profiles are `local-smoke`, `presubmit`, `nightly`, and
`release`. Presubmit is bounded and unprivileged. The complete release matrix
is schedulable, but expensive fixture-scale campaigns remain explicit manual
jobs and are not implied by ordinary conformance.

Public bundles retain the complete selected threshold authority and bounded raw
environment, sample, summary, fault, negative-suite, and conformance evidence.
Both publisher and verifier reproduce derived summaries, gate rows, and final
status rather than trusting claimed success fields.

Generate and verify the authority offline:

```sh
npm run generate
npm test
```

The manifest authenticates every generated schema, registry, profile,
threshold file, and vector, plus the exact OGVCS-001/002/003/004/041
predecessor authorities used by this candidate.
