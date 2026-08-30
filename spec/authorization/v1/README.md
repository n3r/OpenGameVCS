# OpenGameVCS authorization contract v1

This package is the language-neutral authorization, non-disclosure, transfer
grant, audit, revocation, sandbox, and threat-test authority for OpenGameVCS.
It contains closed JSON Schemas, immutable registries, two reference policies,
synthetic golden vectors, and documentation. It does not authenticate users,
store policy, issue production grants, or persist audit events.

The public executable runner and JavaScript bindings are distributed separately
as `@opengamevcs/authorization-contract`. Consumers must pin both packages to
major version 1 and compare the packaged registry-set digest before executing a
conformance campaign.

All content is synthetic and MIT-licensed. The included signing key is expressly
conformance-only and must never be trusted in a deployment.

Transfer roots are domain-separated SHA-256 commitments to canonical sorted
object-ID sets. Verification requires the complete bounded set from trusted
local transfer-plan state and independently checks both its root and the current
object's membership; possession of a root identifier alone conveys no authority.

## Contents

- `schemas/` contains the ten closed Draft 2020-12 request, decision, policy,
  grant, audit, sandbox, threat-vector, and runner-report schemas.
- `registries/` contains 13 immutable vocabularies, including all 45
  authorization-bearing roadmap surfaces. Public maintenance PRD OGVCS-046 is
  subsumed by the existing OGVCS-004 path/filesystem surface because it adds no
  protected resource, permission, audit behavior, or authorization decision.
  Each registered surface carries its public/protected classification and audit
  behavior.
- `policies/` contains the internal-team and restricted-outsourcer fixtures.
- `vectors/` contains 40 policy decisions, 30 abuse cases, 16 grant cases, the
  mixed-visibility authorized view, and their digest manifest.
- `docs/` freezes the threat model, privacy review, versioning, runner protocol,
  sandbox boundary, and operational/revocation behavior.

Run the independent auditor and mutation tests from a checkout:

```sh
npm test --workspace @opengamevcs/authorization-contract-v1
```

The auditor does not import the generator. It independently recalculates every
artifact and registry-set digest, policy decision/fingerprint, grant signature
outcome, authorized view, roadmap mapping, threat/abuse coverage, revocation
ceiling, sandbox invariant, documentation inventory, and MIT license identity.

Normative documents:

- [Threat model](docs/threat-model.md)
- [Privacy review](docs/privacy-review.md)
- [Versioning](docs/versioning.md)
- [Runner protocol](docs/runner-protocol.md)
- [Sandbox contract](docs/sandbox-contract.md)
- [Operations](docs/operations.md)
