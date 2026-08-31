# OpenGameVCS identity, policy, and audit contract v1

This MIT-licensed `0.2.0` candidate defines the OGVCS-009 developer-preview
contract boundary. It includes policy, credential, authority, hash-chain,
checkpoint-verified audit projection, OIDC provider/authentication transaction,
bootstrap recovery, policy mutation, revocation/epoch receipt, and
same-transaction authorization/decision-commitment shapes with bounded limits.
Audit projections omit tenant-global chain
positions and disclose only OGVCS-003 event-class-approved details. The
contract imports rather than reassigns the frozen OGVCS-003 permission,
resource, decision, audit, and transfer-grant vocabularies. It also pins the
OGVCS-004 path authority, the OGVCS-041 public protocol candidate, and the
OGVCS-006 metadata contract.

The public OIDC transaction record contains digests only; its private one-use
secret compartment is an adapter obligation and is not a public schema. The
transaction authorization view binds an authority-owned transaction identity,
credential/policy generations, exact resource checks and one ordinary decision
commitment. That commitment is deliberately not represented as a frozen
OGVCS-003 privileged `AuditEvent`.

The contract does not assign new public routes or `ProblemDetails` codes and
does not claim a production database/secret deployment, latency SLO, or
complete service integration. Those remain lifecycle gates.

```sh
node spec/identity-policy-audit/v1/source/generate.mjs --check
node spec/identity-policy-audit/v1/validate-spec.mjs
node --test spec/identity-policy-audit/v1/test/*.test.mjs
```
