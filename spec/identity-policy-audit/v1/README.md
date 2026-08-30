# OpenGameVCS identity, policy, and audit contract v1

This MIT-licensed `0.1.0` candidate is the first OGVCS-009 contract cut. It
defines only the new policy document, credential-state, authority-state, and
hash-chain record shapes plus bounded implementation limits. It imports rather
than reassigns the frozen OGVCS-003 permission, resource, decision, audit, and
transfer-grant vocabularies. It also pins the OGVCS-004 path authority, the
OGVCS-041 public protocol candidate, and the OGVCS-006 metadata contract.

The contract does not assign new public routes or `ProblemDetails` codes and
does not claim a production OIDC adapter, persistent secret store, latency SLO,
or complete service integration. Those remain later OGVCS-009 cuts.

```sh
node spec/identity-policy-audit/v1/source/generate.mjs --check
node spec/identity-policy-audit/v1/validate-spec.mjs
node --test spec/identity-policy-audit/v1/test/*.test.mjs
```
