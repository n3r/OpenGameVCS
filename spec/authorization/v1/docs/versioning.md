# Authorization contract v1 versioning and compatibility

## Version authorities

The npm package version, `manifest.json.contractVersion`, schema identifiers,
registry envelope versions, signing domain, and runner report version form one
compatibility boundary. Version 1.0.0 freezes:

- JSON field names, required fields, closed shapes, limits, and semantics;
- registry names, numeric codes, existing code-to-name assignments, and the
  complete canonical security semantics of every v1 registry document;
- deny-overrides policy composition and decision fingerprint input;
- transfer-grant claim semantics, canonical JSON encoding, Ed25519 algorithm,
  `OGVCS-AUTH-GRANT-V1\0` signing domain, request-root derivation, and
  `OGVCS-AUTH-REQUEST-ROOT-V1\0` root domain, plus the closed verifier-context
  schema and bounds;
- privacy/redaction, revocation, sandbox, and runner-protocol behavior; and
- the synthetic policy/vector expected results and registry-set digest.

Consumers pin major version 1 and compare the exact `registrySetSha256` used by
their conformance report. A report made against another digest is not comparable.

## Compatible changes

A patch release may clarify prose, add tests that preserve every existing
result, or fix packaging/tooling without changing a schema, registry assignment,
policy/vector result, signed preimage, or observable runtime contract.

A minor release may add a registry assignment, optional vector, or new schema
whose semantics are fail-closed for an older reader. Existing assignments are
immutable. An older reader encountering an unknown permission, resource,
credential, decision, audit class, claim field, or required behavior must deny
or reject; it must never interpret it as a nearby known value.

Generated artifacts, their hashes, the registry-set digest, and reports change
whenever a covered artifact changes. Documentation is shipped but is outside the
artifact digest unless explicitly inventoried by a future manifest version.

## Incompatible changes

The following require contract v2 and a new package major:

- reassigning/removing a registry code or widening an existing permission;
- changing policy composition, matching, path-prefix semantics, required
  context, or decision fingerprint input;
- changing a field from required to inferred, a denial into an allow, the
  authorized-view ordering model, or a privacy-safe disclosure boundary;
- changing grant canonicalization, algorithm, domain, required scope, replay,
  audience, epoch, or validity semantics;
- accepting an artifact previously rejected by a closed schema in a way an old
  implementation cannot safely ignore; or
- weakening revocation, audit, tenant isolation, or sandbox ceilings.

## Evolution procedure

1. Record the security decision in a new accepted ADR and update architecture
   ownership.
2. Generate a new package/version and retain the prior package for explicit
   deny-only compatibility.
3. Publish old/new registries, schemas, vectors, and digest; run both evaluators
   over the same bounded synthetic inputs.
4. Investigate every result difference. Security widening requires explicit
   review and migration authorization.
5. During rollout, consumers advertise exact versions and registry digests;
   mismatches fail closed. Never silently negotiate to broader authority.
6. Retire v1 only after sessions, grants, caches, lock receipts, and replicas
   cannot present v1 authority. Advancing the authority epoch may enforce the
   cutover.

Rollback restores only code capable of validating the still-current contract.
It cannot resurrect revoked credentials, old epochs, removed audit evidence, or
broad grants. If a replacement contract cannot be evaluated, protected
operations remain disabled or deny.
