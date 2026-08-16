# Authorization contract v1 threat model

## Security objective and scope

OpenGameVCS authorization v1 prevents a subject from learning or changing any
repository fact that the current tenant, repository, reference/snapshot, path or
`FileID`, resource, and operation policy does not explicitly allow. A content
hash is an integrity identity only. It is never proof of authorization.

This contract freezes security inputs, privacy-safe outcomes, transfer-grant
claims, trust zones, abuse vectors, revocation ceilings, and sandbox
requirements. OGVCS-009 will implement production authentication, policy
storage/evaluation, issuance, and audit persistence. A conforming implementation
MUST fail closed when required context, current policy, current epoch, or a
required dependency is unavailable.

The model follows the zero-trust principle that no subject or asset receives
implicit trust based on network location, and that authentication and
authorization occur before a session to an enterprise resource is established
([NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final)). It also follows
the deny-by-default and every-request authorization guidance in the
[OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

## Protected assets

The protected set includes:

- tenant and repository existence, names, membership, policy, and keys;
- references, snapshots, history topology, messages, counts, positions, and
  cursors;
- canonical paths, `FileID` values, lock ownership, review/check state, search
  hits, suggestions, events, previews, dependencies, and thumbnails;
- typed object identities, file sizes, manifests, chunks, and content bytes;
- session, service-token, transfer-grant, cache-decision, and offline-lock
  authority;
- policy/audit records, privileged reasons, identity correlations, retention,
  repair, export, and impersonation state; and
- acquisition credentials, KMS authority, sandbox inputs, outputs, and host
  resources.

Integrity identities and public contract files may be publicly visible. That
classification never widens access to protected repository instances.

## Trust zones and boundaries

The normative zone and flow assignments are in
`registries/trust-zones.json` and `registries/data-flows.json`.

| Zone | Assumption | Required boundary |
|---|---|---|
| Client device | Potentially stolen or compromised | Short-lived credentials, server validation, verified downloads, confined writes |
| Control plane | Trusted policy enforcer, not an infallible caller | Complete context, least privilege, deny-overrides, audit, fail closed |
| Metadata store | Authoritative data subject to corruption/operator error | Restricted principal, transactions, integrity verification, backup |
| Object store | Durability only; no user-authorization authority | Opaque tenant keys, immutable writes, scoped grants, end-to-end digest checks |
| Regional/local cache | Disposable and untrusted for policy/correctness | Offline grant verification, tenant namespace, audience and epoch binding |
| Sandbox worker | Hostile repository bytes or code | No credential/network, read-only declared input, isolated bounded scratch |
| Operator | Privileged insider risk | Separate roles, reason-bearing operations, append-only audit, dual control where policy requires |

Every cross-zone input is untrusted until bounded, structurally validated, and
authorized. Services MUST NOT pass a broad service credential into a cache,
hook, importer parser, merge driver, or preview worker on a user's behalf.

## Threat actors and capabilities

The machine registry covers external attackers, malicious or compromised
users, restricted users, administrators, auditors, build identities,
compromised services, cache operators, hostile import files, plugins, hooks,
preview parsers, stolen devices, and confused-deputy services. Their assumed
capabilities include guessing logged hashes; replaying captured requests and
grants; submitting crafted repository data; controlling their own request
ordering and timing; observing response codes, sizes, counts, cursors, and
latency; operating a cache or build identity within its nominal scope; and
attempting privileged operations through compromised credentials.

The model does not assume compromise of the current control-plane signing key,
the active metadata transaction boundary, or the tenant KMS root. Such a
compromise is an incident-recovery and key/epoch-rotation event, not a condition
under which ordinary authorization can remain sound.

## Frozen security invariants

1. Authorization evaluates the full canonical request context. A missing,
   malformed, stale, or unavailable input denies.
2. Policy composition is `deny-overrides-v1`: any matching deny wins; an allow
   requires an explicit matching allow; no match denies.
3. Discovery is a distinct permission. A denial exposes no path, existence,
   size, identity, history, message, dependency, lock, branch, search, event,
   thumbnail, policy, or grant-claim field.
4. Lists, history, reviews, events, search, ranking, facets, counts, pagination,
   and cursors operate on the authorized input view. Post-filtering a global
   result is forbidden.
5. Deduplication, encryption, quotas, purge, metrics, and cache namespaces are
   tenant scoped. Cross-tenant equality queries and content-derived keys are
   forbidden.
6. Content transfer requires a current, signed, audience-bound, operation-bound,
   tenant/repository-bound, epoch/key-generation-bound grant. Object identity
   alone confers no authority.
7. Privileged operations use distinct permissions, require a bounded reason,
   and append an approved redacted audit event.
8. Untrusted tools receive no credential or network by default and cannot make
   output authoritative without independent validation and authorization.

Explicit policy denial and absence of an allow rule share the public
`DENY_NOT_AUTHORIZED` response. Internal policy matching detail is audit-only;
the public decision surface cannot be used to enumerate policy coverage.

## Transfer-grant threat boundary

The conformance envelope uses Ed25519 as specified by
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), over the exact bytes
`"OGVCS-AUTH-GRANT-V1\0" || canonical-json(claims)`. It binds issuer, key ID
and generation, authority epoch, subject, tenant, repository, permission,
operation, audience, issuance/expiry, nonce/replay mode, and either an explicit
object set or bounded request root. A request root is exactly
`"sha256:" || hex(SHA-256("OGVCS-AUTH-REQUEST-ROOT-V1\0" ||
canonical-json(sorted-unique-object-ids)))`. The verifier obtains that bounded
object-ID plan from its own authenticated request state, recomputes the root,
and requires the requested object to be a member. A caller-provided root string
alone is never membership evidence. Verifiers reject an unknown algorithm,
malformed claims, invalid signature, stale epoch/key generation, wrong audience,
wrong scope or plan membership, invalid time window, or consumed single-use
nonce.

The verification key is selected only from trusted local issuer metadata by the
signed `keyId` and `keyGeneration`; it is never accepted from a grant holder.
The verifier context independently supplies the currently accepted key ID and
generation, and both must match the signed claims before use.

The five-minute v1 validity ceiling bounds offline revocation. Production token
transport may use OAuth mechanisms, but it must preserve the scope and audience
properties and the security practices of
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700). The static private key in the
vectors is synthetic conformance material and MUST NOT be trusted or installed
in any deployment.

## Abuse coverage and residual risk

`vectors/abuse-catalog.json` executes guessed-hash access, path/search/event
enumeration, mixed history/review visibility, export completeness/projection,
cross-tenant deduplication, cache replay/audience/epoch, token revocation,
confused-deputy scope, build/service overreach, privileged reason enforcement,
audit redaction, hook/preview/import escape requirements, and encryption/KMS
separation.

All critical and high threats in `registries/threats.json` are mitigated by at
least one executable abuse case. The sole accepted medium risk is aggregate
timing inference across repeated bounded requests. Its owner is
OGVCS-009/OGVCS-035; response-class padding, rate limits, and aggregate
monitoring reduce it; OGVCS-035 must close or re-accept it before its recorded
expiry. No unresolved critical or high risk is accepted for v1.

## Security-review checklist

A review of a consuming implementation must confirm:

- every protected surface maps to the frozen permission/resource registry;
- policy evaluation binds all context and uses deny-overrides;
- denial serialization contains only a registered privacy-safe code and
  correlation material;
- authorized-view construction precedes every aggregate or cursor operation;
- grant issuance follows current policy evaluation and grant verification is
  complete and fail-closed;
- tenant deduplication/KMS/cache keys cannot form equality oracles;
- privileged reasons and audit redaction/append-only integrity are enforced;
- every credential class meets the revocation table; and
- sandbox enforcement is outside the hostile process and output is treated as
  untrusted until validated.
