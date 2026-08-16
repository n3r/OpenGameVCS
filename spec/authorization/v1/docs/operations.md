# Authorization contract v1 operations

## Decision operation

For every protected operation, the enforcement point constructs an
`AuthorizationRequest` with the authenticated actor/credential class and
generation, tenant, repository, permission, resource type and canonical
path/`FileID`/object identity when applicable, reference and snapshot context,
policy generation, and authority epoch. Canonicalization and resource lookup do
not reveal protected values before discovery authorization.

Evaluation order is:

1. bound and validate the complete closed request;
2. verify active credential generation/status and current authority epoch;
3. bind current policy generation and load the exact versioned policy;
4. require a reason for a privileged permission;
5. collect matching rules, apply any matching deny, otherwise an explicit allow,
   otherwise deny;
6. produce only the registered public-safe code and deterministic fingerprint;
7. construct any response from the authorized view; and
8. append required privileged audit in the same authoritative transaction or
   fail the operation.

Policy or audit dependency failure denies. A client-side preflight is advisory;
submit/finalize, grant issue, lock mutation, review promotion, export, repair,
retention, policy change, and impersonation re-evaluate current server state.

## Credential and revocation ceilings

| Class | Maximum validity | Maximum revocation lag | Epoch bound |
|---|---:|---:|---|
| Human session | 8 hours | 5 minutes | Yes |
| Service token | 1 hour | 1 minute | Yes |
| Transfer grant | 5 minutes | 5 minutes | Yes |
| Cached allow decision | 30 seconds | 30 seconds | Yes |
| Offline lock receipt | 5 minutes | 5 minutes | Yes |

Implementations may issue shorter values. A revocation generation/credential
status change invalidates new evaluations within the lag ceiling. Advancing the
authority epoch immediately makes prior-epoch sessions, service tokens, grants,
caches, and lock receipts unusable at the next enforcement checkpoint. A cached
deny may be retained no longer than its declared cache class; cached allows bind
subject, credential generation, tenant/repository, canonical resource context,
permission, policy generation, and epoch.

## Grant issuance and verification

The control plane issues a grant only after a current allow decision and scopes
it to the minimal audience/operation/object set or bounded request root. It uses
an active signing key generation and a validity no longer than five minutes.
Single-use issuance records nonce state before returning success.

The v1 request root is a lower-case `sha256:` digest over the ASCII domain
`OGVCS-AUTH-REQUEST-ROOT-V1\0` followed by canonical JSON of the lexically
sorted, unique object-ID set. The verification context supplies the complete
bounded set from verifier-owned authenticated transfer-plan state. It is capped
at 32,768 IDs and by the contract's 4 MiB canonical-JSON ceiling. The verifier
recomputes the digest and checks membership; neither an untrusted root string nor
an untrusted membership boolean is sufficient authority.

A cache/origin verifies closed claims and envelope, algorithm/key ID, signature,
current accepted key generation and authority epoch, time window, subject,
tenant/repository, operation/permission, audience, object/request scope, and
replay state. It consumes a single-use nonce atomically with first use. Any
failure returns the registered generic denial and no object-existence signal.
The verification JWK MUST be loaded from trusted issuer configuration indexed
by the signed key ID and generation; a key included or selected by the holder is
not acceptable verification material.

Key rotation publishes new verification material before issue, increments key
generation, stops old-key issue, retains old public keys only through outstanding
grant expiry, and then removes them. Compromise advances key generation and,
when authority may be affected, the authority epoch.

## Privileged operations and audit

`export`, `policy.administer`, `lock.force-unlock`, `repair`,
`retention.delete`, `audit.read`, and `impersonate` are separate permissions and
require nonempty bounded reasons. The event class registry chooses the event and
maximum detail. Audit append is tenant scoped, append-only for application
roles, correlated to the operation, redacted before persistence, and included in
backup/integrity verification. Audit access produces `audit.accessed` under its
own authorization.

Alerts are required for authority/key generation changes; policy and role
changes; impersonation; force unlock; retention deletion; repair/restore;
privileged export; repeated grant replay/audience/epoch failures; unusual
cross-tenant probes; and sandbox escapes/resource kills. Alerts use identifiers
available only to authorized responders and keep protected values out of pager
text.

## Metrics and logs

Permitted default metrics are decision latency by bounded operation/result
class, public-safe code count, grant issue/reject/revoke count, cache decision
age, privileged event count, and sandbox resource/termination class. Tenant
identity may use a deployment-local bounded pseudonym where cardinality permits.

Default logs exclude canonical paths, `FileID`, object/content hash, size,
history/message, thumbnail/dependency, lock owner, branch, search/event payload,
policy text, group membership, token, grant claims/signature, encryption key,
and raw audit reason. Diagnostic expansion is a separately authorized and
audited workflow.

## Failure, outage, and recovery

- Authentication, policy, generation, audit, KMS, nonce, or required store
  unavailable: deny; do not use a stale broad allow.
- Cache unavailable or grant invalid: fall back to an authorized origin flow or
  deny; never serve by object ID alone.
- Sandbox cannot enforce its profile: deny execution.
- Audit append fails for a privileged mutation: abort the mutation.
- DR promotion: fence old authority, increment epoch, reject old claims, expire
  lock receipts, and require session/lock reacquisition.
- Suspected disclosure: revoke credential/key generation, advance epoch when
  scope is uncertain, quarantine affected cache/storage, preserve redacted audit
  evidence, and run the complete abuse catalog before reopening.

Contract upgrades dual-evaluate for observation only until explicitly activated.
Differences never broaden authority automatically. Rollback is deny-only and
does not restore revoked state.
