# Authorization contract v1 privacy review

## Decision

Authorization v1 collects only the identity, policy-generation, resource-class,
operation, and correlation facts needed to make or audit a decision. Protected
paths, `FileID` values, object hashes, content sizes, policy text, grant claims,
history, messages, thumbnails, dependencies, lock owners, branch names, search
hits, and event payloads are prohibited from default denial responses, metrics,
and logs.

This review covers the contract and fixture data. OGVCS-009 must select concrete
storage retention and access-control implementations within the ceilings below.

## Data inventory

| Data | Purpose | Default representation | Retention ceiling/trigger | Access |
|---|---|---|---|---|
| Actor ID and group/class inputs | Current authorization decision | In-memory request only | End of request; production policy store separately governed | Policy evaluator only |
| Actor pseudonym | Privileged audit correlation | `pseudonym:` plus tenant-scoped 128-bit value | Audit policy; default 400 days, configurable shorter | `audit.read` plus approved event-class view |
| Tenant/repository IDs | Scope and confused-deputy defense | Canonical identifiers | Decision lifetime; audit events per audit policy | Evaluator; authorized auditor |
| Permission/resource class | Decide and aggregate safe metrics | Closed low-cardinality registry values | Metrics 30 days; audit policy for privileged events | Operators for aggregates; authorized auditors for events |
| Policy/authority generation | Detect stale decisions and credentials | Positive integers | Decision/cache TTL; privileged audit per policy | Evaluator and authorized auditor |
| Privacy-safe outcome code | Client behavior, monitoring, review | Closed `ALLOW_*`/`DENY_*` code | Metrics 30 days; request logs at most 30 days | Subject receives code; operators receive aggregates |
| Privileged reason | Accountability for destructive/elevated work | Bounded human text, no secrets or content | Default 400 days; legal policy may require a documented override | Authorized auditor only; never metrics |
| Correlation/event ID | Trace one operation without protected payload | Opaque bounded ID | Same as containing log/event | Request subject/support and authorized auditor as policy permits |
| Transfer-grant claims | Cache/offline scope verification | Signed canonical envelope | No longer than five-minute validity plus replay/incident window; caches erase promptly | Issuer, intended subject, bound audience verifier |
| Nonce/replay state | Single-use enforcement | Tenant/key-scoped digest or opaque nonce | Grant expiry plus clock-skew window | Grant issuer/verifier only |

The synthetic golden repository, identities, object IDs, paths, policy fixtures,
and Ed25519 key are non-production test data.

## Purpose limitation and minimization

- Decision responses expose `allowed`, a public-safe code, the bound policy
  generation/version, request ID, and deterministic fingerprint. They do not
  echo actor, path, `FileID`, object ID, claims, matched rules, or policy text.
- Denied discovery is indistinguishable by payload shape from a missing or
  otherwise unavailable protected resource. Internal telemetry may distinguish
  operational classes only through registered low-cardinality codes.
- A decision fingerprint is an integrity/comparison value, not a public lookup
  key. It must not be indexed for tenant-crossing queries or logged in globally
  accessible telemetry.
- Audit events contain actor pseudonyms rather than display names, and the
  event-class registry chooses the approved target detail. Implementations must
  not place free-form protected values into `details` or `reason`.
- Transfer grants carry only scope needed by the audience. They never carry
  group membership, full policy, hidden path lists, or broader repository
  inventory.

## Authorized-view redaction

For search, history, reviews, events, suggestions, facets, previews, and export
projections, authorization is an input selection operation, not an output
filter. The service must:

1. evaluate each candidate or an equivalent proven policy partition;
2. remove unauthorized candidates and protected fields;
3. compute count, order, rank, parent projection, grouping, pagination, and
   cursors only over the remaining authorized set; and
4. serialize no hidden total, gap, original position, cross-view cursor, or
   cache-hit signal.

Messages and parent links appear only when independently authorized. A hidden
parent does not produce an identifier-shaped placeholder. A fidelity export
fails atomically if its selected closure is not fully authorized; a projection
uses a distinct projection identity and never claims fidelity.

Timing is not perfectly redactable. Implementations use bounded response
classes, avoid work proportional to hidden result counts after a denial, apply
rate limits, and monitor repeated probes. The residual aggregate timing risk is
the accepted medium threat recorded in `registries/threats.json`.

## Audit access and integrity

Audit read/export is itself privileged, reason-bearing, and audited. Query
authorization runs before event selection, count, and pagination. Event-class
redaction in `registries/audit-classes.json` is a maximum disclosure, not a
minimum. Audit persistence must be append-only from application roles, integrity
protected/checkpointed by OGVCS-009, tenant scoped, and excluded from ordinary
search and analytics stores.

Break-glass or impersonation access requires a distinct permission, explicit
reason, bounded duration, separate start/end events, and subject/operator
pseudonyms. It never silently changes the audited actor.

## Subject and operator controls

- Subjects receive stable public-safe decision codes and correlation IDs, not
  hidden-resource explanations.
- Tenant security administrators can configure shorter retention, rotate
  pseudonymization keys with a documented correlation boundary, revoke
  credentials, and advance the authority epoch.
- Access and deletion requests follow tenant policy and legal holds; deletion
  of audit evidence is a separately authorized `retention.delete` operation.
- Diagnostics and support bundles require explicit authorization and apply the
  same redaction rules before collection.

## Review outcome

The contract is privacy-safe when consumers preserve authorized-view-before-
aggregate ordering, the forbidden response/log field set, tenant scoping,
bounded retention, and separate audit authorization. Any implementation that
logs protected request fields by default, post-filters global results, exposes
hidden counts/cursors, or treats a hash as a secret is non-conforming.
