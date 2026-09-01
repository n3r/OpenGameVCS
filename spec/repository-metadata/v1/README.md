# OpenGameVCS repository metadata contract v1

This MIT-licensed `0.3.0` candidate contract is the language-neutral OGVCS-006
domain authority for repository settings, immutable metadata, reference CAS,
bounded tree/history traversal, FileID lifetime state, idempotency status,
consistency tokens, and transactional outbox consumption.

The candidate now imports the exact OGVCS-041 `ogvcs.control.https-json@1`
authority: `application/json`, its closed `RequestEnvelope` and
`ResponseEnvelope`, its authenticated negotiation receipt, and its registered
safe `ProblemDetails` tuples. The two OGVCS-041 registry identities remain
distinct: the artifact registry-set authenticates the imported authority,
while negotiation selections bind its negotiation registry-set.

All 22 operation identifiers have static `POST` path/status/media assignments
for interoperability and hostile-input testing. The `networkRoutes` inventory
is intentionally empty in v0.3. No production handler is claimed until a
dispatcher can derive the exact OGVCS-009 resource server-side, revalidate
identity and receipt currentness in the same transaction, and retain that
authorized brand through response construction. Consequently every exact
assigned method/path tuple currently closes as `PROTOCOL_UNSUPPORTED` before
parsing its control body, while an unknown path or wrong method remains
`PROTOCOL_MALFORMED`. `repository.list` additionally lacks a project-scoped authority;
repository creation lacks its all-or-nothing coordinator; object put/get lack
a metadata-owned bounded stream carrier; CAS, tombstone/restore, and submit
publication remain coordinator-owned; outbox operations remain internal.

`MetadataHttpResponse` is only an internal success body nested beneath the
OGVCS-041 response envelope. Negotiation verification alone cannot construct a
success response, and the candidate domain errors are not ratified OGVCS-041
problem codes.

Generated JSON is canonical and authenticated by `manifest.json`:

```sh
node spec/repository-metadata/v1/source/generate.mjs --check
node spec/repository-metadata/v1/validate-spec.mjs
node --test spec/repository-metadata/v1/test/*.test.mjs
```

The object put/get operations describe a bounded canonical metadata byte
stream. They do not base64-expand a possible 512 MiB format object into a JSON
control envelope. The eventual public carrier is a separately authenticated
protocol decision.

`file-id.allocate` returns a server-owned opaque `far1` receipt bound to the
authorized repository and authenticated scope. Native `create` and `copy`
registration must present that receipt; the FileID alone is never a bearer
credential. Restore continues to carry `null` in that field and remains subject
to its separate lifetime proof authority.

Idempotency status is resolved only inside the authenticated-scope digest
supplied by the authorization decision. That digest is intentionally absent from
every request and response schema. Outbox delivery is an internal exact-lease
CAS boundary, not an idempotency-key surface: a retry must retain the exact live
lease or be rejected without disclosing delivery state.

The syntax parser bounds each array, object, key, and string while decoding,
then enforces the OGVCS-041 global depth/node/aggregate limits and the tighter
body/extension `JsonValue` limits on the decoded value. Shared global counters
are not yet streaming/pre-allocation enforcement; this is an explicit
pre-network residual while `networkRoutes` is empty.
