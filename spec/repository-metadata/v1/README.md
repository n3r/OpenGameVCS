# OpenGameVCS repository metadata contract v1

This MIT-licensed `0.2.0` candidate contract is the language-neutral OGVCS-006 domain
authority for repository settings, immutable metadata, reference CAS, bounded
tree/history traversal, FileID lifetime state, idempotency status, consistency
tokens, and transactional outbox consumption.

It is intentionally separate from the frozen OGVCS-041 R0 protocol authority.
The operation and error registries define module/domain behavior; they do not
add `ProblemDetails` codes or public routes to R0. A later protocol release must
bind routes, status codes, and media types before public metadata routes are
enabled. `MetadataHttpResponse` is only the framework-neutral JSON/stream result
carrier for that future adapter; it does not make those assignments.

Generated JSON is canonical and authenticated by `manifest.json`:

```sh
node spec/repository-metadata/v1/source/generate.mjs --check
node spec/repository-metadata/v1/validate-spec.mjs
node --test spec/repository-metadata/v1/test/*.test.mjs
```

The object put/get operations describe a bounded canonical metadata byte stream.
They do not base64-expand a possible 512 MiB format object into an R0 JSON control
envelope. The eventual public carrier is a separately negotiated protocol
decision.

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
