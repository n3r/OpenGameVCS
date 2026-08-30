# OpenGameVCS repository metadata contract v1

This MIT-licensed candidate contract is the language-neutral OGVCS-006 domain
authority for repository settings, immutable metadata, reference CAS, bounded
tree/history traversal, FileID lifetime state, idempotency status, consistency
tokens, and transactional outbox consumption.

It is intentionally separate from the frozen OGVCS-041 R0 protocol authority.
The operation and error registries define module/domain behavior; they do not
add `ProblemDetails` codes or public routes to R0. A later protocol release must
bind this contract before public metadata routes are enabled.

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
