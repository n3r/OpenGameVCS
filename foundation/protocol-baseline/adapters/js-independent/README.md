# OpenGameVCS protocol independent adapter

This MIT-licensed process is intentionally independent of the reference
runtime. It accepts only canonical `RunnerCase` JSONL on standard input and
emits a `RunnerHello` followed by one canonical `AdapterResult` per case. The
reference harness audits and digests each bounded trace before projecting the
sanitized `RunnerResult`. Oracle fields from normative scenario rows are never
sent to this process.

```text
node bin/ogvcs-protocol-independent-adapter.mjs --contract /path/to/protocol-contract-v1
```

`--contract` points to the manifest-authenticated adapter execution view: the
manifest plus its exact `profiles/`, `registries/`, and `schemas/` authority.
It must not contain vectors, expected outcomes, or predecessor vector data.
Transfer authorization is evaluated from the carried grant envelope, bounded
context, and public JWK by the public OGVCS-003 verifier.
