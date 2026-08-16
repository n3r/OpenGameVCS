# OpenGameVCS protocol contract v1

This package is the normative, application-neutral public protocol baseline for
OpenGameVCS. The candidate version is `1.0.0-rc.1`; it is not ratified
while the repository-format and path predecessors remain in validation.

The reference control profile is TLS 1.3 over HTTP/1.1 with bounded I-JSON,
RFC 8785 producer emission, semantic (not raw-input) fingerprints, identity
content coding, no redirected mutation, and canonical JSONL streams with an
explicit terminal. Negotiation selects protocol, schema, repository format,
authorization contract, path contract/profile, event, transfer, and extension
axes independently. A MACed receipt binds the selected tuple but grants no
authorization.

The transfer contract is only `ogvcs.transfer.range-resume-probe@1`: an
application-neutral range/resume probe. Production routes, sessions, packs,
compression, placement, and availability belong to OGVCS-008.

## Installed-package self-check

After installing or unpacking this package:

```sh
npm run check
npm test
```

Both commands run the shipped, self-contained contract validator and require no
repository checkout or network access.

## Repository regeneration

In an OpenGameVCS source checkout, regeneration is intentionally owned by
`foundation/protocol-baseline/codegen/generate.mjs`. Repository CI invokes
that generator with `--check`, then runs the packaged validator and the
repository-only tests. The generator is not part of this published contract
package.

Generated Rust, C++, C#, and TypeScript packages are type models and immutable
assignment constants only. They intentionally do not implement JSON, JSONL,
HTTP, TLS, MAC, cursor, authorization, or storage runtimes.

License: MIT.
