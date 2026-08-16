# OpenGameVCS protocol-v1 generator

Dependency-free Node code generation for the numbered protocol model. Run
`node generate.mjs` to regenerate schemas, registries, vectors, manifests, and
the four standard-library-only type packages. Run `node generate.mjs --check`
to compare every expected byte without changing the workspace.

`model.mjs` is the sole semantic/assignment authority. `canonical.mjs` emits
RFC 8785 JSON and semantic fingerprints. `generate.mjs` rejects unknown type or
constraint features before output and never uses the network, timestamps,
absolute output paths, locale ordering, or remote plugins.

License: MIT.
