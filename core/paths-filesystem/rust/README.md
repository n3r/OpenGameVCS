# OGVCS-004 Rust path-contract binding

This dependency-minimal crate implements the pure repository-path, Unicode
case-fold, collision-key, and component-prefix portion of the ratified
OGVCS-004 v1 authority. It is generated from and pinned to the exact companion
manifest, Unicode 16.0.0 `CaseFolding.txt`, profile registry, and fold/path/
collision vectors. It does not implement workspace mutation, materialization,
or watcher behavior.

The crate source is MIT-licensed. The generated Unicode table remains covered
by Unicode-DFS-2016; the bundled `unicode/UNICODE-LICENSE.txt` and
`THIRD_PARTY_NOTICES.md` retain that notice.

The binding rejects non-NFC input instead of normalizing it. `case-folded`
uses only the pinned full default `C` and `F` mappings, excludes `S` and Turkic
`T`, and performs no normalization after folding. Repository keys retain the
exact `ogvcs-path-key-v1` segment-length encoding. `RepositoryPrefix` matches
whole components and exposes bytewise half-open bounds for a future persisted
evaluator; database callers must use binary/C collation.

Regenerate or verify the authenticated derived files with:

```text
node core/paths-filesystem/rust/scripts/sync-contract.mjs
node core/paths-filesystem/rust/scripts/sync-contract.mjs --check
```

The Rust crate is a prerequisite used by the bounded OGVCS-009 direct
participant. It does not implement aggregate authorization or complete
OGVCS-009.
