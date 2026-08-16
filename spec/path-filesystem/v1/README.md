# OpenGameVCS path and workspace filesystem contract v1

This package is the language-neutral authority for OGVCS-004. It freezes:

- repository joined-path and immutable case-mode behavior;
- Unicode 16.0.0 full default case folding from pinned `C`/`F` mappings;
- ratified portable, Windows, macOS, and Linux platform profiles;
- collision, materialization preflight, rename, atomic replacement, crash
  remnant, watcher cursor/gap, and reconciliation outcomes;
- closed JSON Schemas and stable error codes; and
- a cross-platform golden corpus with exact expected results.

It consumes OGVCS-002 canonical NFC segments, entry-kind/mode assignments,
`FileID`, tree bytes, and logical bundles. It never normalizes then accepts a
segment and never changes canonical object or hash preimages.

The public reference implementation is `@opengamevcs/path-filesystem`.
Package consumers use only files listed in this package; generation sources and
tests are deliberately excluded from the published archive. Run `npm test` in
the source package to regenerate-check, independently validate, mutation-test,
and package-test the authority offline.

See [`docs/path-contract.md`](docs/path-contract.md),
[`docs/workspace-safety.md`](docs/workspace-safety.md), and
[`docs/watcher-contract.md`](docs/watcher-contract.md) for the normative
behavior and threat boundaries.
