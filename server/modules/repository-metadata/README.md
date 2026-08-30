# `ogvcs-repository-metadata`

This non-published Rust crate is the first OGVCS-006 module cut. It freezes the
typed domain errors, transaction-composable service ports, opaque consistency
token type, and authenticated PostgreSQL migration inventory. It intentionally
does not expose HTTP routes or contain a database driver yet.

Run static checks and tests:

```sh
node server/modules/repository-metadata/scripts/static-check.mjs
cargo fmt --manifest-path server/modules/repository-metadata/Cargo.toml --check
cargo test --manifest-path server/modules/repository-metadata/Cargo.toml
cargo clippy --manifest-path server/modules/repository-metadata/Cargo.toml --all-targets -- -D warnings
```

The SQL files are complete PostgreSQL transactions and can be applied in manifest
order to an empty PostgreSQL 15+ database with `psql -v ON_ERROR_STOP=1 -f ...`.
The crate tests authenticate every SQL file, enforce phase order, and require the
tables/constraints that define OGVCS-006 ownership. A live database adapter and
container job are deliberately deferred to the next tranche.
