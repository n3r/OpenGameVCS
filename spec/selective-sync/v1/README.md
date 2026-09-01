# Selective-sync selection kernel contract rc.1

This package freezes a language-neutral, private candidate boundary for the
pure OGVCS-013 path-selection kernel. It defines ordered `exact` and `subtree`
rules, last-match semantics, the three `full`, `metadata-only`, and
`absent-by-spec` classes, bounded metadata input, and deterministic binary
projection/digest framing.

The kernel consumes an immutable metadata projection supplied by a separate
caller. Snapshot, repository-settings, consistency-token, path profile,
repository case mode, host platform, selection-spec, metadata projection, and
record-count bindings are all included in the evaluation binding digest.
`subtree` matches its named directory itself and all component descendants.
When exact and subtree rules both match the same path, the rule with the
greatest ordinal wins; match kind has no implicit priority.

The projection is deliberately untrusted. The contract does not authenticate
or filter the input tree, fetch objects, mutate a workspace, update an index,
construct a sync plan, or grant entry to any production operation. A `full`
record may repeat the caller-provided content identity and logical byte count.
`metadata-only` and `absent-by-spec` records encode no entry/content identity
or payload request. The input-only `entryDigest` is an opaque metadata-record
commitment and is never copied into any output record.

The stream header necessarily contains the caller-declared record count and a
binding digest that incorporates the caller-declared metadata projection
digest before the records have been checked. It is not a receipt. Every header
and record byte remains discard-only until EOF, exact count, canonical order,
collision, total-byte, metadata-digest, sink-write, and final flush checks all
finish and a summary is returned. Any error returns no summary.

At the language-neutral sink boundary, completed fragment emission carries no
application value. The Node adapter expresses that assignment by requiring
each synchronous `write` and `flush` callback to return `undefined`; the Rust
adapter expresses the same assignment with `Write::write_all` and `flush`
returning `Ok(())`. A Rust `Write::write` byte count is consumed internally by
`write_all` and is not an application-level result.

This rc.1 package does not register a network or CLI surface and does not make
OGVCS-013 complete. Authentication, request-root integration, permission-
filtered tree production, target resolution, dry-run planning, object
transfer/cache, filesystem staging/application, native watcher integration,
and the one-million-path performance target remain outside this tranche.

Run the independent Node checker with Node 24:

```text
npm test --workspace @opengamevcs/selective-sync-kernel-contract-v1
```
