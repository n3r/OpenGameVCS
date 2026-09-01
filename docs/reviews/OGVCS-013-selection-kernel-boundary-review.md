# OGVCS-013 private selection-kernel rc.1 boundary review

## Decision

This tranche freezes and implements only a pure, private, untrusted selection
kernel. The language-neutral contract is under `spec/selective-sync/v1`; the
independent Node 24 checker and Rust 1.82 streaming evaluator reproduce the
same golden decisions and exact binary projection bytes.

The rule model is deliberately small and deterministic:

- rules have contiguous ordinals and use `exact` or component-bound `subtree`;
- `subtree` includes the named directory itself and all descendants;
- the matching rule with the greatest ordinal wins, including an exact versus
  subtree match at the same path;
- the only result classes are `full`, `metadata-only`, and `absent-by-spec`;
- duplicate scoped rules and repository/platform collision spellings fail;
- metadata input must have contiguous ordinals and strictly increasing exact
  OGVCS-004 repository collision keys.

The caller supplies immutable snapshot, settings, consistency-token,
path-profile, case-mode, platform, spec, metadata-projection, and count
bindings. This kernel verifies only their internal framing and equality. It
does not establish where the tree or bindings came from.

## Streaming and trust boundary

The Rust evaluator consumes one owned metadata record at a time and writes one
bounded fragment at a time. It retains a bounded compiled-rule trie and a
bounded platform-collision map; it never accepts or returns a 100,000-record
`Vec`. Both implementations enforce 100,000 records, 4,096 rules, per-record,
per-rule, collision-key, retained-key, input-total, output-total, logical-byte,
and sink-fragment ceilings.

The output header is emitted from caller-declared bindings before source EOF
and metadata-digest verification. Consequently all output is discard-only
until exact count/order/collision/byte/digest checks and sink flush complete and
a plain summary is returned. A source, cancellation, validation, sink-write,
or flush error returns no summary. The input-only `entryDigest` is never
emitted. `metadata-only` and `absent-by-spec` encode neither entry nor content
identity and cannot request payload.

Completed fragment emission has no application value across languages: the
Node callbacks return `undefined`, and Rust `write_all`/`flush` return `Ok(())`.
Rust partial-write counts are internal to `write_all`, not kernel results.

The exact 100,000 test uses generated records twice—once to derive the caller
projection commitment and once for evaluation—and a counting sink. It does
not retain projection bytes. The million-path target is intentionally not run
or claimed by this tranche.

## Explicit residuals

This candidate has no authentication or permission filtering, repository tree
producer, request-root integration, snapshot/head resolver, sync dry-run or
conflict policy, object transfer/cache, staging/application, workspace-index
generation switch, watcher authority, public native CLI command, network host,
route, or production entry brand. It does not address authorization-revocation
races, cache corruption/resume, crash-safe materialization, or NFR-01/02/03.

OGVCS-013 therefore remains **Todo**. No completion-evidence or public protocol
claim is added by this tranche.
