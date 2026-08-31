# OGVCS-008 S3 and logical-transfer hostile review

**Review date:** 2026-09-01

**Base:** `9ad6ce9`

**Verdict:** bounded candidate is ready for integration review; hosted and
exact-scale acceptance remain open

## Closed findings

- Backend trust does not rely on package exports or structural typing. Exact
  constructors reject subclasses, exact prototypes freeze at module evaluation,
  and service dispatch uses captured package-owned closures. Tests cover
  structural objects, proxies, own/prototype mutation before and after
  construction, and cross-instance/cross-adapter substitution.
- SigV4 query/header ordering uses explicit code-unit comparison. Published AWS
  GET-object and list-object vectors are exact; the hosted MinIO job supplies
  the compatible-service auth check.
- S3 listing derives shard-aware prefixes instead of scanning the full object
  namespace, validates each shard against the final SHA, and enforces page and
  result ceilings including +1.
- PUT acknowledgement, ETag, and existence are never durability. Conditional
  create is followed by exact metadata/checksum/body/ObjectID read-back before a
  receipt. Response loss converges; corrupt acknowledgement/read-back fails
  before lifecycle mutation. Multipart ETags are treated only as opaque CAS
  tokens.
- Generation/permit delete fencing is conditionally persisted before delete;
  prior receipt and observable absence are required, and same-fence response
  loss repairs without accepting a stale generation.
- Logical scale remains paged and bounded: exactly 100 GiB is 1,600 64-MiB
  descriptors (or 12,800 8-MiB objects in the manual run), with durable ledgers,
  no retransmission of verified chunks, and one-chunk reconstruction memory.
- Batch authorization precedes all existence checks. Grant, tenant, complete
  ordered object set, request root, generation, receipt, and pack offset are
  sealed. Tampering, duplicates/+1, and hidden early/middle/last objects disclose
  no partial layout.
- Durable unique quota reserve/commit/release is crash/replay stable. Event
  storage now enforces its record ceiling atomically. Metrics/events reject or
  omit object identity, paths, keys, grants, and credentials.
- The lifecycle adapter seam states whether it is atomic with repository
  metadata and preserves receipt-gated content-manifest availability. No v9
  table, reachability, GC, or OGVCS-010 claim is invented here.

## Evidence and open blockers

The generated contract independently verifies, runtime tests execute shared
filesystem/fake-S3 and hostile cases, and workflow policy proves exact scale is
manual-only. The live test is intentionally skipped offline. The MinIO artifact
release, URL, platform, and SHA-256 are in
`tools/object-transfer-minio-provenance.json` and checked by the Linux-only
loopback job without command tracing or credential output.

Do not move OGVCS-008 from Todo until a retained hosted MinIO run passes, the
manual exact 100-GiB interrupted run publishes whole-hash/throughput/RSS
evidence, and the separately owned repository-metadata lifecycle integration is
validated. Public/wire routes remain unassigned pending OGVCS-041.
