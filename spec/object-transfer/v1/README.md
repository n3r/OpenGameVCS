# OpenGameVCS object-transfer contract v1 candidate

This MIT-licensed `0.1.0-rc.6` candidate defines bounded OGVCS-008 filesystem
and S3-compatible backend profiles, resumable object sessions, generation-
fenced lifecycle behavior, paged logical content transfer, sealed batch
download plans, durable unique-byte quota accounting, internal events, and
privacy-safe telemetry. It imports OGVCS-002 identity, OGVCS-003 grants,
OGVCS-007 production receipts, and OGVCS-041 idempotency/range rules without
reassigning their formats.

The filesystem profile remains the manifest's compatibility anchor. The S3 and
logical-content profiles are additive. Existing error and lifecycle transition
assignments are unchanged. New schemas/vectors cover exact backend capability
claims, SigV4 and S3 durability semantics, the 64-MiB canonical object versus
100-GiB logical-file boundary, durable resume ledgers, batch bindings and hidden
denial, quota replay/release, events, telemetry, and safe error classification.

Generate and independently validate offline with:

```sh
npm test
```

This cut remains development-only. It does not assign public/wire routes,
declare repository-metadata v9 integration, claim reachability/GC or OGVCS-010
completion, substitute bounded fake-S3 execution for the pinned hosted MinIO
gate, or substitute the synthetic 100-GiB plan test for the manual exact-byte
throughput/memory gate.
