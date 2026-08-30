# OpenGameVCS object-transfer contract v1 candidate

This MIT-licensed candidate defines the first bounded OGVCS-008 filesystem
backend, resumable multipart-session, and generation-fenced lifecycle behavior.
It imports OGVCS-002 object identity, OGVCS-003 transfer grants, and OGVCS-041
semantic idempotency and range-carrier rules without redefining their formats.

The cut is development-only. It does not claim S3 parity, production routes,
pack layout, 100-GiB execution, reference throughput, GC reachability, or final
acceptance. Generate and validate offline with:

```sh
npm test
```

The generated vectors cover opaque backend keys, create-if-absent, same-open
verified range reads, exact lifecycle generations, resumable parts,
receipt-loss replay, server-owned grant time, persistent nonce replay,
canonical metadata rejection, pinned-ancestor symlink attempts, closed state,
renewed/fenced locks, authoritative one-use deletion permits, deleted-
generation reupload, the lifecycle transaction participant boundary, Windows'
exact directory-sync capability boundary, and durability faults including
EEXIST recovery. Runtime coverage dispatches every hostile/fault vector and
compares the observed normalized result; source-text presence is not
conformance.
