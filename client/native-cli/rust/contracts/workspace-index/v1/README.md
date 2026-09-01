# Private workspace-index candidate contract v1

This artifact freezes the private local-state semantics implemented by the
Rust OGVCS-012 candidate. It is not a public protocol, route, or completion
claim. The first-party CLI has no workspace-baseline route and no built-in
USN/FSEvents/inotify continuity authority, so it cannot currently return an
authoritative clean status through production-callable adapters.

The contract authenticates exact bounds, generation publication ordering,
current workspace bindings, lookup collision revalidation, watcher journal
continuity, status values, and every HMAC paging-cursor binding. The
owner-private cursor key is generated locally and never serialized into a
status page.

Committed generations are create-new and immutable. The candidate retains all
old committed generations because it has no reader lease or safe generation-GC
authority. Calling the current logical rebuild a physical compaction would be
incorrect. A bounded retention implementation remains an OGVCS-012 blocker.

Verify this candidate contract with Node 24:

```sh
node scripts/generate.mjs --check
node validate.mjs
```

The Rust unit suite independently recomputes the authenticated cursor vector
through the production HMAC routine and pins the manifest artifact-set digest.
