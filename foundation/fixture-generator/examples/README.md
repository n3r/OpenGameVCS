# Black-box consumers

`object-mapping.mjs` maps each public inventory record to a content-addressed object reference. It also consumes the public inventory/group schemas, validates semantic version chains and group references, and proves the expected role families and Unity negative cases. `workload-driver.mjs` feeds each public neutral operation stream to a stateful recording adapter. The adapter validates participant, identity, ACL, network, lock-lifecycle, branch, submit, review, CI, and interruption relationships.

Both examples discover every profile through `ogvcs-fixture list`, generate tiny index-only/virtual fixtures through documented command flags, run deep verification, and emit stable JSON summaries. The fixtures use 32 paths so the Unity sample deterministically includes both missing-sidecar and cross-group duplicate-GUID cases; no private generator module is needed to interpret either case.

They import no fixture-generator `src/` module. Their only fixture contracts are the installed executable, the public JSON Schemas, and completed fixture artifacts referenced by `manifest.json`.

Run from the package source directory with new relative workspaces:

```sh
node examples/object-mapping.mjs --cli ./bin/ogvcs-fixture.mjs \
  --workspace example-output/object-mapping
node examples/workload-driver.mjs --cli ./bin/ogvcs-fixture.mjs \
  --workspace example-output/workload-driver
```

When the `ogvcs-fixture` executable is on `PATH`, omit `--cli`. `OGVCS_FIXTURE_BIN` can also name the installed executable. Each example deliberately retains generated fixtures and refuses unsafe relative workspace paths; it never deletes a pre-existing directory.
