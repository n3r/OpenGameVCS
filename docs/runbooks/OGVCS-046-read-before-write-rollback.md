# OGVCS-046 read-before-write and rollback runbook

Use this runbook when enabling or disabling bounded staged streaming publication. The journal format is additive, but a deployment can leave a durable `write-stream` record that older runtimes cannot interpret.

## Read-before-write rollout

1. Deploy `@opengamevcs/path-filesystem` 1.1.0 readers and recovery tooling before enabling writers or an OGVCS-007 consumer.
2. Quiesce existing workspace mutation and call `inspectCrashRemnants(workspace)`. Resolve every valid pre-existing transaction and investigate malformed or unsafe records before proceeding.
3. Confirm the workspace reports atomic-replace support. Replacing an existing target additionally requires hardlink support; the API fails closed before replacement when a rollback link cannot be created.
4. Construct a closed, owner-bound materialization preflight plan for the exact file path. Supply the producer's independently known `expectedBytes` and lowercase `expectedSha256`.
5. Set workload-specific `maxBytes`, `maxScratchBytes`, `maxChunkBytes`, `maxTimeMs`, and `maxOperations`. Reserve same-filesystem scratch capacity for the staged file and, when replacing a target, its rollback link.
6. Enable writers gradually. Treat a resolved call as committed only after the API completes its file and directory durability barriers; a cancellation or deadline request is a cooperative stop signal, not permission to abandon an in-flight filesystem operation.

## Recovery after interruption

1. Stop all publishers and otherwise quiesce the workspace.
2. Open the repository through the branded workspace API; do not manipulate `.ogvcs/transactions` directly.
3. Call `inspectCrashRemnants(workspace)`. A valid `write-stream` entry exposes only its stable operation, state, canonical repository path, and artifact-presence fields.
4. For every returned transaction identifier, call `rollbackCrashRemnant(workspace, id, { maxBytes, maxTimeMs, maxOperations })` with limits appropriate to the repository. Noncommitted publication states restore the prior target or remove a new target; committed states are finalized.
5. Repeat inspection until it returns no valid remnants. Stop and investigate any typed unsafe, corrupt, or authority-change failure rather than deleting an artifact by pathname.
6. Verify the target byte length and SHA-256 against the producer's expected identity before re-enabling publication.

Recovery depends on the private workspace/control root and its ancestors remaining within the same trusted authority. Portable Node filesystem APIs cannot provide a continuously bound native directory handle across every namespace operation; detected symlink, junction, reparse, identity, or device changes fail closed.

## Rollback or downgrade

1. Stop all producers and consumers that can call `atomicWriteStream`.
2. Using version 1.1.0, inspect and recover or finalize all `write-stream` remnants.
3. Verify that inspection reports no remaining stream transactions and that target identities match application records.
4. Disable the API at the application boundary.
5. Only then downgrade below 1.1.0. Older runtimes must never be expected to recover the additive journal operation.

If recovery cannot validate authority or transaction state, retain the workspace unchanged and escalate with the typed failure and transaction identifier. Do not manually rename, unlink, or copy transaction artifacts.
