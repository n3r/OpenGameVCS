export const CONTRACT_VERSION = '0.1.0-rc.5';
export const PROFILE = 'storage.opengamevcs/filesystem@1';
export const CONFORMANCE_SECRET_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
export const FIXTURE_BYTES = Buffer.from('OpenGameVCS object transfer fixture\n', 'utf8');
export const CLAIMS = Object.freeze({
  schemaVersion: 'ogvcs.authorization/transfer-grant-claims/v1', issuer: 'auth.example', keyId: 'transfer-key',
  keyGeneration: 7, authorityEpoch: 11, subject: 'artist-one', tenant: 'tenant-alpha', repository: 'game-main',
  permission: 'content.upload', operation: 'upload', audience: 'objects.example', issuedAt: 1_800_000_000,
  expiresAt: 1_800_000_300, nonce: 'fixture-nonce', replay: 'idempotent', objectIds: [], requestRoot: null,
});
export const IDEMPOTENCY_KEY = 'ik1.1800000000000.1800000060000.MDEyMzQ1Njc4OWFiY2RlZg';

export const HOSTILE = Object.freeze([
  { id: 'wrong-audience', input: { mutation: 'grant.audience' }, expected: { code: 'TRANSFER_AUTHORIZATION_DENIED', mutationCount: 0 } },
  { id: 'stale-authority-epoch', input: { contextAuthorityEpochDelta: 1 }, expected: { code: 'TRANSFER_AUTHORIZATION_DENIED', mutationCount: 0 } },
  { id: 'replayed-single-use-nonce', input: { consumedNonce: true }, expected: { code: 'TRANSFER_AUTHORIZATION_DENIED', mutationCount: 0 } },
  { id: 'cross-tenant-key-probe', input: { contextTenant: 'tenant-beta' }, expected: { code: 'TRANSFER_AUTHORIZATION_DENIED', mutationCount: 0 } },
  { id: 'backend-key-traversal', input: { opaqueKey: '../protected' }, expected: { code: 'TRANSFER_INPUT_INVALID', mutationCount: 0 } },
  { id: 'conflicting-part-retry', input: { partIndex: 0, secondBytesHex: 'ff' }, expected: { code: 'TRANSFER_PART_CONFLICT', mutationCount: 1 } },
  { id: 'corrupt-stored-payload', input: { xorPayloadByte: 1 }, expected: { code: 'TRANSFER_BACKEND_CORRUPT', available: false } },
  { id: 'stale-lifecycle-generation', input: { expectedGenerationDelta: -1 }, expected: { code: 'TRANSFER_LIFECYCLE_STALE', transitionCount: 0 } },
  { id: 'backend-only-object', input: { durableBackendObject: true, lifecycleRecord: false }, expected: { discoverable: false, available: false } },
  { id: 'symlink-object-fanout', input: { replaceFanoutWithSymlink: true }, expected: { code: 'TRANSFER_BACKEND_IO', outsideWrite: false } },
  { id: 'symlink-object-ancestor', input: { replacePinnedAncestorWithSymlink: true }, expected: { code: 'TRANSFER_BACKEND_IO', outsideWrite: false } },
  { id: 'expired-server-clock-grant', input: { callerSuppliesEarlierNow: true }, expected: { code: 'TRANSFER_AUTHORIZATION_DENIED', mutationCount: 0 } },
  { id: 'malformed-metadata-identity', input: { identityMatchesMalformedMetadata: true }, expected: { code: 'TRANSFER_BACKEND_CORRUPT', available: false } },
  { id: 'stale-finalize-replay', input: { finalizedGeneration: 2, currentGeneration: 3, currentState: 'quarantined' }, expected: { code: 'TRANSFER_LIFECYCLE_STALE', falseCurrentAvailableReceipt: false } },
  { id: 'range-quarantine-race', input: { quarantineAfterBackendRead: true }, expected: { code: 'TRANSFER_LIFECYCLE_STALE', returnedBytes: false } },
  { id: 'corrupt-persisted-state', input: { addUnknownField: true }, expected: { code: 'TRANSFER_BACKEND_CORRUPT', mutationCount: 0 } },
  { id: 'forged-deleting-generation', input: { rawCallerBinding: true }, expected: { code: 'TRANSFER_LIFECYCLE_STALE', deleted: false } },
  { id: 'stale-lock-fencing-token', input: { expireThenTakeover: true }, expected: { code: 'TRANSFER_SESSION_STATE', staleCommit: false } },
  { id: 'windows-directory-sync-capability', input: { unsupportedCode: 'EPERM' }, expected: { windowsEpermUnsupported: true, windowsAccessDeniedUnsupported: false, linuxEpermUnsupported: false } },
]);

export const FAULTS = Object.freeze([
  { id: 'before-temp-file-sync', input: { phase: 'before-file-sync' }, expected: { lifecycleState: 'staged', availableReceipt: false } },
  { id: 'after-file-sync-before-link', input: { phase: 'after-file-sync' }, expected: { lifecycleState: 'staged', availableReceipt: false } },
  { id: 'after-link-before-directory-sync', input: { phase: 'after-link' }, expected: { lifecycleState: 'staged', availableReceipt: false } },
  { id: 'after-durability-before-lifecycle-cas', input: { phase: 'after-directory-sync' }, expected: { lifecycleState: 'staged', availableReceipt: false, retryRepairs: true } },
  { id: 'after-available-before-response', input: { phase: 'after-lifecycle-cas' }, expected: { lifecycleState: 'available', availableReceipt: true, retryReplays: true } },
  { id: 'quarantine-races-finalize-response', input: { phase: 'after-lifecycle-cas', concurrent: 'quarantine' }, expected: { code: 'TRANSFER_LIFECYCLE_STALE', falseCurrentAvailableReceipt: false } },
  { id: 'eexist-retry-directory-sync', input: { firstFailurePhase: 'after-link', retryFindsExisting: true }, expected: { directorySyncedBeforeReceipt: true, createdOnRetry: false } },
  { id: 'live-lock-lease-renewal', input: { operationMilliseconds: 1150, leaseMilliseconds: 1000 }, expected: { ownerCompleted: true, takeover: false } },
  { id: 'delete-response-loss-after-unlink', input: { loseFirstResponse: true }, expected: { firstLifecycleState: 'deleting', finalLifecycleState: 'deleted', retryRepairs: true } },
]);
