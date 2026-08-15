import { requestSettings, resolveRequest } from './request.mjs';
import { operationKinds } from './model.mjs';

function decimal(value) {
  return BigInt(value).toString();
}

function estimateMaterializedPaths(request) {
  const settings = requestSettings(request);
  if (settings.materialization === 'index-only') return 0;
  if (settings.materialization === 'sampled') {
    return Math.min(request.scale.pathCount, settings.materializedPathLimit);
  }
  return request.scale.pathCount;
}

function estimateGroupedPaths(request, settings) {
  const caps = {
    'global-studio': 50_000,
    'large-binary': 10_000 * settings.mutableVersions,
    'unity-like': 20_000,
    'unreal-like': 40_000,
  };
  return Math.min(request.scale.pathCount, caps[request.profile.id] ?? 0);
}

export function planFixture(input) {
  const { profile, request, requestDigest } = resolveRequest(input);
  const settings = requestSettings(request);
  // These are deliberately upper envelopes, not observed averages. Semantic
  // v2 inventory lines currently peak below 1 KiB, while operation records can
  // grow as their state/authorization contracts evolve inside profile v2.
  const smallFileBytesPerPath = 4096n;
  const inventoryBytes = BigInt(request.scale.pathCount) * 1280n;
  const operationStreamBytes = BigInt(request.scale.historyOperationCount) * 2048n;
  const scenarioBytes = operationStreamBytes + 64n * 1024n;
  const groupedPaths = BigInt(estimateGroupedPaths(request, settings));
  const groupsBytes = groupedPaths * 1280n + 4096n;
  const materializedPaths = estimateMaterializedPaths(request);
  const materializedSmallPathCount = Math.max(
    0,
    materializedPaths - (request.scale.largeFileBytes > 0 && materializedPaths > 0 ? 1 : 0),
  );
  const materializedSmallBytes = BigInt(materializedSmallPathCount) * smallFileBytesPerPath;
  const filesystemMetadataBytes = (
    12n + BigInt(materializedPaths) * BigInt(request.scale.maxDepth + 1)
  ) * 512n;
  const largeBytes = BigInt(request.scale.largeFileBytes);
  const versionCount = BigInt(settings.mutableVersions);
  const physicalLargeBytes = settings.largeFileMode === 'full'
    ? largeBytes
    : settings.largeFileMode === 'sparse' && largeBytes > 0n
      // A truncate-with-holes representation can allocate its full apparent
      // length on a filesystem without sparse support. Planning and the
      // request-wide physical ledger therefore reserve the portable worst
      // case, while the descriptor reports extent payload separately.
      ? largeBytes
      : 0n;
  const descriptorBytes = largeBytes > 0n
    // Each v2 version can carry sixteen full-width patch descriptors plus
    // reuse/locality/digest metadata. Four KiB per version covers the maximum
    // canonical recipe, with fixed headroom for stream and physical metadata.
    ? 64n * 1024n + versionCount * 4096n
    : 0n;
  // Owner marker, canonical request, resolved workload profile, checkpoint,
  // and conservative control-artifact headroom.
  const fixedArtifactsBytes = 256n * 1024n;
  const manifestBytes = 128n * 1024n + groupsBytes;
  const durableArtifactBytes = inventoryBytes
    + operationStreamBytes
    + scenarioBytes
    + groupsBytes
    + manifestBytes
    + descriptorBytes
    + materializedSmallBytes
    + physicalLargeBytes
    + filesystemMetadataBytes
    + fixedArtifactsBytes;
  // groups.json or manifest.json is written atomically while the previous
  // durable artifacts still exist. Include that simultaneous temporary inode.
  const largestAtomicTemporaryBytes = groupsBytes > manifestBytes ? groupsBytes : manifestBytes;
  // At publication, hard-linked file data is shared but a second directory
  // hierarchy exists until the owned stage is removed.
  const transientPhysicalBytes = largestAtomicTemporaryBytes > filesystemMetadataBytes
    ? largestAtomicTemporaryBytes
    : filesystemMetadataBytes;
  const estimatedPhysicalBytes = durableArtifactBytes + transientPhysicalBytes;
  const logicalSmallBytes = BigInt(request.scale.pathCount) * 1024n;
  const streamedLargeBytes = settings.largeFileMode === 'stream-verified'
    ? largeBytes * versionCount * 2n
    : settings.largeFileMode === 'full'
      ? largeBytes * (versionCount * 2n + 1n)
      : 0n;
  const verifiedRecoveryLargeBytes = settings.largeFileMode === 'full' ? largeBytes : 0n;
  const durationPhaseSeconds = {
    fixedControlAndPublication: 1,
    // Generation plus mandatory prepublication verification.
    pathGenerationAndVerification: Math.ceil(request.scale.pathCount / 7_500),
    // A late path-phase resume replays the durable inventory and rebuilds the
    // checkpoint-owned materialization before mandatory verification.
    pathRecoveryReplayAndRebuild: Math.ceil(request.scale.pathCount / 7_500),
    // Operation stream generation, final scenario construction, and both
    // operation representations being checked before publication.
    operationRecoveryReplay: Math.ceil(request.scale.historyOperationCount / 5_000),
    scenarioConstructionAndVerification: Math.ceil(request.scale.historyOperationCount / 5_000),
    // Full-mode recovery can deep-check all versions plus the physical final
    // version, then run the same mandatory gate again. One extra logical-file
    // pass beyond fresh generation's seven passes covers that invocation.
    fullLargeRecoveryReplay: Math.ceil(
      Number(verifiedRecoveryLargeBytes) / (250 * 1024 ** 2),
    ),
    streamedLargeGenerationAndVerification: Math.ceil(
      Number(streamedLargeBytes) / (250 * 1024 ** 2),
    ),
  };
  const estimatedDurationSeconds = Math.max(
    1,
    Object.values(durationPhaseSeconds).reduce((total, seconds) => total + seconds, 0),
  );
  const standaloneLargeVerificationBytes = settings.largeFileMode === 'stream-verified'
    ? largeBytes * versionCount
    : settings.largeFileMode === 'full'
      ? largeBytes * (versionCount + 1n)
      : 0n;
  const standaloneVerificationPhaseSeconds = {
    largeFileVerification: Math.ceil(
      Number(standaloneLargeVerificationBytes) / (250 * 1024 ** 2),
    ),
    operationAndScenarioVerification: Math.ceil(request.scale.historyOperationCount / 10_000),
    pathVerification: Math.ceil(request.scale.pathCount / 15_000),
  };
  const standaloneVerificationDurationSeconds = Math.max(
    1,
    Object.values(standaloneVerificationPhaseSeconds)
      .reduce((total, seconds) => total + seconds, 0),
  );
  const acceptanceWorkflowDurationSeconds = estimatedDurationSeconds
    + standaloneVerificationDurationSeconds;
  const warnings = [];
  // Deep verification retains logical-directory identities across the path
  // stream, while global-studio scenarios retain bounded initial state per
  // operation cycle. Code-heavy paths can contain a distinct prefix at every
  // requested depth, and V8 stores those prefix strings plus Set entries with
  // substantially more overhead than their UTF-8 wire form. Model that
  // profile/depth interaction explicitly. Other profiles have fixed shallow
  // directory templates whose bounded identities fit the general per-path
  // allowance. The fixed allowance covers the Node runtime, schemas, stream
  // buffers, and bounded group data.
  const deepDirectoryIdentityBytes = request.profile.id === 'code-heavy'
    ? BigInt(request.scale.pathCount) * BigInt(request.scale.maxDepth) * 384n
    : 0n;
  // Global-studio keeps one initial FileID/path/revision tuple per effective
  // operation cycle in the scenario state. Disabling optional kinds shortens
  // a cycle and can therefore increase retained state substantially even when
  // historyOperationCount is unchanged.
  const globalInitialStateCount = request.profile.id === 'global-studio'
    ? Math.ceil(request.scale.historyOperationCount / operationKinds(request, profile).length)
    : 0;
  const globalInitialStateBytes = BigInt(globalInitialStateCount) * 768n;
  const peakGeneratorMemoryBytes = 192n * 1024n * 1024n
    + BigInt(request.scale.pathCount) * 768n
    + BigInt(request.scale.historyOperationCount) * 128n
    + deepDirectoryIdentityBytes
    + globalInitialStateBytes;

  if (settings.materialization === 'full' && request.scale.pathCount > 100_000) {
    warnings.push('full-materialization-creates-many-files');
  }
  if (settings.largeFileMode === 'full' && largeBytes >= 10n * 1024n ** 3n) {
    warnings.push('full-large-file-requires-logical-size-disk-and-sequential-io');
  }
  if (settings.largeFileMode !== 'full' && largeBytes > 0n) {
    warnings.push(`${settings.largeFileMode}-large-file-is-a-declared-logical-representation`);
  }
  if (settings.largeFileMode === 'stream-verified' && largeBytes > 0n) {
    warnings.push('stream-verified-hashes-every-version-without-storing-large-file-bytes');
  }
  if (settings.largeFileMode === 'sparse' && largeBytes > 0n) {
    warnings.push('sparse-allocation-is-conservatively-budgeted-as-full-logical-size');
  }

  return {
    destination: request.destination,
    estimates: {
      acceptanceWorkflowDurationSeconds,
      artifactIndexBytes: decimal(inventoryBytes + operationStreamBytes),
      durationSeconds: estimatedDurationSeconds,
      durationPhaseSeconds,
      logicalBytes: decimal(logicalSmallBytes + largeBytes),
      materializedPathCount: materializedPaths,
      peakGeneratorMemoryBytes: decimal(peakGeneratorMemoryBytes),
      physicalBytes: decimal(estimatedPhysicalBytes),
      physicalArtifactBreakdown: {
        controlArtifacts: decimal(fixedArtifactsBytes),
        filesystemMetadata: decimal(filesystemMetadataBytes),
        groups: decimal(groupsBytes),
        inventory: decimal(inventoryBytes),
        largeDescriptor: decimal(descriptorBytes),
        manifest: decimal(manifestBytes),
        materializedLargeFile: decimal(physicalLargeBytes),
        materializedSmallFiles: decimal(materializedSmallBytes),
        operations: decimal(operationStreamBytes),
        scenario: decimal(scenarioBytes),
      },
      physicalArtifactBytes: decimal(durableArtifactBytes),
      physicalAtomicTemporaryBytes: decimal(largestAtomicTemporaryBytes),
      physicalFilesystemMetadataBytes: decimal(filesystemMetadataBytes),
      physicalTransientBytes: decimal(transientPhysicalBytes),
      streamedLargeBytes: decimal(streamedLargeBytes),
      runtimeBudgetedPhases: [
        'workspace-preparation',
        'generation',
        'final-scenario-and-manifest',
        'mandatory-prepublication-verification',
        'standalone-verification',
        'publication-before-commit',
      ],
      standaloneVerificationDurationSeconds,
      // Standalone verification can run inside a long-lived embedding whose
      // baseline RSS is outside this fixture's control. This separately named
      // allowance bounds memory added by that invocation; explicit request
      // maximumMemoryBytes remains an absolute RSS ceiling.
      standaloneVerificationMemoryGrowthBytes: decimal(peakGeneratorMemoryBytes),
      standaloneVerificationPhaseSeconds,
    },
    profile: request.profile,
    representation: {
      largeFileMode: settings.largeFileMode,
      materialization: settings.materialization,
    },
    request,
    requestDigest,
    warnings,
  };
}
