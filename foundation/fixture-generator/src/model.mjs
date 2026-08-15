import { createHash } from 'node:crypto';

import { canonicalDigest, canonicalStringify } from './canonical.mjs';
import {
  CONTENT_ALGORITHM as CONTENT_STREAM_ALGORITHM,
  deterministicChunks,
  deterministicId,
  digestDeterministicContent,
  normalizeLogicalPath,
} from './content.mjs';
import { SCENARIO_SCHEMA } from './constants.mjs';
import { deterministicInt } from './prng.mjs';
import { requestSettings } from './request.mjs';
import { mediaTypeFor, semanticBytes, semanticVersionCount } from './semantics.mjs';

const SMALL_CONTENT_MIN = 96;
const SMALL_CONTENT_SPAN = 929;
const SEMANTIC_CONTENT_ALGORITHM = 'ogvcs.fixture/semantic-artifact/v2';
// Group artifacts are intentionally bounded for million-path fixtures. This is
// a coverage boundary, not an ID declaration cap: groupIdentity returns no ID
// at or above it, so inventory can never refer to an undeclared relationship.
const MAX_DECLARED_GROUPS = 10_000;

function padded(index, width = 8) {
  return String(index).padStart(width, '0');
}

function enabled(request, feature) {
  return request.featureFlags[feature] !== false;
}

function boundedPath(segments, filename, maxDepth) {
  const maximumDirectories = Math.max(0, maxDepth - 1);
  return normalizeLogicalPath([...segments.slice(0, maximumDirectories), filename].join('/'));
}

function unityMissingSidecar(request, groupIndex) {
  return enabled(request, 'asset-meta-pairs')
    && enabled(request, 'missing-sidecar-negative')
    && request.featureFlags['negative-cases'] !== false
    && groupIndex % 31 === 7;
}

function unityDuplicateGuid(request, groupIndex) {
  return enabled(request, 'asset-meta-pairs')
    && enabled(request, 'duplicate-sidecar-negative')
    && request.featureFlags['negative-cases'] !== false
    && (groupIndex % 37 === 12 || groupIndex % 37 === 13);
}

function unityGuidOwner(request, groupIndex) {
  return unityDuplicateGuid(request, groupIndex) && groupIndex % 37 === 13 ? groupIndex - 1 : groupIndex;
}

function unityPairIsComplete(request, groupIndex) {
  return groupIndex * 2 + 1 < request.scale.pathCount;
}

function profilePath(profileId, index, maxDepth, request) {
  const shard = padded(index % 97, 2);
  const band = padded(Math.floor(index / 97) % 101, 3);
  const id = padded(index);

  if (profileId === 'code-heavy') {
    const extensions = ['cc', 'h', 'rs', 'py', 'sh', 'json', 'md'];
    const extension = extensions[index % extensions.length];
    const depth = Math.max(1, Math.min(maxDepth - 1, 2 + (index % Math.max(1, maxDepth - 1))));
    const directories = ['src', `module-${shard}`, `band-${band}`];
    while (directories.length < depth) directories.push(`layer-${padded(directories.length, 2)}`);
    if (index % 97 === 0) directories[0] = 'Caf\u00e9';
    return boundedPath(directories, `file-${id}.${extension}`, maxDepth);
  }

  if (profileId === 'unreal-like') {
    const familyIndex = Math.floor(index / 8);
    const family = padded(familyIndex);
    const familyShard = padded(familyIndex % 97, 2);
    const familyBand = padded(Math.floor(familyIndex / 97) % 101, 3);
    const offset = index % 8;
    const variants = [
      { directories: ['Content', 'Synthetic', `Zone-${familyShard}`], filename: `Package-${family}.uasset` },
      enabled(request, 'sidecars')
        ? { directories: ['Content', 'Synthetic', `Zone-${familyShard}`], filename: `Package-${family}.ubulk` }
        : { directories: ['Content', 'Synthetic', `Zone-${familyShard}`], filename: `Package-${family}-variant.uasset` },
      enabled(request, 'maps')
        ? { directories: ['Content', 'Maps', `Zone-${familyShard}`], filename: `Map-${family}.umap` }
        : { directories: ['Content', 'Synthetic', `Zone-${familyShard}`], filename: `MapReplacement-${family}.uasset` },
      enabled(request, 'maps') && enabled(request, 'external-actors')
        ? { directories: ['Content', 'Maps', `Zone-${familyShard}`, 'ExternalActors', familyBand], filename: `Actor-${id}.uasset` }
        : { directories: ['Content', 'Synthetic', `Zone-${familyShard}`], filename: `ActorReplacement-${family}.uasset` },
      { directories: ['Source', 'Synthetic'], filename: `FixturePackage-${family}.cpp` },
      { directories: ['Source', 'Synthetic'], filename: `FixturePackage-${family}.h` },
      { directories: ['Config'], filename: `DefaultFixture-${family}.ini` },
      { directories: ['Content', 'Data'], filename: `Package-${family}.json` },
    ];
    return boundedPath(variants[offset].directories, variants[offset].filename, maxDepth);
  }

  if (profileId === 'unity-like') {
    const groupIndex = Math.floor(index / 2);
    const group = padded(groupIndex);
    const groupShard = padded(groupIndex % 97, 2);
    const groupBand = padded(Math.floor(groupIndex / 97) % 101, 3);
    const baseDirectories = ['Assets', `Area-${groupShard}`, `Collection-${groupBand}`];
    const type = groupIndex % 3;
    const extension = type === 0 ? 'unity' : type === 1 ? 'prefab' : enabled(request, 'binary-imports') ? 'fbx' : 'asset';
    const base = `Asset-${group}.${extension}`;
    if (index % 2 === 0) return boundedPath(baseDirectories, base, maxDepth);
    if (!enabled(request, 'asset-meta-pairs')) {
      return boundedPath(['Assets', 'Standalone'], `Standalone-${group}.asset`, maxDepth);
    }
    if (unityMissingSidecar(request, groupIndex)) {
      return boundedPath(['Assets', 'Negative', 'MissingMetaEvidence'], `Missing-${group}.json`, maxDepth);
    }
    return boundedPath(baseDirectories, `${base}.meta`, maxDepth);
  }

  if (profileId === 'large-binary') {
    if (index === 0 && request.scale.largeFileBytes > 0) {
      return boundedPath(['Assets', 'Binary', 'Mutable'], 'hero-source.bin', maxDepth);
    }
    const versions = requestSettings(request).mutableVersions;
    const family = padded(Math.floor(index / versions));
    const version = index % versions;
    return boundedPath(['Assets', 'Binary', `Bucket-${shard}`, `Family-${band}`], `asset-${family}.v${version}.bin`, maxDepth);
  }

  const variants = [
    ['Source', `Team-${shard}`, `module-${id}.cc`],
    ['Content', `Site-${shard}`, `asset-${id}.uasset`],
    ['Assets', `Team-${shard}`, `item-${id}.asset`],
    ['Config', `Region-${shard}`, `settings-${id}.json`],
    ['Reviews', `Team-${shard}`, `change-${id}.txt`],
  ];
  const selected = variants[index % variants.length];
  return boundedPath(selected.slice(0, -1), selected.at(-1), maxDepth);
}

function roleFor(profileId, index, request) {
  if (profileId === 'code-heavy') {
    return ['source', 'header', 'source', 'script', 'script', 'configuration', 'documentation'][index % 7];
  }
  if (profileId === 'unreal-like') {
    const roles = [
      'package',
      enabled(request, 'sidecars') ? 'sidecar' : 'package',
      enabled(request, 'maps') ? 'map' : 'package',
      enabled(request, 'maps') && enabled(request, 'external-actors') ? 'external-actor' : 'package',
      'source', 'header', 'configuration', 'configuration',
    ];
    return roles[index % 8];
  }
  if (profileId === 'unity-like') {
    const groupIndex = Math.floor(index / 2);
    if (index % 2 === 1) {
      if (!enabled(request, 'asset-meta-pairs')) return 'asset';
      return unityMissingSidecar(request, groupIndex) ? 'negative-evidence' : 'meta';
    }
    return groupIndex % 3 === 0 ? 'scene'
      : groupIndex % 3 === 1 ? 'prefab'
        : enabled(request, 'binary-imports') ? 'binary-import' : 'asset';
  }
  if (profileId === 'large-binary') {
    return index === 0 && request.scale.largeFileBytes > 0
      ? 'mutable-large-file'
      : 'binary-version';
  }
  return ['source', 'package', 'asset', 'configuration', 'review-input'][index % 5];
}

function groupIdentity(profileId, index, request) {
  if (profileId === 'unreal-like') {
    const family = Math.floor(index / 8);
    const offset = index % 8;
    const familyStart = family * 8;
    if (
      offset <= 1
      && familyStart + 1 < request.scale.pathCount
      && enabled(request, 'sidecars')
      && family * 2 < MAX_DECLARED_GROUPS
    ) {
      return { id: `package-${padded(family)}`, kind: 'package-sidecars' };
    }
    if (
      (offset === 2 || offset === 3)
      && familyStart + 3 < request.scale.pathCount
      && enabled(request, 'maps')
      && enabled(request, 'external-actors')
      && family * 2 + 1 < MAX_DECLARED_GROUPS
    ) {
      return { id: `map-${padded(family)}`, kind: 'map-external-actors' };
    }
    return undefined;
  }
  if (profileId === 'unity-like' && enabled(request, 'asset-meta-pairs')) {
    const groupIndex = Math.floor(index / 2);
    if (groupIndex >= MAX_DECLARED_GROUPS || !unityPairIsComplete(request, groupIndex)) return undefined;
    if (index % 2 === 1 && unityMissingSidecar(request, groupIndex)) return undefined;
    return { id: `asset-${padded(groupIndex)}`, kind: 'asset-meta' };
  }
  if (profileId === 'large-binary') {
    const family = Math.floor(index / requestSettings(request).mutableVersions);
    if (family >= MAX_DECLARED_GROUPS) return undefined;
    return {
      id: `family-${padded(family)}`,
      kind: 'binary-version-family',
    };
  }
  if (profileId === 'global-studio') {
    const groupIndex = Math.floor(index / 5);
    if (groupIndex >= MAX_DECLARED_GROUPS) return undefined;
    return { id: `studio-${padded(groupIndex)}`, kind: ['site', 'team', 'asset'][groupIndex % 3] };
  }
  return undefined;
}

function sourceIndexFor(request, index) {
  const settings = requestSettings(request);
  const firstSmallIndex = request.scale.largeFileBytes > 0 ? 1 : 0;
  if (
    request.profile.id === 'large-binary'
    && enabled(request, 'duplication')
    && index > firstSmallIndex
    && deterministicInt(request.seed, 'content/duplicate-decision', 1000, index) < settings.duplicationPermille
  ) {
    const maximumDistance = Math.min(index - firstSmallIndex, 31);
    return index - 1 - deterministicInt(request.seed, 'content/duplicate-distance', maximumDistance, index);
  }
  return index;
}

function randomSmallContentDescriptor(request, index) {
  const settings = requestSettings(request);
  const sourceIndex = sourceIndexFor(request, index);
  const logicalBytes = SMALL_CONTENT_MIN + deterministicInt(request.seed, 'content/size', SMALL_CONTENT_SPAN, sourceIndex);
  const stream = `file/${request.profile.id}/${sourceIndex}`;
  const digest = digestDeterministicContent({
    compressionClass: settings.compressionClass,
    seed: request.seed,
    size: logicalBytes,
    stream,
  });
  return {
    algorithm: digest.algorithm,
    contentAlgorithm: digest.contentAlgorithm,
    digest: digest.digest,
    logicalBytes,
    mediaType: 'application/octet-stream',
    representation: 'deterministic-binary',
    sourceIndex,
    stream,
  };
}

function semanticContentDescriptor(request, record) {
  const count = semanticVersionCount(request, record.role);
  const versions = [];
  for (let version = 0; version < count; version += 1) {
    const bytes = semanticBytes({ ...record, profileId: request.profile.id, seed: request.seed, version });
    versions.push({
      baseVersion: version === 0 ? null : version - 1,
      delta: version === 0 ? 'create' : record.role === 'binary-import' || ['package', 'map', 'sidecar', 'external-actor'].includes(record.role)
        ? 'binary-region-replace' : 'structured-line-edit',
      digest: createHash('sha256').update(bytes).digest('hex'),
      logicalBytes: bytes.length,
      version,
    });
  }
  const current = versions.at(-1);
  return {
    algorithm: 'sha256',
    contentAlgorithm: SEMANTIC_CONTENT_ALGORITHM,
    digest: current.digest,
    logicalBytes: current.logicalBytes,
    mediaType: mediaTypeFor(request.profile.id, record.role, record.logicalPath),
    representation: 'semantic-v2',
    sourceIndex: record.index,
    stream: `semantic/${request.profile.id}/${record.index}`,
    version: current.version,
    versions,
  };
}

function effectiveMutableVersions(request) {
  if (request.profile.id === 'unreal-like' && !enabled(request, 'large-file-churn')) return 1;
  return requestSettings(request).mutableVersions;
}

function patchStream(request, version, patch) {
  return `large/${request.profile.id}/version-${version}/patch-${patch}`;
}

function unionLength(ranges) {
  if (ranges.length === 0) return 0;
  const sorted = ranges.map(({ offset, length }) => [offset, offset + length]).sort((a, b) => a[0] - b[0]);
  let total = 0;
  let [start, end] = sorted[0];
  for (const [nextStart, nextEnd] of sorted.slice(1)) {
    if (nextStart <= end) end = Math.max(end, nextEnd);
    else {
      total += end - start;
      [start, end] = [nextStart, nextEnd];
    }
  }
  return total + end - start;
}

export function largeFileRecipe(request, logicalPath) {
  const settings = requestSettings(request);
  const size = request.scale.largeFileBytes;
  const versionCount = effectiveMutableVersions(request);
  const reuse = request.profile.id !== 'large-binary' || enabled(request, 'cross-version-reuse');
  const locality = request.profile.id !== 'large-binary' || enabled(request, 'edit-locality');
  const versions = [];
  const cumulativePatches = [];
  for (let version = 0; version < versionCount; version += 1) {
    const patchCount = version === 0 || size === 0 ? 0 : Math.min(16, Math.max(1, Math.ceil(size / (1024 ** 3))));
    const patches = [];
    const length = Math.min(64 * 1024, size);
    const anchor = size === 0 ? 0 : deterministicInt(request.seed, `large/version-${version}/anchor`, size, 0);
    for (let patch = 0; patch < patchCount; patch += 1) {
      const maximumOffset = Math.max(1, size - length + 1);
      const globalOffset = deterministicInt(request.seed, `large/version-${version}/patch-offset`, maximumOffset, patch);
      const configuredLocality = locality ? settings.editLocalityPermille : 0;
      const localWindow = Math.max(length, Math.floor(size * (1000 - configuredLocality) / 1000));
      const localStart = Math.max(0, Math.min(maximumOffset - 1, anchor - Math.floor(localWindow / 2)));
      const localSpan = Math.max(1, Math.min(maximumOffset - localStart, localWindow));
      const offset = configuredLocality === 0 ? globalOffset
        : localStart + deterministicInt(request.seed, `large/version-${version}/local-offset`, localSpan, patch);
      const patchDigest = digestDeterministicContent({
        compressionClass: settings.compressionClass,
        seed: request.seed,
        size: length,
        stream: patchStream(request, version, patch),
      }).digest;
      patches.push({ digest: patchDigest, length, offset, patch, version });
    }
    if (reuse) cumulativePatches.push(...patches);
    const reusedBytes = version === 0 || !reuse ? 0 : size - unionLength(cumulativePatches);
    const body = {
      baseStream: reuse ? `large/${request.profile.id}/base` : `large/${request.profile.id}/version-${version}/base`,
      baseVersion: version === 0 || !reuse ? null : version - 1,
      editLocalityPermille: locality ? settings.editLocalityPermille : 0,
      patches,
      reusePermille: size === 0 ? 0 : Math.floor(reusedBytes * 1000 / size),
      version,
    };
    versions.push({ ...body, recipeDigest: canonicalDigest(body, 'ogvcs.fixture/large-file-version/v2') });
  }
  const body = {
    compressionClass: settings.compressionClass,
    contentAlgorithm: CONTENT_STREAM_ALGORITHM,
    logicalBytes: size,
    logicalPath,
    representation: settings.largeFileMode,
    stream: `large/${request.profile.id}/base`,
    versions,
  };
  return { ...body, recipeDigest: canonicalDigest(body, 'ogvcs.fixture/large-file-recipe/v2') };
}

function patchesForVersion(recipe, version) {
  if (recipe.versions[version].baseVersion === null) return recipe.versions[version].patches;
  return recipe.versions.slice(1, version + 1).flatMap((entry) => entry.patches);
}

/** Yield the actual bytes described by a large-file version recipe. */
export function* largeVersionChunks(request, recipe, version, options = {}) {
  if (!Number.isSafeInteger(version) || version < 0 || version >= recipe.versions.length) {
    throw new RangeError('large-file version is outside the recipe');
  }
  const start = options.start ?? 0;
  const chunkSize = options.chunkSize ?? 1024 * 1024;
  const entry = recipe.versions[version];
  const patches = patchesForVersion(recipe, version);
  let absolute = start;
  for (const source of deterministicChunks({
    chunkSize,
    compressionClass: recipe.compressionClass,
    seed: request.seed,
    size: recipe.logicalBytes,
    start,
    stream: entry.baseStream,
  })) {
    const chunk = Buffer.from(source);
    const chunkEnd = absolute + chunk.length;
    for (const patch of patches) {
      const overlapStart = Math.max(absolute, patch.offset);
      const overlapEnd = Math.min(chunkEnd, patch.offset + patch.length);
      if (overlapStart >= overlapEnd) continue;
      const patchBytes = Buffer.concat([...deterministicChunks({
        chunkSize: overlapEnd - overlapStart,
        compressionClass: recipe.compressionClass,
        seed: request.seed,
        size: overlapEnd - patch.offset,
        start: overlapStart - patch.offset,
        stream: patchStream(request, patch.version, patch.patch),
      })]);
      patchBytes.copy(chunk, overlapStart - absolute);
    }
    yield chunk;
    absolute = chunkEnd;
  }
}

export function createPathRecord(request, profile, index) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= request.scale.pathCount) {
    throw new RangeError('path index is outside the request');
  }
  const logicalPath = profilePath(profile.id, index, request.scale.maxDepth, request);
  const role = roleFor(profile.id, index, request);
  const group = groupIdentity(profile.id, index, request);
  const record = {
    fileId: deterministicId(request.seed, 'file', logicalPath),
    index,
    kind: 'file',
    logicalPath,
    mode: profile.id === 'code-heavy' && enabled(request, 'executables') && ['sh', 'py'].some((extension) => logicalPath.endsWith(`.${extension}`))
      ? '100755' : '100644',
    role,
  };
  if (group) record.group = group;
  if (
    profile.id === 'unity-like'
    && enabled(request, 'asset-meta-pairs')
    && unityPairIsComplete(request, Math.floor(index / 2))
  ) {
    const groupIndex = Math.floor(index / 2);
    const ownerPath = profilePath(profile.id, unityGuidOwner(request, groupIndex) * 2, request.scale.maxDepth, request);
    record.syntheticGuid = deterministicId(request.seed, 'guid', ownerPath);
    if (unityMissingSidecar(request, groupIndex)) record.negativeCase = 'missing-sidecar';
    else if (unityDuplicateGuid(request, groupIndex)) record.negativeCase = 'duplicate-guid';
  }
  if (index === 0 && request.scale.largeFileBytes > 0) {
    const recipe = largeFileRecipe(request, logicalPath);
    record.content = {
      algorithm: 'sha256-recipe-v2',
      contentAlgorithm: recipe.contentAlgorithm,
      digest: recipe.recipeDigest,
      logicalBytes: recipe.logicalBytes,
      mediaType: 'application/octet-stream',
      representation: 'large-version-recipe',
      sourceIndex: 0,
      stream: recipe.stream,
    };
  } else if (profile.id === 'large-binary') record.content = randomSmallContentDescriptor(request, index);
  else record.content = semanticContentDescriptor(request, record);
  return record;
}

export function* contentChunksForRecord(request, record, options = {}) {
  if (record.content.algorithm !== 'sha256') {
    throw new RangeError('Recipe-backed large content must use the large-file materializer');
  }
  if (record.content.contentAlgorithm === SEMANTIC_CONTENT_ALGORITHM) {
    const version = options.version ?? record.content.version;
    const bytes = semanticBytes({ ...record, profileId: request.profile.id, seed: request.seed, version });
    const start = options.start ?? 0;
    const chunkSize = options.chunkSize ?? 1024 * 1024;
    for (let offset = start; offset < bytes.length; offset += chunkSize) yield bytes.subarray(offset, offset + chunkSize);
    return;
  }
  yield* deterministicChunks({
    chunkSize: options.chunkSize,
    compressionClass: requestSettings(request).compressionClass,
    seed: request.seed,
    size: record.content.logicalBytes,
    start: options.start ?? 0,
    stream: record.content.stream,
  });
}

/**
 * Materialize the explicit group relation for every record. This is O(paths)
 * and request-bounded. groupIdentity() applies the documented coverage bound
 * before assigning an ID; this same pass declares every ID it can return.
 */
export function createGroups(request, profile) {
  const groups = new Map();
  const coveragePathLimit = profile.id === 'unreal-like' ? MAX_DECLARED_GROUPS * 4
    : profile.id === 'unity-like' ? MAX_DECLARED_GROUPS * 2
      : profile.id === 'large-binary' ? MAX_DECLARED_GROUPS * requestSettings(request).mutableVersions
        : profile.id === 'global-studio' ? MAX_DECLARED_GROUPS * 5
          : 0;
  const boundedPathCount = Math.min(request.scale.pathCount, coveragePathLimit);
  for (let index = 0; index < boundedPathCount; index += 1) {
    const identity = groupIdentity(profile.id, index, request);
    if (!identity) continue;
    const group = groups.get(identity.id) ?? { ...identity, members: [] };
    const groupIndex = Math.floor(index / 2);
    if (!(profile.id === 'unity-like' && index % 2 === 1 && unityMissingSidecar(request, groupIndex))) {
      group.members.push(profilePath(profile.id, index, request.scale.maxDepth, request));
    }
    if (profile.id === 'unity-like' && (unityMissingSidecar(request, groupIndex) || unityDuplicateGuid(request, groupIndex))) {
      group.negativeCase = unityMissingSidecar(request, groupIndex) ? 'missing-sidecar' : 'duplicate-guid';
    }
    groups.set(identity.id, group);
  }
  return [...groups.values()];
}

const FEATURE_FOR_OPERATION = {
  'branch-update': 'branch-update',
  branch: 'branches',
  'ci-materialize': 'ci-materialization',
  copy: 'copies',
  delete: 'deletes',
  edit: 'text-edits',
  interrupt: 'interruptions',
  'lock-conflict': 'lock-conflicts',
  'lock-loss': 'lock-lifecycle',
  merge: 'merges',
  move: 'moves',
  'network-condition': 'network-conditions',
  rename: 'renames',
  review: 'review',
  'selective-sync': 'selective-sync',
};

const BASELINE_CHANGE = 'change-99999999';
const BASELINE_REVISION = `${BASELINE_CHANGE}-r0`;

export function operationKinds(request, profile) {
  const kinds = profile.operationKinds.filter((kind) => {
    // A merge source is created by the branch operation. Keeping merges while
    // branches are disabled would emit successful merges of undefined heads.
    if (kind === 'merge' && Object.hasOwn(request.featureFlags, 'branches') && !enabled(request, 'branches')) {
      return false;
    }
    const feature = FEATURE_FOR_OPERATION[kind];
    if (!feature || !Object.hasOwn(request.featureFlags, feature)) return true;
    return enabled(request, feature);
  });
  return kinds.length === 0 ? ['create'] : kinds;
}

function operationBaseTarget(request, profile, cycle) {
  const targetIndex = deterministicInt(request.seed, 'operations/target', request.scale.pathCount, cycle);
  const logicalPath = profilePath(profile.id, targetIndex, request.scale.maxDepth, request);
  const segments = logicalPath.split('/');
  const filename = segments.pop();
  return normalizeLogicalPath([...segments, `history-${padded(cycle)}-${filename}`].join('/'));
}

function operationRelatedTarget(kind, cycle, target, maxDepth) {
  const segments = target.split('/');
  const root = segments.shift();
  return boundedPath(
    [root, 'Changes', kind],
    `${padded(cycle)}-${segments.at(-1)}`,
    maxDepth,
  );
}

function operationFileId(request, profile, cycle) {
  return deterministicId(request.seed, 'file-id', `${profile.id}/history/${padded(cycle)}`);
}

function operationFileState(request, profile, kind, cycle, kindIndex, kinds) {
  const baseTarget = operationBaseTarget(request, profile, cycle);
  const primaryFileId = operationFileId(request, profile, cycle);
  let target = baseTarget;
  let present = profile.id === 'global-studio';
  let deleted = false;
  for (const precedingKind of kinds.slice(0, kindIndex)) {
    if (precedingKind === 'create') present = true;
    if (precedingKind === 'move' || precedingKind === 'rename') {
      target = operationRelatedTarget(precedingKind, cycle, target, request.scale.maxDepth);
    }
    if (precedingKind === 'delete') {
      present = false;
      deleted = true;
    }
  }

  if (kind === 'create') {
    return {
      fileId: { result: primaryFileId, semantics: 'created', source: null },
      presentBefore: false,
      target,
    };
  }
  if (kind === 'copy') {
    return {
      fileId: {
        result: deterministicId(request.seed, 'file-id', `${profile.id}/history/${padded(cycle)}/copy`),
        semantics: 'copied',
        source: primaryFileId,
      },
      presentBefore: present,
      target,
    };
  }
  if (kind === 'move' || kind === 'rename') {
    return {
      fileId: { result: primaryFileId, semantics: kind === 'move' ? 'moved' : 'renamed', source: primaryFileId },
      presentBefore: present,
      target,
    };
  }
  if (kind === 'delete') {
    return {
      fileId: { result: null, semantics: 'deleted', source: primaryFileId },
      presentBefore: present,
      target,
    };
  }
  return {
    fileId: deleted
      ? { result: null, semantics: 'tombstone-observed', source: primaryFileId }
      : { result: primaryFileId, semantics: kind === 'edit' ? 'modified' : 'observed', source: primaryFileId },
    presentBefore: present,
    target,
  };
}

const ACTION_FOR_OPERATION = Object.freeze({
  'branch-update': 'branch',
  branch: 'branch',
  'ci-materialize': 'materialize',
  copy: 'write',
  create: 'write',
  delete: 'write',
  edit: 'write',
  interrupt: 'write',
  'lock-acquire': 'lock',
  'lock-conflict': 'lock',
  'lock-loss': 'lock',
  merge: 'merge',
  move: 'write',
  'network-condition': 'read',
  rename: 'write',
  review: 'read',
  'selective-sync': 'read',
  submit: 'write',
});

function actorRoleFor(kind, target) {
  if (kind === 'ci-materialize') return 'automation';
  return ['Content', 'Assets'].includes(target.split('/')[0]) ? 'artist' : 'developer';
}

function actorFor(request, kind, target, cycle, contender = false) {
  const role = actorRoleFor(kind, target);
  const pool = role === 'artist' ? [0, 1] : role === 'developer' ? [2, 3, 4, 5] : [6, 7];
  const base = deterministicInt(request.seed, `operations/actor/${role}`, pool.length, cycle);
  return `actor-${pool[(base + (contender ? 1 : 0)) % pool.length]}`;
}

function authorizationFor(kind, actor, target) {
  const role = actorRoleFor(kind, target);
  return {
    action: ACTION_FOR_OPERATION[kind],
    decision: 'allow',
    matchedPathPrefix: role === 'automation' ? '' : target.split('/')[0],
    matchedPrincipal: `group-${role === 'automation' ? role : `${role}s`}`,
  };
}

function expectedOutcome(profile, kind, kinds) {
  if (kind === 'lock-conflict') return { code: 'lock-held', status: 'rejected' };
  if (
    profile.id === 'global-studio'
    && kind === 'submit'
    && kinds.indexOf('lock-loss') < kinds.indexOf('submit')
    && kinds.includes('lock-loss')
  ) {
    return { code: 'lock-not-held', status: 'rejected' };
  }
  const code = {
    'branch-update': 'branch-updated',
    branch: 'branch-created',
    'ci-materialize': 'materialized',
    copy: 'copied',
    create: 'created',
    delete: 'deleted',
    edit: 'edited',
    interrupt: 'interrupted-resumable',
    'lock-acquire': 'lock-acquired',
    'lock-loss': 'lock-lost',
    merge: 'merged',
    move: 'moved',
    'network-condition': 'network-profile-applied',
    rename: 'renamed',
    review: 'review-recorded',
    'selective-sync': 'sync-completed',
    submit: 'submitted',
  }[kind];
  return { code, status: 'succeeded' };
}

function operationParameters(request, profile, kind, sequence, cycle, target, actor) {
  const retryKey = deterministicId(request.seed, 'operation', `operations/${padded(sequence)}`);
  const change = `change-${padded(cycle)}`;
  const lockId = deterministicId(request.seed, 'lock', target);
  const common = { 'change-id': change, 'retry-key': retryKey };
  const kinds = operationKinds(request, profile);
  const currentRevision = profile.id === 'global-studio'
    ? BASELINE_REVISION
    : `${change}-r${kinds.includes('edit') ? 2 : 1}`;
  if (kind === 'create') return { ...common, 'result-revision': `${change}-r1` };
  if (kind === 'edit') return { ...common, 'base-revision': `${change}-r1`, 'delta-kind': 'semantic-v2', 'result-revision': `${change}-r2` };
  if (['copy', 'move', 'rename'].includes(kind)) return { ...common, 'preserve-file-id': kind === 'move' || kind === 'rename' };
  if (kind === 'delete') return { ...common, 'base-revision': currentRevision, tombstone: true };
  if (kind === 'branch') return { ...common, 'from-revision': currentRevision, 'source-branch': 'main', 'target-branch': `feature-${padded(cycle)}` };
  if (kind === 'merge') return { ...common, 'common-base': currentRevision, 'source-branch': `feature-${padded(cycle)}`, strategy: 'three-way', 'target-branch': 'main' };
  if (kind === 'lock-acquire') return { ...common, 'lease-seconds': 300, 'lock-id': lockId };
  if (kind === 'lock-conflict') return {
    ...common,
    contender: actor,
    holder: actorFor(request, 'lock-acquire', target, cycle),
    'lock-id': lockId,
    outcome: 'denied',
  };
  if (kind === 'lock-loss') return {
    ...common,
    'lock-id': lockId,
    reason: 'lease-expired',
    recovery: 'shelve-local-work',
    'submit-policy': 'reject-until-reacquired',
  };
  if (kind === 'submit') {
    const rejectedAfterLockLoss = profile.id === 'global-studio'
      && kinds.includes('lock-loss')
      && kinds.indexOf('lock-loss') < kinds.indexOf('submit');
    return {
      ...common,
      atomic: true,
      'parent-change': rejectedAfterLockLoss
        ? 'root'
        : cycle === 0
          ? profile.id === 'global-studio' ? BASELINE_CHANGE : 'root'
          : `change-${padded(cycle - 1)}`,
    };
  }
  if (kind === 'branch-update') return { ...common, 'expected-head': BASELINE_REVISION, 'source-branch': 'main', 'target-branch': `release-${cycle % 4}` };
  if (kind === 'review') return { ...common, decision: cycle % 3 === 0 ? 'changes-requested' : 'approved', reviewers: ['actor-2', 'actor-3'] };
  if (kind === 'selective-sync') return { ...common, excludes: ['Library', 'DerivedDataCache'], includes: ['Source', 'Content'], 'revision-selector': currentRevision };
  if (kind === 'ci-materialize') return { ...common, 'clean-workspace': true, platform: ['linux', 'macos', 'windows'][cycle % 3], revision: currentRevision };
  if (kind === 'interrupt') return { ...common, 'after-bytes': 1_048_576 * (1 + cycle % 8), phase: ['transfer', 'apply', 'submit'][cycle % 3], recovery: 'resume-with-retry-key' };
  if (kind === 'network-condition') return { ...common, 'duration-seconds': 30 + cycle % 90, transition: 'apply-link-profile' };
  return common;
}

export function createOperation(request, profile, sequence) {
  const kinds = operationKinds(request, profile);
  const kindIndex = sequence % kinds.length;
  const kind = kinds[kindIndex];
  const cycle = Math.floor(sequence / kinds.length);
  const state = operationFileState(request, profile, kind, cycle, kindIndex, kinds);
  const actor = actorFor(request, kind, state.target, cycle, kind === 'lock-conflict');
  const operation = {
    actor,
    authorization: authorizationFor(kind, actor, state.target),
    expectedOutcome: expectedOutcome(profile, kind, kinds),
    fileId: state.fileId,
    kind,
    parameters: operationParameters(request, profile, kind, sequence, cycle, state.target, actor),
    sequence,
    target: state.target,
  };
  if (['copy', 'move', 'rename'].includes(kind)) {
    operation.relatedTarget = operationRelatedTarget(
      kind,
      cycle,
      state.target,
      request.scale.maxDepth,
    );
  } else if (['branch', 'merge', 'branch-update'].includes(kind)) {
    operation.relatedTarget = kind === 'merge' ? 'branches/main'
      : kind === 'branch-update' ? `branches/release-${cycle % 4}`
        : `branches/feature-${padded(cycle)}`;
  }
  if (kind === 'network-condition') operation.networkCondition = `link-${1 + cycle % 2}`;
  return operation;
}

function participantsFor(profile) {
  return Array.from({ length: 8 }, (_, index) => ({
    id: `actor-${index}`,
    role: index < 2 ? 'artist' : index < 6 ? 'developer' : 'automation',
    site: `site-${index % 3}`,
  }));
}

function aclPathPrefixes(profile) {
  if (profile.id === 'code-heavy') return { artists: [], developers: ['Caf\u00e9', 'src'] };
  if (profile.id === 'unreal-like') return { artists: ['Content'], developers: ['Config', 'Source'] };
  if (profile.id === 'unity-like' || profile.id === 'large-binary') return { artists: ['Assets'], developers: [] };
  return { artists: ['Assets', 'Content'], developers: ['Config', 'Reviews', 'Source'] };
}

function initialFileState(request, profile) {
  if (profile.id !== 'global-studio') return [];
  const kinds = operationKinds(request, profile);
  const cycleCount = Math.ceil(request.scale.historyOperationCount / kinds.length);
  return Array.from({ length: cycleCount }, (_, cycle) => ({
    fileId: operationFileId(request, profile, cycle),
    logicalPath: operationBaseTarget(request, profile, cycle),
    revision: BASELINE_REVISION,
  }));
}

function initialBranchState(profile) {
  const names = profile.id === 'global-studio'
    ? ['main', 'release-0', 'release-1', 'release-2', 'release-3']
    : ['main'];
  return names.map((name) => ({
    head: profile.id === 'global-studio' ? BASELINE_REVISION : null,
    name,
  }));
}

function initialChangeState(profile) {
  return profile.id === 'global-studio'
    ? [{ id: BASELINE_CHANGE, parent: 'root', status: 'committed' }]
    : [];
}

function initialRevisionState(profile) {
  return profile.id === 'global-studio'
    ? [{ changeId: BASELINE_CHANGE, revision: BASELINE_REVISION }]
    : [];
}

function accessControlExtensions(request, profile, participants) {
  const prefixes = aclPathPrefixes(profile);
  const pathRules = [];
  for (const pathPrefix of prefixes.artists) {
    pathRules.push({ actions: ['read', 'write', 'lock', 'branch', 'merge'], effect: 'allow', pathPrefix, principal: 'group-artists' });
  }
  for (const pathPrefix of prefixes.developers) {
    pathRules.push({ actions: ['read', 'write', 'lock', 'branch', 'merge'], effect: 'allow', pathPrefix, principal: 'group-developers' });
  }
  return {
    'acl-model': {
      algorithm: 'ordered-prefix-acl-v1',
      default: 'deny',
      rules: [
        ...pathRules,
        { actions: ['read', 'materialize'], effect: 'allow', pathPrefix: '', principal: 'group-automation' },
      ],
    },
    'identity-model': {
      algorithm: 'synthetic-principal-v1',
      identities: participants.map(({ id, role, site }) => ({ groups: [`group-${role === 'automation' ? role : `${role}s`}`, `group-${site}`], id, site })),
    },
    'state-model': {
      algorithm: 'path-file-id-revision-branch-state-v2',
      branches: initialBranchState(profile),
      changes: initialChangeState(profile),
      files: initialFileState(request, profile),
      locks: [],
      revisions: initialRevisionState(profile),
    },
  };
}

export function scenarioEnvelope(request, profile, operations, operationsDigest) {
  const networkConditions = [
    { bandwidthBytesPerSecond: 1_000_000_000, id: 'link-0', jitterMilliseconds: 1, latencyMilliseconds: 1, lossPartsPerMillion: 0 },
  ];
  if (profile.id !== 'global-studio' || enabled(request, 'network-conditions')) {
    networkConditions.push(
      { bandwidthBytesPerSecond: 100_000_000, id: 'link-1', jitterMilliseconds: 15, latencyMilliseconds: 90, lossPartsPerMillion: 100 },
      { bandwidthBytesPerSecond: 20_000_000, id: 'link-2', jitterMilliseconds: 40, latencyMilliseconds: 200, lossPartsPerMillion: 1000 },
    );
  }
  const participants = participantsFor(profile);
  const body = {
    extensions: accessControlExtensions(request, profile, participants),
    networkConditions,
    operations,
    participants,
    profile: { id: profile.id, version: profile.version },
    scenarioId: `${profile.id}-scenario-v2`,
    schemaVersion: SCENARIO_SCHEMA,
    seed: request.seed,
  };
  return { ...body, digest: canonicalDigest({ ...body, operationsDigest }, 'ogvcs.fixture/operation-scenario/v2') };
}

export function historyShape(request, profile, budget) {
  const initialBranches = new Set(initialBranchState(profile).map(({ name }) => name));
  const updatedBranches = new Set(initialBranches);
  let createdBranchCount = 0;
  let mergeCount = 0;
  const initialChangeDepths = new Map();
  const initialRevisionDepths = new Map();
  let maximumDepth = 0;
  let rootCount = 0;
  for (const change of initialChangeState(profile)) {
    const revision = initialRevisionState(profile).find((entry) => entry.changeId === change.id);
    const depth = 1;
    if (revision) initialRevisionDepths.set(revision.revision, depth);
    initialChangeDepths.set(change.id, depth);
    maximumDepth = Math.max(maximumDepth, depth);
    if (change.parent === 'root') rootCount += 1;
  }

  let currentChangeId;
  let information;
  let lastChangeId;
  let lastChangeTerminalDepth;
  const finishChange = () => {
    if (currentChangeId === undefined || information === undefined) return;
    if (!information.submitted && information.revisions.length === 0) return;
    const hasParent = information.submitted
      && information.parentChange !== undefined
      && information.parentChange !== 'root';
    const parentDepth = hasParent
      ? initialChangeDepths.get(information.parentChange)
        ?? (information.parentChange === lastChangeId ? lastChangeTerminalDepth : undefined)
      : 0;
    if (hasParent && parentDepth === undefined) {
      throw new Error(`History change ${currentChangeId} references an unknown parent ${information.parentChange}`);
    }
    if (!hasParent) rootCount += 1;
    let terminalDepth = parentDepth ?? 0;
    const currentRevisionDepths = new Map();
    for (const revision of information.revisions) {
      const baseDepth = revision.baseRevision === null
        ? terminalDepth
        : currentRevisionDepths.get(revision.baseRevision)
          ?? initialRevisionDepths.get(revision.baseRevision);
      if (baseDepth === undefined) {
        throw new Error(`History revision ${revision.revision} references an unknown base ${revision.baseRevision}`);
      }
      const depth = baseDepth + 1;
      currentRevisionDepths.set(revision.revision, depth);
      terminalDepth = Math.max(terminalDepth, depth);
    }
    if (information.revisions.length === 0) terminalDepth += 1;
    lastChangeId = currentChangeId;
    lastChangeTerminalDepth = terminalDepth;
    maximumDepth = Math.max(maximumDepth, terminalDepth);
  };

  for (let sequence = 0; sequence < request.scale.historyOperationCount; sequence += 1) {
    if (sequence % 1024 === 0) budget?.checkRuntime('history-shape-replay');
    const operation = createOperation(request, profile, sequence);
    if (operation.expectedOutcome.status === 'succeeded') {
      if (operation.kind === 'branch') createdBranchCount += 1;
      if (operation.kind === 'branch-update') updatedBranches.add(operation.parameters['target-branch']);
      if (operation.kind === 'merge') mergeCount += 1;
    }
    const changeId = operation.parameters['change-id'];
    if (changeId !== currentChangeId) {
      finishChange();
      currentChangeId = changeId;
      information = { parentChange: undefined, revisions: [], submitted: false };
    }
    const resultRevision = operation.parameters['result-revision'];
    if (typeof resultRevision === 'string') {
      information.revisions.push({
        baseRevision: operation.parameters['base-revision'] ?? null,
        revision: resultRevision,
      });
    }
    if (operation.kind === 'submit' && operation.expectedOutcome.status === 'succeeded') {
      information.parentChange = operation.parameters['parent-change'];
      information.submitted = true;
    }
  }
  finishChange();

  return {
    branchCount: updatedBranches.size + createdBranchCount,
    maximumDepth,
    mergeCount,
    rootCount,
  };
}

export function contentIndexLine(record) {
  return `${canonicalStringify({ digest: record.content.digest, logicalBytes: record.content.logicalBytes, logicalPath: record.logicalPath })}\n`;
}

export function computeDirectorySet(record, set) {
  const segments = record.logicalPath.split('/');
  for (let length = 1; length < segments.length; length += 1) set.add(segments.slice(0, length).join('/'));
}

export function hashCanonicalLines(domain, records) {
  const hash = createHash('sha256');
  hash.update(`${domain}\0`, 'utf8');
  for (const record of records) hash.update(`${canonicalStringify(record)}\n`, 'utf8');
  return hash.digest('hex');
}
