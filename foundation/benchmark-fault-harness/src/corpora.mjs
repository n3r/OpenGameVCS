import { constants as fsConstants } from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';

import { createRequest, generateFixture, inspectFixture, verifyFixture } from '@opengamevcs/fixture-generator';

import { deepFreeze } from './canonical.mjs';
import { harnessFail } from './errors.mjs';
import { HARNESS_LIMITS } from './limits.mjs';
import { snapshotData, snapshotOptions } from './input.mjs';

export const REFERENCE_CORPORA = Object.freeze(['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like']);

function requestFor(profileId, destination, seed, options) {
  return createRequest({
    profile: { id: profileId, version: '2.0.0' }, destination, seed: `${seed}-${profileId}`,
    scale: { pathCount: options.pathCount ?? 8, historyOperationCount: options.historyOperationCount ?? 8, largeFileBytes: profileId === 'code-heavy' ? 0 : options.largeFileBytes ?? 4096, maxDepth: options.maxDepth ?? 6 },
    extensions: {
      'generation.checkpoint-every': 4,
      'generation.compression-class': 'mixed',
      'generation.duplication-permille': 100,
      'generation.edit-locality-permille': 800,
      'generation.large-file-mode': 'virtual',
      'generation.materialization': 'index-only',
      'generation.materialized-path-limit': 0,
      'generation.mutable-versions': 2,
    },
  });
}

async function boundedJson(pathname, maximum = HARNESS_LIMITS.maxResultBundleBytes) {
  let handle;
  try {
    handle = await open(pathname, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const before = await handle.stat();
    if (!before.isFile() || before.size < 1 || before.size > maximum) harnessFail('HARNESS_LIMIT_EXCEEDED', 'fixture scenario exceeds harness input bounds');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || before.ino !== 0 && after.ino !== 0 && before.ino !== after.ino) harnessFail('HARNESS_INPUT_INVALID', 'fixture scenario changed while loading');
    try { return JSON.parse(bytes); } catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'fixture scenario is not JSON', { cause: error }); }
  } catch (error) {
    if (error?.code?.startsWith?.('HARNESS_')) throw error;
    harnessFail('HARNESS_IO', 'fixture scenario cannot be read safely', { cause: error });
  } finally { await handle?.close().catch(() => {}); }
}

export async function loadReferenceCorpus(root, destination) {
  if (typeof root !== 'string' || root.length < 1 || root.includes('\0') || typeof destination !== 'string' || destination.length < 1 || destination.length > 4096 || destination.includes('\0') || destination.includes('\\') || destination.startsWith('/') || destination.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')) harnessFail('HARNESS_INPUT_INVALID', 'fixture corpus root or destination is invalid');
  const verification = await verifyFixture(destination, { cwd: root, deep: true });
  if (!verification.verified) harnessFail('HARNESS_ASSERTION_FAILED', 'fixture corpus failed deterministic verification');
  const inspection = await inspectFixture(destination, { cwd: root });
  const scenario = await boundedJson(path.join(root, ...destination.split('/'), 'scenario.json'));
  if (!inspection?.profile || !Array.isArray(scenario?.operations) || scenario.operations.some((operation) => !operation || typeof operation.kind !== 'string') || typeof scenario.digest !== 'string') harnessFail('HARNESS_INPUT_INVALID', 'fixture corpus inspection is incomplete');
  return deepFreeze({
    id: inspection.profile.id,
    destination,
    manifestDigest: inspection.manifestDigest,
    requestDigest: inspection.requestDigest,
    profile: { id: inspection.profile.id, version: inspection.profile.version },
    logicalBytes: inspection.logicalBytes,
    counts: inspection.counts,
    operationKinds: [...new Set(scenario.operations.map(({ kind }) => kind))].sort(),
    scenarioDigest: scenario.digest,
    verified: true,
  });
}

export async function materializeReferenceCorpora(root, options = {}) {
  options = snapshotOptions(options, 'reference corpus options');
  if (typeof root !== 'string' || root.length < 1) harnessFail('HARNESS_INPUT_INVALID', 'fixture workspace root is required');
  const profiles = options.profiles === undefined ? REFERENCE_CORPORA : snapshotData(options.profiles, 'reference corpus profiles');
  if (!Array.isArray(profiles) || profiles.length < 1 || profiles.length > HARNESS_LIMITS.maxCorpora || profiles.some((id) => !REFERENCE_CORPORA.includes(id)) || new Set(profiles).size !== profiles.length) harnessFail('HARNESS_INPUT_INVALID', 'reference corpus selection is invalid');
  const seed = options.seed ?? 'ogvcs-benchmark-smoke-v1';
  const output = [];
  for (const profileId of profiles) {
    const destination = `corpora/${profileId}`;
    await generateFixture(requestFor(profileId, destination, seed, options), { cwd: root });
    output.push(await loadReferenceCorpus(root, destination));
  }
  return deepFreeze(output);
}
