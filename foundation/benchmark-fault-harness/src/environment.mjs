import os from 'node:os';

import { canonicalDigest, deepFreeze } from './canonical.mjs';
import { harnessFail } from './errors.mjs';
import { snapshotData, snapshotOptions } from './input.mjs';

function safeLabel(value, fallback) {
  const result = value ?? fallback;
  if (typeof result !== 'string' || result.length < 1 || result.length > 256 || result.includes('\0') || result.normalize('NFC') !== result || /[\uD800-\uDFFF]/u.test(result)) harnessFail('HARNESS_INPUT_INVALID', 'environment label is invalid');
  return result;
}

function capturedDate(clock) {
  if (clock !== undefined && typeof clock !== 'function') harnessFail('HARNESS_INPUT_INVALID', 'environment clock must be callable');
  let raw;
  try { raw = clock?.() ?? new Date(); } catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'environment clock failed', { cause: error }); }
  const value = raw instanceof Date ? new Date(raw.valueOf()) : new Date(raw);
  try { value.toISOString(); } catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'environment clock returned an invalid date', { cause: error }); }
  return value;
}

export function captureEnvironment(options) {
  options = snapshotOptions(options, 'environment options');
  if (options.corpus !== undefined) options.corpus = snapshotData(options.corpus, 'environment corpus');
  if (options.cacheInspection !== undefined) options.cacheInspection = snapshotData(options.cacheInspection, 'environment cache inspection');
  if (options.network !== undefined) options.network = snapshotData(options.network, 'environment network profile');
  if (!options?.corpus || !options.cacheInspection || !options.network || !options.thresholdDigest || !options.seed) harnessFail('HARNESS_INPUT_INVALID', 'environment capture is incomplete');
  const classification = options.classification ?? 'synthetic';
  if (!['synthetic', 'partner-derived'].includes(classification)) harnessFail('HARNESS_INPUT_INVALID', 'environment classification is invalid');
  const cpu = safeLabel((os.cpus()[0]?.model ?? 'unknown-cpu').normalize('NFC').slice(0, 256), 'unknown-cpu');
  const commit = canonicalDigest(safeLabel(options.implementationCommit, 'working-tree'), 'ogvcs.benchmark/implementation-commit/v1');
  const record = {
    schemaVersion: 'ogvcs.benchmark/environment/v1',
    capturedAt: capturedDate(options.clock).toISOString(),
    classification,
    operatorDigest: canonicalDigest(safeLabel(options.operator, 'local-operator'), 'ogvcs.benchmark/operator/v1'),
    implementation: { id: safeLabel(options.implementationId, 'ogvcs.reference/fake-service@1'), version: safeLabel(options.implementationVersion, '1.0.0-rc.2'), commit },
    corpus: {
      profileId: options.corpus.profile.id,
      profileVersion: options.corpus.profile.version,
      requestDigest: options.corpus.requestDigest,
      manifestDigest: options.corpus.manifestDigest,
      generatorVersion: safeLabel(options.corpus.generatorVersion, '1.0.0'),
    },
    configuration: { harnessVersion: '1.0.0-rc.2', harnessProfile: options.harnessProfile, thresholdDigest: options.thresholdDigest, seedDigest: canonicalDigest(options.seed, 'ogvcs.benchmark/seed/v1'), iterations: options.iterations, concurrency: options.concurrency, cacheState: options.cacheInspection.state, networkProfile: options.network.id },
    hardware: { architecture: safeLabel(os.arch(), 'unknown-architecture'), cpuModel: cpu, cpuCount: Math.max(1, os.cpus().length), memoryBytes: os.totalmem() },
    platform: { os: ['linux', 'darwin', 'win32'].includes(process.platform) ? process.platform : 'other', release: os.release().slice(0, 256), filesystem: safeLabel(options.filesystem, 'unknown'), nodeVersion: process.version },
    topology: { clientRegion: safeLabel(options.clientRegion, 'local-client'), serviceRegion: safeLabel(options.serviceRegion, 'local-service'), cacheRegion: safeLabel(options.cacheRegion, 'local-cache') },
    network: { rttMs: options.network.rttMs, bandwidthBytesPerSecond: options.network.bandwidthBytesPerSecond, lossPartsPerMillion: options.network.lossPartsPerMillion, interruptionEvery: options.network.interruptionEvery, duplicateEvery: options.network.duplicateEvery, reorderWindow: options.network.reorderWindow, mode: options.network.mode },
    cacheInspection: { state: options.cacheInspection.state, localBytes: options.cacheInspection.localBytes, regionalBytes: options.cacheInspection.regionalBytes, stateDigest: options.cacheInspection.stateDigest },
  };
  return deepFreeze(record);
}
