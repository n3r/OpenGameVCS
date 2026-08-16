import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { lstatSync, readFileSync } from 'node:fs';

import {
  CONTRACT_MANIFEST_SHA256,
  CONTRACT_VERSION,
  ERROR_ENTRIES,
  PLATFORM_PROFILES,
  REGISTRY_SET_SHA256,
  UNICODE_CASE_FOLDING_SHA256,
} from './generated-contract.mjs';

const require = createRequire(import.meta.url);
const CONTRACT_ROOT = dirname(require.resolve('@opengamevcs/path-contract-v1/package.json'));

function boundedFile(relativePath, maximumBytes) {
  if (typeof relativePath !== 'string' || relativePath.length === 0 || isAbsolute(relativePath) || relativePath.includes('\\')
    || relativePath.split('/').some((part) => part === '' || part === '.' || part === '..')
    || !Number.isSafeInteger(maximumBytes) || maximumBytes < 0) throw new Error('packaged path contract request is invalid');
  const absolute = resolve(CONTRACT_ROOT, relativePath);
  const rel = relative(CONTRACT_ROOT, absolute);
  if (rel === '' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error('packaged path contract request escapes its package');
  const info = lstatSync(absolute);
  if (!info.isFile() || info.isSymbolicLink() || info.size > maximumBytes) throw new Error(`packaged path contract ${relativePath} is not a bounded regular file`);
  const bytes = readFileSync(absolute);
  if (bytes.length !== info.size) throw new Error(`packaged path contract ${relativePath} changed while reading`);
  return bytes;
}

const manifestBytes = boundedFile('manifest.json', 1024 * 1024);
if (createHash('sha256').update(manifestBytes).digest('hex') !== CONTRACT_MANIFEST_SHA256) {
  throw new Error('packaged path contract manifest differs from generated bindings');
}
const manifest = JSON.parse(manifestBytes);
if (manifest.contractVersion !== CONTRACT_VERSION || manifest.registrySetSha256 !== REGISTRY_SET_SHA256 || manifest.unicode.caseFoldingSha256 !== UNICODE_CASE_FOLDING_SHA256) {
  throw new Error('packaged path contract authority differs from generated bindings');
}
const artifacts = new Map(manifest.artifacts.map((record) => [record.path, record]));

const caseFoldingBytes = boundedFile('data/CaseFolding-16.0.0.txt', 256 * 1024);
if (createHash('sha256').update(caseFoldingBytes).digest('hex') !== UNICODE_CASE_FOLDING_SHA256) {
  throw new Error('packaged Unicode case-fold table differs from the frozen authority');
}

export const pathContract = Object.freeze({
  root: CONTRACT_ROOT,
  manifest: Object.freeze(manifest),
  manifestSha256: CONTRACT_MANIFEST_SHA256,
  caseFoldingText: caseFoldingBytes.toString('utf8'),
  contractVersion: CONTRACT_VERSION,
  errorEntries: ERROR_ENTRIES,
  profiles: PLATFORM_PROFILES,
  registrySetSha256: REGISTRY_SET_SHA256,
  unicodeCaseFoldingSha256: UNICODE_CASE_FOLDING_SHA256,
});

export function loadContractJson(relative, maximumBytes = 16 * 1024 * 1024) {
  const record = artifacts.get(relative);
  if (record === undefined || !relative.endsWith('.json')) throw new Error('path contract artifact is not declared JSON');
  const bytes = boundedFile(relative, Math.min(maximumBytes, record.bytes));
  if (bytes.length !== record.bytes || createHash('sha256').update(bytes).digest('hex') !== record.sha256) throw new Error('path contract artifact differs from its manifest');
  return JSON.parse(bytes);
}
