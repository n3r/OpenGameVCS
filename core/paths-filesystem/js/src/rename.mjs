import { createHash } from 'node:crypto';

import { PathFilesystemError, errorDecision, pathFail } from './errors.mjs';
import { findPathCollisions, pathCollisionKeys } from './path.mjs';

function canonicalJson(value) {
  if (typeof value === 'string') return JSON.stringify(value);
  if (Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}
const compare = (left, right) => Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));

function canonicalArraySha256(values) {
  const hash = createHash('sha256');
  hash.update('[');
  for (let index = 0; index < values.length; index += 1) {
    if (index > 0) hash.update(',');
    hash.update(canonicalJson(values[index]));
  }
  hash.update(']\n');
  return hash.digest('hex');
}

export function planRenames(request, options = {}) {
  const maximum = options.maxRenames ?? 100_000;
  if (request === null || typeof request !== 'object' || !Array.isArray(request.renames) || !Number.isSafeInteger(maximum) || maximum < 0 || request.renames.length > maximum) pathFail('PATH_INPUT_INVALID');
  const sources = []; const destinations = []; const normalized = [];
  for (let index = 0; index < request.renames.length; index += 1) {
    const item = request.renames[index];
    const from = pathCollisionKeys(item?.from, { caseMode: request.caseMode, profile: request.profile });
    const to = pathCollisionKeys(item?.to, { caseMode: request.caseMode, profile: request.profile });
    if (typeof item.fileId !== 'string' || !/^[0-9a-f]{32}$/u.test(item.fileId)) pathFail('ENTRY_INVALID', undefined, { rename: index });
    sources.push({ id: String(index), path: from.canonical }); destinations.push({ id: String(index), path: to.canonical });
    normalized.push(Object.freeze({ fileId: item.fileId, from: from.canonical, to: to.canonical }));
  }
  try { findPathCollisions(sources, { caseMode: request.caseMode, profile: request.profile, maxPaths: maximum }); }
  catch (error) { if (error instanceof PathFilesystemError && error.code === 'PATH_COLLISION') pathFail('RENAME_CONFLICT', undefined, error.details); throw error; }
  try { findPathCollisions(destinations, { caseMode: request.caseMode, profile: request.profile, maxPaths: maximum }); }
  catch (error) { if (error instanceof PathFilesystemError && error.code === 'PATH_COLLISION') pathFail('RENAME_CONFLICT', undefined, error.details); throw error; }
  const ordered = normalized.map((item, index) => ({ ...item, index })).sort((left, right) => compare(left.from, right.from));
  const canonical = ordered.map(({ index: _index, ...item }) => item);
  const transaction = canonicalArraySha256(canonical).slice(0, 24);
  const staged = ordered.map((item, index) => Object.freeze({
    from: item.from, to: `.ogvcs/rename/${transaction}-${String(index).padStart(6, '0')}`, fileId: item.fileId, phase: 'stage',
  }));
  const temp = new Map(staged.map(({ from, to }) => [from, to]));
  const publish = [...normalized].sort((left, right) => compare(left.to, right.to)).map((item) => Object.freeze({ from: temp.get(item.from), to: item.to, fileId: item.fileId, phase: 'publish' }));
  return Object.freeze({ caseMode: request.caseMode, profile: request.profile, transaction, steps: Object.freeze([...staged, ...publish]) });
}

export function evaluateRenames(request, options = {}) {
  try { return Object.freeze({ accepted: true, ...planRenames(request, options) }); }
  catch (error) { if (!(error instanceof PathFilesystemError)) throw error; return errorDecision(error); }
}
