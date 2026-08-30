#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(process.env.OGVCS_CHUNK_CONTRACT_ROOT ?? dirname(fileURLToPath(import.meta.url)));
const MAX_JSON = 16 * 1024 * 1024; const MASK64 = (1n << 64n) - 1n;
const PROFILE = 'chunking.opengamevcs/gear-fastcdc-1m@1';
function fail(message) { throw new Error(`chunking-manifest-contract-v1: ${message}`); }
const hash = (value) => createHash('sha256').update(value).digest();
const hexHash = (value) => hash(value).toString('hex');
const canonical = (value) => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  fail('noncanonical JSON value');
};
async function load(path) {
  const absolute = resolve(ROOT, path); const stat = await lstat(absolute).catch(() => null);
  if (!stat?.isFile() || stat.isSymbolicLink() || stat.size > MAX_JSON) fail(`${path} is not a bounded regular file`);
  const bytes = await readFile(absolute); let value;
  try { value = JSON.parse(bytes); } catch { fail(`${path} is invalid JSON`); }
  if (!bytes.equals(Buffer.from(`${canonical(value)}\n`))) fail(`${path} is not canonical JSON`);
  return { bytes, value };
}
function u16(value) { const out = Buffer.alloc(2); out.writeUInt16BE(value); return out; }
function u64(value) { const out = Buffer.alloc(8); out.writeBigUInt64BE(BigInt(value)); return out; }
const tableDomain = Buffer.from('4f70656e47616d655643532047656172207461626c6520763100', 'hex');
const gear = Array.from({ length: 256 }, (_, index) => hash(Buffer.concat([tableDomain, u16(index)])).readBigUInt64BE());
const gearDigest = hexHash(Buffer.concat(gear.map(u64)));

function source(recipe) {
  if (recipe.kind === 'literal' && /^(?:[0-9a-f]{2})*$/u.test(recipe.hex)) return Buffer.from(recipe.hex, 'hex');
  if (recipe.kind === 'repeat' && Number.isSafeInteger(recipe.length) && recipe.length >= 0 && Number.isInteger(recipe.byte) && recipe.byte >= 0 && recipe.byte <= 255) return Buffer.alloc(recipe.length, recipe.byte);
  if (recipe.kind === 'sha256-counter' && typeof recipe.seed === 'string' && Number.isSafeInteger(recipe.length) && recipe.length >= 0) {
    const result = Buffer.alloc(recipe.length); let position = 0; let sequence = 0n;
    while (position < result.length) {
      const suffix = Buffer.alloc(8); suffix.writeBigUInt64BE(sequence);
      const block = hash(Buffer.concat([Buffer.from('OpenGameVCS chunk vector block v1\0'), Buffer.from(recipe.seed), Buffer.from([0]), suffix]));
      const count = Math.min(32, result.length - position); block.copy(result, position, 0, count); position += count; sequence += 1n;
    }
    return result;
  }
  if (recipe.kind === 'insert' && Number.isSafeInteger(recipe.offset) && /^(?:[0-9a-f]{2})*$/u.test(recipe.hex)) {
    const base = source(recipe.base); if (recipe.offset < 0 || recipe.offset > base.length) fail('insert recipe offset is invalid');
    return Buffer.concat([base.subarray(0, recipe.offset), Buffer.from(recipe.hex, 'hex'), base.subarray(recipe.offset)]);
  }
  fail('invalid vector recipe');
}
function cborHeader(major, input) {
  const value = BigInt(input);
  if (value < 24n) return Buffer.from([(major << 5) + Number(value)]);
  if (value <= 255n) return Buffer.from([(major << 5) + 24, Number(value)]);
  if (value <= 65535n) { const out = Buffer.alloc(3); out[0] = (major << 5) + 25; out.writeUInt16BE(Number(value), 1); return out; }
  if (value <= 0xffff_ffffn) { const out = Buffer.alloc(5); out[0] = (major << 5) + 26; out.writeUInt32BE(Number(value), 1); return out; }
  const out = Buffer.alloc(9); out[0] = (major << 5) + 27; out.writeBigUInt64BE(value, 1); return out;
}
function encode(value) {
  if (Number.isSafeInteger(value) && value >= 0) return cborHeader(0, value);
  if (typeof value === 'string') { const body = Buffer.from(value); return Buffer.concat([cborHeader(3, body.length), body]); }
  if (value instanceof Uint8Array) { const body = Buffer.from(value); return Buffer.concat([cborHeader(2, body.length), body]); }
  if (Array.isArray(value)) return Buffer.concat([cborHeader(4, value.length), ...value.map(encode)]);
  if (value instanceof Map) {
    const fields = [...value].map(([key, field]) => [encode(key), encode(field)]).sort(([a], [b]) => a.length - b.length || Buffer.compare(a, b));
    return Buffer.concat([cborHeader(5, fields.length), ...fields.flat()]);
  }
  fail('invalid manifest value');
}
const objectDomain = Buffer.from('OpenGameVCS object\0');
const objectDigest = (kind, body) => hash(Buffer.concat([objectDomain, u16(1), u16(kind), body]));
const objectId = (kind, digest) => `ogvcs:v1:${kind === 1 ? 'chunk' : 'content-manifest'}:sha256:${digest.toString('hex')}`;
function resultFor(bytes) {
  const boundaries = []; let beginning = 0; let fingerprint = 0n;
  if (bytes.length > 262144) for (let position = 0; position < bytes.length; position += 1) {
    const length = position - beginning + 1;
    fingerprint = ((fingerprint * 2n) + gear[bytes[position]]) & MASK64;
    if (length >= 262144 && ((fingerprint & (length < 1048576 ? 0x1f_ffffn : 0x07_ffffn)) === 0n || length === 2097152)) {
      boundaries.push(position + 1); beginning = position + 1; fingerprint = 0n;
    }
  }
  if (bytes.length > 0 && boundaries.at(-1) !== bytes.length) boundaries.push(bytes.length);
  let previous = 0; const internal = boundaries.map((boundary) => {
    const body = bytes.subarray(previous, boundary); previous = boundary; const digest = objectDigest(1, body);
    return { digest, length: body.length, objectId: objectId(1, digest) };
  });
  const whole = hash(bytes); const ref = ({ digest }) => new Map([[0, 1], [1, 1], [2, 1], [3, digest]]);
  const manifest = encode(new Map([[0, 1], [1, 2], [2, []], [16, bytes.length], [17, new Map([[0, 1], [1, whole]])], [18, new Map([[0, 'chunking.opengamevcs'], [1, 'gear-fastcdc-1m'], [2, 1]])], [19, internal.map((part) => new Map([[0, ref(part)], [1, part.length]]))]]));
  return { boundaries, chunks: internal.map(({ digest, ...rest }) => rest), class: bytes.length === 0 ? 'empty' : bytes.length <= 262144 ? 'whole' : 'cdc-1m', logicalLength: bytes.length, manifestHex: manifest.toString('hex'), manifestObjectId: objectId(2, objectDigest(2, manifest)), wholeFileSha256: whole.toString('hex') };
}

const profile = (await load('profiles/gear-fastcdc-1m-v1.json')).value;
if (profile.profile !== PROFILE || profile.candidateState !== 'proposed-not-production-write-eligible' || profile.boundary.minimumBytes !== 262144 || profile.boundary.targetBytes !== 1048576 || profile.boundary.maximumBytes !== 2097152) fail('profile constants differ from ADR-0016');
if (profile.resource?.fixedWorkingBytes !== 65536 || profile.resource?.inputFragmentBytesMaximum !== 67108864 || profile.resource?.queuedChunksMaximum !== 64 || profile.resource?.workingBytesFormula !== '65536+(1+workers+queuedChunks)*2097152' || profile.resource?.workingBytesMaximum !== 1073741824 || profile.resource?.workersMinimum !== 1 || profile.resource?.workersMaximum !== 64) fail('profile resource rules differ from ADR-0016');
const limitEntries = (await load('registries/limits.json')).value.entries;
const expectedLimits = new Map([['chunk-count-maximum', 1048576], ['declared-logical-bytes-maximum', 1099511627776], ['fixed-working-bytes', 65536], ['input-fragment-bytes-maximum', 67108864], ['queued-completed-chunks-maximum', 64], ['scalar-working-memory-bytes-minimum', 4259840], ['worker-count-maximum', 64], ['working-memory-bytes-maximum', 1073741824]]);
if (limitEntries.length !== expectedLimits.size || limitEntries.some(({ name, value }, index) => expectedLimits.get(name) !== value || index > 0 && limitEntries[index - 1].name >= name)) fail('limits registry differs from ADR-0016');
const tableVector = (await load('vectors/gear-table.json')).value;
if (tableVector.tableSha256 !== gearDigest || tableVector.entries.length !== 256 || tableVector.entries.some((value, index) => value !== gear[index].toString(16).padStart(16, '0'))) fail('Gear table differs from the independent derivation');
const golden = (await load('vectors/golden.json')).value;
if (golden.profile !== PROFILE || golden.tableSha256 !== gearDigest || golden.cases.length < 8) fail('golden vector header is invalid');
for (const vector of golden.cases) if (canonical(resultFor(source(vector.recipe))) !== canonical(vector.expected)) fail(`${vector.caseId} differs from independent calculation`);
const malformed = (await load('vectors/malformed.json')).value;
if (malformed.cases.length < 8 || new Set(malformed.cases.map(({ caseId }) => caseId)).size !== malformed.cases.length || malformed.cases.some(({ expectedError }) => !/^CHUNK_[A-Z_]+$/u.test(expectedError))) fail('malformed vectors are invalid');
const fragments = (await load('vectors/fragmentation.json')).value;
if (fragments.cases.length < 3 || fragments.cases.some(({ caseId, fragmentPatterns }) => !golden.cases.some((item) => item.caseId === caseId) || fragmentPatterns.length < 3 || fragmentPatterns.flat().some((size) => !Number.isSafeInteger(size) || size < 1))) fail('fragmentation vectors are invalid');
const selectionWorkloads = (await load('vectors/selection-benchmark-workloads.json')).value;
const expectedWorkloadIds = ['source-like', 'structured', 'already-compressed', 'encrypted-random', 'insertion', 'replacement', 'append'];
if (selectionWorkloads.profile !== PROFILE
  || selectionWorkloads.workloads.length !== expectedWorkloadIds.length
  || canonical(selectionWorkloads.workloads.map(({ workloadId }) => workloadId)) !== canonical(expectedWorkloadIds)) {
  fail('selection benchmark workloads are invalid');
}
const selectionThresholds = (await load('thresholds/selection-bounded-v1.json')).value;
if (selectionThresholds.profile !== PROFILE
  || selectionThresholds.owner !== 'ogvcs-007'
  || selectionThresholds.version !== 1
  || new Set(selectionThresholds.entries.map(({ id }) => id)).size !== selectionThresholds.entries.length
  || selectionThresholds.entries.some(({ workloadId, metric, operator, severity, value }) => (workloadId !== '*' && !expectedWorkloadIds.includes(workloadId)) || !['workloadCount', 'successCount', 'accountingMismatchCount', 'reusedBytes', 'newlyRequiredBytes', 'resynchronizationDistanceBytes'].includes(metric) || !['maximum', 'minimum'].includes(operator) || !['gate', 'warning'].includes(severity) || !Number.isSafeInteger(value) || value < 0)) {
  fail('selection benchmark thresholds are invalid');
}

const manifestRecord = await load('manifest.json'); const manifest = manifestRecord.value;
if (manifest.profile !== PROFILE || manifest.tableSha256 !== gearDigest || manifest.contractVersion !== '0.1.0-rc.1') fail('contract manifest header is invalid');
if (new Set(manifest.artifacts.map(({ path }) => path)).size !== manifest.artifacts.length || manifest.artifacts.some(({ path }, index) => !/^[A-Za-z0-9._/-]+$/u.test(path) || path.startsWith('/') || path.split('/').includes('..') || index > 0 && manifest.artifacts[index - 1].path >= path)) fail('contract artifact inventory is unsafe, duplicated, or unsorted');
for (const artifact of manifest.artifacts) {
  const body = await readFile(resolve(ROOT, artifact.path));
  if (body.length !== artifact.bytes || hexHash(body) !== artifact.sha256) fail(`${artifact.path} differs from its manifest record`);
  if (artifact.path.endsWith('.json') && artifact.path !== 'package.json') await load(artifact.path);
}
const artifactSet = hexHash(Buffer.concat(manifest.artifacts.map((item) => Buffer.from(`${item.path}\0${item.sha256}\0${item.bytes}\n`))));
if (artifactSet !== manifest.artifactSetSha256
  || manifest.counts.artifacts !== manifest.artifacts.length
  || manifest.counts.benchmarkThresholds !== 1
  || manifest.counts.benchmarkWorkloads !== selectionWorkloads.workloads.length
  || manifest.counts.goldenCases !== golden.cases.length
  || manifest.counts.malformedCases !== malformed.cases.length
  || manifest.counts.fragmentationCases !== fragments.cases.length
  || manifest.counts.schemas !== 7) fail('contract manifest counts or aggregate digest differ');
process.stdout.write(`${canonical({ artifactSetSha256: artifactSet, benchmarkWorkloads: selectionWorkloads.workloads.length, goldenCases: golden.cases.length, profile: PROFILE, tableSha256: gearDigest })}\n`);
