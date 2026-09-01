#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(import.meta.url);
const PATH_ROOT = dirname(require.resolve('@opengamevcs/path-contract-v1/package.json'));
const MAX_JSON_BYTES = 16_777_216;
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (message) => { throw new Error(`selective-sync-kernel-contract-v1: ${message}`); };
const canonical = (value) => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  fail('unsupported canonical JSON value');
};
async function load(path) {
  const absolute = resolve(ROOT, path); const stat = await lstat(absolute).catch(() => null);
  if (!stat?.isFile() || stat.isSymbolicLink() || stat.size > MAX_JSON_BYTES) fail(`${path} is not a bounded regular file`);
  const bytes = await readFile(absolute); let value;
  try { value = JSON.parse(bytes); } catch { fail(`${path} is invalid JSON`); }
  if (!bytes.equals(Buffer.from(`${canonical(value)}\n`))) fail(`${path} is not canonical JSON`);
  return { bytes, value };
}

const { value: contract } = await load('contract.json');
const limits = contract.limits;
if (contract.schemaVersion !== 'ogvcs.selective-sync/kernel-contract/v1'
    || contract.contractVersion !== '0.1.0-rc.1' || contract.state !== 'private-untrusted-selection-candidate'
    || contract.owner !== 'OGVCS-013' || contract.networkRoutes.length !== 0
    || Object.values(contract.publicClaims).some((value) => value !== false)) fail('contract public state or nonclaims drifted');
const expectedLimits = {
  collisionKeyBytesMaximum: 32_768, collisionKeyBytesTotalMaximum: 67_108_864,
  compiledRuleBytesMaximum: 16_777_216,
  fullLogicalBytesMaximum: 9_007_199_254_740_991,
  inputRecordBytesMaximum: 4_185, logicalBytesMaximum: 1_099_511_627_776,
  metadataBytesMaximum: 67_108_864, metadataRecordsMaximum: 100_000,
  outputBytesMaximum: 75_497_472, outputRecordBytesMaximum: 4_154,
  ruleBytesMaximum: 4_114, rulesMaximum: 4_096, sinkFragmentBytesMaximum: 4_154,
};
if (canonical(limits) !== canonical(expectedLimits)) fail('exact bounded-resource assignments drifted');
if (canonical(contract.bindings) !== canonical([
  'snapshot-digest', 'settings-digest', 'consistency-token-digest', 'path-profile', 'case-mode',
  'platform', 'selection-spec-digest', 'metadata-projection-digest', 'metadata-record-count',
])) fail('binding registry drifted');
if (contract.selection.semantics.length !== 8
    || !contract.selection.semantics.includes('subtree-matches-the-named-path-and-component-descendants')
    || !contract.selection.semantics.includes('exact-and-subtree-have-no-priority-beyond-ordinal')) fail('last-match semantics drifted');
if (contract.output.metadataOnlyAndAbsentContentTag !== 0
    || contract.output.entryDigest !== 'input-only-opaque-metadata-record-commitment-never-emitted'
    || contract.output.headerTrust !== 'caller-declared-bindings-discard-only-until-eof-count-order-collision-byte-digest-write-and-flush-checks-complete'
    || canonical(contract.output.cancellationCheckpoints) !== canonical(['before-header', 'before-source-poll', 'after-source-poll', 'before-flush'])
    || contract.output.sinkSemantics !== 'synchronous-fragment-emission-has-no-application-value;-javascript-callback-write-and-flush-return-undefined;-rust-write-all-and-flush-complete-with-ok-unit;-each-javascript-call-receives-a-private-fragment-copy'
    || contract.output.result !== 'plain-untrusted-summary-with-digests-counts-and-byte-ledgers-only'
    || contract.output.errorDisposition !== 'discard-all-sink-bytes-no-summary') fail('projection trust boundary drifted');
const { value: schema } = await load('schemas/workspace-selection-spec.schema.json');
if (schema.additionalProperties !== false || schema.properties.rules.maxItems !== limits.rulesMaximum
    || schema.properties.rules.items.additionalProperties !== false) fail('selection schema is not strict and bounded');
const { value: errors } = await load('registries/errors.json');
if (errors.schemaVersion !== 'ogvcs.selective-sync/error-registry/v1' || errors.entries.length !== 32
    || errors.entries.some(({ code, name }, index) => code !== index + 1 || !/^SELECT_[A-Z_]+$/u.test(name))
    || new Set(errors.entries.map(({ name }) => name)).size !== errors.entries.length) fail('error registry is malformed');
const { value: golden } = await load('vectors/golden.json');
if (golden.schemaVersion !== 'ogvcs.selective-sync/golden-vectors/v1' || golden.cases.length !== 3
    || new Set(golden.cases.map(({ caseId }) => caseId)).size !== golden.cases.length
    || golden.cases.some(({ expected }) => !/^[0-9a-f]{64}$/u.test(expected?.specDigest ?? '')
      || !/^[0-9a-f]{64}$/u.test(expected?.metadataProjectionDigest ?? '')
      || !/^[0-9a-f]+$/u.test(expected?.projectionHex ?? ''))) fail('golden vector authority is malformed');
const packageValue = JSON.parse(await readFile(resolve(ROOT, 'package.json'), 'utf8'));
if (packageValue.engines?.node !== '>=24'
    || canonical(packageValue.dependencies) !== canonical({ '@opengamevcs/path-contract-v1': '1.0.0' })
    || canonical(packageValue.files) !== canonical(['contract.json', 'LICENSE', 'manifest.json', 'README.md', 'registries', 'schemas', 'scripts', 'source', 'test', 'validate-spec.mjs', 'vectors'])) fail('packed package inventory or Node floor drifted');
const { bytes: manifestBytes, value: manifest } = await load('manifest.json');
if (manifest.schemaVersion !== 'ogvcs.selective-sync/contract-manifest/v1'
    || manifest.contractVersion !== contract.contractVersion || manifest.state !== contract.state
    || manifest.counts.artifacts !== 13 || manifest.counts.errors !== 32 || manifest.counts.goldenCases !== 3 || manifest.counts.schemas !== 1
    || manifest.networkRoutes.length !== 0 || Object.values(manifest.publicClaims).some((value) => value !== false)) fail('manifest header/count/nonclaims drifted');
if (manifest.artifacts.some(({ path }, index) => !/^[A-Za-z0-9._/-]+$/u.test(path) || path.startsWith('/') || path.split('/').includes('..') || index > 0 && manifest.artifacts[index - 1].path >= path)
    || new Set(manifest.artifacts.map(({ path }) => path)).size !== manifest.artifacts.length) fail('artifact inventory is unsafe or noncanonical');
const expectedArtifacts = ['LICENSE', 'README.md', 'contract.json', 'package.json', 'registries/errors.json', 'schemas/workspace-selection-spec.schema.json', 'scripts/generate.mjs', 'scripts/reference.mjs', 'source/golden.json', 'source/model.mjs', 'test/contract.test.mjs', 'validate-spec.mjs', 'vectors/golden.json'];
if (canonical(manifest.artifacts.map(({ path }) => path)) !== canonical(expectedArtifacts)) fail('manifest does not inventory every non-manifest packed file');
for (const artifact of manifest.artifacts) {
  const bytes = await readFile(resolve(ROOT, artifact.path));
  if (bytes.length !== artifact.bytes || digest(bytes) !== artifact.sha256) fail(`${artifact.path} differs from its manifest record`);
}
const artifactSet = digest(Buffer.concat(manifest.artifacts.map(({ path, sha256, bytes }) => Buffer.from(`${path}\0${sha256}\0${bytes}\n`))));
if (artifactSet !== manifest.artifactSetSha256) fail('artifact set digest drifted');
const pathPin = contract.predecessorPins.path;
const pathManifestBytes = await readFile(resolve(PATH_ROOT, 'manifest.json'));
const pathManifest = JSON.parse(pathManifestBytes);
if (digest(pathManifestBytes) !== pathPin.manifestSha256 || pathManifest.registrySetSha256 !== pathPin.registrySetSha256
    || pathManifest.contractVersion !== pathPin.contractVersion || pathManifest.unicode?.version !== pathPin.unicodeVersion
    || pathManifest.unicode?.caseFoldingSha256 !== pathPin.unicodeCaseFoldingSha256) fail('path predecessor pin drifted');
const referenceSource = await readFile(resolve(ROOT, 'scripts/reference.mjs'), 'utf8');
const referenceErrors = [...new Set(referenceSource.match(/SELECT_[A-Z_]+/gu) ?? [])].sort();
const registeredErrors = errors.entries.map(({ name }) => name).sort();
if (canonical(referenceErrors) !== canonical(registeredErrors)) fail('independent reference errors differ from the exact registry');
const generatorSource = await readFile(resolve(ROOT, 'scripts/generate.mjs'), 'utf8');
const generatorImports = [...generatorSource.matchAll(/^import .*? from ['"]([^'"]+)['"];?$/gmu)].map((match) => match[1]);
if (generatorImports.some((path) => /reference|core\/selective-sync|ogvcs-selective-sync-kernel/u.test(path))) fail('data-only generator imports an evaluator');
process.stdout.write(`validated selective-sync kernel contract ${digest(manifestBytes)}: ${manifest.artifacts.length} artifacts, ${golden.cases.length} golden cases\n`);
