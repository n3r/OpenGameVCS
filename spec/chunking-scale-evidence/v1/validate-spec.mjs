#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest, canonicalJson } from '../../../foundation/benchmark-fault-harness/src/index.mjs';

const SOURCE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const ROOT = resolve(process.env.OGVCS_CHUNK_SCALE_CONTRACT_ROOT ?? dirname(fileURLToPath(import.meta.url)));
const SHA256 = /^[0-9a-f]{64}$/u;
const EXPECTED_ARTIFACTS = ['registries/exact-scale-authority.json', 'schemas/retained-publication.schema.json', 'schemas/scale-report.schema.json', 'thresholds/chunking-exact-scale-release-v1.json'];
const EXPECTED_ASSERTIONS = ['chunking-exact-source-bound', 'chunking-exact-byte-accounting', 'chunking-exact-canonical-manifest-emitted', 'chunking-exact-cross-implementation-result-parity', 'chunking-exact-resource-bounds', 'chunking-exact-no-whole-file-copy', 'chunking-exact-report-content-bound'];
const EXPECTED_COMPLETION = 'the campaign has run each implementation over exactly 100 GiB; each emitted one canonical manifest through a bounded sink, accounted for every chunk and the whole file, and satisfied resource and cleanup bounds; the independent comparator accepted exactly matching result projections';
const EXPECTED_THRESHOLD_IDS = ['exact-scale-executed', 'exact-logical-bytes', 'wall-time-bound', 'cpu-time-bound', 'process-write-bound', 'peak-rss-bound', 'ledger-memory-bound', 'ledger-scratch-bound', 'manifest-byte-bound', 'scratch-cleaned', 'no-whole-file-temporary'];
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
function fail(message) { throw new Error(`chunking exact-scale contract: ${message}`); }

async function load(root, path, maximum = 1024 * 1024) {
  const target = join(root, path);
  const stat = await lstat(target).catch(() => null);
  if (!stat?.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > maximum) fail(`${path} is not a bounded regular file`);
  const bytes = await readFile(target);
  let value;
  try { value = JSON.parse(bytes); } catch { fail(`${path} is not JSON`); }
  if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) fail(`${path} is not canonical terminal-LF JSON`);
  return { bytes, value };
}

const manifestRecord = await load(ROOT, 'manifest.json');
const manifest = manifestRecord.value;
if (manifest.schemaVersion !== 'ogvcs.chunking-manifest/exact-scale-contract-manifest/v1'
    || manifest.contractVersion !== '0.1.0-rc.1' || manifest.owner !== 'ogvcs-007'
    || canonicalJson(Object.keys(manifest).sort()) !== canonicalJson(['artifactSetSha256', 'artifacts', 'authoritySetSha256', 'contractVersion', 'counts', 'generatedBy', 'owner', 'predecessorPins', 'schemaVersion'].sort())) fail('manifest header or shape is invalid');
if (manifest.artifacts.length !== EXPECTED_ARTIFACTS.length
    || canonicalJson(manifest.artifacts.map(({ path }) => path)) !== canonicalJson(EXPECTED_ARTIFACTS)
    || manifest.artifacts.some(({ bytes, mediaType, path, sha256: digest }) => !Number.isSafeInteger(bytes) || bytes < 2 || mediaType !== (path.startsWith('schemas/') ? 'application/schema+json' : 'application/json') || !SHA256.test(digest) || !/^[a-z0-9./-]+$/u.test(path))) fail('manifest inventory is invalid');
for (const record of manifest.artifacts) {
  const artifact = await load(ROOT, record.path);
  if (artifact.bytes.byteLength !== record.bytes || sha256(artifact.bytes) !== record.sha256) fail(`${record.path} differs from its manifest record`);
}
if (manifest.artifactSetSha256 !== canonicalDigest(manifest.artifacts, 'ogvcs.chunking-manifest/exact-scale-artifact-set/v1')) fail('artifact-set digest does not reproduce');

const authority = (await load(ROOT, 'registries/exact-scale-authority.json')).value;
const threshold = (await load(ROOT, 'thresholds/chunking-exact-scale-release-v1.json')).value;
const schema = (await load(ROOT, 'schemas/scale-report.schema.json')).value;
const retainedPublicationSchema = (await load(ROOT, 'schemas/retained-publication.schema.json')).value;
if (authority.schemaVersion !== 'ogvcs.chunking-manifest/exact-scale-authority/v1' || authority.owner !== 'ogvcs-007'
    || authority.corpus.id !== 'chunking-exact-scale' || authority.corpus.profile !== 'chunking.opengamevcs/gear-fastcdc-1m@1'
    || authority.corpus.source.logicalBytes !== '107374182400' || authority.corpus.source.patternBytes !== 8_388_608 || authority.corpus.source.repetitions !== 12_800
    || authority.task.id !== 'chunking-exact-scale-verify' || authority.task.completionCondition !== EXPECTED_COMPLETION
    || canonicalJson(authority.task.assertions) !== canonicalJson(EXPECTED_ASSERTIONS)
    || authority.profile.id !== 'chunking-exact-scale-release' || canonicalJson(authority.profile.implementations) !== canonicalJson(['javascript', 'rust'])
    || authority.profile.repetitions !== 1 || authority.profile.releaseOnly !== true || authority.profile.exactScaleExecutedRequired !== true
    || authority.profile.ordinaryDispatchAllowed !== false || authority.profile.sourceRevisionBinding !== 'workflow-supplied-not-git-bound') fail('exact-scale corpus/task/profile authority is invalid');
if (threshold.schemaVersion !== 'ogvcs.chunking-manifest/exact-scale-thresholds/v1' || threshold.id !== 'chunking-exact-scale-release-v1' || threshold.owner !== 'ogvcs-007' || threshold.profile !== authority.profile.id
    || canonicalJson(threshold.entries.map(({ id }) => id)) !== canonicalJson(EXPECTED_THRESHOLD_IDS)
    || new Set(threshold.entries.map(({ id }) => id)).size !== threshold.entries.length
    || threshold.entries.some(({ requirementId }) => !/^OGVCS-007-(?:FR|NFR|AC)-[0-9]{2}$/u.test(requirementId))) fail('exact-scale threshold authority is invalid');
if (schema.$schema !== 'https://json-schema.org/draft/2020-12/schema' || schema.additionalProperties !== false
    || schema.properties?.exactScaleExecuted?.const !== true || schema.properties?.source?.const?.logicalBytes !== '107374182400'
    || schema.properties?.resources?.properties?.processWriteBytes?.maximum !== 536_870_912
    || schema.properties?.resources?.properties?.processWriteSource?.const !== 'linux:/proc/self/io:wchar'
    || schema.properties?.resources?.properties?.peakRssBytes?.maximum !== 536_870_912
    || schema.properties?.bounds?.const?.temporaryWholeFileAllowed !== false) fail('exact-scale report schema is invalid');
if (retainedPublicationSchema.$schema !== 'https://json-schema.org/draft/2020-12/schema'
    || retainedPublicationSchema.additionalProperties !== false
    || retainedPublicationSchema.properties?.schemaVersion?.const !== 'ogvcs.chunking-manifest/exact-scale-retained-publication/v1'
    || retainedPublicationSchema.properties?.artifacts?.minItems !== 3
    || retainedPublicationSchema.properties?.artifacts?.maxItems !== 3
    || canonicalJson(retainedPublicationSchema.properties.artifacts.prefixItems.map(({ properties }) => properties.path.const))
      !== canonicalJson(['manifest.json', 'projection.json', 'report.json'])) fail('retained publication schema is invalid');
if (manifest.authoritySetSha256 !== canonicalDigest({ authority, threshold }, 'ogvcs.chunking-manifest/exact-scale-authority-set/v1')) fail('authority-set digest does not reproduce');
if (manifest.counts.artifacts !== 4 || manifest.counts.assertions !== 7 || manifest.counts.thresholds !== 11) fail('manifest counts are invalid');
for (const [name, expectedPath] of [['benchmark', 'spec/benchmark-fault/v1/manifest.json'], ['chunking', 'spec/chunking-manifest/v1/manifest.json']]) {
  const pin = manifest.predecessorPins[name];
  const bytes = await readFile(join(SOURCE_ROOT, expectedPath));
  const value = JSON.parse(bytes);
  if (pin.manifestPath !== expectedPath || pin.manifestSha256 !== sha256(bytes) || pin.contractVersion !== value.contractVersion) fail(`${name} predecessor pin differs`);
  if (name === 'chunking' && (pin.profile !== value.profile || pin.tableSha256 !== value.tableSha256)) fail('chunking profile predecessor pin differs');
}
if (!SHA256.test(manifest.generatedBy?.generatorSha256) || !SHA256.test(manifest.generatedBy?.modelSha256)) fail('generator authority is invalid');
process.stdout.write(`${canonicalJson({ artifactSetSha256: manifest.artifactSetSha256, authoritySetSha256: manifest.authoritySetSha256, contractVersion: manifest.contractVersion, verified: true })}\n`);
