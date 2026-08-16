#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

function moduleTarget(configured, fallback) {
  if (configured === undefined) return fallback;
  if (isAbsolute(configured) || configured.startsWith('./') || configured.startsWith('../')) {
    return pathToFileURL(resolve(configured)).href;
  }
  return configured;
}

const {
  decodeCanonical,
  hashLogicalRecord,
  hashObject,
  loadBundledRegistry,
  registrySetDigest,
  scanMetadata,
  validateLogicalRecord,
  verifyLogicalBundle
} = await import(moduleTarget(
  process.env.OGVCS_OBJECT_MODEL_JS_MODULE,
  new URL('../core/object-model/js/src/index.js', import.meta.url).href
));
import { executeJavascriptScenarios } from './object-model-scenario-report-js.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FORMAT_ROOT = resolve(process.env.OGVCS_FORMAT_ROOT ?? join(ROOT, 'spec', 'repository-format', 'v1'));
const VECTORS = resolve(process.env.OGVCS_VECTOR_ROOT ?? join(FORMAT_ROOT, 'vectors'));
const PACKAGE_JSON = resolve(process.env.OGVCS_OBJECT_MODEL_JS_PACKAGE_JSON ??
  join(ROOT, 'core', 'object-model', 'js', 'package.json'));
const REGISTRIES = resolve(process.env.OGVCS_OBJECT_MODEL_JS_REGISTRIES ??
  join(ROOT, 'core', 'object-model', 'js', 'registries'));

function parseArguments(argv) {
  if (argv.length !== 2 || argv[0] !== '--output' || argv[1].length === 0) {
    throw new Error('usage: node tools/object-model-conformance-report.mjs --output <report.json>');
  }
  return resolve(process.cwd(), argv[1]);
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function json(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function fileDigest(relativePath) {
  return sha256(await readFile(join(VECTORS, relativePath)));
}

async function objectSummary(registry) {
  const index = await json(join(VECTORS, 'objects', 'index.json'));
  const rows = [];
  for (const vector of index.objects) {
    const payload = new Uint8Array(await readFile(join(VECTORS, vector.payloadPath)));
    const reference = hashObject(vector.kind, payload, { registry: registry.kindNames });
    if (Buffer.from(reference.digest).toString('hex') !== vector.objectId) {
      throw new Error(`object identity mismatch for ${vector.name}`);
    }
    if (vector.kind !== 1) {
      const scanned = scanMetadata(payload, { registry });
      if (scanned.kind !== vector.kind || scanned.highestLayer < 1) {
        throw new Error(`object framing mismatch for ${vector.name}`);
      }
    }
    rows.push({ bytes: payload.length, kind: vector.kind, objectId: vector.objectId });
  }
  return Object.freeze({ count: rows.length, rowsSha256: sha256(canonicalJson(rows)) });
}

async function logicalRecordSummary(registry) {
  const index = await json(join(VECTORS, 'logical-records', 'index.json'));
  const vectors = index.records ?? index.logicalRecords;
  if (!Array.isArray(vectors)) throw new Error('logical-record index has no record array');
  const rows = [];
  for (const vector of vectors) {
    const payload = new Uint8Array(await readFile(join(VECTORS, vector.payloadPath)));
    const decoded = validateLogicalRecord(decodeCanonical(payload), { registry });
    const digest = hashLogicalRecord(decoded.type, payload, { registry: registry.logicalRecordTypes });
    const digestHex = Buffer.from(digest.bytes).toString('hex');
    const expected = vector.identity ?? vector.logicalRecordId ?? vector.recordId ?? vector.digest;
    if (expected !== undefined && digestHex !== expected) {
      throw new Error(`logical-record identity mismatch for ${vector.name ?? vector.payloadPath}`);
    }
    rows.push({ bytes: payload.length, digest: digestHex, type: decoded.type });
  }
  return Object.freeze({ count: rows.length, rowsSha256: sha256(canonicalJson(rows)) });
}

async function bundleSummary(registry) {
  const names = [
    'logical-bundles/valid-supplied-closure.cborseq',
    'logical-bundles/valid-all-families.cborseq',
    'logical-bundles/scenario-bundle-zero-sections.cborseq'
  ];
  const rows = [];
  for (const name of names) {
    const payload = new Uint8Array(await readFile(join(VECTORS, name)));
    const result = verifyLogicalBundle(payload, { registry });
    rows.push({
      bytes: result.bytes,
      indexEntries: result.indexEntries,
      items: result.items,
      logicalRecordCount: result.logicalRecordCount,
      objectCount: result.objectCount,
      rootCount: result.rootCount,
      transcriptDigest: result.transcriptDigest,
      traversalEdges: result.traversalEdges
    });
  }
  return Object.freeze({ count: rows.length, rows });
}

function artifactMetadata(environmentName, packageJson, packedType) {
  if (process.env[environmentName] === undefined) {
    return Object.freeze({ name: packageJson.name, type: 'workspace', version: packageJson.version });
  }
  let value;
  try { value = JSON.parse(process.env[environmentName]); }
  catch { throw new Error(`${environmentName} is not valid JSON`); }
  if (!value || value.name !== packageJson.name || value.version !== packageJson.version ||
      value.type !== packedType || !/^[0-9a-f]{64}$/u.test(value.sha256) ||
      Object.keys(value).sort().join(',') !== 'name,sha256,type,version') {
    throw new Error(`${environmentName} does not bind the installed package`);
  }
  return Object.freeze(value);
}

async function main() {
  const output = parseArguments(process.argv.slice(2));
  const registry = await loadBundledRegistry();
  const packageJson = await json(PACKAGE_JSON);
  const formatPackageJson = await json(join(FORMAT_ROOT, 'package.json'));
  const scenarios = await executeJavascriptScenarios();
  if (scenarios.failed !== 0) {
    const failed = scenarios.rows.filter(row => row.status === 'failed').map(row => row.scenarioId).join(', ');
    throw new Error(`scenario execution failed: ${failed}`);
  }
  const conformance = {
    bundles: await bundleSummary(registry),
    corpus: {
      coverageMatrixSha256: await fileDigest('coverage-matrix.json'),
      manifestSha256: await fileDigest('manifest.json'),
      scenarioIndexSha256: await fileDigest('scenarios/index.json')
    },
    formatVersion: 1,
    logicalRecords: await logicalRecordSummary(registry),
    objects: await objectSummary(registry),
    packageVersion: packageJson.version,
    registrySetDigest: await registrySetDigest(REGISTRIES),
    scenarios
  };
  const report = {
    artifact: artifactMetadata('OGVCS_IMPLEMENTATION_ARTIFACT', packageJson, 'npm-tarball'),
    conformance,
    conformanceSha256: sha256(canonicalJson(conformance)),
    implementation: '@opengamevcs/object-model/javascript',
    formatArtifact: artifactMetadata('OGVCS_FORMAT_ARTIFACT', formatPackageJson, 'npm-tarball'),
    platform: { arch: process.arch, os: process.platform },
    runtime: process.version,
    schema: 'ogvcs.object-model.conformance-report/v1',
    sourceRevision: process.env.GITHUB_SHA ?? 'working-tree'
  };
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${canonicalJson(report)}\n`, { encoding: 'utf8', flag: 'wx' });
  process.stdout.write(`${canonicalJson(report)}\n`);
}

await main();
