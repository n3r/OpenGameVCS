#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CHECK = process.argv.slice(2).includes('--check');
if (process.argv.length > 3 || (process.argv.length === 3 && !CHECK)) {
  throw new Error('usage: node scripts/generate.mjs [--check]');
}

const CONTRACT_VERSION = '0.2.0-rc.2';
const ARTIFACTS = [
  'LICENSE',
  'README.md',
  'package.json',
  'registries/exit-classes.json',
  'schemas/CliResult.schema.json',
  'schemas/CapabilitySelection.schema.json',
  'schemas/ConfigResolution.schema.json',
  'schemas/DiagnosticPreview.schema.json',
  'schemas/InitializationRecord.schema.json',
  'schemas/IntentReport.schema.json',
  'schemas/ProgressEvent.schema.json',
  'schemas/RemovalRecord.schema.json',
  'schemas/StagingState.schema.json',
  'schemas/VerifiedDiagnosticPreview.schema.json',
  'schemas/VerifiedWorkspaceMetadata.schema.json',
  'schemas/VerifiedWorkspaceReport.schema.json',
  'schemas/WorkspaceMetadata.schema.json',
  'schemas/WorkspaceJournal.schema.json',
  'schemas/WorkspaceReport.schema.json',
  'scripts/generate.mjs',
  'validate-spec.mjs',
  'vectors/contract-v1.json',
].sort();

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalBytes = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');

const records = [];
for (const path of ARTIFACTS) {
  const bytes = await readFile(resolve(ROOT, path));
  records.push({ path, bytes: bytes.length, sha256: sha256(bytes) });
}

const selectedDigest = (prefix) => sha256(canonicalBytes(records.filter(({ path }) => path.startsWith(prefix))));
const manifest = {
  schema: 'ogvcs.cli-workspace/contract-manifest/v1',
  contractVersion: CONTRACT_VERSION,
  artifactSetSha256: sha256(canonicalBytes(records)),
  registrySetSha256: selectedDigest('registries/'),
  schemaSetSha256: selectedDigest('schemas/'),
  vectorSetSha256: selectedDigest('vectors/'),
  generatorSha256: records.find(({ path }) => path === 'scripts/generate.mjs').sha256,
  counts: {
    artifacts: records.length,
    registries: records.filter(({ path }) => path.startsWith('registries/')).length,
    schemas: records.filter(({ path }) => path.startsWith('schemas/')).length,
    vectors: records.filter(({ path }) => path.startsWith('vectors/')).length,
  },
  artifacts: records,
};
const expected = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
const destination = resolve(ROOT, 'manifest.json');

if (CHECK) {
  const actual = await readFile(destination).catch(() => null);
  if (actual === null || !actual.equals(expected)) {
    process.stderr.write('manifest.json: generated content differs\n');
    process.exitCode = 1;
  }
} else {
  await writeFile(destination, expected);
}
