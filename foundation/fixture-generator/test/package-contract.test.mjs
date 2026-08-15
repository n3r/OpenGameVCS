import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import * as publicApi from '../src/index.mjs';
import {
  jsonOutput,
  packageDirectory,
  resolveProcessInvocation,
  runProcess,
  temporaryDirectory,
} from './test-helpers.mjs';

const EXPECTED_EXPORTS = [
  'EXIT_CODES',
  'FixtureError',
  'canonicalBytes',
  'canonicalClone',
  'canonicalDigest',
  'canonicalStringify',
  'createRequest',
  'deterministicChunks',
  'deterministicId',
  'digestDeterministicContent',
  'generateFixture',
  'getProfile',
  'inspectFixture',
  'listProfiles',
  'normalizeLogicalPath',
  'planFixture',
  'referenceScaleRequest',
  'requestSettings',
  'resolveProfile',
  'resolveRequest',
  'verifyFixture',
];

test('public index is the complete supported reusable-library boundary', () => {
  assert.deepEqual(Object.keys(publicApi).sort(), EXPECTED_EXPORTS.sort());
  assert.deepEqual(publicApi.EXIT_CODES, {
    CONFLICT: 5,
    INTEGRITY: 6,
    INTERNAL: 70,
    INTERRUPTED: 8,
    INVALID_REQUEST: 3,
    OK: 0,
    RESOURCE_LIMIT: 7,
    UNSAFE_DESTINATION: 4,
    USAGE: 2,
  });
});

test('Windows npm subprocesses use the npm JavaScript entry point without shell quoting', () => {
  const npmEntryPoint = 'C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js';
  assert.deepEqual(
    resolveProcessInvocation('npm', ['pack', '--json'], { npmEntryPoint, platform: 'win32' }),
    {
      args: [npmEntryPoint, 'pack', '--json'],
      executable: process.execPath,
      shell: false,
    },
  );
  assert.deepEqual(
    resolveProcessInvocation('npm', ['pack'], { npmEntryPoint: null, platform: 'win32' }),
    { args: ['pack'], executable: 'npm.cmd', shell: true },
  );
});

test('packed tarball installs offline with CLI, schemas, examples, and protected internals', async (t) => {
  const scratch = await temporaryDirectory(t, 'ogvcs-fixture-package-');
  const npmEnvironment = { npm_config_cache: path.join(scratch, '.npm-cache') };
  const packed = await runProcess('npm', [
    'pack',
    '--json',
    '--pack-destination', scratch,
  ], { cwd: packageDirectory, env: npmEnvironment });
  assert.equal(packed.code, 0, packed.stderr);
  const packResult = JSON.parse(packed.stdout)[0];
  const included = new Set(packResult.files.map(({ path: filePath }) => filePath));
  for (const required of [
    'bin/ogvcs-fixture.mjs',
    'src/index.mjs',
    'schemas/FixtureRequest.schema.json',
    'schemas/FixtureManifest.schema.json',
    'schemas/GroupRelationships.schema.json',
    'schemas/InventoryRecord.schema.json',
    'schemas/LargeFileDescriptor.schema.json',
    'examples/object-mapping.mjs',
    'examples/workload-driver.mjs',
    'scripts/run-scale-test.mjs',
    'test/primitives.test.mjs',
    'LICENSE',
    'package.json',
  ]) {
    assert.ok(included.has(required), `tarball is missing ${required}`);
  }

  const consumer = path.join(scratch, 'consumer');
  await mkdir(consumer);
  await writeFile(path.join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  const tarball = path.join(scratch, packResult.filename);
  const installed = await runProcess('npm', [
    'install',
    '--offline',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    tarball,
  ], { cwd: consumer, env: npmEnvironment });
  assert.equal(installed.code, 0, installed.stderr);

  const consumerScript = `
    import { createRequest, listProfiles, planFixture } from '@opengamevcs/fixture-generator';
    const profiles = listProfiles().map(({ id }) => id);
    const plans = profiles.map((id) => planFixture(createRequest({
      destination: 'fixtures/' + id,
      extensions: {
        'generation.large-file-mode': 'virtual',
        'generation.materialization': 'index-only'
      },
      profile: { id, version: '2.0.0' },
      scale: { historyOperationCount: 1, largeFileBytes: 0, maxDepth: 2, pathCount: 2 }
    })).requestDigest);
    let privateImport = 'unexpected-success';
    try { await import('@opengamevcs/fixture-generator/src/model.mjs'); }
    catch (error) { privateImport = error.code; }
    process.stdout.write(JSON.stringify({ plans, privateImport, profiles }));
  `;
  await writeFile(path.join(consumer, 'consumer.mjs'), consumerScript);
  const consumed = await runProcess(process.execPath, ['consumer.mjs'], { cwd: consumer });
  assert.equal(consumed.code, 0, consumed.stderr);
  const contract = JSON.parse(consumed.stdout);
  assert.deepEqual(contract.profiles, [
    'code-heavy',
    'global-studio',
    'large-binary',
    'unity-like',
    'unreal-like',
  ]);
  assert.equal(new Set(contract.plans).size, 5);
  assert.equal(contract.privateImport, 'ERR_PACKAGE_PATH_NOT_EXPORTED');

  const installedPackage = path.join(consumer, 'node_modules', '@opengamevcs', 'fixture-generator');
  const cli = await runProcess(process.execPath, [
    path.join(installedPackage, 'bin', 'ogvcs-fixture.mjs'),
    'list',
  ], { cwd: consumer });
  assert.equal(cli.code, 0, cli.stderr);
  assert.equal(jsonOutput(cli).result.profiles.length, 5);

  for (const example of ['object-mapping', 'workload-driver']) {
    const executed = await runProcess(process.execPath, [
      path.join(installedPackage, 'examples', `${example}.mjs`),
      '--cli', path.join(installedPackage, 'bin', 'ogvcs-fixture.mjs'),
      '--workspace', `installed-examples/${example}`,
    ], { cwd: consumer });
    assert.equal(executed.code, 0, executed.stderr);
    assert.equal(executed.stderr, '');
    const summary = JSON.parse(executed.stdout);
    assert.equal(summary.consumer, `ogvcs-${example}-example/v1`);
    assert.deepEqual(summary.profiles.map(({ profile }) => profile), [
      'code-heavy@2.0.0',
      'global-studio@2.0.0',
      'large-binary@2.0.0',
      'unity-like@2.0.0',
      'unreal-like@2.0.0',
    ]);
    assert.ok(summary.profiles.every(({ verified }) => verified === true));
    if (example === 'object-mapping') {
      assert.ok(summary.profiles.every(({ semanticVersions, pathCount }) => semanticVersions >= pathCount));
      assert.ok(summary.profiles.find(({ profile }) => profile.startsWith('unity-like@')).negativeCases >= 6);
    } else {
      assert.ok(summary.profiles.every(({ identityCount, operationCount, semanticChecks }) => (
        identityCount === 8 && semanticChecks === operationCount
      )));
      assert.ok(summary.profiles.find(({ profile }) => profile.startsWith('global-studio@')).kinds['lock-loss'] > 0);
    }
  }

  for (const schema of [
    'FixtureManifest',
    'FixtureRequest',
    'GenerationCheckpoint',
    'GroupRelationships',
    'InventoryRecord',
    'LargeFileDescriptor',
    'OperationScenario',
    'VerificationResult',
    'WorkloadProfile',
  ]) {
    const document = JSON.parse(await readFile(path.join(installedPackage, 'schemas', `${schema}.schema.json`), 'utf8'));
    assert.equal(document.$schema, 'https://json-schema.org/draft/2020-12/schema');
  }
});
