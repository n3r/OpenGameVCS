import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import test from 'node:test';

const PACKAGE = resolve(import.meta.dirname, '..');
const REPOSITORY = resolve(PACKAGE, '../../..');
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function run(command, args, options = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code, signal) => resolvePromise({
      code,
      signal,
      stderr: Buffer.concat(stderr).toString('utf8'),
      stdout: Buffer.concat(stdout).toString('utf8')
    }));
  });
}

async function temporary(t) {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-object-package-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  return directory;
}

test('packed public package and fixture peer install and run offline without repository-private imports', { timeout: 240_000 }, async t => {
  const directory = await temporary(t);
  const packDirectory = join(directory, 'pack');
  const consumer = join(directory, 'consumer');
  const cache = join(directory, 'npm-cache');
  await mkdir(packDirectory);
  await mkdir(consumer);
  const environment = { ...process.env, npm_config_cache: cache, npm_config_audit: 'false', npm_config_fund: 'false' };

  const packed = await run(NPM, ['pack', PACKAGE, '--json', '--pack-destination', packDirectory], {
    cwd: REPOSITORY,
    env: environment
  });
  assert.equal(packed.code, 0, packed.stderr || packed.stdout);
  const packResult = JSON.parse(packed.stdout);
  assert.equal(packResult.length, 1);
  const tarball = join(packDirectory, basename(packResult[0].filename));
  const fileNames = new Set(packResult[0].files.map(file => file.path));
  for (const required of [
    'bin/ogvcs-object.mjs',
    'examples/reference-roundtrip.mjs',
    'LICENSE',
    'examples/registry-inspection.mjs',
    'registries/profiles.json',
    'src/bundle-scratch.js',
    'src/bundle-spool.js',
    'src/index.js'
  ]) assert.equal(fileNames.has(required), true, `packed artifact omitted ${required}`);
  assert.equal([...fileNames].some(name => name.startsWith('test/')), false);

  const fixturePacked = await run(NPM, [
    'pack', join(REPOSITORY, 'foundation', 'fixture-generator'), '--json', '--pack-destination', packDirectory
  ], { cwd: REPOSITORY, env: environment });
  assert.equal(fixturePacked.code, 0, fixturePacked.stderr || fixturePacked.stdout);
  const fixturePackResult = JSON.parse(fixturePacked.stdout);
  assert.equal(fixturePackResult.length, 1);
  const fixtureTarball = join(packDirectory, basename(fixturePackResult[0].filename));
  const fixtureFileNames = new Set(fixturePackResult[0].files.map(file => file.path));
  for (const required of ['LICENSE', 'src/index.mjs', 'schemas/FixtureManifest.schema.json']) {
    assert.equal(fixtureFileNames.has(required), true, `packed fixture artifact omitted ${required}`);
  }

  const formatPacked = await run(NPM, [
    'pack', join(REPOSITORY, 'spec', 'repository-format', 'v1'), '--json', '--pack-destination', packDirectory
  ], { cwd: REPOSITORY, env: environment });
  assert.equal(formatPacked.code, 0, formatPacked.stderr || formatPacked.stdout);
  const formatPackResult = JSON.parse(formatPacked.stdout);
  assert.equal(formatPackResult.length, 1);
  const formatTarball = join(packDirectory, basename(formatPackResult[0].filename));
  const formatFileNames = new Set(formatPackResult[0].files.map(file => file.path));
  for (const required of [
    'index.mjs', 'LICENSE', 'repository-format.cddl', 'registries/object-kinds.json',
    'vectors/manifest.json', 'vectors/logical-bundles/valid-supplied-closure.cborseq'
  ]) assert.equal(formatFileNames.has(required), true, `packed format artifact omitted ${required}`);

  await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n', 'utf8');
  const installed = await run(NPM, [
    'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false',
    tarball, fixtureTarball, formatTarball
  ], { cwd: consumer, env: environment });
  assert.equal(installed.code, 0, installed.stderr || installed.stdout);

  const packageRoot = join(consumer, 'node_modules', '@opengamevcs', 'object-model');
  for (const example of ['reference-roundtrip.mjs', 'registry-inspection.mjs']) {
    const result = await run(process.execPath, [join(packageRoot, 'examples', example)], { cwd: consumer, env: environment });
    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.doesNotThrow(() => JSON.parse(result.stdout));
  }

  const cli = await run(process.execPath, [join(packageRoot, 'bin', 'ogvcs-object.mjs'), 'registry', 'list'], {
    cwd: consumer,
    env: environment
  });
  assert.equal(cli.code, 0, cli.stderr || cli.stdout);
  const cliResult = JSON.parse(cli.stdout);
  assert.equal(cliResult.ok, true);
  assert.equal(cliResult.result.counts.objectKinds, 11);

  const bundlePath = join(consumer, 'valid-supplied-closure.cborseq');
  const scratchPath = join(consumer, 'scratch');
  await mkdir(scratchPath);
  await writeFile(join(consumer, 'verify-bundle.mjs'), `
import { copyFile } from 'node:fs/promises';
import { loadBundledRegistry, verifyLogicalBundleFile } from '@opengamevcs/object-model';
import { formatVersion, vectorsUrl } from '@opengamevcs/repository-format-v1';
if (formatVersion !== 1) throw new Error('unexpected installed format version');
await copyFile(new URL('logical-bundles/valid-supplied-closure.cborseq', vectorsUrl), process.argv[2]);
const registry = await loadBundledRegistry();
const result = await verifyLogicalBundleFile(process.argv[2], {
  registry,
  mode: 'conformance',
  scratchDirectory: process.argv[3],
  maxMemoryBytes: 16_777_216,
  maxScratchBytes: 16_777_216
});
process.stdout.write(JSON.stringify({ objectCount: result.objectCount, status: 'valid' }) + '\\n');
`, 'utf8');
  const publicApi = await run(process.execPath, [
    join(consumer, 'verify-bundle.mjs'), bundlePath, scratchPath
  ], { cwd: consumer, env: environment });
  assert.equal(publicApi.code, 0, publicApi.stderr || publicApi.stdout);
  assert.deepEqual(JSON.parse(publicApi.stdout), { objectCount: 2, status: 'valid' });

  const bundleCli = await run(process.execPath, [
    join(packageRoot, 'bin', 'ogvcs-object.mjs'),
    'bundle', 'verify', bundlePath,
    '--scratch', scratchPath,
    '--max-memory-bytes', '16777216',
    '--max-scratch-bytes', '16777216'
  ], { cwd: consumer, env: environment });
  assert.equal(bundleCli.code, 0, bundleCli.stderr || bundleCli.stdout);
  const bundleCliResult = JSON.parse(bundleCli.stdout);
  assert.equal(bundleCliResult.ok, true);
  assert.equal(bundleCliResult.result.claim, 'supplied-closure');
  assert.equal(bundleCliResult.result.objectCount, 2);
  assert.equal(bundleCliResult.result.status, 'valid');

  await writeFile(join(consumer, 'adapt-fixtures.mjs'), `
import { adaptFixture } from '@opengamevcs/object-model';
import { createRequest, generateFixture } from '@opengamevcs/fixture-generator';

const profiles = ['code-heavy', 'unreal-like', 'unity-like', 'large-binary', 'global-studio'];
const summaries = [];
for (const profile of profiles) {
  const destination = 'fixtures/' + profile;
  const request = createRequest({
    destination,
    extensions: {
      'generation.large-file-mode': profile === 'large-binary' ? 'full' : 'virtual',
      'generation.materialization': 'full'
    },
    ...(profile === 'unity-like' ? { featureFlags: { 'negative-cases': false } } : {}),
    profile: { id: profile, version: '2.0.0' },
    scale: {
      historyOperationCount: 8,
      largeFileBytes: profile === 'large-binary' ? 1_048_576 : 0,
      maxDepth: 5,
      pathCount: 6
    },
    seed: 'packed-adapter-' + profile
  });
  await generateFixture(request, { cwd: process.cwd() });
  let ledger;
  const result = await adaptFixture(destination, {
    cwd: process.cwd(),
    ...(profile === 'large-binary' ? { largeFileVersion: 2 } : {}),
    isTargetFileIdConsumed: async () => false,
    persistLedger: async value => { ledger = value; }
  });
  if (!ledger) throw new Error('ledger was not persisted for ' + profile);
  summaries.push({
    files: result.summary.files,
    profile: result.summary.fixtureProfile,
    records: result.summary.logicalRecords
  });
}
process.stdout.write(JSON.stringify(summaries) + '\\n');
`, 'utf8');
  const adapted = await run(process.execPath, [join(consumer, 'adapt-fixtures.mjs')], {
    cwd: consumer,
    env: { ...environment, npm_config_offline: 'true' }
  });
  assert.equal(adapted.code, 0, adapted.stderr || adapted.stdout);
  assert.deepEqual(JSON.parse(adapted.stdout), [
    'code-heavy', 'unreal-like', 'unity-like', 'large-binary', 'global-studio'
  ].map(profile => ({ files: 6, profile: `${profile}@2.0.0`, records: 8 })));

  const installedPackage = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
  assert.equal(installedPackage.exports, './src/index.js');
  assert.equal(installedPackage.bin['ogvcs-object'], 'bin/ogvcs-object.mjs');
  assert.equal(installedPackage.license, 'MIT');
  const expectedLicense = await readFile(join(REPOSITORY, 'LICENSE'), 'utf8');
  for (const installedRoot of [
    packageRoot,
    join(consumer, 'node_modules', '@opengamevcs', 'fixture-generator'),
    join(consumer, 'node_modules', '@opengamevcs', 'repository-format-v1')
  ]) {
    const metadata = JSON.parse(await readFile(join(installedRoot, 'package.json'), 'utf8'));
    assert.equal(metadata.license, 'MIT');
    assert.equal(await readFile(join(installedRoot, 'LICENSE'), 'utf8'), expectedLicense);
  }
});
