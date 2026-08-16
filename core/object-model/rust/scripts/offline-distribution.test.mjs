import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const CRATE_ROOT = resolve(import.meta.dirname, '..');
const BUILDER = join(import.meta.dirname, 'build-offline-distribution.mjs');

function run(args) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [BUILDER, ...args], {
      cwd: CRATE_ROOT,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.once('error', rejectPromise);
    child.once('close', (code, signal) => resolvePromise({
      code,
      signal,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8')
    }));
  });
}

async function temporary(t) {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-rust-offline-test-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  return directory;
}

function firstDifference(left, right, path = '$') {
  if (Object.is(left, right)) return null;
  if (typeof left !== typeof right || left === null || right === null) return path;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return path;
    for (let index = 0; index < left.length; index += 1) {
      const difference = firstDifference(left[index], right[index], `${path}[${index}]`);
      if (difference !== null) return difference;
    }
    return null;
  }
  if (typeof left === 'object') {
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();
    if (JSON.stringify(leftKeys) !== JSON.stringify(rightKeys)) return path;
    for (const key of leftKeys) {
      const difference = firstDifference(left[key], right[key], `${path}.${key}`);
      if (difference !== null) return difference;
    }
    return null;
  }
  return path;
}

test('offline distribution is reproducible, self-verifying, and fail-closed', {
  timeout: 300_000
}, async t => {
  const temporaryRoot = await temporary(t);
  const versionMatch = /^version\s*=\s*"([^"]+)"/mu.exec(
    await readFile(join(CRATE_ROOT, 'Cargo.toml'), 'utf8')
  );
  assert.ok(versionMatch);
  const bundleName = `ogvcs-object-model-offline-${versionMatch[1]}`;
  const firstParent = join(temporaryRoot, 'first');
  const secondParent = join(temporaryRoot, 'second');
  await mkdir(firstParent);
  await mkdir(secondParent);
  const first = join(firstParent, bundleName);
  const second = join(secondParent, bundleName);

  const firstBuild = await run(['--output', first, '--allow-dirty']);
  assert.equal(firstBuild.code, 0, firstBuild.stderr || firstBuild.stdout);
  const firstResult = JSON.parse(firstBuild.stdout);
  assert.equal(firstResult.schema, 'ogvcs.rust-offline-distribution-result/v1');
  assert.equal(firstResult.operation, 'build');
  assert.equal(firstResult.bundle, bundleName);
  assert.equal(firstResult.offlineConsumerVerified, true);
  assert.equal(firstResult.offlineFormatVerified, true);

  const secondBuild = await run(['--output', second, '--allow-dirty']);
  assert.equal(secondBuild.code, 0, secondBuild.stderr || secondBuild.stdout);
  const firstManifest = await readFile(join(first, 'MANIFEST.json'), 'utf8');
  const secondManifest = await readFile(join(second, 'MANIFEST.json'), 'utf8');
  const manifestDifference = firstDifference(JSON.parse(firstManifest), JSON.parse(secondManifest));
  assert.equal(manifestDifference, null, `offline manifests first differ at ${manifestDifference}`);
  assert.equal(secondManifest.length, firstManifest.length);
  assert.equal(secondBuild.stdout, firstBuild.stdout);
  const manifest = JSON.parse(firstManifest);
  assert.equal(manifest.schema, 'ogvcs.rust-offline-distribution/v1');
  assert.equal(manifest.dependencies.length > 0, true);
  assert.equal(manifest.verification.emptyCargoHome, true);
  assert.equal(manifest.verification.offlineFormatVerified, true);
  assert.equal(manifest.package.licenseExpression, 'MIT');
  assert.equal(manifest.package.licenseArtifact.path, 'LICENSE');
  assert.equal(manifest.conformance.packageName, '@opengamevcs/repository-format-v1');
  assert.match(manifest.conformance.archive.path,
    /^conformance\/opengamevcs-repository-format-v1-0\.[0-9]+\.[0-9]+\.tgz$/u);
  assert.equal(
    manifest.package.sourceRevision === null
      || /^[0-9a-f]{40}$/u.test(manifest.package.sourceRevision),
    true
  );
  assert.equal(
    manifest.package.sourceTreeDirty === null
      || typeof manifest.package.sourceTreeDirty === 'boolean',
    true
  );
  assert.equal(manifest.files.some(file => file.path.endsWith('.crate')), true);
  assert.equal(manifest.files.some(file => file.path === 'Cargo.lock'), true);
  assert.equal(manifest.files.some(file => file.path === 'LICENSE'), true);
  assert.equal(manifest.files.some(file => file.path === '.cargo/config.toml'), true);
  for (const dependency of manifest.dependencies) {
    assert.match(dependency.packageChecksum, /^[0-9a-f]{64}$/u);
    assert.equal(dependency.licenseExpression !== null || dependency.licenseFile !== null, true);
    assert.equal(dependency.licenseFiles.length > 0, true);
  }
  assert.equal(firstManifest.includes(temporaryRoot), false);
  assert.equal(firstManifest.includes(CRATE_ROOT), false);
  assert.equal(
    await readFile(join(first, 'LICENSE'), 'utf8'),
    await readFile(join(CRATE_ROOT, 'LICENSE'), 'utf8')
  );
  if (process.env.HOME) assert.equal(firstManifest.includes(process.env.HOME), false);

  const verified = await run(['--verify', first]);
  assert.equal(verified.code, 0, verified.stderr || verified.stdout);
  const verifyResult = JSON.parse(verified.stdout);
  assert.equal(verifyResult.operation, 'verify');
  assert.equal(verifyResult.manifestSha256, firstResult.manifestSha256);

  const tamperedParent = join(temporaryRoot, 'tampered');
  await mkdir(tamperedParent);
  const tampered = join(tamperedParent, bundleName);
  await cp(first, tampered, { recursive: true });
  await writeFile(join(tampered, 'OFFLINE-README.md'), 'tampered\n', 'utf8');
  const rejected = await run(['--verify', tampered]);
  assert.notEqual(rejected.code, 0);

  const failedParent = join(temporaryRoot, 'failed');
  await mkdir(failedParent);
  const failedOutput = join(failedParent, bundleName);
  const failed = await run([
    '--output', failedOutput, '--allow-dirty',
    '--cargo', join(temporaryRoot, 'missing-cargo-executable')
  ]);
  assert.notEqual(failed.code, 0);
  assert.deepEqual(await readdir(failedParent), []);
});
