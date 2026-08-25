import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

const ROOT = resolve(import.meta.dirname, '..');
const SPEC = resolve(ROOT, '../../../spec/path-filesystem/v1');
const npmCli = process.env.npm_execpath;

function run(command, args, options = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd: options.cwd, env: options.env ?? process.env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const stdout = []; const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => resolvePromise({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}
function npm(args, options) { return npmCli ? run(process.execPath, [npmCli, ...args], options) : run('npm', args, options); }

test('offline-installed packed runtime exposes its public API and every documented CLI command', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-path-pack-'));
  try {
    const packages = join(scratch, 'packages'); const consumer = join(scratch, 'consumer');
    await mkdir(packages); await mkdir(consumer);
    const environment = { ...process.env, npm_config_cache: join(scratch, 'cache'), npm_config_audit: 'false', npm_config_fund: 'false' };
    const specPack = await npm(['pack', SPEC, '--json', '--pack-destination', packages], { cwd: ROOT, env: environment });
    assert.equal(specPack.code, 0, specPack.stderr);
    const runtimePack = await npm(['pack', ROOT, '--json', '--pack-destination', packages], { cwd: ROOT, env: environment });
    assert.equal(runtimePack.code, 0, runtimePack.stderr);
    const [specResult] = JSON.parse(specPack.stdout); const [runtimeResult] = JSON.parse(runtimePack.stdout);
    assert.equal(runtimeResult.name, '@opengamevcs/path-filesystem');
    const binary = runtimeResult.files.find(({ path }) => path === 'bin/ogvcs-path.mjs');
    assert.ok(binary);
    if (process.platform !== 'win32') assert.ok((binary.mode & 0o111) !== 0);
    assert.ok(runtimeResult.files.some(({ path }) => path === 'LICENSE'));
    assert.ok(runtimeResult.files.every(({ path }) => !path.startsWith('test/') && !path.startsWith('scripts/')));
    await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n');
    const installed = await npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', join(packages, basename(specResult.filename)), join(packages, basename(runtimeResult.filename))], { cwd: consumer, env: environment });
    assert.equal(installed.code, 0, installed.stderr);
    const runtimeRoot = join(consumer, 'node_modules/@opengamevcs/path-filesystem');
    const cli = join(runtimeRoot, 'bin/ogvcs-path.mjs');
    const offlineEnvironment = { ...environment, npm_config_offline: 'true' };
    const publicApiSmoke = join(consumer, 'public-api-smoke.mjs');
    await writeFile(publicApiSmoke, `
import assert from 'node:assert/strict';
import * as api from '@opengamevcs/path-filesystem';

for (const name of [
  'atomicWriteFile',
  'buildConformanceReport',
  'createPathTelemetry',
  'createObjectModelPathProfileAdapter',
  'openWorkspaceRoot',
  'pathCollisionKeys',
  'preflightMaterialization',
  'preflightWorkspaceMaterialization',
  'snapshotPathTelemetry',
]) assert.equal(typeof api[name], 'function', name);

const telemetry = api.createPathTelemetry();
assert.equal(api.snapshotPathTelemetry(telemetry).schemaVersion, 'ogvcs.path/telemetry-snapshot/v1');

const adapter = api.createObjectModelPathProfileAdapter({
  profile: 'path.opengamevcs/linux@1', caseMode: 'case-folded',
});
assert.deepEqual(adapter.validate({
  profile: adapter.profile, caseMode: adapter.caseMode, segments: ['Content', 'Hero'],
}), {
  accepted: true,
  repositoryKey: 'ogvcs-path-key-v1:case-folded:0007:636f6e74656e74/0004:6865726f',
  platformKey: 'ogvcs-platform-key-v1:path.opengamevcs/linux@1:0007:436f6e74656e74/0004:4865726f',
});
process.stdout.write(JSON.stringify({ imported: true }));
`);
    const publicApi = await run(process.execPath, [publicApiSmoke], { cwd: consumer, env: offlineEnvironment });
    assert.equal(publicApi.code, 0, publicApi.stderr);
    assert.deepEqual(JSON.parse(publicApi.stdout), { imported: true });

    const help = await run(process.execPath, [cli, '--help'], { cwd: consumer, env: offlineEnvironment });
    assert.equal(help.code, 0, help.stderr);
    for (const command of ['validate', 'collisions', 'preflight', 'renames', 'capabilities', 'write', 'conformance']) {
      assert.match(help.stdout, new RegExp(`^  ${command}\\b`, 'm'));
    }

    const validation = await run(process.execPath, [cli, 'validate', 'Content/Café.uasset', '--case-mode', 'case-folded'], { cwd: consumer, env: offlineEnvironment });
    assert.equal(validation.code, 0, validation.stderr);
    assert.equal(JSON.parse(validation.stdout).accepted, true);

    const collisionsPath = join(scratch, 'collisions.json');
    await writeFile(collisionsPath, JSON.stringify({
      caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1',
      items: [{ id: 'left', path: 'Content/Hero' }, { id: 'right', path: 'content/hero' }],
    }));
    const collisions = await run(process.execPath, [cli, 'collisions', collisionsPath], { cwd: consumer, env: offlineEnvironment });
    assert.equal(collisions.code, 0, collisions.stderr);
    assert.equal(JSON.parse(collisions.stdout).accepted, true);

    const platform = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux';
    const preflightPath = join(scratch, 'preflight.json');
    await writeFile(preflightPath, JSON.stringify({
      schemaVersion: 'ogvcs.path/preflight-request/v1', caseMode: 'case-sensitive',
      profile: 'path.opengamevcs/portable@1', platform,
      capabilities: { atomicReplace: true, executableBit: true, symlink: true },
      entries: [{ id: 'root', path: 'Content', kind: 'directory', mode: 'directory' }],
    }));
    const preflight = await run(process.execPath, [cli, 'preflight', preflightPath], { cwd: consumer, env: offlineEnvironment });
    assert.equal(preflight.code, 0, preflight.stderr);
    assert.equal(JSON.parse(preflight.stdout).accepted, true);

    const renamesPath = join(scratch, 'renames.json');
    await writeFile(renamesPath, JSON.stringify({
      caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1',
      renames: [{ from: 'Old', to: 'New', fileId: '11'.repeat(16) }],
    }));
    const renames = await run(process.execPath, [cli, 'renames', renamesPath], { cwd: consumer, env: offlineEnvironment });
    assert.equal(renames.code, 0, renames.stderr);
    assert.equal(JSON.parse(renames.stdout).accepted, true);

    const workspace = join(scratch, 'workspace');
    await mkdir(workspace, { mode: 0o700 });
    const capabilities = await run(process.execPath, [cli, 'capabilities', workspace], { cwd: consumer, env: offlineEnvironment });
    assert.equal(capabilities.code, 0, capabilities.stderr);
    assert.equal(JSON.parse(capabilities.stdout).schemaVersion, 'ogvcs.path/filesystem-capabilities/v1');

    const source = join(scratch, 'source.bin');
    await writeFile(source, 'packed public CLI');
    const write = await run(process.execPath, [cli, 'write', workspace, 'Content/asset.bin', source], { cwd: consumer, env: offlineEnvironment });
    assert.equal(write.code, 0, write.stderr);
    assert.equal(JSON.parse(write.stdout).bytes, 17);
    assert.equal(await readFile(join(workspace, 'Content/asset.bin'), 'utf8'), 'packed public CLI');

    for (const args of [['capabilities', 'relative-root'], ['write', 'relative-root', 'Content/asset.bin', source]]) {
      const rejected = await run(process.execPath, [cli, ...args], { cwd: consumer, env: offlineEnvironment });
      assert.equal(rejected.code, 2, rejected.stderr);
      assert.equal(JSON.parse(rejected.stderr).code, 'PATH_INPUT_INVALID');
    }

    const reportPath = join(scratch, 'packed-report.json');
    const conformance = await run(process.execPath, [cli, 'conformance', '--output', reportPath], { cwd: consumer, env: offlineEnvironment });
    assert.equal(conformance.code, 0, conformance.stderr);
    const report = JSON.parse(await readFile(reportPath));
    assert.equal(report.total, 78); assert.equal(report.passed, 78); assert.equal(report.failed, 0);
  } finally { await rm(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 }); }
});
