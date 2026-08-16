import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

const PACKAGE = resolve(import.meta.dirname, '..');
const SPEC = resolve(PACKAGE, '../../../spec/authorization/v1');
const REPOSITORY = resolve(PACKAGE, '../../..');
const NPM_CLI = process.env.npm_execpath ?? (process.platform === 'win32' ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js') : null);

function run(command, args, options = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd: options.cwd, env: options.env ?? process.env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code, signal) => resolvePromise({ code, signal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

function npm(args, options) {
  return NPM_CLI ? run(process.execPath, [NPM_CLI, ...args], options) : run('npm', args, options);
}

test('packed bindings install offline with the exact packed contract and run the complete public suite', { timeout: 180_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-authz-pack-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  const pack = join(root, 'pack');
  const consumer = join(root, 'consumer');
  const cache = join(root, 'cache');
  await mkdir(pack);
  await mkdir(consumer);
  const env = { ...process.env, npm_config_cache: cache, npm_config_audit: 'false', npm_config_fund: 'false' };
  const specPack = await npm(['pack', SPEC, '--json', '--pack-destination', pack], { cwd: REPOSITORY, env });
  assert.equal(specPack.code, 0, specPack.stderr || specPack.stdout);
  const [specResult] = JSON.parse(specPack.stdout);
  const runtimePack = await npm(['pack', PACKAGE, '--json', '--pack-destination', pack], { cwd: REPOSITORY, env });
  assert.equal(runtimePack.code, 0, runtimePack.stderr || runtimePack.stdout);
  const [runtimeResult] = JSON.parse(runtimePack.stdout);
  const files = new Set(runtimeResult.files.map(({ path }) => path));
  for (const required of ['LICENSE', 'README.md', 'bin/ogvcs-authz.mjs', 'examples/external-adapter.mjs', 'src/index.mjs', 'src/generated.mjs', 'types/index.d.ts']) {
    assert.equal(files.has(required), true, `packed runtime omitted ${required}`);
  }
  assert.equal([...files].some((name) => name.startsWith('test/') || name.startsWith('scripts/')), false);
  await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n');
  const installed = await npm([
    'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false',
    join(pack, basename(specResult.filename)), join(pack, basename(runtimeResult.filename)),
  ], { cwd: consumer, env });
  assert.equal(installed.code, 0, installed.stderr || installed.stdout);

  const installedBin = await npm(['exec', '--offline', '--', 'ogvcs-authz', '--help'], {
    cwd: consumer,
    env: { ...env, npm_config_offline: 'true' },
  });
  assert.equal(installedBin.code, 0, installedBin.stderr || installedBin.stdout);
  assert.match(installedBin.stdout, /OpenGameVCS authorization contract runner/);

  const runtimeRoot = join(consumer, 'node_modules/@opengamevcs/authorization-contract');
  const cli = join(runtimeRoot, 'bin/ogvcs-authz.mjs');
  for (const args of [['inspect'], ['verify-grants'], ['run']]) {
    const result = await run(process.execPath, [cli, ...args], { cwd: consumer, env: { ...env, npm_config_offline: 'true' } });
    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.doesNotThrow(() => JSON.parse(result.stdout));
  }
  const usageFailure = await run(process.execPath, [cli, 'unknown-command'], { cwd: consumer, env });
  assert.equal(usageFailure.code, 2, usageFailure.stderr || usageFailure.stdout);
  assert.equal(JSON.parse(usageFailure.stderr).error.code, 'AUTHZ_INPUT_INVALID');
  const adapter = await run(process.execPath, [cli, 'run', '--adapter', process.execPath, '--adapter-arg', join(runtimeRoot, 'examples/external-adapter.mjs')], { cwd: consumer, env });
  assert.equal(adapter.code, 0, adapter.stderr || adapter.stdout);
  assert.equal(JSON.parse(adapter.stdout).passed, 30);

  const installedPackage = JSON.parse(await readFile(join(runtimeRoot, 'package.json'), 'utf8'));
  assert.equal(installedPackage.dependencies['@opengamevcs/authorization-contract-v1'], '1.0.0');
  assert.equal(installedPackage.license, 'MIT');
  assert.equal(await readFile(join(runtimeRoot, 'LICENSE'), 'utf8'), await readFile(join(REPOSITORY, 'LICENSE'), 'utf8'));
});
