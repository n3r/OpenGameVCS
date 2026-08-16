import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

const PACKAGE = resolve(import.meta.dirname, '..');
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

test('packed language-neutral contract ships the complete offline authority', { timeout: 120_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-authz-spec-pack-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  const pack = join(root, 'pack');
  const consumer = join(root, 'consumer');
  const cache = join(root, 'cache');
  await mkdir(pack);
  await mkdir(consumer);
  const env = { ...process.env, npm_config_cache: cache, npm_config_audit: 'false', npm_config_fund: 'false' };
  const packed = await npm(['pack', PACKAGE, '--json', '--pack-destination', pack], { cwd: REPOSITORY, env });
  assert.equal(packed.code, 0, packed.stderr || packed.stdout);
  const [result] = JSON.parse(packed.stdout);
  const names = new Set(result.files.map(({ path }) => path));
  for (const required of [
    'LICENSE', 'README.md', 'manifest.json', 'docs/threat-model.md', 'docs/privacy-review.md',
    'docs/runner-protocol.md', 'schemas/AuthorizationRequest.schema.json',
    'registries/permissions.json', 'policies/internal-team.json', 'vectors/abuse-catalog.json',
  ]) assert.equal(names.has(required), true, `packed contract omitted ${required}`);
  assert.equal([...names].some((name) => name.startsWith('source/') || name.startsWith('scripts/') || name.startsWith('test/')), false);
  const tarball = join(pack, basename(result.filename));
  await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n');
  const installed = await npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', tarball], { cwd: consumer, env });
  assert.equal(installed.code, 0, installed.stderr || installed.stdout);
  const installedRoot = join(consumer, 'node_modules/@opengamevcs/authorization-contract-v1');
  const manifest = JSON.parse(await readFile(join(installedRoot, 'manifest.json'), 'utf8'));
  assert.equal(manifest.contractVersion, '1.0.0');
  assert.equal(manifest.registrySetSha256.length, 64);
  assert.equal(await readFile(join(installedRoot, 'LICENSE'), 'utf8'), await readFile(join(REPOSITORY, 'LICENSE'), 'utf8'));
});
