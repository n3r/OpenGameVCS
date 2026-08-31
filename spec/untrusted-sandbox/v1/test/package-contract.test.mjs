import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

const PACKAGE = resolve(import.meta.dirname, '..');
const NPM_CLI = process.env.npm_execpath
  ?? (process.platform === 'win32' ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js') : null);

const run = (command, arguments_, options = {}) => new Promise((resolvePromise, reject) => {
  const child = spawn(command, arguments_, { cwd: options.cwd, env: options.env ?? process.env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  const stdout = []; const stderr = [];
  child.stdout.on('data', (chunk) => stdout.push(chunk)); child.stderr.on('data', (chunk) => stderr.push(chunk));
  child.once('error', reject);
  child.once('close', (code) => resolvePromise({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
});
const npm = (arguments_, options = {}) => NPM_CLI
  ? run(process.execPath, [NPM_CLI, ...arguments_], options)
  : run('npm', arguments_, options);

test('packed contract runs its advertised check without repository predecessors', { timeout: 60_000 }, async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-sandbox-contract-pack-'));
  t.after(() => rm(scratch, { recursive: true, force: true }));
  const packages = join(scratch, 'packages'); const consumer = join(scratch, 'consumer'); const cache = join(scratch, 'npm-cache');
  await mkdir(packages); await mkdir(consumer); await mkdir(cache);
  const environment = { ...process.env, npm_config_cache: cache, npm_config_offline: 'true', npm_config_audit: 'false', npm_config_fund: 'false' };
  delete environment.NODE_TEST_CONTEXT;
  const packed = await npm(['pack', PACKAGE, '--json', '--ignore-scripts', '--pack-destination', packages], { cwd: PACKAGE, env: environment });
  assert.equal(packed.code, 0, packed.stderr || packed.stdout);
  const [record] = JSON.parse(packed.stdout); const tarball = join(packages, basename(record.filename));
  await writeFile(join(consumer, 'package.json'), '{"name":"sandbox-contract-packed-consumer","private":true}\n');
  const installed = await npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', tarball], { cwd: consumer, env: environment });
  assert.equal(installed.code, 0, installed.stderr || installed.stdout);
  const installedPackage = join(consumer, 'node_modules/@opengamevcs/untrusted-sandbox-contract-v1');
  const checked = await npm(['run', 'check'], { cwd: installedPackage, env: environment });
  assert.equal(checked.code, 0, checked.stderr || checked.stdout);
  assert.match(checked.stdout, /manifestSha256/u);
  const tested = await npm(['test'], { cwd: installedPackage, env: environment });
  assert.equal(tested.code, 0, tested.stderr || tested.stdout);
  assert.match(`${tested.stdout}\n${tested.stderr}`, /independent semantics reject/u);
});
