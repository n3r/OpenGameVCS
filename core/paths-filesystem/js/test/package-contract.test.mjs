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

test('offline-installed packed runtime binds the packed contract and passes conformance', async () => {
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
    assert.ok(runtimeResult.files.some(({ path, mode }) => path === 'bin/ogvcs-path.mjs' && (mode & 0o111) !== 0));
    assert.ok(runtimeResult.files.some(({ path }) => path === 'LICENSE'));
    assert.ok(runtimeResult.files.every(({ path }) => !path.startsWith('test/') && !path.startsWith('scripts/')));
    await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n');
    const installed = await npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', join(packages, basename(specResult.filename)), join(packages, basename(runtimeResult.filename))], { cwd: consumer, env: environment });
    assert.equal(installed.code, 0, installed.stderr);
    const runtimeRoot = join(consumer, 'node_modules/@opengamevcs/path-filesystem');
    const cli = join(runtimeRoot, 'bin/ogvcs-path.mjs');
    const validation = await run(process.execPath, [cli, 'validate', 'Content/Café.uasset', '--case-mode', 'case-folded'], { cwd: consumer, env: { ...environment, npm_config_offline: 'true' } });
    assert.equal(validation.code, 0, validation.stderr);
    assert.equal(JSON.parse(validation.stdout).accepted, true);
    const reportPath = join(scratch, 'packed-report.json');
    const conformance = await run(process.execPath, [cli, 'conformance', '--output', reportPath], { cwd: consumer, env: { ...environment, npm_config_offline: 'true' } });
    assert.equal(conformance.code, 0, conformance.stderr);
    const report = JSON.parse(await readFile(reportPath));
    assert.equal(report.total, 72); assert.equal(report.passed, 72); assert.equal(report.failed, 0);
  } finally { await rm(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 }); }
});
