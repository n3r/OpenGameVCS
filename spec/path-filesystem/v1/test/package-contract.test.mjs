import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const npmCli = process.env.npm_execpath;

function run(command, args, cwd, env = process.env) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const stdout = []; const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => resolvePromise({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

function npm(args, cwd, env) { return npmCli ? run(process.execPath, [npmCli, ...args], cwd, env) : run('npm', args, cwd, env); }

test('packed contract is offline-usable and contains only the declared authority', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-path-contract-pack-'));
  try {
    const environment = { ...process.env, npm_config_cache: join(scratch, 'npm-cache'), npm_config_audit: 'false', npm_config_fund: 'false' };
    const packed = await npm(['pack', ROOT, '--json', '--pack-destination', scratch], ROOT, environment);
    assert.equal(packed.code, 0, packed.stderr);
    const [result] = JSON.parse(packed.stdout);
    assert.equal(result.name, '@opengamevcs/path-contract-v1');
    assert.equal(result.version, '1.0.0');
    assert.ok(result.files.some(({ path }) => path === 'LICENSE'));
    assert.ok(result.files.some(({ path }) => path === 'manifest.json'));
    assert.ok(result.files.some(({ path }) => path === 'data/CaseFolding-16.0.0.txt'));
    assert.ok(result.files.some(({ path }) => path === 'vectors/path-cases.json'));
    assert.ok(result.files.every(({ path }) => !path.startsWith('source/') && !path.startsWith('scripts/') && !path.startsWith('test/')));
    const tarball = join(scratch, basename(result.filename));
    assert.ok((await readFile(tarball)).length > 0);
  } finally { await rm(scratch, { recursive: true, force: true }); }
});
