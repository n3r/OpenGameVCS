import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const ROOT = resolve(import.meta.dirname, '../../../..');

function run(command, arguments_, options = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, arguments_, { cwd: options.cwd ?? ROOT, env: options.env ?? process.env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const stdout = []; const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk)); child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => resolvePromise({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

test('offline packed consumer imports the candidate contract, runtime, and isolated testing adapters', async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-identity-packed-'));
  t.after(() => rm(scratch, { recursive: true, force: true }));
  const packages = join(scratch, 'packages'); const consumer = join(scratch, 'consumer'); const cache = join(scratch, 'npm-cache');
  await mkdir(packages); await mkdir(consumer); await mkdir(cache);
  const packageRoots = [
    'spec/authorization/v1',
    'spec/path-filesystem/v1',
    'spec/protocols/v1',
    'spec/repository-metadata/v1',
    'spec/identity-policy-audit/v1',
    'foundation/protocol-baseline/bindings/typescript',
    'core/authz-contract/js',
    'core/paths-filesystem/js',
    'foundation/protocol-baseline/js',
    'core/identity-policy-audit/js',
  ];
  const archives = [];
  for (const packageRoot of packageRoots) {
    const packed = await run('npm', ['pack', resolve(ROOT, packageRoot), '--pack-destination', packages, '--json', '--ignore-scripts'], {
      env: { ...process.env, npm_config_cache: cache },
    });
    assert.equal(packed.code, 0, packed.stderr);
    const [record] = JSON.parse(packed.stdout);
    archives.push(join(packages, record.filename));
  }
  await writeFile(join(consumer, 'package.json'), JSON.stringify({ name: 'ogvcs-identity-packed-consumer', private: true, type: 'module' }));
  const installed = await run('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', ...archives], {
    cwd: consumer,
    env: { ...process.env, npm_config_cache: cache },
  });
  assert.equal(installed.code, 0, installed.stderr);
  const probe = await run(process.execPath, ['--input-type=module', '--eval', `
    import * as runtime from '@opengamevcs/identity-policy-audit';
    import * as testing from '@opengamevcs/identity-policy-audit/testing';
    import manifest from '@opengamevcs/identity-policy-audit-contract-v1/manifest.json' with { type: 'json' };
    process.stdout.write(JSON.stringify({
      version: runtime.identityPolicyContract.contractVersion,
      manifest: manifest.contractVersion,
      policy: typeof runtime.PolicyEngine,
      audit: typeof runtime.AuditLedger,
      rootMemoryStore: typeof runtime.MemoryCredentialStore,
      testingMemoryStore: typeof testing.MemoryCredentialStore,
    }));
  `], { cwd: consumer, env: { ...process.env, npm_config_cache: cache, npm_config_offline: 'true' } });
  assert.equal(probe.code, 0, probe.stderr);
  assert.deepEqual(JSON.parse(probe.stdout), {
    version: '0.1.0', manifest: '0.1.0', policy: 'function', audit: 'function',
    rootMemoryStore: 'undefined', testingMemoryStore: 'function',
  });
  const runtimePackage = JSON.parse(await readFile(join(consumer, 'node_modules/@opengamevcs/identity-policy-audit/package.json')));
  assert.equal(runtimePackage.version, '0.1.0');
});
