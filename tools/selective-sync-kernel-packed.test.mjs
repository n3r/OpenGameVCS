import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

const REPOSITORY = resolve(import.meta.dirname, '..');
const SELECTIVE = resolve(REPOSITORY, 'spec/selective-sync/v1');
const PATH_CONTRACT = resolve(REPOSITORY, 'spec/path-filesystem/v1');
const npmCli = process.env.npm_execpath;

function run(command, arguments_, cwd, environment) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, arguments_, {
      cwd,
      env: environment,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout = []; const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => resolvePromise({
      code,
      stderr: Buffer.concat(stderr).toString('utf8'),
      stdout: Buffer.concat(stdout).toString('utf8'),
    }));
  });
}

function npm(arguments_, cwd, environment) {
  return npmCli
    ? run(process.execPath, [npmCli, ...arguments_], cwd, environment)
    : run('npm', arguments_, cwd, environment);
}

async function requirePass(result, label) {
  assert.equal(result.code, 0, `${label}\n${result.stderr || result.stdout}`);
  return result;
}

test('packed selective kernel is exact and runs from a fully offline extracted consumer', { timeout: 300_000 }, async (context) => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-selective-pack-'));
  context.after(() => rm(scratch, { force: true, recursive: true }));
  const packages = join(scratch, 'packages'); const consumer = join(scratch, 'consumer');
  await mkdir(packages); await mkdir(consumer);
  const environment = {
    ...process.env,
    npm_config_audit: 'false',
    npm_config_cache: join(scratch, 'npm-cache'),
    npm_config_fund: 'false',
    npm_config_offline: 'true',
  };
  delete environment.NODE_TEST_CONTEXT;

  const dryRun = await requirePass(await npm([
    'pack', SELECTIVE, '--dry-run', '--json', '--ignore-scripts',
  ], REPOSITORY, environment), 'selective package dry run');
  const [dryRecord] = JSON.parse(dryRun.stdout);
  const manifest = JSON.parse(await readFile(resolve(SELECTIVE, 'manifest.json'), 'utf8'));
  const expected = [...manifest.artifacts.map(({ path }) => path), 'manifest.json'].sort();
  assert.deepEqual(dryRecord.files.map(({ path }) => path).sort(), expected);

  const pathPack = await requirePass(await npm([
    'pack', PATH_CONTRACT, '--json', '--ignore-scripts', '--pack-destination', packages,
  ], REPOSITORY, environment), 'path authority package');
  const selectivePack = await requirePass(await npm([
    'pack', SELECTIVE, '--json', '--ignore-scripts', '--pack-destination', packages,
  ], REPOSITORY, environment), 'selective package');
  const [pathRecord] = JSON.parse(pathPack.stdout); const [selectiveRecord] = JSON.parse(selectivePack.stdout);
  assert.equal(pathRecord.name, '@opengamevcs/path-contract-v1');
  assert.equal(selectiveRecord.name, '@opengamevcs/selective-sync-kernel-contract-v1');
  const pathTarball = join(packages, basename(pathRecord.filename));
  const selectiveTarball = join(packages, basename(selectiveRecord.filename));
  await writeFile(join(consumer, 'package.json'), `${JSON.stringify({
    name: 'ogvcs-selective-offline-consumer',
    private: true,
    dependencies: {
      '@opengamevcs/path-contract-v1': `file:${pathTarball}`,
      '@opengamevcs/selective-sync-kernel-contract-v1': `file:${selectiveTarball}`,
    },
  })}\n`);
  await requirePass(await npm([
    'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false',
  ], consumer, environment), 'offline consumer install');
  const installed = join(consumer, 'node_modules/@opengamevcs/selective-sync-kernel-contract-v1');
  assert.equal(JSON.parse(await readFile(join(installed, 'package.json'), 'utf8')).version, '0.1.0-rc.1');
  assert.equal((await readFile(join(installed, 'manifest.json'))).equals(await readFile(resolve(SELECTIVE, 'manifest.json'))), true);
  const checked = await requirePass(await npm(['run', 'check'], installed, environment), 'offline installed check');
  assert.match(checked.stdout, /validated selective-sync kernel contract/u);
  const tested = await requirePass(await npm(['test'], installed, environment), 'offline installed test');
  assert.match(`${tested.stdout}\n${tested.stderr}`, /tests 17/u);
});
