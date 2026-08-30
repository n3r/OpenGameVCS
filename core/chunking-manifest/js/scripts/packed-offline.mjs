#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const objectModelDirectory = resolve(packageDirectory, '../../object-model/js');
const temporary = await mkdtemp(join(tmpdir(), 'ogvcs-chunk-packed-'));
const environment = { ...process.env, npm_config_cache: join(temporary, 'npm-cache') };

function run(command, arguments_, cwd) {
  const result = spawnSync(command, arguments_, { cwd, encoding: 'utf8', env: environment });
  if (result.status !== 0) {
    throw new Error(`${command} ${arguments_.join(' ')} failed\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout;
}

function pack(directory) {
  const report = JSON.parse(run('npm', [
    'pack', '--ignore-scripts', '--json', '--pack-destination', temporary,
  ], directory));
  if (report.length !== 1) throw new Error(`unexpected npm pack report for ${directory}`);
  return report[0];
}

try {
  const objectModel = pack(objectModelDirectory);
  const chunking = pack(packageDirectory);
  const files = new Set(chunking.files.map(({ path }) => path));
  for (const required of [
    'package.json', 'README.md', 'src/cache-key.mjs', 'src/control.mjs',
    'src/errors.mjs', 'src/gear.mjs', 'src/identity.mjs', 'src/index.mjs',
    'src/ledger.mjs', 'src/verify.mjs',
  ]) {
    if (!files.has(required)) throw new Error(`packed chunk package is missing ${required}`);
  }
  if ([...files].some((path) => path.startsWith('test/') || path.startsWith('scripts/'))) {
    throw new Error('packed chunk package contains development-only files');
  }

  await writeFile(join(temporary, 'package.json'), '{"private":true,"type":"module"}\n');
  const objectTarball = join(temporary, objectModel.filename);
  const chunkTarball = join(temporary, chunking.filename);
  run('npm', [
    'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund',
    '--package-lock=false', objectTarball, chunkTarball,
  ], temporary);
  await writeFile(join(temporary, 'check.mjs'), `
    import { chunkBytes, chunkCacheKey, verifyManifest } from '@opengamevcs/chunking-manifest';
    const bytes = Buffer.from('packed-offline');
    const generated = await chunkBytes(bytes);
    const source = new Map([[generated.chunks[0].objectId, bytes]]);
    const verified = await verifyManifest({ manifest: generated.manifest.bytes, source });
    if (verified.logicalBytes !== String(bytes.length)) throw new Error('verification mismatch');
    if (!chunkCacheKey(generated.chunks[0]).startsWith('ogvcs:chunk-cache:v1:sha256:')) {
      throw new Error('cache key mismatch');
    }
  `);
  run(process.execPath, [join(temporary, 'check.mjs')], temporary);
  process.stdout.write(`verified ${chunking.filename} from an offline packed install\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
