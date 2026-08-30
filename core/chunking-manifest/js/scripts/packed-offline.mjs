#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const objectModelDirectory = resolve(packageDirectory, '../../object-model/js');
const pathContractDirectory = resolve(packageDirectory, '../../../spec/path-filesystem/v1');
const pathFilesystemDirectory = resolve(packageDirectory, '../../paths-filesystem/js');
const temporary = await mkdtemp(join(tmpdir(), 'ogvcs-chunk-packed-'));
const environment = { ...process.env, npm_config_cache: join(temporary, 'npm-cache') };
const npmCli = process.env.npm_execpath
  ?? (process.platform === 'win32'
    ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
    : null);

function run(command, arguments_, cwd) {
  const result = spawnSync(command, arguments_, { cwd, encoding: 'utf8', env: environment });
  if (result.status !== 0) {
    throw new Error(`${command} ${arguments_.join(' ')} failed\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout;
}

function runNpm(arguments_, cwd) {
  return npmCli
    ? run(process.execPath, [npmCli, ...arguments_], cwd)
    : run('npm', arguments_, cwd);
}

function pack(directory) {
  const report = JSON.parse(runNpm([
    'pack', '--ignore-scripts', '--json', '--pack-destination', temporary,
  ], directory));
  if (report.length !== 1) throw new Error(`unexpected npm pack report for ${directory}`);
  return report[0];
}

try {
  const objectModel = pack(objectModelDirectory);
  const pathContract = pack(pathContractDirectory);
  const pathFilesystem = pack(pathFilesystemDirectory);
  const chunking = pack(packageDirectory);
  const files = new Set(chunking.files.map(({ path }) => path));
  for (const required of [
    'package.json', 'README.md', 'src/cache-key.mjs', 'src/control.mjs',
    'src/errors.mjs', 'src/gear.mjs', 'src/identity.mjs', 'src/index.mjs',
    'src/ledger.mjs', 'src/publication.mjs', 'src/receipt.mjs', 'src/verify.mjs',
  ]) {
    if (!files.has(required)) throw new Error(`packed chunk package is missing ${required}`);
  }
  if ([...files].some((path) => path.startsWith('test/') || path.startsWith('scripts/'))) {
    throw new Error('packed chunk package contains development-only files');
  }

  await writeFile(join(temporary, 'package.json'), '{"private":true,"type":"module"}\n');
  const objectTarball = join(temporary, objectModel.filename);
  const pathContractTarball = join(temporary, pathContract.filename);
  const pathTarball = join(temporary, pathFilesystem.filename);
  const chunkTarball = join(temporary, chunking.filename);
  runNpm([
    'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund',
    '--package-lock=false', objectTarball, pathContractTarball, pathTarball, chunkTarball,
  ], temporary);
  await writeFile(join(temporary, 'check.mjs'), `
    import { mkdtemp, readFile } from 'node:fs/promises';
    import { tmpdir } from 'node:os';
    import { join } from 'node:path';
    import { createHash } from 'node:crypto';
    import { rm } from 'node:fs/promises';
    import { openWorkspaceRoot, preflightWorkspaceMaterialization, probeFilesystemCapabilities } from '@opengamevcs/path-filesystem';
    import { chunkBytes, chunkCacheKey, consumeVerificationReceipt, createAtomicWriteStreamPublicationAdapter, reconstructManifest, verifyManifest } from '@opengamevcs/chunking-manifest';
    const bytes = Buffer.from('packed-offline');
    const generated = await chunkBytes(bytes);
    const source = new Map([[generated.chunks[0].objectId, bytes]]);
    const verified = await verifyManifest({ manifest: generated.manifest.bytes, source });
    if (verified.logicalBytes !== String(bytes.length)) throw new Error('verification mismatch');
    if (!chunkCacheKey(generated.chunks[0]).startsWith('ogvcs:chunk-cache:v1:sha256:')) {
      throw new Error('cache key mismatch');
    }
    const root = await mkdtemp(join(tmpdir(), 'ogvcs-chunk-packed-root-'));
    try {
      const workspace = await openWorkspaceRoot(root);
      const capabilities = await probeFilesystemCapabilities(workspace.root);
      const plan = await preflightWorkspaceMaterialization(workspace, {
        schemaVersion: 'ogvcs.path/preflight-request/v1',
        caseMode: workspace.caseMode,
        profile: workspace.profile,
        platform: capabilities.platform,
        capabilities: { atomicReplace: capabilities.atomicReplace, executableBit: capabilities.executableBit, symlink: capabilities.symlink },
        entries: [
          { id: 'parent-1', path: 'Content', kind: 'directory', mode: 'directory' },
          { id: 'asset', path: 'Content/asset.bin', kind: 'regular', mode: 'regular-file' },
        ],
      });
      const reconstructed = await reconstructManifest({
        manifest: generated.manifest.bytes,
        source,
        publication: createAtomicWriteStreamPublicationAdapter(workspace, 'Content/asset.bin', { manifest: generated.manifest.bytes, createParents: true, plan, maxBytes: bytes.length, maxScratchBytes: bytes.length }),
      });
      const workspacePublication = reconstructed.publicationResult.workspacePublication;
      const fileBytes = await readFile(join(root, 'Content', 'asset.bin'));
      if (Buffer.compare(fileBytes, bytes) !== 0) throw new Error('reconstruction mismatch');
      const receipt = consumeVerificationReceipt(reconstructed.verificationReceipt, {
        manifest: generated.manifest.bytes,
        manifestObjectId: generated.manifest.objectId,
        logicalBytes: String(bytes.length),
        wholeFileSha256: createHash('sha256').update(bytes).digest('hex'),
        workspacePublication,
      });
      if (receipt.workspacePublication.transaction !== workspacePublication.transaction) throw new Error('receipt mismatch');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  `);
  run(process.execPath, [join(temporary, 'check.mjs')], temporary);
  process.stdout.write(`verified ${chunking.filename} from an offline packed install\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
