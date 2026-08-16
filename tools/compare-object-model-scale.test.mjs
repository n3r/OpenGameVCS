import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const ROOT = resolve(import.meta.dirname, '..');
const REVISION = '0123456789abcdef0123456789abcdef01234567';

function run(args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', code => resolvePromise({
      code,
      stderr: Buffer.concat(stderr).toString('utf8'),
      stdout: Buffer.concat(stdout).toString('utf8')
    }));
  });
}

function reports() {
  const shared = {
    sourceRevision: REVISION,
    exactV1Scale: true,
    tree: {
      entries: 1_000_000,
      objectRef: 'ogvcs:v1:tree:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      outputBytes: 111_000_054,
      payloadSha256Hex: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      logicalBytes: '123456789',
      byteForByteParity: true,
      orderedFileIdPeakScratchBytes: 16_000_000,
      orderedWallTimeNanoseconds: '100',
      sortedPeakScratchBytes: 128_000_000,
      sortedWallTimeNanoseconds: '200'
    },
    manifest: {
      chunks: 1_048_576,
      chunkBytes: 1_048_576,
      chunkObjectRef: 'ogvcs:v1:chunk:sha256:8d40b35dab2f8ff4305af64230cecf10c9c7616c2ca75e606ced44114aa9224a',
      rawChunkSha256Hex: '223066858638b498e56e28ecc6fb8a0cd5d1c7d1ac99c3c4ce286df776bedc3f',
      logicalBytes: '1099511627776',
      wholeFileDigestHex: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      objectRef: 'ogvcs:v1:content-manifest:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      outputBytes: 50_000_000,
      payloadSha256Hex: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
      wallTimeNanoseconds: '300'
    },
    process: { maxRssBytes: 300_000_000 }
  };
  return {
    javascript: {
      ...structuredClone(shared),
      schema: 'ogvcs.object-model.javascript-scale-report/v1',
      packagedCli: {
        name: '@opengamevcs/object-model',
        tarballSha256Hex: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        version: '0.1.0'
      },
      recurrence: {
        tree: { seedHex: 'a73b9b82eb035d7f2d8bbfa98a94b71be16360dacc1b22a5c2d28bf5fa56fc80' },
        manifest: {
          seedHex: '860f753350ec981c19f401b44ed6a36a0ac76353a5389e31dc36048dd2d78f65',
          blockHex: '8e5a7fde9a212a4bdab640aaa5541de91d981498ac28bc8d8a901722ca807a24'
        }
      }
    },
    rust: {
      ...structuredClone(shared),
      schema: 'ogvcs.object-model.rust-scale-report/v1',
      recurrence: {
        treeSeedHex: 'a73b9b82eb035d7f2d8bbfa98a94b71be16360dacc1b22a5c2d28bf5fa56fc80',
        manifestSeedHex: '860f753350ec981c19f401b44ed6a36a0ac76353a5389e31dc36048dd2d78f65',
        manifestBlockHex: '8e5a7fde9a212a4bdab640aaa5541de91d981498ac28bc8d8a901722ca807a24'
      }
    }
  };
}

test('exact scale comparison binds identity, bounds, uniqueness, and revision', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-scale-comparison-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  const javascriptPath = join(directory, 'javascript.json');
  const rustPath = join(directory, 'rust.json');
  const outputPath = join(directory, 'comparison.json');
  const fixtures = reports();
  fixtures.javascript.tree.summary = { logicalBytes: 123456789 };
  fixtures.javascript.tree.fileIdUniqueness = {
    cliDiskIndex: 'verified',
    orderedDiskIndex: 'verified',
    sortedSideIndex: 'verified'
  };
  fixtures.javascript.tree.cliVerification = {
    objectRef: fixtures.javascript.tree.objectRef,
    peakScratchBytes: 64_000_000,
    processMaxRssBytes: 400_000_000,
    status: 'valid'
  };
  fixtures.javascript.manifest.verification = { contentVerified: true };
  fixtures.javascript.manifest.structuralOnly = false;
  fixtures.rust.tree.fileIdUniqueness = 'verified-exact-disk-index';
  fixtures.rust.manifest.contentVerified = true;
  await writeFile(javascriptPath, `${JSON.stringify(fixtures.javascript)}\n`, 'utf8');
  await writeFile(rustPath, `${JSON.stringify(fixtures.rust)}\n`, 'utf8');

  const compared = await run([
    'tools/compare-object-model-scale.mjs',
    '--javascript', javascriptPath,
    '--rust', rustPath,
    '--output', outputPath
  ]);
  assert.equal(compared.code, 0, compared.stderr || compared.stdout);
  const result = JSON.parse(await readFile(outputPath, 'utf8'));
  assert.equal(result.result, 'byte-identical-and-bounded');
  assert.equal(result.sourceRevision, REVISION);
  assert.equal(result.packagedCli.tarballSha256Hex,
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');

  fixtures.rust.sourceRevision = 'different-revision';
  await writeFile(rustPath, `${JSON.stringify(fixtures.rust)}\n`, 'utf8');
  await rm(outputPath);
  const rejected = await run([
    'tools/compare-object-model-scale.mjs',
    '--javascript', javascriptPath,
    '--rust', rustPath,
    '--output', outputPath
  ]);
  assert.notEqual(rejected.code, 0);
  assert.match(rejected.stderr, /source revision/);
  await assert.rejects(readFile(outputPath));
});
