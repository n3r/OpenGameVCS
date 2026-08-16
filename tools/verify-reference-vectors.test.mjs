import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const ROOT = resolve(import.meta.dirname, '..');
const AUDITOR = join(ROOT, 'tools', 'verify-reference-vectors.mjs');

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]));
  }
  return value;
}

function stableJson(value) { return `${JSON.stringify(stableValue(value), null, 2)}\n`; }
function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

function run(root) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [AUDITOR, '--root', root], {
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

test('independent vector audit rejects byte and coverage drift even with a refreshed inventory hash', {
  timeout: 60_000
}, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-vector-audit-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  await cp(join(ROOT, 'spec'), join(directory, 'spec'), { recursive: true });
  await cp(join(ROOT, 'tools', 'reference-vector-generator'),
    join(directory, 'tools', 'reference-vector-generator'), { recursive: true });

  const valid = await run(directory);
  assert.equal(valid.code, 0, valid.stderr || valid.stdout);
  const summary = JSON.parse(valid.stdout);
  assert.deepEqual({
    artifacts: summary.artifacts,
    obligations: summary.obligations,
    scenarios: summary.scenarios,
    stableErrors: summary.stableErrors,
    validationStages: summary.validationStages
  }, { artifacts: 1236, obligations: 148, scenarios: 235, stableErrors: 81, validationStages: 10 });

  const errorsPath = join(directory, 'spec', 'repository-format', 'v1', 'errors.json');
  const originalErrors = await readFile(errorsPath);
  const errors = JSON.parse(originalErrors);
  const bundleRoot = errors.errors.find(error => error.code === 'BUNDLE_ROOT_INVALID');
  bundleRoot.sites = bundleRoot.sites.filter(site => site.stage !== 'closure-and-reference-resolution');
  await writeFile(errorsPath, stableJson(errors));
  const siteDrift = await run(directory);
  assert.notEqual(siteDrift.code, 0);
  assert.match(siteDrift.stderr, /scenario rejection mismatch for bundle-root-invalid/);
  await writeFile(errorsPath, originalErrors);

  const vectorRoot = join(directory, 'spec', 'repository-format', 'v1', 'vectors');
  const manifestPath = join(vectorRoot, 'manifest.json');
  const originalManifest = await readFile(manifestPath);
  const objectPath = join(vectorRoot, 'objects', '01-chunk.bin');
  const original = await readFile(objectPath);
  const changed = Buffer.from(original); changed[0] ^= 1;
  await writeFile(objectPath, changed);
  const byteDrift = await run(directory);
  assert.notEqual(byteDrift.code, 0);
  assert.match(byteDrift.stderr, /bytes or media type differ/);
  await writeFile(objectPath, original);

  const seedPath = join(vectorRoot, 'seed.json');
  const originalSeed = await readFile(seedPath);
  const seed = JSON.parse(originalSeed);
  seed.independentlyReproducible.formula = 'SHA-256(payloadHex)';
  const seedBytes = Buffer.from(stableJson(seed));
  await writeFile(seedPath, seedBytes);
  const seedManifest = JSON.parse(originalManifest);
  const seedRecord = seedManifest.artifacts.find(item => item.path === 'seed.json');
  seedRecord.bytes = seedBytes.length;
  seedRecord.sha256 = digest(seedBytes);
  await writeFile(manifestPath, stableJson(seedManifest));
  const seedDrift = await run(directory);
  assert.notEqual(seedDrift.code, 0);
  assert.match(seedDrift.stderr, /hand-auditable seed or preimage invariant/);
  await writeFile(seedPath, originalSeed);
  await writeFile(manifestPath, originalManifest);

  const coveragePath = join(vectorRoot, 'coverage-matrix.json');
  const coverage = JSON.parse(await readFile(coveragePath, 'utf8'));
  coverage.obligations[0].scenarios = [];
  const coverageBytes = Buffer.from(stableJson(coverage));
  await writeFile(coveragePath, coverageBytes);
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const record = manifest.artifacts.find(item => item.path === 'coverage-matrix.json');
  record.bytes = coverageBytes.length;
  record.sha256 = digest(coverageBytes);
  await writeFile(manifestPath, stableJson(manifest));
  const semanticDrift = await run(directory);
  assert.notEqual(semanticDrift.code, 0);
  assert.match(semanticDrift.stderr, /coverage matrix/);
});
