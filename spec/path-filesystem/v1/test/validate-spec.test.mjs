import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const VALIDATOR = join(ROOT, 'validate-spec.mjs');

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}
const canonicalBytes = (value) => Buffer.from(`${canonicalJson(value)}\n`);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function run(root = ROOT) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [VALIDATOR], {
      env: { ...process.env, OGVCS_PATH_CONTRACT_ROOT: root },
      stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    });
    const stdout = []; const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => resolvePromise({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

async function fixture() {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-path-spec-'));
  const copy = join(scratch, 'v1');
  await cp(ROOT, copy, { recursive: true });
  return { copy, scratch };
}

async function refreshManifest(copy, relative) {
  const manifestPath = join(copy, 'manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath));
  const bytes = await readFile(join(copy, relative));
  const record = manifest.artifacts.find(({ path }) => path === relative);
  record.bytes = bytes.length; record.sha256 = sha256(bytes);
  if (relative.startsWith('registries/')) manifest.registrySetSha256 = sha256(canonicalBytes(manifest.artifacts.filter(({ path }) => path.startsWith('registries/'))));
  if (relative.startsWith('vectors/')) manifest.vectorSetSha256 = sha256(canonicalBytes(manifest.artifacts.filter(({ path }) => path.startsWith('vectors/'))));
  await writeFile(manifestPath, canonicalBytes(manifest));
}

test('independent validator accepts the frozen source authority', async () => {
  const result = await run();
  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.deepEqual({ vectors: report.vectors, errors: report.errors, profiles: report.profiles, result: report.result }, { vectors: 63, errors: 23, profiles: 4, result: 'valid' });
});

test('validator rejects self-consistent registry reassignment', async () => {
  const { copy, scratch } = await fixture();
  try {
    const path = join(copy, 'registries/platform-profiles.json');
    const value = JSON.parse(await readFile(path));
    value.entries[0].limits.depth = 255;
    await writeFile(path, canonicalBytes(value));
    await refreshManifest(copy, 'registries/platform-profiles.json');
    const result = await run(copy);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /frozen registry assignment differs/u);
  } finally { await rm(scratch, { recursive: true, force: true }); }
});

test('validator independently rejects a self-consistent vector mutation', async () => {
  const { copy, scratch } = await fixture();
  try {
    const path = join(copy, 'vectors/fold-cases.json');
    const value = JSON.parse(await readFile(path));
    value.cases[0].expected = 'wrong';
    await writeFile(path, canonicalBytes(value));
    await refreshManifest(copy, 'vectors/fold-cases.json');
    const result = await run(copy);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /independent fold result differs/u);
  } finally { await rm(scratch, { recursive: true, force: true }); }
});

test('validator rejects Unicode-source and license drift even when the manifest is refreshed', async () => {
  for (const [relative, replacement, pattern] of [
    ['data/CaseFolding-16.0.0.txt', '# changed\n', /Unicode source\/license digest differs/u],
    ['LICENSE', 'MIT-ish\n', /MIT license differs/u],
  ]) {
    const { copy, scratch } = await fixture();
    try {
      await writeFile(join(copy, relative), replacement);
      await refreshManifest(copy, relative);
      const result = await run(copy);
      assert.notEqual(result.code, 0);
      assert.match(result.stderr, pattern);
    } finally { await rm(scratch, { recursive: true, force: true }); }
  }
});

test('validator rejects noncanonical generated JSON', async () => {
  const { copy, scratch } = await fixture();
  try {
    const path = join(copy, 'vectors/fold-cases.json');
    const value = JSON.parse(await readFile(path));
    await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
    await refreshManifest(copy, 'vectors/fold-cases.json');
    const result = await run(copy);
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /not canonical JSON/u);
  } finally { await rm(scratch, { recursive: true, force: true }); }
});
