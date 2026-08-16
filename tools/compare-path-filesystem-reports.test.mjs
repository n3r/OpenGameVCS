import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const ROOT = resolve(import.meta.dirname, '..');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}
async function writeJson(path, value) { await writeFile(path, `${canonicalJson(value)}\n`); }
function run(paths) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [join(ROOT, 'tools/compare-path-filesystem-reports.mjs'), ...paths], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const stdout = []; const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk)); child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject); child.once('close', (code) => resolvePromise({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

test('comparator requires exact cross-OS decisions and packed package bytes', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-path-compare-')); t.after(() => rm(scratch, { recursive: true, force: true }));
  const decision = sha256(Buffer.from(canonicalJson('passed')));
  const results = Array.from({ length: 72 }, (_, index) => ({ id: `row-${index}`, category: 'test', passed: true, expectedSha256: decision, actualSha256: decision }));
  const resultDigest = sha256(Buffer.from(canonicalJson(results)));
  const paths = [];
  for (const platform of ['linux', 'macos', 'windows']) {
    const directory = join(scratch, platform); const packagesDirectory = join(directory, 'packages');
    await mkdir(packagesDirectory, { recursive: true });
    const packageItems = [];
    for (const [name, filename, bytes] of [['@opengamevcs/path-contract-v1', 'contract.tgz', 'contract'], ['@opengamevcs/path-filesystem', 'runtime.tgz', 'runtime']]) {
      const body = Buffer.from(bytes); await writeFile(join(packagesDirectory, filename), body);
      packageItems.push({ name, version: '1.0.0', filename, sha256: sha256(body) });
    }
    const report = {
      schemaVersion: 'ogvcs.path/conformance-report/v1', contractVersion: '1.0.0',
      implementation: { name: 'test', version: '1.0.0', runtime: 'node test' }, platform,
      capabilities: { atomicReplace: true, casePreserving: true, caseSensitive: platform === 'linux', directorySync: true, executableBit: platform !== 'windows', hardlink: true, normalizationSensitive: platform !== 'macos', symlink: platform !== 'windows' },
      manifestSha256: '11'.repeat(32), registrySetSha256: '22'.repeat(32), unicodeCaseFoldingSha256: '33'.repeat(32), resultsSha256: resultDigest,
      total: 72, passed: 72, failed: 0, results,
    };
    const reportPath = join(directory, 'conformance-report.json'); await writeJson(reportPath, report); paths.push(reportPath);
    const reportBytes = Buffer.from(`${canonicalJson(report)}\n`);
    await writeJson(join(directory, 'packed-evidence.json'), {
      schemaVersion: 'ogvcs.path/packed-evidence/v1', contractVersion: '1.0.0', manifestSha256: report.manifestSha256,
      registrySetSha256: report.registrySetSha256, unicodeCaseFoldingSha256: report.unicodeCaseFoldingSha256,
      resultsSha256: resultDigest, platform, packages: packageItems,
      report: { filename: 'conformance-report.json', sha256: sha256(reportBytes) },
    });
  }
  const accepted = await run(paths);
  assert.equal(accepted.code, 0, accepted.stderr);
  assert.equal(JSON.parse(accepted.stdout).result, 'equal');

  const windows = JSON.parse(await import('node:fs/promises').then(({ readFile }) => readFile(paths[2])));
  windows.results[0].actualSha256 = 'ff'.repeat(32);
  await writeJson(paths[2], windows);
  const rejected = await run(paths);
  assert.notEqual(rejected.code, 0);
});
