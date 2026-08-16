import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const ROOT = resolve(import.meta.dirname, '..');
function run(script, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [join(ROOT, 'tools', script), ...args], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, env: { ...process.env, npm_config_cache: join(tmpdir(), 'ogvcs-path-tool-cache') } });
    const stdout = []; const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk)); child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject); child.once('close', (code) => resolvePromise({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

test('source report is bounded, complete, and green', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-path-tool-')); t.after(() => rm(scratch, { recursive: true, force: true }));
  const reportPath = join(scratch, 'report.json');
  const result = await run('path-filesystem-conformance-report.mjs', ['--output', reportPath]);
  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(await readFile(reportPath));
  assert.deepEqual({ total: report.total, passed: report.passed, failed: report.failed }, { total: 72, passed: 72, failed: 0 });
  assert.equal(report.results.filter(({ category }) => category !== 'native-filesystem').length, 62);
});

test('packed runner retains both exact archives and its report', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-path-packed-tool-')); t.after(() => rm(scratch, { recursive: true, force: true }));
  const output = join(scratch, 'evidence');
  const result = await run('run-packed-path-filesystem-conformance.mjs', ['--output', output]);
  assert.equal(result.code, 0, result.stderr);
  const evidence = JSON.parse(await readFile(join(output, 'packed-evidence.json')));
  assert.equal(evidence.packages.length, 2);
  assert.deepEqual(new Set(evidence.packages.map(({ name }) => name)), new Set(['@opengamevcs/path-contract-v1', '@opengamevcs/path-filesystem']));
  const report = JSON.parse(await readFile(join(output, 'conformance-report.json')));
  assert.equal(report.failed, 0);
});
