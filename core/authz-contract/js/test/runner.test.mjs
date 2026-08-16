import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { AuthorizationContractError, runThreatVectors } from '../src/index.mjs';

const EXAMPLE = resolve(import.meta.dirname, '../examples/external-adapter.mjs');

async function temporary(t, source) {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-authz-adapter-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  const file = join(root, 'adapter.mjs');
  await writeFile(file, source);
  return file;
}

test('reference runner executes all 30 abuse vectors with a stable digest', async () => {
  const report = await runThreatVectors();
  assert.equal(report.vectors, 30);
  assert.equal(report.passed, 30);
  assert.equal(report.failed, 0);
  assert.match(report.resultsSha256, /^[0-9a-f]{64}$/);
  assert.equal(new Set(report.rows.map(({ id }) => id)).size, 30);
  assert.deepEqual(report.rows.map(({ id }) => id), report.rows.map(({ id }) => id).toSorted());
  assert.match(report.manifestSha256, /^[0-9a-f]{64}$/);
});

test('bounded external NDJSON adapter reproduces the public abuse suite', { timeout: 30_000 }, async () => {
  const report = await runThreatVectors({ adapter: [process.execPath, EXAMPLE], timeoutMs: 20_000 });
  assert.equal(report.adapter, 'external-adapter');
  assert.equal(report.passed, 30);
  assert.equal(report.failed, 0);
});

test('well-formed but wrong adapter results produce an honest failed report', async (t) => {
  const adapter = await temporary(t, `
import { createInterface } from 'node:readline';
let hello = true; let index = 0;
for await (const line of createInterface({input:process.stdin,crlfDelay:Infinity})) {
  const message = JSON.parse(line);
  if (hello) { hello = false; continue; }
  const vector = message.vector;
  const code = index++ === 0 ? 'DENY_CONTEXT_INCOMPLETE' : vector.expected.code;
  const result = code.startsWith('ALLOW_') ? 'allow' : 'deny';
  process.stdout.write('{"code":'+JSON.stringify(code)+',"id":'+JSON.stringify(vector.id)+',"result":'+JSON.stringify(result)+',"schemaVersion":"ogvcs.authorization/runner-result/v1"}\\n');
}`);
  const report = await runThreatVectors({ adapter: [process.execPath, adapter], timeoutMs: 10_000 });
  assert.equal(report.failed, 1);
  assert.equal(report.rows[0].status, 'failed');
  assert.equal(report.rows[0].actualCode, 'DENY_CONTEXT_INCOMPLETE');
});

test('noncanonical or extra-field adapter output is a protocol failure', async (t) => {
  const adapter = await temporary(t, `
import { createInterface } from 'node:readline';
let hello = true;
for await (const line of createInterface({input:process.stdin,crlfDelay:Infinity})) {
  const message = JSON.parse(line);
  if (hello) { hello = false; continue; }
  const vector = message.vector;
  process.stdout.write(JSON.stringify({schemaVersion:'ogvcs.authorization/runner-result/v1',id:vector.id,result:vector.expected.result,code:vector.expected.code,path:'secret'})+'\\n');
}`);
  await assert.rejects(() => runThreatVectors({ adapter: [process.execPath, adapter], timeoutMs: 10_000 }), (error) => error instanceof AuthorizationContractError && error.code === 'AUTHZ_ADAPTER_PROTOCOL');
});

test('invalid UTF-8 adapter output is a protocol failure', async (t) => {
  const adapter = await temporary(t, `
import { createInterface } from 'node:readline';
let hello = true;
for await (const line of createInterface({input:process.stdin,crlfDelay:Infinity})) {
  const message = JSON.parse(line);
  if (hello) { hello = false; continue; }
  const vector = message.vector;
  const lineBytes = Buffer.from(JSON.stringify({schemaVersion:'ogvcs.authorization/runner-result/v1',id:vector.id,result:vector.expected.result,code:vector.expected.code})+'\\n');
  if (vector.id === 'vector-altered-transfer-grant') lineBytes[10] = 255;
  process.stdout.write(lineBytes);
}`);
  await assert.rejects(() => runThreatVectors({ adapter: [process.execPath, adapter], timeoutMs: 10_000 }), (error) => error instanceof AuthorizationContractError && error.code === 'AUTHZ_ADAPTER_PROTOCOL');
});

test('nonsettling adapter is killed at the configured elapsed deadline', async (t) => {
  const adapter = await temporary(t, 'setInterval(() => {}, 1000);\n');
  const started = Date.now();
  await assert.rejects(() => runThreatVectors({ adapter: [process.execPath, adapter], timeoutMs: 50 }), (error) => error.code === 'AUTHZ_TIMEOUT');
  assert.ok(Date.now() - started < 5_000);
});

test('adapter stdout is bounded before parsing', async (t) => {
  const adapter = await temporary(t, `process.stdout.write('x'.repeat(1024)); setInterval(() => {}, 1000);\n`);
  await assert.rejects(() => runThreatVectors({ adapter: [process.execPath, adapter], timeoutMs: 5_000, maxStdoutBytes: 100 }), (error) => error.code === 'AUTHZ_LIMIT_EXCEEDED');
});
