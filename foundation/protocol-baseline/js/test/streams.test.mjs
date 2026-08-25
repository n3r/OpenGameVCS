import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import test from 'node:test';

import { encodeStreamFrame, loadProtocolContract, parseCanonicalStream, writeCanonicalStream } from '../src/index.mjs';
import { protocolRoot } from './roots.mjs';

let contract;
test.before(async () => { contract = await loadProtocolContract({ root: protocolRoot }); });

const streamId = 'stream-000000001';

const frames = Object.freeze([
  Object.freeze({ schemaVersion: 'ogvcs.protocol/stream-frame/v1', streamId, sequence: 0, kind: 'data', payload: { value: 1 } }),
  Object.freeze({ schemaVersion: 'ogvcs.protocol/stream-frame/v1', streamId, sequence: 1, kind: 'terminal' }),
]);

test('stream writer emits canonical LF frames and parser requires explicit terminal state', async () => {
  const chunks = [];
  const output = new Writable({ write(chunk, _encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); } });
  const summary = await writeCanonicalStream(frames, output, { contract });
  assert.equal(summary.terminalKind, 'terminal');
  const encoded = Buffer.concat(chunks);
  assert.equal(encoded.toString('utf8'), `{"kind":"data","payload":{"value":1},"schemaVersion":"ogvcs.protocol/stream-frame/v1","sequence":0,"streamId":"${streamId}"}\n{"kind":"terminal","schemaVersion":"ogvcs.protocol/stream-frame/v1","sequence":1,"streamId":"${streamId}"}\n`);
  const parsed = parseCanonicalStream(encoded, { contract });
  assert.deepEqual(parsed.summary, { streamId, frames: 2, terminalKind: 'terminal' });
});

test('EOF, noncanonical lines, ordinal errors, changed IDs, and post-terminal frames fail', () => {
  const data = `{"kind":"data","payload":null,"schemaVersion":"ogvcs.protocol/stream-frame/v1","sequence":0,"streamId":"${streamId}"}`;
  const terminal = `{"kind":"terminal","schemaVersion":"ogvcs.protocol/stream-frame/v1","sequence":1,"streamId":"${streamId}"}`;
  assert.throws(() => parseCanonicalStream(`${data}\n`, { contract }), /terminal/u);
  assert.throws(() => parseCanonicalStream(` ${terminal}\n`, { contract }), /canonical/u);
  assert.throws(() => parseCanonicalStream(`${data.replace('"sequence":0', '"sequence":1')}\n${terminal.replace('"sequence":1', '"sequence":2')}\n`, { contract }), /sequence numbers/u);
  assert.throws(() => parseCanonicalStream(`${data}\n${terminal.replace(streamId, 'stream-000000002')}\n`, { contract }), /identifier/u);
  assert.throws(() => parseCanonicalStream(`${terminal.replace('"sequence":1', '"sequence":0')}\n${data.replace('"sequence":0', '"sequence":1')}\n`, { contract }), /after its terminal/u);
  assert.throws(() => parseCanonicalStream(terminal, { contract }), /within a frame/u);
});

test('stream resource ceilings reject before returning partially trusted frames', async () => {
  const encoded = Buffer.concat(frames.map((frame) => encodeStreamFrame(frame, { contract })));
  assert.throws(() => parseCanonicalStream(encoded, { contract, maxFrames: 1 }), /frame ceiling/u);
  assert.throws(() => parseCanonicalStream(encoded, { contract, maxRetainedBytes: 600 }), /memory ceiling/u);
  assert.throws(() => parseCanonicalStream(encoded, { contract, maxBytes: encoded.length - 1 }), /byte ceiling/u);
  assert.throws(() => parseCanonicalStream(encoded, { contract, maxRetainedBytes: 10_000, maxWorkingMemoryBytes: 2_000 }), /combined working-memory/u);
  assert.throws(() => encodeStreamFrame(frames[0], { contract, maxWorkingMemoryBytes: 1 }), /working-memory/u);

  let writes = 0;
  const output = new Writable({ write(_chunk, _encoding, callback) { writes += 1; callback(); } });
  await assert.rejects(() => writeCanonicalStream([frames[0]], output, { contract }), /terminal/u);
  assert.equal(writes, 1, 'writer output remains staging/untrusted until the returned promise succeeds');

  writes = 0;
  await assert.rejects(() => writeCanonicalStream(frames, output, { contract, maxWorkingMemoryBytes: 1 }), /working-memory/u);
  assert.equal(writes, 0, 'configured working memory fails before the first staged write');
});

test('stream writer surfaces destination failures', async () => {
  const output = new Writable({ write(_chunk, _encoding, callback) { callback(new Error('disk failure')); } });
  await assert.rejects(() => writeCanonicalStream(frames, output, { contract }), /stream output failed|disk failure/u);
});

test('normative stream API requires its authenticated schema and frozen terminal semantics', () => {
  assert.throws(() => encodeStreamFrame(frames[0]), /authenticated protocol contract/u);
  assert.throws(() => parseCanonicalStream(Buffer.concat(frames.map((frame) => encodeStreamFrame(frame, { contract }))), { contract, terminalKinds: ['data'] }), /cannot be overridden/u);
  const missingVersion = { ...frames[0] };
  delete missingVersion.schemaVersion;
  assert.throws(() => encodeStreamFrame(missingVersion, { contract }), /protocol value|schema validation failed/u);
  assert.throws(() => encodeStreamFrame({ ...frames[0], kind: 'item' }, { contract }), /protocol value|schema validation failed/u);
});
