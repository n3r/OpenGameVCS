import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { TransferEventStore } from '../src/events.mjs';
import { DurableQuotaLedger } from '../src/quota-ledger.mjs';
import { BoundedTransferTelemetry } from '../src/telemetry.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');

test('durable unique-byte reservations survive crash/replay and remain tenant-isolated', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-durable-quota-'));
  const tenant = sha('tenant');
  const otherTenant = sha('other-tenant');
  const firstKey = sha('first-key');
  const secondKey = sha('second-key');
  let fail = true;
  let ledger = await new DurableQuotaLedger({
    root,
    maximumBytes: 10,
    now: () => 1_800_000_000_000,
    fault: async (phase) => { if (fail && phase === 'after-durable-quota-reserve') throw new Error('simulated response loss'); },
  }).initialize();
  await assert.rejects(() => ledger.reserve({ tenantScopeSha256: tenant, opaqueKey: firstKey, length: 7 }), /simulated response loss/u);
  fail = false;
  ledger = await new DurableQuotaLedger({ root, maximumBytes: 10, now: () => 1_800_000_000_001 }).initialize();
  assert.equal((await ledger.reserve({ tenantScopeSha256: tenant, opaqueKey: firstKey, length: 7 })).replay, true);
  assert.equal((await ledger.commit({ tenantScopeSha256: tenant, opaqueKey: firstKey, length: 7, backendReceiptSha256: sha('receipt') })).replay, false);
  assert.equal((await ledger.commit({ tenantScopeSha256: tenant, opaqueKey: firstKey, length: 7, backendReceiptSha256: sha('receipt') })).replay, true);
  await assert.rejects(() => ledger.reserve({ tenantScopeSha256: tenant, opaqueKey: secondKey, length: 4 }), { code: 'TRANSFER_LIMIT_EXCEEDED' });
  await ledger.reserve({ tenantScopeSha256: otherTenant, opaqueKey: secondKey, length: 4 });
  assert.deepEqual(await ledger.usage(tenant), { reservedBytes: 0, durableBytes: 7, totalBytes: 7, records: 2 });
  assert.equal((await ledger.release({ tenantScopeSha256: tenant, opaqueKey: firstKey, backendReceiptSha256: sha('receipt') })).replay, false);
  assert.equal((await ledger.release({ tenantScopeSha256: tenant, opaqueKey: firstKey, backendReceiptSha256: sha('receipt') })).replay, true);
  assert.equal((await ledger.usage(tenant)).totalBytes, 0);

  const boundedRoot = await mkdtemp(join(tmpdir(), 'ogvcs-durable-quota-bound-'));
  const bounded = await new DurableQuotaLedger({
    root: boundedRoot,
    maximumBytes: 10,
    maximumRecords: 1,
  }).initialize();
  const raced = await Promise.allSettled([
    bounded.reserve({ tenantScopeSha256: tenant, opaqueKey: firstKey, length: 1 }),
    bounded.reserve({ tenantScopeSha256: otherTenant, opaqueKey: secondKey, length: 1 }),
  ]);
  assert.equal(raced.filter(({ status }) => status === 'fulfilled').length, 1);
  assert.equal(raced.filter(({ status, reason }) => status === 'rejected'
    && reason.code === 'TRANSFER_LIMIT_EXCEEDED').length, 1);
});

test('internal events are durable/idempotent and integrity events contain no object identity or path', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-events-'));
  let now = 10;
  const events = await new TransferEventStore({ root, now: () => now, maximumRecords: 2 }).initialize();
  const input = {
    tenantScopeSha256: sha('tenant'),
    objectId: `ogvcs:v1:chunk:sha256:${sha('object')}`,
    generation: 2,
    backendReceiptSha256: sha('receipt'),
  };
  const first = await events.contentAvailable(input);
  now = 20;
  const replay = await events.contentAvailable(input);
  assert.equal(replay.replay, true);
  assert.equal(replay.eventId, first.eventId);
  assert.equal(replay.occurredAtUnixMs, 10);
  const integrity = await events.integrityFailure({
    tenantScopeSha256: input.tenantScopeSha256,
    backendKind: 's3-compatible',
    operation: 'download-range',
  });
  const serialized = JSON.stringify(integrity);
  assert.equal(serialized.includes('objectId'), false);
  assert.equal(serialized.includes(input.objectId), false);
  assert.equal((await events.listBounded(2)).length, 2);
  await assert.rejects(() => events.listBounded(1), { code: 'TRANSFER_LIMIT_EXCEEDED' });
  await assert.rejects(() => events.integrityFailure({
    tenantScopeSha256: input.tenantScopeSha256,
    backendKind: 's3-compatible',
    operation: 'finalize-upload',
  }), { code: 'TRANSFER_LIMIT_EXCEEDED' });
  assert.equal((await events.contentAvailable(input)).replay, true);
});

test('telemetry aggregates only bounded privacy-safe labels and all transfer dimensions', () => {
  const telemetry = new BoundedTransferTelemetry({ seriesMaximum: 2 });
  telemetry.observe({ operation: 'download-range', backend: 's3-compatible', outcome: 'retry', quota: 'transfer-bytes', integrity: 'none', bytes: 8, durationMs: 3, retries: 1, resume: 1, parts: 2 });
  telemetry.observe({ operation: 'download-range', backend: 's3-compatible', outcome: 'retry', quota: 'transfer-bytes', integrity: 'none', bytes: 5, durationMs: 2, retries: 1, resume: 0, parts: 1 });
  const [series] = telemetry.snapshot();
  assert.deepEqual(series, {
    operation: 'download-range', backend: 's3-compatible', outcome: 'retry', quota: 'transfer-bytes', integrity: 'none',
    observations: 2, bytes: 13, durationMs: 5, retries: 2, resumes: 1, parts: 3,
  });
  assert.throws(() => telemetry.observe({
    operation: 'download-range', backend: 'service', outcome: 'success', quota: 'none', integrity: 'verified',
    bytes: 1, durationMs: 1, retries: 0, resume: 0, parts: 1, objectId: 'forbidden-label',
  }), { code: 'TRANSFER_INPUT_INVALID' });
});
