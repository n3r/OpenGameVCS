#!/usr/bin/env node
import { createHash, createHmac } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { hashObject } from '@opengamevcs/object-model';
import {
  ContentTransferPlanStore,
  CONTENT_TRANSFER_LIMITS,
  FilesystemObjectBackend,
} from '@opengamevcs/object-transfer';

const EXACT_LOGICAL_BYTES = 107_374_182_400;
const DEFAULT_CHUNK_BYTES = 8_388_608;

function fail(message) { throw new Error(`object-transfer-release-scale: ${message}`); }
function argument(name, fallback = null) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  if (index + 1 >= process.argv.length) fail(`${name} requires a value`);
  return process.argv[index + 1];
}
function integer(name, fallback, minimum, maximum) {
  const value = Number(argument(name, String(fallback)));
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(`${name} is invalid`);
  return value;
}
const sha = (value) => createHash('sha256').update(value).digest('hex');
const confirmation = argument('--confirm');
if (confirmation !== 'RUN-EXACT-100-GIB') fail('exact execution requires --confirm RUN-EXACT-100-GIB');
const root = resolve(argument('--root') ?? fail('--root is required'));
const output = resolve(argument('--output') ?? fail('--output is required'));
if (!isAbsolute(root) || !isAbsolute(output) || root === '/' || root === resolve('.')) fail('scale paths must be explicit absolute non-workspace paths');
const logicalBytes = integer('--logical-bytes', EXACT_LOGICAL_BYTES, EXACT_LOGICAL_BYTES, EXACT_LOGICAL_BYTES);
const chunkBytes = integer('--chunk-bytes', DEFAULT_CHUNK_BYTES, 1_048_576, CONTENT_TRANSFER_LIMITS.canonicalObjectBytesMaximum);
if (logicalBytes % chunkBytes !== 0) fail('logical bytes must divide exactly into fixed chunks');
const interruptEvery = integer('--interrupt-every', 257, 1, 100_000);
const minimumMiBPerSecond = integer('--minimum-mibps', 25, 1, 10_000);
const maximumRssMiB = integer('--maximum-rss-mib', 512, 64, 16_384);
const chunkCount = logicalBytes / chunkBytes;
if (chunkCount > CONTENT_TRANSFER_LIMITS.chunksMaximum) fail('chunk count exceeds the content-plan bound');

await mkdir(root, { recursive: false });
await mkdir(resolve(output, '..'), { recursive: true });
const planRoot = join(root, 'plan-state');
const backendRoot = join(root, 'backend-state');
const planSecret = Buffer.alloc(32, 0x73);
const tenantScopeSha256 = sha('ogvcs-release-scale-tenant');
const grantBindingSha256 = sha('ogvcs-release-scale-grant');
const requestRoot = `sha256:${sha('ogvcs-release-scale-request')}`;
let peakRss = process.memoryUsage().rss;
const sampleMemory = () => { peakRss = Math.max(peakRss, process.memoryUsage().rss); };
const payload = (index) => {
  const bytes = Buffer.alloc(chunkBytes, index % 251);
  bytes.writeBigUInt64BE(BigInt(index), 0);
  return bytes;
};
const opaqueKey = (objectId) => createHmac('sha256', planSecret)
  .update('OGVCS-RELEASE-SCALE-OPAQUE-KEY-V1\0').update(objectId).digest('hex');

const whole = createHash('sha256');
const hashStarted = performance.now();
for (let index = 0; index < chunkCount; index += 1) {
  whole.update(payload(index));
  sampleMemory();
}
const wholeFileSha256 = whole.digest('hex');
const hashSeconds = (performance.now() - hashStarted) / 1000;

let plans = await new ContentTransferPlanStore({ root: planRoot, planSecret }).initialize();
const manifest = await plans.createPlan({
  tenantScopeSha256,
  grantBindingSha256,
  requestRoot,
  logicalLength: logicalBytes,
  wholeFileSha256,
  chunks: (async function* () {
    for (let index = 0; index < chunkCount; index += 1) {
      const bytes = payload(index);
      yield { index, objectId: hashObject(1, bytes).toString(), length: bytes.length, sha256: sha(bytes) };
      sampleMemory();
    }
  })(),
});

let backend = await new FilesystemObjectBackend({ root: backendRoot }).initialize();
let interruptions = 0;
let createReplays = 0;
const uploadStarted = performance.now();
for (let page = 0; page < manifest.pageCount; page += 1) {
  const pending = await plans.nextPending({ planId: manifest.planId, page });
  for (const item of pending.pending) {
    const bytes = payload(item.index);
    const key = opaqueKey(item.objectId);
    let durable = await backend.createIfAbsent({ opaqueKey: key, objectId: item.objectId, length: item.length, source: bytes });
    if ((item.index + 1) % interruptEvery === 0) {
      interruptions += 1;
      backend = await new FilesystemObjectBackend({ root: backendRoot }).initialize();
      plans = await new ContentTransferPlanStore({ root: planRoot, planSecret }).initialize();
      durable = await backend.createIfAbsent({ opaqueKey: key, objectId: item.objectId, length: item.length, source: bytes });
      if (durable.created) fail('interrupted durable part was retransmitted into a second object');
      createReplays += 1;
    }
    await plans.recordVerified({
      planId: manifest.planId,
      ...item,
      receiptSha256: durable.receiptSha256,
    });
    sampleMemory();
  }
}
const uploadSeconds = (performance.now() - uploadStarted) / 1000;
const status = await plans.status(manifest.planId);
if (!status.complete) fail('durable ledger is incomplete after upload');

const reconstructionStarted = performance.now();
const reconstruction = await plans.reconstruct({
  planId: manifest.planId,
  readVerifiedChunk: async (item) => {
    const range = await backend.readVerifiedRange(opaqueKey(item.objectId), 0, item.length);
    return range.bytes;
  },
  write: async () => { sampleMemory(); },
});
const reconstructionSeconds = (performance.now() - reconstructionStarted) / 1000;
const mib = logicalBytes / 1_048_576;
const result = {
  schemaVersion: 'ogvcs.object-transfer/release-scale-result/v1',
  exact: true,
  logicalBytes,
  chunkBytes,
  chunkCount,
  pageCount: manifest.pageCount,
  wholeFileSha256,
  reconstructedWholeFileSha256: reconstruction.wholeFileSha256,
  interruptions,
  createReplays,
  verifiedChunks: status.verifiedChunks,
  hashSeconds,
  uploadSeconds,
  reconstructionSeconds,
  uploadMiBPerSecond: mib / uploadSeconds,
  reconstructionMiBPerSecond: mib / reconstructionSeconds,
  peakRssBytes: peakRss,
  minimumMiBPerSecond,
  maximumRssBytes: maximumRssMiB * 1_048_576,
  node: process.version,
  platform: `${process.platform}-${process.arch}`,
};
await writeFile(output, `${JSON.stringify(result)}\n`, { flag: 'wx', mode: 0o600 });
if (result.reconstructedWholeFileSha256 !== wholeFileSha256) fail('whole-file hash differs after reconstruction');
if (result.uploadMiBPerSecond < minimumMiBPerSecond || result.reconstructionMiBPerSecond < minimumMiBPerSecond) fail('reference throughput threshold was not met');
if (peakRss > result.maximumRssBytes) fail('reference memory threshold was exceeded');
process.stdout.write(`${JSON.stringify({ output, ...result })}\n`);
