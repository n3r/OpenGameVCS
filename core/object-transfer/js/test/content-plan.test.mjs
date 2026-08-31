import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { hashObject } from '@opengamevcs/object-model';
import { ContentTransferPlanStore, CONTENT_TRANSFER_LIMITS } from '../src/content-plan.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const secret = Buffer.alloc(32, 0x4f);
const tenantScopeSha256 = sha('tenant-scope');
const grantBindingSha256 = sha('grant-binding');
const requestRoot = `sha256:${sha('request-root')}`;

async function store(root) {
  return new ContentTransferPlanStore({ root, planSecret: secret, now: () => 1_800_000_000_000 }).initialize();
}

function chunk(bytes, index) {
  return Object.freeze({ index, objectId: hashObject(1, bytes).toString(), length: bytes.length, sha256: sha(bytes) });
}

async function* chunksOf(values) { for (const value of values) yield value; }

test('a paged durable ledger resumes verified chunks and reconstructs with whole-file verification', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-content-plan-'));
  const pieces = [Buffer.from('first-'), Buffer.from('second-'), Buffer.from('last')];
  const whole = Buffer.concat(pieces);
  let plans = await store(root);
  const manifest = await plans.createPlan({
    tenantScopeSha256,
    grantBindingSha256,
    requestRoot,
    logicalLength: whole.length,
    wholeFileSha256: sha(whole),
    chunks: chunksOf(pieces.map(chunk)),
  });
  assert.equal(manifest.chunkCount, 3);
  const first = pieces.map(chunk)[0];
  const recorded = await plans.recordVerified({
    planId: manifest.planId,
    ...first,
    receiptSha256: sha('receipt-0'),
  });
  assert.equal(recorded.replay, false);
  assert.equal((await plans.recordVerified({ planId: manifest.planId, ...first, receiptSha256: sha('receipt-0') })).replay, true);
  plans = await store(root);
  const pending = await plans.nextPending({ planId: manifest.planId });
  assert.deepEqual(pending.pending.map(({ index }) => index), [1, 2]);
  const pagedPending = await plans.nextPending({ planId: manifest.planId, maximum: 1 });
  assert.deepEqual(pagedPending.pending.map(({ index }) => index), [1]);
  assert.equal(pagedPending.nextPage, 0);
  assert.equal(pagedPending.complete, false);
  for (const item of pieces.map(chunk).slice(1)) {
    await plans.recordVerified({ planId: manifest.planId, ...item, receiptSha256: sha(`receipt-${item.index}`) });
  }
  assert.equal((await plans.status(manifest.planId)).complete, true);
  const output = [];
  const receipt = await plans.reconstruct({
    planId: manifest.planId,
    readVerifiedChunk: async ({ index }) => pieces[index],
    write: async (bytes) => output.push(Buffer.from(bytes)),
  });
  assert.equal(Buffer.concat(output).equals(whole), true);
  assert.equal(receipt.wholeFileSha256, sha(whole));
});

test('the exact 100-GiB logical plan is paged without lifting the 64-MiB object bound', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-content-plan-100gib-'));
  const plans = await store(root);
  const count = CONTENT_TRANSFER_LIMITS.logicalBytesMaximum / CONTENT_TRANSFER_LIMITS.canonicalObjectBytesMaximum;
  assert.equal(count, 1600);
  let yielded = 0;
  const chunks = (async function* () {
    for (let index = 0; index < count; index += 1) {
      yielded += 1;
      yield {
        index,
        objectId: `ogvcs:v1:chunk:sha256:${sha(`logical-chunk-${index}`)}`,
        length: CONTENT_TRANSFER_LIMITS.canonicalObjectBytesMaximum,
        sha256: sha(`logical-payload-${index}`),
      };
    }
  })();
  const manifest = await plans.createPlan({
    tenantScopeSha256,
    grantBindingSha256,
    requestRoot,
    logicalLength: CONTENT_TRANSFER_LIMITS.logicalBytesMaximum,
    wholeFileSha256: sha('manual-exact-scale-placeholder-until-bytes-run'),
    chunks,
  });
  assert.equal(yielded, 1600);
  assert.equal(manifest.pageCount, 7);
  assert.equal(manifest.pages.every(({ count: pageCount }) => pageCount <= 256), true);
  assert.equal((await plans.status(manifest.planId)).pendingChunks, 1600);
  await assert.rejects(() => plans.createPlan({
    tenantScopeSha256,
    grantBindingSha256,
    requestRoot,
    logicalLength: CONTENT_TRANSFER_LIMITS.logicalBytesMaximum + 1,
    wholeFileSha256: sha('too-large'),
    chunks: chunksOf([]),
  }), { code: 'TRANSFER_INPUT_INVALID' });
});

test('plan descriptor/ledger tampering, duplicate indexes, and +1 chunk bounds fail closed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-content-plan-hostile-'));
  const plans = await store(root);
  const bytes = Buffer.from('bounded');
  await assert.rejects(() => plans.createPlan({
    tenantScopeSha256,
    grantBindingSha256,
    requestRoot,
    logicalLength: bytes.length * 2,
    wholeFileSha256: sha(Buffer.concat([bytes, bytes])),
    chunks: chunksOf([chunk(bytes, 0), chunk(bytes, 0)]),
  }), { code: 'TRANSFER_INPUT_INVALID' });
  const manifest = await plans.createPlan({
    tenantScopeSha256,
    grantBindingSha256: sha('separate-plan'),
    requestRoot,
    logicalLength: bytes.length,
    wholeFileSha256: sha(bytes),
    chunks: chunksOf([chunk(bytes, 0)]),
  });
  const pagePath = join(root, 'plans', manifest.planId, 'page-000000.json');
  const page = JSON.parse(await readFile(pagePath));
  page.chunks[0].sha256 = sha('tampered');
  await writeFile(pagePath, canonical(page));
  await assert.rejects(() => plans.nextPending({ planId: manifest.planId }), { code: 'TRANSFER_BACKEND_CORRUPT' });
  const tooLarge = { ...chunk(bytes, 0), length: CONTENT_TRANSFER_LIMITS.canonicalObjectBytesMaximum + 1 };
  await assert.rejects(() => plans.createPlan({
    tenantScopeSha256,
    grantBindingSha256: sha('plus-one-plan'),
    requestRoot,
    logicalLength: tooLarge.length,
    wholeFileSha256: sha('plus-one'),
    chunks: chunksOf([tooLarge]),
  }), { code: 'TRANSFER_INPUT_INVALID' });
});

function canonical(value) {
  const render = (input) => input === null || typeof input === 'boolean' || typeof input === 'string' || Number.isSafeInteger(input)
    ? JSON.stringify(input) : Array.isArray(input) ? `[${input.map(render).join(',')}]`
      : `{${Object.keys(input).sort().map((key) => `${JSON.stringify(key)}:${render(input[key])}`).join(',')}}`;
  return Buffer.from(render(value));
}
