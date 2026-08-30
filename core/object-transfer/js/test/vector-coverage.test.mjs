import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  FAULT_DISPATCH,
  HOSTILE_DISPATCH,
  executeVectorSet,
} from './executable-vectors.mjs';

const CONTRACT = resolve(import.meta.dirname, '../../../../spec/object-transfer/v1/vectors');

test('every hostile vector is dispatched and its actual result matches the versioned expectation', async () => {
  const vectors = JSON.parse(await readFile(resolve(CONTRACT, 'hostile.json')));
  await executeVectorSet(vectors, HOSTILE_DISPATCH);
});

test('every fault vector is dispatched and its actual result matches the versioned expectation', async () => {
  const vectors = JSON.parse(await readFile(resolve(CONTRACT, 'faults.json')));
  await executeVectorSet(vectors, FAULT_DISPATCH);
});
