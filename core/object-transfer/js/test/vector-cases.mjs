import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '../../../../spec/object-transfer/v1/vectors');
const hostile = JSON.parse(await readFile(resolve(ROOT, 'hostile.json'))).cases;
const faults = JSON.parse(await readFile(resolve(ROOT, 'faults.json'))).cases;

function selected(cases, id, kind) {
  const value = cases.find((entry) => entry.id === id);
  if (!value) throw new Error(`missing executable ${kind} vector ${id}`);
  return value;
}

export const hostileCase = (id) => selected(hostile, id, 'hostile');
export const faultCase = (id) => selected(faults, id, 'fault');
