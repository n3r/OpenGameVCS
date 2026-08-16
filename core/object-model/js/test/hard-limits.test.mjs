import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

import { evaluateHardLimit, HARD_LIMIT_NAMES } from '../src/hard-limits.js';
import { loadBundledRegistry } from '../src/registry.js';

const CONSTRUCTORS = resolve(import.meta.dirname,
  '../../../../spec/repository-format/v1/vectors/limits/virtual-constructors.json');

test('all 50 normative max/max+1 constructors execute through the hard-limit preflight', async () => {
  const document = JSON.parse(await readFile(CONSTRUCTORS, 'utf8'));
  const registry = await loadBundledRegistry();
  const seen = new Map();
  assert.equal(document.cases.length, 50);
  assert.equal(HARD_LIMIT_NAMES.length, 25);
  for (const item of document.cases) {
    assert.equal(item.algorithm.id, 'ogvcs.virtual-boundary-constructor');
    assert.equal(item.algorithm.version, 1);
    const result = evaluateHardLimit(registry, item.case, item.valueDecimal);
    assert.equal(result.name, item.case);
    assert.equal(result.valueDecimal, item.valueDecimal);
    assert.equal(result.accepted, item.expected.result === 'accept', `${item.case}/${item.variant}`);
    assert.equal(result.code, item.expected.code ?? null, `${item.case}/${item.variant}`);
    assert.equal(result.layer, item.expected.layer ?? item.expected.highestLayer, `${item.case}/${item.variant}`);
    assert.equal(result.stage, item.expected.stage ?? null, `${item.case}/${item.variant}`);
    const variants = seen.get(item.case) ?? new Set();
    variants.add(item.variant);
    seen.set(item.case, variants);
  }
  assert.deepEqual([...seen.keys()].sort(), [...HARD_LIMIT_NAMES].sort());
  for (const variants of seen.values()) {
    assert.deepEqual([...variants].sort(), ['maximum', 'maximum-plus-one']);
  }
});
