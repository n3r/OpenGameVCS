import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  ERROR_STAGE_ORDER, OgvcsError, compareErrorPrecedence, errorSites
} from '../src/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ERRORS = resolve(HERE, '../../../../spec/repository-format/v1/errors.json');

async function authority() {
  return JSON.parse(await readFile(ERRORS, 'utf8'));
}

function key(code, layer, stage) { return `${code}\0${layer}\0${stage}`; }

test('public JS diagnostic authority exactly matches all frozen sites', async () => {
  const catalogue = await authority();
  assert.deepEqual(ERROR_STAGE_ORDER, catalogue.precedence.stageOrder);
  assert.equal(catalogue.errors.length, 81);

  const expected = [];
  const actual = [];
  for (const entry of catalogue.errors) {
    for (const site of entry.sites) {
      for (const layer of site.layers) expected.push(key(entry.code, layer, site.stage));
    }
    for (const site of errorSites(entry.code)) {
      actual.push(key(entry.code, site.layer, site.stage));
      const error = new OgvcsError(entry.code, site);
      assert.equal(error.code, entry.code);
      assert.equal(error.layer, site.layer);
      assert.equal(error.stage, site.stage);
    }
  }
  assert.equal(expected.length, 94);
  assert.deepEqual(actual.sort(), expected.sort());

  const byPair = new Map();
  for (const entry of catalogue.errors) for (const site of entry.sites) for (const layer of site.layers) {
    const pair = `${entry.code}\0${layer}`;
    byPair.set(pair, [...(byPair.get(pair) ?? []), site.stage]);
  }
  for (const [pair, stages] of byPair) {
    const [code, layerText] = pair.split('\0');
    const layer = Number(layerText);
    if (stages.length === 1) assert.equal(new OgvcsError(code, { layer }).stage, stages[0], pair);
    else assert.throws(() => new OgvcsError(code, { layer }), TypeError, pair);
  }
});

test('mixed-stage selection uses layer, frozen stage, then catalogue order', () => {
  const configured = new OgvcsError('BUNDLE_BUDGET_EXCEEDED', {
    layer: 1, stage: 'configured-resource-preflight'
  });
  const framing = new OgvcsError('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'canonical-framing', offset: 0
  });
  const sequence = new OgvcsError('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  const known = new OgvcsError('SCHEMA_FIELD_UNKNOWN', { layer: 2 });
  assert.deepEqual([known, sequence, framing, configured].sort(compareErrorPrecedence),
    [configured, framing, sequence, known]);
  assert.throws(() => new OgvcsError('BUNDLE_ROOT_INVALID', {
    layer: 2, stage: 'repository-semantics'
  }), TypeError);
});
