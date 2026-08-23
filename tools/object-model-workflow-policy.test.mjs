import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const ordinaryPath = new URL('../.github/workflows/object-model.yml', import.meta.url);
const scalePath = new URL('../.github/workflows/object-model-scale.yml', import.meta.url);

test('exact object-model scale is isolated from ordinary pull-request and branch CI', async () => {
  const [ordinary, scale] = await Promise.all([
    readFile(ordinaryPath, 'utf8'),
    readFile(scalePath, 'utf8')
  ]);

  assert.match(ordinary, /\n  pull_request:\n/);
  assert.match(ordinary, /\n  push:\n    branches:\n/);
  assert.doesNotMatch(ordinary, /run-scale\.mjs/);
  assert.doesNotMatch(ordinary, /release_scale_tree_and_one_tib_manifest/);
  assert.doesNotMatch(ordinary, /ogvcs-002-scale-/);
  assert.doesNotMatch(ordinary, /run_scale/);

  const triggerEnd = scale.indexOf('\npermissions:');
  assert.notEqual(triggerEnd, -1);
  const triggers = scale.slice(0, triggerEnd);
  assert.match(
    triggers,
    /\n  workflow_dispatch:\n    inputs:\n      confirm_exact_scale:\n(?:        .+\n)+?        required: true\n        type: boolean\n        default: false\n/
  );
  assert.match(triggers, /\n  push:\n    tags:\n      - "ogvcs-002-scale-\*"\n/);
  assert.doesNotMatch(triggers, /pull_request:/);
  assert.doesNotMatch(triggers, /schedule:/);
  assert.doesNotMatch(triggers, /branches:/);

  assert.match(scale, /cancel-in-progress: false/);
  assert.doesNotMatch(scale, /\n    needs:/);
  assert.match(
    scale,
    /\n  exact-scale:\n    if: \$\{\{ github\.event_name == 'push' \|\| inputs\.confirm_exact_scale == true \}\}/
  );
  assert.match(scale, /node core\/object-model\/js\/scripts\/run-scale\.mjs/);
  assert.match(scale, /release_scale_tree_and_one_tib_manifest/);
  assert.match(scale, /tools\/compare-object-model-scale\.mjs/);
});
