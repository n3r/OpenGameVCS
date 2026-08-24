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

  const javascriptStart = scale.indexOf('\n  javascript-exact-scale:\n');
  const rustStart = scale.indexOf('\n  rust-exact-scale:\n');
  const comparisonStart = scale.indexOf('\n  compare-exact-scale:\n');
  assert.ok(javascriptStart > 0 && rustStart > javascriptStart && comparisonStart > rustStart);
  const javascript = scale.slice(javascriptStart, rustStart);
  const rust = scale.slice(rustStart, comparisonStart);
  const comparison = scale.slice(comparisonStart);

  assert.match(
    javascript,
    /\n  javascript-exact-scale:\n    if: \$\{\{ github\.event_name == 'push' \|\| inputs\.confirm_exact_scale == true \}\}/
  );
  assert.match(
    rust,
    /\n  rust-exact-scale:\n    if: \$\{\{ github\.event_name == 'push' \|\| inputs\.confirm_exact_scale == true \}\}/
  );
  assert.doesNotMatch(javascript, /\n    needs:/);
  assert.doesNotMatch(rust, /\n    needs:/);
  assert.match(javascript, /timeout-minutes: 120/);
  assert.match(rust, /timeout-minutes: 120/);
  assert.match(javascript, /node core\/object-model\/js\/scripts\/run-scale\.mjs/);
  assert.doesNotMatch(javascript, /release_scale_tree_and_one_tib_manifest/);
  assert.doesNotMatch(javascript, /rust-toolchain/);
  assert.doesNotMatch(javascript, /npm ci/);
  assert.match(rust, /release_scale_tree_and_one_tib_manifest/);
  assert.doesNotMatch(rust, /core\/object-model\/js\/scripts\/run-scale\.mjs/);
  assert.doesNotMatch(rust, /setup-node/);
  assert.match(
    rust,
    /OGVCS_SCALE_REPORT_PATH: \$\{\{ github\.workspace \}\}\/artifacts\/rust-scale\.json/
  );
  assert.match(javascript, /name: object-model-scale-javascript-Linux/);
  assert.match(rust, /name: object-model-scale-rust-Linux/);

  assert.match(
    comparison,
    /\n  compare-exact-scale:\n(?:    .+\n)+?    needs:\n      - javascript-exact-scale\n      - rust-exact-scale\n/
  );
  assert.match(comparison, /name: object-model-scale-javascript-Linux/);
  assert.match(comparison, /name: object-model-scale-rust-Linux/);
  assert.match(comparison, /tools\/compare-object-model-scale\.mjs/);
  assert.match(comparison, /name: object-model-scale-Linux/);
  assert.doesNotMatch(comparison, /release_scale_tree_and_one_tib_manifest/);
  assert.doesNotMatch(comparison, /core\/object-model\/js\/scripts\/run-scale\.mjs/);
});
