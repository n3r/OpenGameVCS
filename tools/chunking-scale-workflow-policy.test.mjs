import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { validateChunkingScaleDispatch } from './chunking-scale-dispatch-guard.mjs';

const boundedPath = new URL('../.github/workflows/chunking-manifest-bounded.yml', import.meta.url);
const scalePath = new URL('../.github/workflows/chunking-manifest-scale.yml', import.meta.url);
const javascriptRunnerPath = new URL('../core/chunking-manifest/js/scripts/run-scale.mjs', import.meta.url);
const rustRunnerPath = new URL('../core/chunking-manifest/rust/examples/run_scale.rs', import.meta.url);
const comparisonAdapterPath = new URL('./compare-chunking-scale.mjs', import.meta.url);
const boundedProofPath = new URL('./chunking-scale-bounded-proof.mjs', import.meta.url);
const packagePath = new URL('../package.json', import.meta.url);

test('exact 100-GiB work is isolated from ordinary and bounded checks', async () => {
  const [bounded, scale, javascriptRunner, rustRunner, manifest] = await Promise.all([
    readFile(boundedPath, 'utf8'),
    readFile(scalePath, 'utf8'),
    readFile(javascriptRunnerPath, 'utf8'),
    readFile(rustRunnerPath, 'utf8'),
    readFile(packagePath, 'utf8').then(JSON.parse),
  ]);

  const triggers = scale.slice(scale.indexOf('on:'), scale.indexOf('\npermissions:'));
  assert.match(triggers, /workflow_dispatch:/u);
  assert.match(triggers, /confirm_exact_scale:/u);
  assert.match(triggers, /type: boolean/u);
  assert.match(triggers, /default: false/u);
  assert.match(triggers, /expected_source_revision:\n\s+description:[^\n]+\n\s+required: true\n\s+type: string/u);
  assert.match(triggers, /push:\n\s+tags:\n\s+- ["']ogvcs-007-scale-\*["']/u);
  assert.doesNotMatch(triggers, /pull_request|schedule|branches/u);

  assert.doesNotMatch(bounded, /run-scale|run_scale|ogvcs-007-scale/u);
  for (const script of Object.values(manifest.scripts)) {
    assert.doesNotMatch(script, /scripts\/run-scale\.mjs|--example run_scale/u);
  }

  assert.match(javascriptRunner, /const LOGICAL_BYTES = 100 \* 1024 \* 1024 \* 1024;/u);
  assert.match(javascriptRunner, /const REPETITIONS = LOGICAL_BYTES \/ PATTERN_BYTES;/u);
  assert.match(javascriptRunner, /PATTERN_SHA256 = 'b4798e6f4c78cbeb0b69d6a83b60dfb1bb68196f8c7913dec1bf1bc6fa3921a4'/u);
  assert.match(javascriptRunner, /const PROCESS_WRITE_BYTES_MAXIMUM = 512 \* 1024 \* 1024;/u);
  assert.match(javascriptRunner, /const processWriteBytes = Number\(values\.get\('wchar'\)\);/u);
  assert.ok(javascriptRunner.indexOf('await rm(scratchRoot, { recursive: true });') < javascriptRunner.indexOf('const ioEnded = await processIo();'));
  assert.match(javascriptRunner, /processWriteBytes > PROCESS_WRITE_BYTES_MAXIMUM/u);
  assert.doesNotMatch(javascriptRunner, /process\.argv/u);
  assert.match(rustRunner, /const LOGICAL_BYTES: u64 = 100 \* 1024 \* 1024 \* 1024;/u);
  assert.match(rustRunner, /const REPETITIONS: u64 = LOGICAL_BYTES \/ PATTERN_BYTES as u64;/u);
  assert.match(rustRunner, /PATTERN_SHA256: &str = "b4798e6f4c78cbeb0b69d6a83b60dfb1bb68196f8c7913dec1bf1bc6fa3921a4"/u);
  assert.match(rustRunner, /const PROCESS_WRITE_BYTES_MAXIMUM: u64 = 512 \* 1024 \* 1024;/u);
  assert.match(rustRunner, /process_write_bytes: field\("wchar:"\)/u);
  const rustIoEnd = rustRunner.indexOf('let io_ended = process_io();');
  assert.ok(rustIoEnd > 0 && rustRunner.lastIndexOf('fs::remove_dir_all(&scratch_root.0)', rustIoEnd) > 0);
  assert.match(rustRunner, /process_write_bytes > PROCESS_WRITE_BYTES_MAXIMUM/u);
  assert.match(rustRunner, /"x86_64" => "x64"/u);
  assert.match(rustRunner, /"aarch64" => "arm64"/u);
  assert.match(rustRunner, /\.finish_to_manifest\(&mut manifest_sink\)/u);
  assert.match(rustRunner, /create_new\(true\)/u);
  assert.match(rustRunner, /manifest\.cbor\.partial/u);
  assert.match(rustRunner, /maximum_write_bytes > MANIFEST_EMIT_BYTES_MAXIMUM/u);
  assert.match(rustRunner, /MANIFEST_BYTES_MAXIMUM\.saturating_sub\(self\.bytes\)/u);
  assert.match(rustRunner, /sync_and_remove/u);
  assert.doesNotMatch(rustRunner, /result\.manifest\.bytes/u);
  assert.doesNotMatch(rustRunner, /let mut manifest(?:_bytes)? = Vec/u);
  assert.doesNotMatch(rustRunner, /env::args/u);
});

test('release-only workflow runs both implementations independently before comparison', async () => {
  const [scale, boundedProof] = await Promise.all([
    readFile(scalePath, 'utf8'),
    readFile(boundedProofPath, 'utf8'),
  ]);
  assert.match(scale, /^  exact_scale_preflight:/mu);
  assert.doesNotMatch(scale, /if: \$\{\{ github\.event_name == 'push' \|\| inputs\.confirm_exact_scale == true \}\}/u);
  assert.match(scale, /^  javascript-exact-scale:/mu);
  assert.match(scale, /^  rust-exact-scale:/mu);
  assert.match(scale, /^  compare-exact-scale:/mu);
  assert.equal(scale.match(/timeout-minutes: 360/gu)?.length, 2);
  assert.equal(scale.match(/needs: exact_scale_preflight/gu)?.length, 2);
  assert.match(scale, /needs:\n\s+- exact_scale_preflight\n\s+- javascript-exact-scale\n\s+- rust-exact-scale/u);
  assert.match(scale, /node-version: 24/u);
  assert.match(scale, /# 1\.82\.0/u);
  assert.match(scale, /node tools\/chunking-scale-dispatch-guard\.mjs/u);
  assert.match(scale, /permissions:\n  contents: read/u);
  assert.match(scale, /^  exact_scale_preflight:\n    name: Bind exact-scale dispatch to the reviewed source\n    permissions:\n      actions: read\n      contents: read$/mu);
  assert.equal(scale.match(/actions: read/gu)?.length, 1);
  assert.match(scale, /name: Require successful same-revision bounded conformance\n        env:\n          GITHUB_TOKEN: \$\{\{ github\.token \}\}\n          OGVCS_SOURCE_REVISION: \$\{\{ steps\.source\.outputs\.source_revision \}\}\n        run: node tools\/chunking-scale-bounded-proof\.mjs/u);
  assert.ok(scale.indexOf('node tools/chunking-scale-dispatch-guard.mjs')
    < scale.indexOf('node tools/chunking-scale-bounded-proof.mjs'));
  assert.equal(scale.match(/persist-credentials: false/gu)?.length, 4);
  assert.equal(scale.match(/ref: \$\{\{ needs\.exact_scale_preflight\.outputs\.source_revision \}\}/gu)?.length, 3);
  assert.equal(scale.match(/OGVCS_SOURCE_REVISION: \$\{\{ needs\.exact_scale_preflight\.outputs\.source_revision \}\}/gu)?.length, 2);
  assert.match(scale, /OGVCS_RUST_VERSION: 1\.82\.0/u);
  assert.match(scale, /node core\/chunking-manifest\/js\/scripts\/run-scale\.mjs/u);
  assert.match(scale, /--release --example run_scale/u);
  assert.match(scale, /node tools\/compare-chunking-scale\.mjs/u);
  assert.match(scale, /retention-days: 30/u);
  assert.equal(scale.match(/uses: actions\/upload-artifact@/gu)?.length, 3);

  assert.match(boundedProof, /actions\/workflows\/\$\{workflow\.id\}\/runs/u);
  assert.match(boundedProof, /\?head_sha=\$\{revision\}&status=completed/u);
  assert.match(boundedProof, /actions\/runs\/\$\{run\.id\}\/attempts\/\$\{run\.run_attempt\}\/jobs/u);
  assert.match(boundedProof, /\['JavaScript bounded \(Linux\)', 'ubuntu-latest'\]/u);
  assert.match(boundedProof, /\['Rust bounded \(Windows\)', 'windows-latest'\]/u);
  assert.match(boundedProof, /\['Cross-language and cross-OS parity', 'ubuntu-latest'\]/u);
  assert.match(boundedProof, /response\.body\?\.getReader\(\)/u);
  assert.match(boundedProof, /MAXIMUM_RESPONSE_BYTES - offset/u);
  assert.match(boundedProof, /await cancelReader\(reader\)/u);
  assert.doesNotMatch(boundedProof, /response\.text\(\)/u);
  assert.doesNotMatch(boundedProof, /method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/u);

  const mutableOfficialActions = [...scale.matchAll(/uses: actions\/[^@\s]+@([^\s#]+)/gu)]
    .map((match) => match[1])
    .filter((reference) => !/^[0-9a-f]{40}$/u.test(reference));
  assert.deepEqual(mutableOfficialActions, []);
});

test('dispatch guard accepts only an explicitly reviewed exact commit', () => {
  const reviewed = 'a'.repeat(40);
  const other = 'b'.repeat(40);
  const manual = {
    actualSourceRevision: reviewed,
    confirmed: 'true',
    eventName: 'workflow_dispatch',
    expectedSourceRevision: reviewed,
    refName: 'r1-foundation-integration',
    refType: 'branch',
  };
  const tag = {
    actualSourceRevision: reviewed,
    confirmed: '',
    eventName: 'push',
    expectedSourceRevision: '',
    refName: `ogvcs-007-scale-${reviewed}`,
    refType: 'tag',
  };
  assert.equal(validateChunkingScaleDispatch(manual), reviewed);
  assert.equal(validateChunkingScaleDispatch(tag), reviewed);

  for (const candidate of [
    { ...manual, confirmed: 'false' },
    { ...manual, expectedSourceRevision: other },
    { ...manual, expectedSourceRevision: reviewed.toUpperCase() },
    { ...manual, actualSourceRevision: other },
    { ...tag, refName: 'ogvcs-007-scale-release' },
    { ...tag, refName: `ogvcs-007-scale-${reviewed}-extra` },
    { ...tag, refName: `ogvcs-007-scale-${other}` },
    { ...tag, refType: 'branch' },
    { ...tag, eventName: 'pull_request' },
  ]) assert.throws(() => validateChunkingScaleDispatch(candidate), /chunking exact-scale dispatch rejected/u);
});

test('the protected raw-report command publishes current-source-bound retained JSON before comparison', async () => {
  const [scale, adapter, manifest] = await Promise.all([
    readFile(scalePath, 'utf8'),
    readFile(comparisonAdapterPath, 'utf8'),
    readFile(packagePath, 'utf8').then(JSON.parse),
  ]);
  assert.doesNotMatch(scale, /chunking-scale-evidence-bundle|verify-chunking-scale-evidence-bundle|--javascript-bundle|--rust-bundle/u);
  assert.match(scale, /node tools\/compare-chunking-scale\.mjs\s+--javascript artifacts\/javascript-scale\.json\s+--rust artifacts\/rust-scale\.json\s+--output artifacts\/scale-comparison\.json/u);
  assert.match(scale, /path: artifacts\/\*\.json/u);
  assert.match(adapter, /loadScaleReport\(options\.javascript, 'javascript'\)/u);
  assert.match(adapter, /buildChunkingScaleEvidenceBundle/u);
  assert.match(adapter, /writeChunkingScaleEvidenceBundle/u);
  assert.match(adapter, /verifyChunkingScaleEvidenceBundle/u);
  assert.match(adapter, /writeRetainedChunkingScalePublication/u);
  assert.match(adapter, /verifyRetainedChunkingScalePublication/u);
  assert.match(adapter, /\.publication\.json/u);
  assert.match(adapter, /writeChunkingScaleEvidenceValidation/u);
  assert.match(manifest.scripts['test:chunking:report'], /chunking-scale-evidence\.test\.mjs/u);
  assert.match(manifest.scripts['test:chunking:report'], /chunking-scale-bounded-proof\.test\.mjs/u);
  assert.doesNotMatch(manifest.scripts['test:chunking:report'], /scripts\/run-scale\.mjs|--example run_scale/u);
});
