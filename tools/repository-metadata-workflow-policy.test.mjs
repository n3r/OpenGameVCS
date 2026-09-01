import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const workflowPath = new URL('../.github/workflows/repository-metadata.yml', import.meta.url);
const reportPath = new URL(
  '../server/modules/repository-metadata/scripts/service-report.mjs',
  import.meta.url,
);

test('repository metadata workflow pins the bounded three-host and PostgreSQL boundary', async () => {
  const workflow = await readFile(workflowPath, 'utf8');
  assert.match(workflow, /^name: Repository metadata bounded conformance$/mu);
  assert.match(workflow, /runner: macos-latest, label: macOS/u);
  assert.match(workflow, /runner: windows-latest, label: Windows/u);
  assert.match(workflow, /^  linux-postgres:$/mu);
  assert.doesNotMatch(workflow, /^    needs:/mu);
  assert.equal(workflow.match(/node-version: 24/gu)?.length, 2);
  assert.doesNotMatch(workflow, /node-version: (?:18|20|22)\b/u);
  assert.equal(
    workflow.match(/actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/gu)?.length,
    2,
  );
  assert.equal(
    workflow.match(/actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/gu)?.length,
    2,
  );
  assert.equal(
    workflow.match(/dtolnay\/rust-toolchain@7d11e79e1714f6b6da93cac39ad8435666f5c337/gu)?.length,
    2,
  );
  assert.match(
    workflow,
    /postgres@sha256:5d1d70e254e3c5d7d76847a9deebb18478cd518df37abf6b278d4bdb1fe5d96c/u,
  );
  assert.match(workflow, /ALTER SYSTEM SET max_connections = 160/u);
  assert.match(workflow, /ogvcs_metadata_test_ci/u);
  assert.equal(workflow.match(/cargo fetch .* --locked/gu)?.length, 2);
  assert.equal(workflow.match(/cargo test .* --locked --offline/gu)?.length, 4);
  assert.equal(workflow.match(/--features legacy-test-adapter/gu)?.length, 2);
  assert.equal(workflow.match(/npm run test:metadata$/gmu)?.length, 1);
  assert.equal(
    workflow.match(/npm run test:package --workspace @opengamevcs\/repository-metadata-contract-v1/gu)?.length,
    2,
  );
  assert.equal(workflow.match(/spec\/benchmark-fault\/v1\/\*\*/gu)?.length, 2);
  assert.equal(workflow.match(/spec\/object-transfer\/v1\/\*\*/gu)?.length, 2);
  assert.equal(workflow.match(/docs\/changelog\/OGVCS-006\.md/gu)?.length, 2);
  assert.equal(workflow.match(/server\/migrations\/identity-policy-audit\/\*\*/gu)?.length, 2);
  assert.equal(workflow.match(/server\/modules\/identity-policy-audit\/\*\*/gu)?.length, 2);
  assert.match(workflow, /cargo clippy .* --locked --offline --all-targets -- -D warnings/u);
  assert.match(workflow, /cargo clippy .* --all-targets --features legacy-test-adapter -- -D warnings/u);
  assert.match(workflow, /CARGO_NET_OFFLINE: 'true'/u);
  assert.match(
    workflow,
    /OGVCS_METADATA_IDENTITY_DATABASE_URL: postgresql:\/\/postgres:postgres@127\.0\.0\.1:5432\/ogvcs_metadata_test_ci/u,
  );
  assert.match(
    workflow,
    /cargo test .* --locked --offline --test identity_binding_live -- --test-threads=1/u,
  );
  assert.match(
    workflow,
    /- name: Run the bounded live PostgreSQL report\n        shell: bash\n/u,
  );
  assert.match(workflow, /repository-metadata-service-report\.jsonl/u);
  assert.doesNotMatch(workflow, /100.?GiB|1.?TiB|million-entry|exact.?scale/iu);
});

test('repository metadata report declares every bounded live row without claiming scale', () => {
  const result = spawnSync(process.execPath, [fileURLToPath(reportPath), '--check'], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.schemaVersion, 'ogvcs.repository-metadata/service-report/v1');
  assert.equal(report.exactScaleExecuted, false);
  assert.equal(report.status, 'declared');
  assert.equal(report.rows.length, 15);
  assert.equal(new Set(report.rows.map(({ id }) => id)).size, report.rows.length);
  assert.ok(report.rows.every(({ status }) => status === 'declared'));
  for (const id of [
    'migration-v1-v5-upgrade-preserves-unpublished-history',
    'project-repository-list-cursors',
    'bounded-ancestry-file-path-history',
    'outbox-lease-ack-release',
    'lifecycle-v9-atomic-publication',
  ]) {
    assert.ok(report.rows.some((row) => row.id === id), `missing bounded report row ${id}`);
  }
});
