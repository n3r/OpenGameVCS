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
const restartSupervisorPath = new URL(
  '../server/modules/repository-metadata/scripts/atomic-submit-restart-matrix.mjs',
  import.meta.url,
);
const atomicSubmitPath = new URL(
  '../server/modules/repository-metadata/src/postgres/atomic_submit.rs',
  import.meta.url,
);
const aggregateLiveTestPath = new URL(
  '../server/modules/repository-metadata/tests/aggregate_bridge_postgres_live.rs',
  import.meta.url,
);

test('repository metadata workflow pins the bounded three-host and PostgreSQL boundary', async () => {
  const workflow = await readFile(workflowPath, 'utf8');
  assert.match(workflow, /^name: Repository metadata bounded conformance$/mu);
  assert.match(workflow, /branches: \[main, r1-foundation-integration\]/u);
  assert.match(workflow, /runner: macos-latest, label: macOS/u);
  assert.match(workflow, /runner: windows-latest, label: Windows/u);
  assert.match(workflow, /^  linux-postgres:$/mu);
  assert.doesNotMatch(workflow, /^    needs:/mu);
  assert.equal(workflow.match(/node-version: 24/gu)?.length, 3);
  assert.doesNotMatch(workflow, /node-version: (?:18|20|22)\b/u);
  assert.equal(
    workflow.match(/actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/gu)?.length,
    3,
  );
  assert.equal(workflow.match(/persist-credentials: false/gu)?.length, 3);
  assert.equal(
    workflow.match(/actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/gu)?.length,
    3,
  );
  assert.equal(
    workflow.match(/dtolnay\/rust-toolchain@7d11e79e1714f6b6da93cac39ad8435666f5c337/gu)?.length,
    3,
  );
  assert.equal(
    workflow.match(/postgres@sha256:5d1d70e254e3c5d7d76847a9deebb18478cd518df37abf6b278d4bdb1fe5d96c/gu)?.length,
    2,
  );
  assert.match(workflow, /ALTER SYSTEM SET max_connections = 160/u);
  assert.match(workflow, /ogvcs_metadata_test_ci/u);
  assert.equal(workflow.match(/cargo fetch .* --locked/gu)?.length, 3);
  assert.equal(workflow.match(/cargo test .* --locked --offline/gu)?.length, 7);
  assert.equal(workflow.match(/--features legacy-test-adapter/gu)?.length, 5);
  assert.equal(workflow.match(/npm run test:metadata$/gmu)?.length, 1);
  assert.equal(
    workflow.match(/npm run test:package --workspace @opengamevcs\/repository-metadata-contract-v1/gu)?.length,
    2,
  );
  assert.equal(workflow.match(/spec\/benchmark-fault\/v1\/\*\*/gu)?.length, 2);
  assert.equal(workflow.match(/spec\/object-transfer\/v1\/\*\*/gu)?.length, 2);
  assert.equal(workflow.match(/docs\/changelog\/OGVCS-006\.md/gu)?.length, 2);
  assert.equal(workflow.match(/docs\/changelog\/OGVCS-008\.md/gu)?.length, 2);
  assert.equal(workflow.match(/docs\/evidence\/OGVCS-006\/\*\*/gu)?.length, 2);
  assert.equal(workflow.match(/docs\/evidence\/OGVCS-008\/\*\*/gu)?.length, 2);
  assert.equal(
    workflow.match(/docs\/reviews\/OGVCS-006-public-metadata-surface-audit\.md/gu)?.length,
    2,
  );
  assert.equal(
    workflow.match(/docs\/reviews\/OGVCS-008-content-manifest-production-acceptor-review\.md/gu)?.length,
    2,
  );
  assert.equal(
    workflow.match(/prd\/todo\/OGVCS-006-repository-metadata-snapshot-service\.md/gu)?.length,
    2,
  );
  assert.equal(
    workflow.match(/prd\/todo\/OGVCS-008-object-storage-transfer-service\.md/gu)?.length,
    2,
  );
  assert.equal(workflow.match(/tools\/atomic-submit-retained-evidence\.test\.mjs/gu)?.length, 2);
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
    /docker exec "\$\{\{ job\.services\.postgres\.id \}\}" createdb -U postgres ogvcs_metadata_dispatch_ci/u,
  );
  assert.match(
    workflow,
    /OGVCS_METADATA_DISPATCH_DATABASE_URL: postgresql:\/\/postgres:postgres@127\.0\.0\.1:5432\/ogvcs_metadata_dispatch_ci/u,
  );
  assert.match(
    workflow,
    /cargo test .* --locked --offline --test metadata_dispatcher_live -- --test-threads=1/u,
  );
  assert.match(
    workflow,
    /cargo test .* --locked --offline --test identity_binding_live -- --test-threads=1/u,
  );
  assert.match(
    workflow,
    /OGVCS_METADATA_AGGREGATE_DATABASE_URL: postgresql:\/\/postgres:postgres@127\.0\.0\.1:5432\/ogvcs_metadata_test_ci/u,
  );
  assert.match(
    workflow,
    /cargo test .* --locked --offline --features legacy-test-adapter --test aggregate_bridge_postgres_live -- --test-threads=1/u,
  );
  assert.match(
    workflow,
    /docker exec "\$\{\{ job\.services\.postgres\.id \}\}" createdb -U postgres ogvcs_metadata_test_transfer_ci/u,
  );
  assert.match(
    workflow,
    /OGVCS_METADATA_OBJECT_TRANSFER_DATABASE_URL: postgresql:\/\/postgres:postgres@127\.0\.0\.1:5432\/ogvcs_metadata_test_transfer_ci/u,
  );
  assert.match(
    workflow,
    /cargo test .* --locked --offline --features legacy-test-adapter --test content_manifest_transfer_postgres_live -- --test-threads=1/u,
  );
  assert.match(
    workflow,
    /- name: Run the bounded live PostgreSQL report\n        shell: bash\n/u,
  );
  assert.match(workflow, /repository-metadata-service-report\.jsonl/u);
  assert.match(
    workflow,
    /run: node prd\/validate-roadmap\.mjs && node --test prd\/validate-roadmap\.test\.mjs/u,
  );
  assert.match(workflow, /^  postgres-hard-restart:$/mu);
  assert.match(workflow, /timeout-minutes: 35/u);
  assert.match(
    workflow,
    /OGVCS_METADATA_RESTART_POSTGRES_CONTAINER: \$\{\{ job\.services\.postgres\.id \}\}/u,
  );
  assert.match(
    workflow,
    /OGVCS_METADATA_RESTART_DATABASE_URL_PREFIX: postgresql:\/\/postgres:postgres@127\.0\.0\.1:5432\//u,
  );
  assert.match(
    workflow,
    /OGVCS_METADATA_RESTART_CONFIRM_DISPOSABLE: hard-kill-postgres-13-times/u,
  );
  assert.match(workflow, /atomic-submit-restart-matrix\.mjs/u);
  assert.match(workflow, /repository-metadata-atomic-submit-restart\.jsonl/u);
  assert.doesNotMatch(workflow, /100.?GiB|1.?TiB|million-entry|exact.?scale/iu);
});

test('atomic submit restart supervisor is bounded, pinned, serial, and identity-changing', async () => {
  const declarationResult = spawnSync(
    process.execPath,
    [fileURLToPath(restartSupervisorPath), '--check'],
    { encoding: 'utf8' },
  );
  assert.equal(declarationResult.status, 0, declarationResult.stderr);
  const declaration = JSON.parse(declarationResult.stdout);
  assert.equal(
    declaration.schemaVersion,
    'ogvcs.repository-metadata/restart-matrix-declaration/v1',
  );
  assert.equal(declaration.maximumCases, 13);
  assert.equal(declaration.maximumParallelApplicationClients, 1);
  assert.equal(declaration.signal, 'SIGKILL');
  assert.equal(declaration.retainsLocalEvidence, false);
  assert.equal(declaration.containerIdFormat, '64-lowercase-hex');
  assert.equal(declaration.disposableConfirmation, 'hard-kill-postgres-13-times');
  assert.deepEqual(declaration.requiredInitialDatabases, [
    'postgres', 'template0', 'template1',
  ]);
  assert.deepEqual(declaration.boundaries, [
    'before-bridge',
    'after-bridge',
    'after-file-id-consumption',
    'after-snapshot-marker',
    'after-branch-cas',
    'after-audit',
    'after-outbox-event',
    'after-consistency-token',
    'after-final-outcome',
    'after-reconciliation',
    'before-commit',
    'commit-io',
    'after-commit-before-response',
  ]);
  assert.equal(
    declaration.pinnedPostgresImage,
    'postgres@sha256:5d1d70e254e3c5d7d76847a9deebb18478cd518df37abf6b278d4bdb1fe5d96c',
  );
  assert.deepEqual(declaration.expectedInitialState, Object.fromEntries(
    declaration.boundaries.map((boundary) => [
      boundary,
      boundary === 'commit-io'
        ? 'old-or-new'
        : boundary === 'after-commit-before-response' ? 'new' : 'old',
    ]),
  ));

  const shortContainer = spawnSync(process.execPath, [fileURLToPath(restartSupervisorPath)], {
    encoding: 'utf8',
    env: {
      ...process.env,
      OGVCS_METADATA_RESTART_POSTGRES_CONTAINER: 'a'.repeat(12),
      OGVCS_METADATA_RESTART_CONFIRM_DISPOSABLE: 'hard-kill-postgres-13-times',
      OGVCS_METADATA_RESTART_DATABASE_URL_PREFIX:
        'postgresql://postgres:postgres@127.0.0.1:5432/',
    },
  });
  assert.notEqual(shortContainer.status, 0);
  assert.match(shortContainer.stderr, /container ID is not exact/u);

  const alternateUrl = spawnSync(process.execPath, [fileURLToPath(restartSupervisorPath)], {
    encoding: 'utf8',
    env: {
      ...process.env,
      OGVCS_METADATA_RESTART_POSTGRES_CONTAINER: 'a'.repeat(64),
      OGVCS_METADATA_RESTART_CONFIRM_DISPOSABLE: 'hard-kill-postgres-13-times',
      OGVCS_METADATA_RESTART_DATABASE_URL_PREFIX:
        'postgresql://postgres:wrong@127.0.0.1:5432/',
    },
  });
  assert.notEqual(alternateUrl.status, 0);
  assert.match(alternateUrl.stderr, /Expected values to be strictly equal/u);

  const supervisor = await readFile(restartSupervisorPath, 'utf8');
  const [atomicSubmit, aggregateLiveTest] = await Promise.all([
    readFile(atomicSubmitPath, 'utf8'),
    readFile(aggregateLiveTestPath, 'utf8'),
  ]);
  for (const boundary of declaration.boundaries) {
    assert(
      atomicSubmit.includes(`"${boundary}"`),
      `Rust restart boundary mapping omits ${boundary}`,
    );
    assert(
      aggregateLiveTest.includes(`"${boundary}"`),
      `live restart oracle mapping omits ${boundary}`,
    );
  }
  assert.match(
    aggregateLiveTest,
    /AtomicSubmitRestartBoundaryForTest::CommitIo => \{\}/u,
  );
  assert.match(
    aggregateLiveTest,
    /AtomicSubmitRestartBoundaryForTest::AfterCommitBeforeResponse => assert_eq!/u,
  );
  assert.match(aggregateLiveTest, /_ => assert_eq!/u);
  assert.match(supervisor, /CONTAINER_ID_PATTERN = \/\^\[a-f0-9\]\{64\}\$\/u/u);
  assert.match(supervisor, /docker\(\['kill', '--signal', 'KILL', containerId\]\)/u);
  assert.match(supervisor, /killedExitCode, 137/u);
  assert.match(supervisor, /afterIdentity\.dockerPid, beforeIdentity\.dockerPid/u);
  assert.match(supervisor, /afterIdentity\.postmasterStartTime/u);
  assert.match(supervisor, /wait_event_type = 'Timeout'/u);
  assert.match(supervisor, /wait_event = 'PgSleep'/u);
  assert.match(supervisor, /child\.exitCode, null/u);
  assert.match(supervisor, /pg_stat_activity/u);
  assert.match(supervisor, /dockerInspect\('\{\{\.Image\}\}'\)/u);
  assert.match(supervisor, /'image', 'inspect', '--format', '\{\{\.Id\}\}'/u);
  assert.match(supervisor, /child\.emit\('restart-output-overflow'\)/u);
  assert.match(supervisor, /child\.kill\('SIGKILL'\)/u);
  assert.match(supervisor, /createdb/u);
  assert.match(supervisor, /dropdb/u);
  assert.match(supervisor, /databaseCreated = false/u);
  assert.match(supervisor, /if \(databaseCreated\)/u);
  assert.match(
    supervisor,
    /\['postgres', 'template0', 'template1'\]/u,
  );
  assert.match(supervisor, /hard-kill-postgres-13-times/u);
  assert.doesNotMatch(supervisor, /shell:\s*true/u);
  assert.doesNotMatch(supervisor, /writeFile|createWriteStream/u);
  const reportStart = supervisor.indexOf('const report = {');
  const reportEnd = supervisor.indexOf('caseReports.push(report)', reportStart);
  assert(reportStart >= 0 && reportEnd > reportStart);
  const reportProjection = supervisor.slice(reportStart, reportEnd);
  for (const forbidden of ['databaseUrl', 'containerId', 'backendPid:', 'dockerPid:', 'query:']) {
    assert(!reportProjection.includes(forbidden), `JSONL exposes ${forbidden}`);
  }
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
