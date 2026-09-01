#!/usr/bin/env node

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';

const PINNED_POSTGRES_IMAGE =
  'postgres@sha256:5d1d70e254e3c5d7d76847a9deebb18478cd518df37abf6b278d4bdb1fe5d96c';
const BOUNDARIES = Object.freeze([
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
const EXPECTED_INITIAL_STATE = Object.freeze(Object.fromEntries(BOUNDARIES.map((boundary) => [
  boundary,
  boundary === 'commit-io'
    ? 'old-or-new'
    : boundary === 'after-commit-before-response' ? 'new' : 'old',
])));
const MARKER_TIMEOUT_MS = 90_000;
const RESTART_TIMEOUT_MS = 60_000;
const CHILD_TIMEOUT_MS = 180_000;
const MATRIX_TIMEOUT_MS = 25 * 60_000;
const POLL_INTERVAL_MS = 250;
const MAX_CHILD_OUTPUT_BYTES = 4 * 1024 * 1024;
const CONTAINER_ID_PATTERN = /^[a-f0-9]{64}$/u;

if (process.argv.length === 3 && process.argv[2] === '--check') {
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 'ogvcs.repository-metadata/restart-matrix-declaration/v1',
    boundaries: BOUNDARIES,
    expectedInitialState: EXPECTED_INITIAL_STATE,
    pinnedPostgresImage: PINNED_POSTGRES_IMAGE,
    containerIdFormat: '64-lowercase-hex',
    disposableConfirmation: 'hard-kill-postgres-13-times',
    requiredInitialDatabases: ['postgres', 'template0', 'template1'],
    maximumCases: BOUNDARIES.length,
    maximumParallelApplicationClients: 1,
    signal: 'SIGKILL',
    retainsLocalEvidence: false,
  })}\n`);
  process.exit(0);
}
assert.equal(process.argv.length, 2, 'the restart supervisor accepts only --check or no arguments');

const containerId = requiredEnvironment('OGVCS_METADATA_RESTART_POSTGRES_CONTAINER');
assert.match(containerId, CONTAINER_ID_PATTERN, 'workflow PostgreSQL container ID is not exact');
assert.equal(
  requiredEnvironment('OGVCS_METADATA_RESTART_CONFIRM_DISPOSABLE'),
  'hard-kill-postgres-13-times',
  'exact disposable-service confirmation is required',
);
const databaseUrlPrefix = validatedDatabaseUrlPrefix(
  requiredEnvironment('OGVCS_METADATA_RESTART_DATABASE_URL_PREFIX'),
);
const matrixDeadline = Date.now() + MATRIX_TIMEOUT_MS;
const runToken = randomBytes(6).toString('hex');

const image = dockerInspect('{{.Config.Image}}');
assert.equal(image, PINNED_POSTGRES_IMAGE, 'PostgreSQL service image is not the pinned PG15 image');
const pinnedImageId = docker([
  'image', 'inspect', '--format', '{{.Id}}', PINNED_POSTGRES_IMAGE,
]).trim();
assert.match(pinnedImageId, /^sha256:[a-f0-9]{64}$/u, 'pinned PostgreSQL image ID is invalid');
assert.equal(
  dockerInspect('{{.Image}}'),
  pinnedImageId,
  'workflow container does not resolve to the pinned PostgreSQL image ID',
);
assert.equal(dockerInspect('{{.State.Running}}'), 'true', 'PostgreSQL service is not running');
const serverVersion = docker([
  'exec', containerId, 'psql', '-U', 'postgres', '-d', 'postgres', '-AtX',
  '-v', 'ON_ERROR_STOP=1', '-c', 'SHOW server_version_num',
]).trim();
assert.match(serverVersion, /^15\d{4}$/u, 'live restart service is not PostgreSQL 15');
const initialDatabases = docker([
  'exec', containerId, 'psql', '-U', 'postgres', '-d', 'postgres', '-AtX',
  '-v', 'ON_ERROR_STOP=1', '-c', 'SELECT datname FROM pg_database ORDER BY datname',
]).trim().split('\n');
assert.deepEqual(
  initialDatabases,
  ['postgres', 'template0', 'template1'],
  'restart service is not a fresh system-database-only PostgreSQL instance',
);

const caseReports = [];
for (const [index, boundary] of BOUNDARIES.entries()) {
  assert(
    Date.now() < matrixDeadline,
    'restart matrix exceeded its total bounded duration',
  );
  const database = `ogvcs_metadata_test_restart_${runToken}_${String(index).padStart(2, '0')}`;
  assert.match(database, /^ogvcs_metadata_test_restart_[a-f0-9]{12}_\d{2}$/u);
  const databaseUrl = `${databaseUrlPrefix}${database}`;
  let child;
  let databaseCreated = false;
  try {
    docker(['exec', containerId, 'createdb', '-U', 'postgres', database]);
    databaseCreated = true;
    const beforeIdentity = postgresIdentity();
    child = startCase(boundary, databaseUrl, remainingMatrixTimeout(CHILD_TIMEOUT_MS));
    const marker = await waitForMarker(database, boundary, child);

    docker(['kill', '--signal', 'KILL', containerId]);
    await waitUntil(
      () => dockerInspect('{{.State.Running}}') === 'false',
      remainingMatrixTimeout(RESTART_TIMEOUT_MS),
      'container did not stop after SIGKILL',
    );
    const killedExitCode = Number.parseInt(dockerInspect('{{.State.ExitCode}}'), 10);
    assert.equal(killedExitCode, 137, 'PostgreSQL did not record SIGKILL exit code 137');

    docker(['start', containerId]);
    await waitUntil(
      () => readiness(database),
      remainingMatrixTimeout(RESTART_TIMEOUT_MS),
      'PostgreSQL did not become ready after hard restart',
    );
    const afterIdentity = postgresIdentity();
    assert(Date.now() < matrixDeadline, 'restart matrix exceeded its total bounded duration');
    assert.notEqual(afterIdentity.dockerPid, beforeIdentity.dockerPid, 'Docker process ID did not change');
    assert.notEqual(
      afterIdentity.postmasterStartTime,
      beforeIdentity.postmasterStartTime,
      'PostgreSQL postmaster start time did not change',
    );

    const completed = await child.restartCompletion;
    assert.equal(completed.signal, null, `restart test child ended from ${completed.signal}`);
    assert.equal(completed.code, 0, `restart test child failed with ${completed.code}`);
    const recovery = exactCaseResult(completed.output, boundary);
    const report = {
      schemaVersion: 'ogvcs.repository-metadata/restart-case-evidence/v1',
      status: 'passed',
      boundary,
      postgresImage: image,
      postgresVersion: serverVersion,
      signal: 'SIGKILL',
      exit137Observed: killedExitCode === 137,
      queryClass: marker.queryClass,
      pgSleepObserved: true,
      backendPidObserved: marker.backendPid > 0,
      dockerPidChanged: afterIdentity.dockerPid !== beforeIdentity.dockerPid,
      postmasterStartChanged:
        afterIdentity.postmasterStartTime !== beforeIdentity.postmasterStartTime,
      recovery,
    };
    caseReports.push(report);
    process.stdout.write(`${JSON.stringify(report)}\n`);
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    if (dockerInspect('{{.State.Running}}') !== 'true') {
      docker(['start', containerId]);
      await waitUntil(
        () => readiness('postgres'),
        RESTART_TIMEOUT_MS,
        'PostgreSQL did not recover for exact database cleanup',
      );
    }
    if (databaseCreated) {
      docker(['exec', containerId, 'dropdb', '-U', 'postgres', '--force', database]);
    }
  }
}

assert.equal(caseReports.length, BOUNDARIES.length, 'restart matrix report is incomplete');
process.stdout.write(`${JSON.stringify({
  schemaVersion: 'ogvcs.repository-metadata/restart-matrix-summary/v1',
  status: 'passed',
  caseCount: caseReports.length,
  boundaries: caseReports.map(({ boundary }) => boundary),
  postgresImage: image,
  postgresVersion: serverVersion,
  allObservedExit137: caseReports.every(({ exit137Observed }) => exit137Observed),
  allDockerPidsChanged: caseReports.every(({ dockerPidChanged }) => dockerPidChanged),
  allPostmasterStartsChanged: caseReports.every(
    ({ postmasterStartChanged }) => postmasterStartChanged,
  ),
})}\n`);

function requiredEnvironment(name) {
  const value = process.env[name];
  assert(value, `${name} is required`);
  return value;
}

function validatedDatabaseUrlPrefix(value) {
  const parsed = new URL(value);
  assert.equal(parsed.protocol, 'postgresql:');
  assert.equal(parsed.username, 'postgres');
  assert.equal(parsed.password, 'postgres');
  assert.equal(parsed.hostname, '127.0.0.1');
  assert.equal(parsed.port, '5432');
  assert.equal(parsed.pathname, '/');
  assert.equal(parsed.search, '');
  assert.equal(parsed.hash, '');
  assert(value.endsWith('/'));
  assert.equal(parsed.href, 'postgresql://postgres:postgres@127.0.0.1:5432/');
  return value;
}

function command(commandName, args, options = {}) {
  const result = spawnSync(commandName, args, {
    encoding: 'utf8',
    timeout: options.timeout ?? 10_000,
    maxBuffer: 1024 * 1024,
    ...options,
  });
  assert.equal(result.error, undefined, `${commandName} failed to start: ${result.error?.message}`);
  assert.equal(
    result.status,
    0,
    `${commandName} ${args[0] ?? ''} failed (${result.status}): ${result.stderr}`,
  );
  return result.stdout;
}

function docker(args, options) {
  return command('docker', args, options);
}

function dockerInspect(format) {
  return docker(['inspect', '--format', format, containerId]).trim();
}

function postgresIdentity() {
  const dockerPid = Number.parseInt(dockerInspect('{{.State.Pid}}'), 10);
  assert(Number.isSafeInteger(dockerPid) && dockerPid > 0, 'invalid Docker process ID');
  const postmasterStartTime = docker([
    'exec', containerId, 'psql', '-U', 'postgres', '-d', 'postgres', '-AtX',
    '-v', 'ON_ERROR_STOP=1', '-c',
    "SELECT to_char(pg_postmaster_start_time(), 'YYYY-MM-DD\"T\"HH24:MI:SS.USOF')",
  ]).trim();
  assert.match(
    postmasterStartTime,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[+-]\d{2}(?::?\d{2})?$/u,
    'invalid PostgreSQL postmaster start time',
  );
  return { dockerPid, postmasterStartTime };
}

function startCase(boundary, databaseUrl, timeout) {
  const args = [
    'test', '--manifest-path', 'server/modules/repository-metadata/Cargo.toml',
    '--locked', '--offline', '--features', 'legacy-test-adapter',
    '--test', 'aggregate_bridge_postgres_live',
    'private_atomic_submit_hard_restart_is_exact_old_or_new_and_recoverable',
    '--', '--exact', '--nocapture', '--test-threads=1',
  ];
  const child = spawn('cargo', args, {
    cwd: process.cwd(),
    env: {
      ...process.env,
      CARGO_NET_OFFLINE: 'true',
      OGVCS_METADATA_RESTART_DATABASE_URL: databaseUrl,
      OGVCS_METADATA_RESTART_BOUNDARY: boundary,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.restartOutput = '';
  child.restartOutputBytes = 0;
  child.restartCompletion = boundedChildCompletion(child, timeout);
  void child.restartCompletion.catch(() => {});
  for (const stream of [child.stdout, child.stderr]) {
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      child.restartOutputBytes += Buffer.byteLength(chunk);
      if (child.restartOutputBytes > MAX_CHILD_OUTPUT_BYTES) {
        if (!child.restartOutputOverflow) {
          child.restartOutputOverflow = true;
          child.emit('restart-output-overflow');
        }
        return;
      }
      child.restartOutput += chunk;
      process.stderr.write(chunk);
    });
  }
  return child;
}

async function waitForMarker(database, boundary, child) {
  let marker;
  await waitUntil(() => {
    assert.equal(child.exitCode, null, 'restart child exited before publishing its rendezvous');
    assert.equal(child.signalCode, null, 'restart child was signaled before its rendezvous');
    const applicationName = `ogvcs.restart.${boundary}`;
    const sql = `SELECT pid::text || E'\\t' || regexp_replace(query, E'\\\\s+', ' ', 'g')
      FROM pg_stat_activity
      WHERE datname = current_database()
        AND application_name = '${applicationName}'
        AND state = 'active'
        AND wait_event_type = 'Timeout'
        AND wait_event = 'PgSleep'
      ORDER BY pid`;
    const observed = docker([
      'exec', containerId, 'psql', '-U', 'postgres', '-d', database, '-AtX',
      '-v', 'ON_ERROR_STOP=1', '-c', sql,
    ], { timeout: 5_000 }).trim();
    if (!observed) return false;
    const rows = observed.split('\n');
    assert.equal(rows.length, 1, 'more than one application client reached the restart marker');
    const [backendPidText, query] = rows[0].split('\t');
    const backendPid = Number.parseInt(backendPidText, 10);
    assert(Number.isSafeInteger(backendPid) && backendPid > 0, 'invalid rendezvous backend PID');
    const queryClass = /^COMMIT\b/iu.test(query) ? 'commit' : 'rendezvous-select';
    assert.equal(
      queryClass,
      boundary === 'commit-io' ? 'commit' : 'rendezvous-select',
      'observed PostgreSQL query does not match the requested boundary',
    );
    marker = { backendPid, queryClass };
    return true;
  }, remainingMatrixTimeout(MARKER_TIMEOUT_MS), `did not observe the ${boundary} PostgreSQL rendezvous`);
  return marker;
}

function readiness(database) {
  const result = spawnSync('docker', [
    'exec', containerId, 'pg_isready', '-U', 'postgres', '-d', database,
  ], { encoding: 'utf8', timeout: 5_000 });
  return result.status === 0;
}

async function waitUntil(predicate, timeout, message) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  throw new Error(message);
}

function remainingMatrixTimeout(maximum) {
  const remaining = matrixDeadline - Date.now();
  assert(remaining > 0, 'restart matrix exceeded its total bounded duration');
  return Math.min(maximum, remaining);
}

function boundedChildCompletion(child, timeout) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      reject(new Error('restart test child exceeded its bounded completion time'));
    }, timeout);
    child.once('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.once('restart-output-overflow', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill('SIGKILL');
      reject(new Error('restart child output exceeded its bounded capture size'));
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, signal, output: child.restartOutput });
    });
  });
}

function exactCaseResult(output, boundary) {
  const matches = [...output.matchAll(/OGVCS_METADATA_RESTART_RESULT (\{[^\n]+\})/gu)];
  assert.equal(matches.length, 1, 'restart child emitted no unique case result');
  const result = JSON.parse(matches[0][1]);
  assert.deepEqual(Object.keys(result).sort(), [
    'boundary', 'fileIdConsumptions', 'finalOutcomes', 'identityConsumptions',
    'initialState', 'lifecycleApplications', 'resultDigest', 'schemaVersion',
  ]);
  assert.equal(result.schemaVersion, 'ogvcs.repository-metadata/restart-case-result/v1');
  assert.equal(result.boundary, boundary);
  assert(['old', 'new'].includes(result.initialState));
  const expected = EXPECTED_INITIAL_STATE[boundary];
  assert(
    expected === 'old-or-new' || result.initialState === expected,
    `${boundary} recovered to unexpected ${result.initialState} state`,
  );
  assert.equal(result.identityConsumptions, 1);
  assert.equal(result.lifecycleApplications, 1);
  assert.equal(result.fileIdConsumptions, 1);
  assert.equal(result.finalOutcomes, 1);
  assert.match(result.resultDigest, /^[a-f0-9]{64}$/u);
  return result;
}
