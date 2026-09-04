import assert from 'node:assert/strict';
import test from 'node:test';

import {
  findChunkingBoundedProof,
  validateChunkingBoundedProof,
} from './chunking-scale-bounded-proof.mjs';

const REVISION = '0123456789abcdef0123456789abcdef01234567';
const REPOSITORY = 'example/OpenGameVCS';
const WORKFLOW = Object.freeze({
  id: 346_013_511,
  name: 'Chunking manifest bounded conformance',
  path: '.github/workflows/chunking-manifest-bounded.yml',
  state: 'active',
});
const RUN = Object.freeze({
  id: 33_521_316_277,
  run_attempt: 1,
  workflow_id: WORKFLOW.id,
  name: WORKFLOW.name,
  path: WORKFLOW.path,
  head_sha: REVISION,
  status: 'completed',
  conclusion: 'success',
  event: 'workflow_dispatch',
  repository: { id: 1_334_770_412, full_name: REPOSITORY },
  head_repository: { id: 1_334_770_412, full_name: REPOSITORY },
  pull_requests: [],
});
const JOBS = Object.freeze([
  ['JavaScript bounded (Linux)', 'ubuntu-latest'],
  ['JavaScript bounded (macOS)', 'macos-latest'],
  ['JavaScript bounded (Windows)', 'windows-latest'],
  ['Rust bounded (Linux)', 'ubuntu-latest'],
  ['Rust bounded (macOS)', 'macos-latest'],
  ['Rust bounded (Windows)', 'windows-latest'],
  ['Cross-language and cross-OS parity', 'ubuntu-latest'],
].map(([name, label], index) => ({
  id: 99_901_723_794 + index,
  run_id: RUN.id,
  run_attempt: RUN.run_attempt,
  workflow_name: WORKFLOW.name,
  head_sha: REVISION,
  status: 'completed',
  conclusion: 'success',
  name,
  labels: [label],
  steps: [{ name: 'Complete job', status: 'completed', conclusion: 'success' }],
})));

function jobsPayload(jobs = structuredClone(JOBS)) {
  return { total_count: jobs.length, jobs };
}

function proof(overrides = {}) {
  return {
    jobsPayload: jobsPayload(),
    repository: REPOSITORY,
    run: structuredClone(RUN),
    sourceRevision: REVISION,
    workflow: structuredClone(WORKFLOW),
    ...overrides,
  };
}

test('same-revision bounded proof requires six successful platform legs and aggregate parity', () => {
  assert.deepEqual(validateChunkingBoundedProof(proof()), {
    event: 'workflow_dispatch',
    jobCount: 7,
    runAttempt: 1,
    runId: RUN.id,
    sourceRevision: REVISION,
    verified: true,
    workflowId: WORKFLOW.id,
  });
  const push = structuredClone(RUN);
  push.event = 'push';
  assert.equal(validateChunkingBoundedProof(proof({ run: push })).verified, true);
});

const rejectionCases = [
  {
    name: 'an inactive workflow',
    mutate(value) { value.workflow.state = 'disabled_manually'; },
  },
  {
    name: 'a different workflow path',
    mutate(value) { value.workflow.path = '.github/workflows/other.yml'; },
  },
  {
    name: 'a different source revision',
    mutate(value) { value.run.head_sha = 'f'.repeat(40); },
  },
  {
    name: 'a pull-request run',
    mutate(value) { value.run.event = 'pull_request'; },
  },
  {
    name: 'a foreign head repository',
    mutate(value) { value.run.head_repository.full_name = 'fork/OpenGameVCS'; },
  },
  {
    name: 'a foreign endpoint repository',
    mutate(value) { value.run.repository.full_name = 'other/OpenGameVCS'; },
  },
  {
    name: 'a mismatched repository identity',
    mutate(value) { value.run.head_repository.id += 1; },
  },
  {
    name: 'a missing matrix leg',
    mutate(value) {
      value.jobsPayload.jobs.pop();
      value.jobsPayload.total_count -= 1;
    },
  },
  {
    name: 'a duplicated matrix job',
    mutate(value) { value.jobsPayload.jobs[1].name = value.jobsPayload.jobs[0].name; },
  },
  {
    name: 'a duplicated matrix job identity',
    mutate(value) { value.jobsPayload.jobs[1].id = value.jobsPayload.jobs[0].id; },
  },
  {
    name: 'a wrong runner label',
    mutate(value) { value.jobsPayload.jobs[2].labels = ['ubuntu-latest']; },
  },
  {
    name: 'an extra self-hosted runner label',
    mutate(value) { value.jobsPayload.jobs[0].labels.unshift('self-hosted'); },
  },
  {
    name: 'a skipped matrix step',
    mutate(value) { value.jobsPayload.jobs[3].steps[0].conclusion = 'skipped'; },
  },
  {
    name: 'a failed parity job',
    mutate(value) { value.jobsPayload.jobs[6].conclusion = 'failure'; },
  },
  {
    name: 'a stale run attempt',
    mutate(value) { value.jobsPayload.jobs[0].run_attempt = 2; },
  },
  {
    name: 'a job from another run',
    mutate(value) { value.jobsPayload.jobs[0].run_id += 1; },
  },
];

for (const rejection of rejectionCases) {
  test(`same-revision bounded proof rejects ${rejection.name}`, () => {
    const value = proof();
    rejection.mutate(value);
    assert.throws(
      () => validateChunkingBoundedProof(value),
      /chunking exact-scale bounded prerequisite rejected/u,
    );
  });
}

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers });
}

function apiFixture({ runs = [structuredClone(RUN)], jobs = jobsPayload(), responseMutator } = {}) {
  const calls = [];
  const request = async (url, options) => {
    calls.push({ options, url: String(url) });
    let response;
    if (String(url).endsWith('/actions/workflows/chunking-manifest-bounded.yml')) {
      response = jsonResponse(WORKFLOW);
    } else if (String(url).includes(`/actions/workflows/${WORKFLOW.id}/runs?`)) {
      response = jsonResponse({ total_count: runs.length, workflow_runs: runs });
    } else if (String(url).includes(`/actions/runs/${RUN.id}/attempts/${RUN.run_attempt}/jobs?`)) {
      response = jsonResponse(jobs);
    } else {
      response = jsonResponse({ message: 'unexpected test URL' }, 404);
    }
    return responseMutator?.(response, calls.length, url, options) ?? response;
  };
  return { calls, request };
}

test('GitHub metadata reader binds the active workflow, exact revision, attempt, and job inventory', async () => {
  const fixture = apiFixture();
  const result = await findChunkingBoundedProof({
    apiUrl: 'https://api.github.example/api/v3',
    repository: REPOSITORY,
    request: fixture.request,
    sourceRevision: REVISION,
    token: 'test-token',
  });
  assert.equal(result.runId, RUN.id);
  assert.equal(result.verified, true);
  assert.equal(fixture.calls.length, 3);
  assert.match(
    fixture.calls[0].url,
    /\/api\/v3\/repos\/example\/OpenGameVCS\/actions\/workflows\/chunking-manifest-bounded\.yml$/u,
  );
  assert.match(fixture.calls[1].url, new RegExp(`head_sha=${REVISION}`, 'u'));
  assert.match(fixture.calls[2].url, new RegExp(`/runs/${RUN.id}/attempts/1/jobs`, 'u'));
  for (const { options } of fixture.calls) {
    assert.equal(options.headers.Authorization, 'Bearer test-token');
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal instanceof AbortSignal);
  }
});

test('GitHub metadata reader skips an invalid success and accepts a later exact proof', async () => {
  const invalid = structuredClone(RUN);
  invalid.id += 1;
  invalid.event = 'pull_request';
  const fixture = apiFixture({ runs: [invalid, structuredClone(RUN)] });
  const result = await findChunkingBoundedProof({
    apiUrl: 'https://api.github.com',
    repository: REPOSITORY,
    request: fixture.request,
    sourceRevision: REVISION,
    token: 'test-token',
  });
  assert.equal(result.runId, RUN.id);
  assert.equal(fixture.calls.length, 3);
});

test('GitHub metadata reader fails closed on missing proof, API failure, and oversized metadata', async () => {
  const missing = apiFixture({ runs: [] });
  await assert.rejects(
    findChunkingBoundedProof({
      apiUrl: 'https://api.github.com', repository: REPOSITORY, request: missing.request,
      sourceRevision: REVISION, token: 'test-token',
    }),
    /no successful exact-revision six-leg bounded run/u,
  );

  let failedBodyCancelled = false;
  const failedBody = new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(1024)); },
    cancel() { failedBodyCancelled = true; },
  }, { highWaterMark: 0 });
  const failed = apiFixture({
    responseMutator(response, call) {
      return call === 1 ? new Response(failedBody, { status: 403 }) : response;
    },
  });
  await assert.rejects(
    findChunkingBoundedProof({
      apiUrl: 'https://api.github.com', repository: REPOSITORY, request: failed.request,
      sourceRevision: REVISION, token: 'test-token',
    }),
    /metadata request failed \(403\)/u,
  );
  assert.equal(failedBodyCancelled, true);

  await assert.rejects(
    findChunkingBoundedProof({
      apiUrl: 'https://api.github.com', repository: REPOSITORY,
      request: async () => { throw new Error('secret transport detail'); },
      sourceRevision: REVISION, token: 'test-token',
    }),
    (error) => {
      assert.equal(error.message,
        'chunking exact-scale bounded prerequisite rejected: GitHub Actions metadata request failed');
      assert.doesNotMatch(error.message, /secret transport detail/u);
      return true;
    },
  );

  const oversized = apiFixture({
    responseMutator(response, call) {
      return call === 1
        ? jsonResponse(WORKFLOW, 200, { 'content-length': String(4 * 1024 * 1024 + 1) })
        : response;
    },
  });
  await assert.rejects(
    findChunkingBoundedProof({
      apiUrl: 'https://api.github.com', repository: REPOSITORY, request: oversized.request,
      sourceRevision: REVISION, token: 'test-token',
    }),
    /metadata response exceeded the byte limit/u,
  );
});

test('GitHub metadata reader cancels a response with unreadable headers', async () => {
  let cancelled = false;
  const response = {
    ok: true,
    body: { async cancel() { cancelled = true; } },
    headers: { get() { throw new Error('secret header failure'); } },
  };
  const fixture = apiFixture({
    responseMutator(baseline, call) { return call === 1 ? response : baseline; },
  });
  await assert.rejects(
    findChunkingBoundedProof({
      apiUrl: 'https://api.github.com', repository: REPOSITORY, request: fixture.request,
      sourceRevision: REVISION, token: 'test-token',
    }),
    (error) => {
      assert.equal(error.message,
        'chunking exact-scale bounded prerequisite rejected: '
        + 'GitHub Actions metadata response is unreadable');
      assert.doesNotMatch(error.message, /secret header failure/u);
      return true;
    },
  );
  assert.equal(cancelled, true);
});

test('GitHub metadata reader cancels chunked overflow without trusting Content-Length', async () => {
  let pull = 0;
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) {
      pull += 1;
      if (pull === 1) controller.enqueue(new Uint8Array(3 * 1024 * 1024));
      else if (pull === 2) controller.enqueue(new Uint8Array(2 * 1024 * 1024));
      else controller.close();
    },
    cancel() { cancelled = true; },
  }, { highWaterMark: 0 });
  const response = new Response(body, { status: 200 });
  assert.equal(response.headers.get('content-length'), null);
  const fixture = apiFixture({
    responseMutator(baseline, call) { return call === 1 ? response : baseline; },
  });
  await assert.rejects(
    findChunkingBoundedProof({
      apiUrl: 'https://api.github.com', repository: REPOSITORY, request: fixture.request,
      sourceRevision: REVISION, token: 'test-token',
    }),
    /metadata response exceeded the byte limit/u,
  );
  assert.equal(cancelled, true);
  assert.equal(pull, 2);
});

test('GitHub metadata reader sanitizes a streaming body failure', async () => {
  let pull = 0;
  const body = new ReadableStream({
    pull(controller) {
      pull += 1;
      if (pull === 1) controller.enqueue(new TextEncoder().encode('{'));
      else controller.error(new Error('secret body reader failure'));
    },
  });
  const fixture = apiFixture({
    responseMutator(baseline, call) {
      return call === 1 ? new Response(body, { status: 200 }) : baseline;
    },
  });
  await assert.rejects(
    findChunkingBoundedProof({
      apiUrl: 'https://api.github.com', repository: REPOSITORY, request: fixture.request,
      sourceRevision: REVISION, token: 'test-token',
    }),
    (error) => {
      assert.equal(error.message,
        'chunking exact-scale bounded prerequisite rejected: '
        + 'GitHub Actions metadata response is unreadable');
      assert.doesNotMatch(error.message, /secret body reader failure/u);
      return true;
    },
  );
  assert.equal(pull, 2);
});

test('GitHub metadata reader rejects malformed invocation before network access', async () => {
  const request = () => assert.fail('network access was not expected');
  for (const input of [
    { apiUrl: 'http://api.github.com', repository: REPOSITORY, sourceRevision: REVISION, token: 'token' },
    { apiUrl: 'https://api.github.com', repository: '../other', sourceRevision: REVISION, token: 'token' },
    {
      apiUrl: 'https://api.github.com', repository: REPOSITORY,
      sourceRevision: REVISION.toUpperCase(), token: 'token',
    },
    { apiUrl: 'https://api.github.com', repository: REPOSITORY, sourceRevision: REVISION, token: '' },
  ]) {
    await assert.rejects(
      findChunkingBoundedProof({ ...input, request }),
      /chunking exact-scale bounded prerequisite rejected/u,
    );
  }
});
