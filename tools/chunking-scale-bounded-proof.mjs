#!/usr/bin/env node

import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHA = /^[0-9a-f]{40}$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const WORKFLOW_NAME = 'Chunking manifest bounded conformance';
const WORKFLOW_PATH = '.github/workflows/chunking-manifest-bounded.yml';
const WORKFLOW_FILE = 'chunking-manifest-bounded.yml';
const MAXIMUM_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAXIMUM_CANDIDATE_RUNS = 100;
const MAXIMUM_PROOF_ATTEMPTS = 8;

const EXPECTED_JOBS = Object.freeze(new Map([
  ['JavaScript bounded (Linux)', 'ubuntu-latest'],
  ['JavaScript bounded (macOS)', 'macos-latest'],
  ['JavaScript bounded (Windows)', 'windows-latest'],
  ['Rust bounded (Linux)', 'ubuntu-latest'],
  ['Rust bounded (macOS)', 'macos-latest'],
  ['Rust bounded (Windows)', 'windows-latest'],
  ['Cross-language and cross-OS parity', 'ubuntu-latest'],
]));

function fail(message) {
  throw new Error(`chunking exact-scale bounded prerequisite rejected: ${message}`);
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function requireSourceRevision(value) {
  if (typeof value !== 'string' || !SHA.test(value)) {
    fail('the source revision must be one exact lowercase Git object ID');
  }
  return value;
}

function requireRepository(value) {
  const segments = typeof value === 'string' ? value.split('/') : [];
  if (typeof value !== 'string' || !REPOSITORY.test(value)
      || segments.some((segment) => segment === '.' || segment === '..')) {
    fail('GITHUB_REPOSITORY must be one owner/name pair');
  }
  return value;
}

function requireApiBase(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    fail('GITHUB_API_URL is invalid');
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== ''
      || url.search !== '' || url.hash !== '') {
    fail('GITHUB_API_URL must be one credential-free HTTPS origin/path');
  }
  url.pathname = url.pathname.replace(/\/+$/u, '');
  return url;
}

function validateWorkflow(workflow) {
  if (workflow === null || typeof workflow !== 'object' || Array.isArray(workflow)
      || !positiveInteger(workflow.id) || workflow.name !== WORKFLOW_NAME
      || workflow.path !== WORKFLOW_PATH || workflow.state !== 'active') {
    fail('the bounded workflow authority is missing, inactive, or different');
  }
}

function validateRun({ repository, run, sourceRevision, workflowId }) {
  if (run === null || typeof run !== 'object' || Array.isArray(run)
      || !positiveInteger(run.id) || !positiveInteger(run.run_attempt)
      || run.workflow_id !== workflowId || run.name !== WORKFLOW_NAME
      || run.path !== WORKFLOW_PATH || run.head_sha !== sourceRevision
      || run.status !== 'completed' || run.conclusion !== 'success'
      || !['push', 'workflow_dispatch'].includes(run.event)
      || run.repository?.full_name !== repository
      || run.head_repository?.full_name !== repository
      || !positiveInteger(run.repository?.id)
      || run.head_repository?.id !== run.repository.id) {
    fail('the bounded workflow run is not a successful same-repository exact-revision run');
  }
}

function validateJob(job, { run, sourceRevision }) {
  if (job === null || typeof job !== 'object' || Array.isArray(job)
      || !positiveInteger(job.id) || job.run_id !== run.id
      || job.run_attempt !== run.run_attempt || job.workflow_name !== WORKFLOW_NAME
      || job.head_sha !== sourceRevision || job.status !== 'completed'
      || job.conclusion !== 'success' || !Array.isArray(job.labels)
      || !Array.isArray(job.steps) || job.steps.length === 0
      || job.steps.some((step) => step?.status !== 'completed' || step?.conclusion !== 'success')) {
    fail('a bounded matrix job is incomplete, skipped, failed, or bound to different source');
  }
}

export function validateChunkingBoundedProof({
  jobsPayload,
  repository,
  run,
  sourceRevision,
  workflow,
}) {
  const revision = requireSourceRevision(sourceRevision);
  const repositoryName = requireRepository(repository);
  validateWorkflow(workflow);
  validateRun({ repository: repositoryName, run, sourceRevision: revision, workflowId: workflow.id });

  if (jobsPayload === null || typeof jobsPayload !== 'object' || Array.isArray(jobsPayload)
      || jobsPayload.total_count !== EXPECTED_JOBS.size || !Array.isArray(jobsPayload.jobs)
      || jobsPayload.jobs.length !== EXPECTED_JOBS.size) {
    fail('the bounded workflow did not expose exactly six matrix jobs and one parity job');
  }

  const jobsByName = new Map();
  const jobIds = new Set();
  for (const job of jobsPayload.jobs) {
    validateJob(job, { run, sourceRevision: revision });
    if (!EXPECTED_JOBS.has(job.name) || jobsByName.has(job.name) || jobIds.has(job.id)) {
      fail('the bounded workflow job inventory is unexpected or duplicated');
    }
    const requiredLabel = EXPECTED_JOBS.get(job.name);
    if (job.labels.length !== 1 || job.labels[0] !== requiredLabel) {
      fail(`the bounded workflow job ${job.name} did not use ${requiredLabel}`);
    }
    jobIds.add(job.id);
    jobsByName.set(job.name, job);
  }
  for (const name of EXPECTED_JOBS.keys()) {
    if (!jobsByName.has(name)) fail(`the bounded workflow job ${name} is missing`);
  }

  return Object.freeze({
    event: run.event,
    jobCount: EXPECTED_JOBS.size,
    runAttempt: run.run_attempt,
    runId: run.id,
    sourceRevision: revision,
    verified: true,
    workflowId: workflow.id,
  });
}

function releaseReader(reader) {
  try { reader.releaseLock(); } catch {}
}

async function cancelBody(body) {
  try { await body?.cancel?.(); } catch {}
}

async function cancelReader(reader) {
  try { await reader.cancel(); } catch {}
  releaseReader(reader);
}

async function boundedJson(response) {
  if (response === null || typeof response !== 'object' || response.ok !== true) {
    const status = positiveInteger(response?.status) ? ` (${response.status})` : '';
    await cancelBody(response?.body);
    fail(`GitHub Actions metadata request failed${status}`);
  }
  let declared;
  try {
    declared = Number(response.headers?.get?.('content-length'));
  } catch {
    await cancelBody(response.body);
    fail('GitHub Actions metadata response is unreadable');
  }
  if (Number.isFinite(declared) && declared > MAXIMUM_RESPONSE_BYTES) {
    await cancelBody(response.body);
    fail('GitHub Actions metadata response exceeded the byte limit');
  }

  let reader;
  try {
    reader = response.body?.getReader();
  } catch {
    await cancelBody(response.body);
    fail('GitHub Actions metadata response is unreadable');
  }
  if (reader === undefined || typeof reader.read !== 'function'
      || typeof reader.cancel !== 'function' || typeof reader.releaseLock !== 'function') {
    await cancelBody(response.body);
    fail('GitHub Actions metadata response is unreadable');
  }

  const bytes = Buffer.allocUnsafe(MAXIMUM_RESPONSE_BYTES);
  let offset = 0;
  for (;;) {
    let result;
    try {
      result = await reader.read();
    } catch {
      await cancelReader(reader);
      fail('GitHub Actions metadata response is unreadable');
    }
    if (result === null || typeof result !== 'object' || typeof result.done !== 'boolean') {
      await cancelReader(reader);
      fail('GitHub Actions metadata response is unreadable');
    }
    if (result.done) {
      releaseReader(reader);
      break;
    }
    if (!(result.value instanceof Uint8Array)) {
      await cancelReader(reader);
      fail('GitHub Actions metadata response is unreadable');
    }
    if (result.value.byteLength > MAXIMUM_RESPONSE_BYTES - offset) {
      await cancelReader(reader);
      fail('GitHub Actions metadata response exceeded the byte limit');
    }
    Buffer.from(result.value.buffer, result.value.byteOffset, result.value.byteLength)
      .copy(bytes, offset);
    offset += result.value.byteLength;
  }

  const text = bytes.toString('utf8', 0, offset);
  try {
    return JSON.parse(text);
  } catch {
    fail('GitHub Actions metadata response is not JSON');
  }
}

async function githubJson({ apiBase, path, request, token }) {
  const url = new URL(`${apiBase.href.replace(/\/+$/u, '')}/${path.replace(/^\/+/u, '')}`);
  let response;
  try {
    response = await request(url, {
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'User-Agent': 'OpenGameVCS-exact-scale-bounded-prerequisite',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    fail('GitHub Actions metadata request failed');
  }
  return boundedJson(response);
}

export async function findChunkingBoundedProof({
  apiUrl,
  repository,
  request = globalThis.fetch,
  sourceRevision,
  token,
}) {
  const revision = requireSourceRevision(sourceRevision);
  const repositoryName = requireRepository(repository);
  const apiBase = requireApiBase(apiUrl);
  if (typeof token !== 'string' || token.length < 1) fail('GITHUB_TOKEN is required');
  if (typeof request !== 'function') fail('the GitHub Actions metadata reader is unavailable');

  const encodedRepository = repositoryName.split('/').map(encodeURIComponent).join('/');
  const workflow = await githubJson({
    apiBase,
    path: `/repos/${encodedRepository}/actions/workflows/${WORKFLOW_FILE}`,
    request,
    token,
  });
  validateWorkflow(workflow);
  const runsPayload = await githubJson({
    apiBase,
    path: `/repos/${encodedRepository}/actions/workflows/${workflow.id}/runs`
      + `?head_sha=${revision}&status=completed&per_page=${MAXIMUM_CANDIDATE_RUNS}`,
    request,
    token,
  });
  if (runsPayload === null || typeof runsPayload !== 'object' || Array.isArray(runsPayload)
      || !Number.isSafeInteger(runsPayload.total_count) || runsPayload.total_count < 0
      || runsPayload.total_count > MAXIMUM_CANDIDATE_RUNS
      || !Array.isArray(runsPayload.workflow_runs)
      || runsPayload.workflow_runs.length !== runsPayload.total_count) {
    fail('the exact-revision bounded workflow run inventory is invalid or exceeds its bound');
  }

  const candidates = runsPayload.workflow_runs.filter((run) => run?.status === 'completed'
    && run?.conclusion === 'success' && run?.head_sha === revision);
  for (const run of candidates.slice(0, MAXIMUM_PROOF_ATTEMPTS)) {
    try {
      validateRun({ repository: repositoryName, run, sourceRevision: revision, workflowId: workflow.id });
      const jobsPayload = await githubJson({
        apiBase,
        path: `/repos/${encodedRepository}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`,
        request,
        token,
      });
      return validateChunkingBoundedProof({
        jobsPayload,
        repository: repositoryName,
        run,
        sourceRevision: revision,
        workflow,
      });
    } catch (error) {
      if (!(error instanceof Error)
        || !error.message.startsWith('chunking exact-scale bounded prerequisite rejected:')) throw error;
    }
  }
  fail('no successful exact-revision six-leg bounded run with parity was found');
}

async function main() {
  await findChunkingBoundedProof({
    apiUrl: process.env.GITHUB_API_URL,
    repository: process.env.GITHUB_REPOSITORY,
    sourceRevision: process.env.OGVCS_SOURCE_REVISION,
    token: process.env.GITHUB_TOKEN,
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    await main();
  } catch (error) {
    const message = error instanceof Error
      ? error.message
      : 'chunking exact-scale bounded prerequisite rejected';
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}
