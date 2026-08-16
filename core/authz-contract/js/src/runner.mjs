import { spawn } from 'node:child_process';

import { canonicalJson, deepFreeze, inspectJson, parseCanonicalJson, sha256 } from './canonical.mjs';
import { loadAuthorizationContract } from './contract.mjs';
import { ERROR_CODES, AuthorizationContractError, contractError } from './errors.mjs';
import { evaluateFixturePolicy, makeFixtureRequest } from './evaluator.mjs';
import { verifyTransferGrant } from './grants.mjs';
import { evaluateSandboxAttempt } from './sandbox.mjs';
import { validateRunnerResult, validateThreatVector } from './validate.mjs';
import { buildAuthorizedView } from './view.mjs';

const HARD = Object.freeze({
  timeoutMs: 120_000,
  stdoutBytes: 64 * 1024 * 1024,
  stderrBytes: 8 * 1024 * 1024,
  lineBytes: 4 * 1024 * 1024,
  vectors: 10_000,
});

function outcome(code) {
  return { result: code.startsWith('ALLOW_') ? 'allow' : 'deny', code };
}

function findProfile(contract, id) {
  return contract.registries['sandbox-profiles'].entries.find((profile) => profile.id === id);
}

function viewOutcome(contract, input) {
  const repository = contract.vectors.goldenRepository;
  const policy = contract.policies[input.policy];
  if (!policy) return outcome('DENY_POLICY_UNAVAILABLE');
  if (input.candidates) {
    const view = buildAuthorizedView({
      policy,
      repository,
      actorId: input.actor,
      permission: input.permission,
      candidates: input.candidates,
      pageSize: Math.min(input.candidates.length || 1, 1000),
      maxCandidates: Math.max(input.candidates.length, 1),
    });
    if (input.projectionIdentity !== undefined && input.projectionIdentity !== 'distinct') return outcome('DENY_RESOURCE_SCOPE');
    return view.items.length > 0 ? outcome('ALLOW_EXPLICIT') : outcome('DENY_NOT_AUTHORIZED');
  }
  if (input.auditClass) {
    const request = makeFixtureRequest(repository, 'runner-audit-view', input.actor, 'repository-audit', input.permission, { reason: 'conformance audit view' });
    const decision = evaluateFixturePolicy(policy, request);
    return outcome(decision.code);
  }
  return outcome('DENY_CONTEXT_INCOMPLETE');
}

export async function executeReferenceVector(vector, suppliedContract) {
  const contract = suppliedContract ?? await loadAuthorizationContract();
  vector = validateThreatVector(vector);
  const input = vector.input;
  switch (vector.kind) {
    case 'authorization': {
      const policy = contract.policies[input.policy];
      if (!policy) return outcome('DENY_POLICY_UNAVAILABLE');
      const decision = evaluateFixturePolicy(policy, input.request);
      return outcome(decision.code);
    }
    case 'authorized-view':
      return viewOutcome(contract, input);
    case 'transfer-grant':
      return verifyTransferGrant(input.envelope, input.context, input.publicJwk);
    case 'sandbox': {
      const profile = findProfile(contract, input.profile);
      return profile ? evaluateSandboxAttempt(profile, input.attempt) : outcome('DENY_SANDBOX_REQUIREMENTS');
    }
    case 'deduplication':
      if (input.keyDerivation === 'content-hash') return outcome('DENY_TENANT_BOUNDARY');
      return input.tenant !== input.probedTenant ? outcome('DENY_TENANT_BOUNDARY') : outcome('ALLOW_EXPLICIT');
    default:
      return outcome('DENY_CONTEXT_INCOMPLETE');
  }
}

function configured(value, fallback, maximum, label) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result <= 0 || result > maximum) contractError(ERROR_CODES.INPUT_INVALID, `${label} is outside its configured range`);
  return result;
}

function adapterCommand(adapter) {
  inspectJson(adapter, { maxBytes: 64 * 1024, maxDepth: 4, maxNodes: 1024 });
  if (Array.isArray(adapter) && adapter.length > 0 && adapter.every((item) => typeof item === 'string' && item.length > 0)) {
    if (adapter.length > 256 || adapter.some((item) => item.length > 16_384 || item.includes('\0'))) contractError(ERROR_CODES.INPUT_INVALID, 'adapter command array exceeds its bounds');
    return { command: adapter[0], args: adapter.slice(1), env: {} };
  }
  if (adapter && typeof adapter === 'object' && typeof adapter.command === 'string' && adapter.command.length > 0 && Array.isArray(adapter.args ?? []) && (adapter.args ?? []).every((item) => typeof item === 'string')) {
    const keys = Object.keys(adapter).sort();
    if (keys.some((key) => !['args', 'command', 'env'].includes(key)) || adapter.command.length > 16_384 || adapter.command.includes('\0') || (adapter.args ?? []).length > 255 || (adapter.args ?? []).some((item) => item.length > 16_384 || item.includes('\0'))) contractError(ERROR_CODES.INPUT_INVALID, 'adapter descriptor is invalid');
    const env = adapter.env ?? {};
    const envEntries = env && typeof env === 'object' && !Array.isArray(env) ? Object.entries(env) : [];
    if (!env || typeof env !== 'object' || Array.isArray(env) || envEntries.length > 128 || envEntries.some(([key, value]) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || typeof value !== 'string' || value.length > 65_536 || value.includes('\0'))) contractError(ERROR_CODES.INPUT_INVALID, 'adapter environment is invalid');
    return { command: adapter.command, args: adapter.args ?? [], env };
  }
  contractError(ERROR_CODES.INPUT_INVALID, 'adapter must be a nonempty command array or descriptor');
}

function minimalEnvironment(extra) {
  const output = { ...extra };
  for (const key of ['PATH', 'PATHEXT', 'SystemRoot', 'WINDIR', 'ComSpec', 'TMPDIR', 'TMP', 'TEMP']) {
    if (process.env[key] !== undefined && output[key] === undefined) output[key] = process.env[key];
  }
  return output;
}

async function terminate(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  if (process.platform === 'win32' && child.pid) {
    await new Promise((resolve) => {
      const killer = spawn('taskkill', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' });
      killer.once('error', () => resolve());
      killer.once('close', () => resolve());
    });
  } else {
    try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch {} }
  }
}

async function runAdapter(adapter, vectors, manifest, options) {
  const descriptor = adapterCommand(adapter);
  const timeoutMs = configured(options.timeoutMs, HARD.timeoutMs, HARD.timeoutMs, 'adapter timeout');
  const maxStdoutBytes = configured(options.maxStdoutBytes, HARD.stdoutBytes, HARD.stdoutBytes, 'adapter stdout ceiling');
  const maxStderrBytes = configured(options.maxStderrBytes, HARD.stderrBytes, HARD.stderrBytes, 'adapter stderr ceiling');
  const maxLineBytes = configured(options.maxLineBytes, HARD.lineBytes, HARD.lineBytes, 'adapter line ceiling');
  const hello = {
    schemaVersion: 'ogvcs.authorization/runner-hello/v1',
    contractVersion: manifest.contractVersion,
    manifestSha256: manifest.manifestSha256,
    registrySetSha256: manifest.registrySetSha256,
    vectors: vectors.length,
  };
  const stdin = `${canonicalJson(hello)}\n${vectors.map((vector) => canonicalJson({ schemaVersion: 'ogvcs.authorization/runner-vector/v1', vector })).join('\n')}\n`;
  const child = spawn(descriptor.command, descriptor.args, {
    detached: process.platform !== 'win32',
    env: minimalEnvironment(descriptor.env),
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  const stdout = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let boundaryError;
  const stop = async (error) => {
    boundaryError ??= error;
    await terminate(child);
  };
  child.stdout.on('data', (chunk) => {
    stdoutBytes += chunk.length;
    if (stdoutBytes > maxStdoutBytes) void stop(new AuthorizationContractError(ERROR_CODES.LIMIT_EXCEEDED, 'adapter stdout ceiling exceeded'));
    else stdout.push(chunk);
  });
  child.stderr.on('data', (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > maxStderrBytes) void stop(new AuthorizationContractError(ERROR_CODES.LIMIT_EXCEEDED, 'adapter stderr ceiling exceeded'));
  });
  const close = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  const timeout = setTimeout(() => void stop(new AuthorizationContractError(ERROR_CODES.TIMEOUT, 'adapter elapsed-time ceiling exceeded')), timeoutMs);
  timeout.unref?.();
  const abort = () => void stop(new AuthorizationContractError(ERROR_CODES.TIMEOUT, 'adapter run was aborted'));
  if (options.signal?.aborted) abort();
  else options.signal?.addEventListener('abort', abort, { once: true });
  child.stdin.on('error', (error) => { if (error.code !== 'EPIPE') void stop(new AuthorizationContractError(ERROR_CODES.ADAPTER_FAILED, 'adapter input failed', { cause: error })); });
  child.stdin.end(stdin);
  let status;
  try { status = await close; } catch (error) { boundaryError ??= new AuthorizationContractError(ERROR_CODES.ADAPTER_FAILED, 'adapter process could not start', { cause: error }); }
  clearTimeout(timeout);
  options.signal?.removeEventListener('abort', abort);
  if (boundaryError) throw boundaryError;
  if (status.code !== 0 || status.signal !== null) contractError(ERROR_CODES.ADAPTER_FAILED, 'adapter process failed');

  const outputBytes = Buffer.concat(stdout);
  let output;
  try { output = new TextDecoder('utf-8', { fatal: true }).decode(outputBytes); } catch (error) { contractError(ERROR_CODES.ADAPTER_PROTOCOL, 'adapter output is not valid UTF-8', { cause: error }); }
  if (!output.endsWith('\n')) contractError(ERROR_CODES.ADAPTER_PROTOCOL, 'adapter output must end with LF');
  const lines = output.slice(0, -1).split('\n');
  if (lines.length !== vectors.length) contractError(ERROR_CODES.ADAPTER_PROTOCOL, 'adapter returned an invalid result count');
  return lines.map((line, index) => {
    if (Buffer.byteLength(line, 'utf8') > maxLineBytes) contractError(ERROR_CODES.LIMIT_EXCEEDED, 'adapter result line ceiling exceeded');
    let parsed;
    try { parsed = parseCanonicalJson(line, { maxBytes: maxLineBytes }); } catch (error) { contractError(ERROR_CODES.ADAPTER_PROTOCOL, 'adapter returned invalid canonical JSON', { cause: error }); }
    let result;
    try { result = validateRunnerResult(parsed); } catch (error) { contractError(ERROR_CODES.ADAPTER_PROTOCOL, 'adapter returned an invalid result envelope', { cause: error }); }
    if (result.id !== vectors[index].id) contractError(ERROR_CODES.ADAPTER_PROTOCOL, 'adapter result order or identity mismatch');
    return { result: result.result, code: result.code };
  });
}

export async function runThreatVectors(options = {}) {
  const contract = await loadAuthorizationContract();
  const vectors = [...contract.vectors.abuseCatalog.cases].sort((left, right) => left.id.localeCompare(right.id));
  if (!Array.isArray(vectors) || vectors.length === 0 || vectors.length > HARD.vectors) contractError(ERROR_CODES.CONTRACT_INVALID, 'abuse vector inventory is invalid');
  const actual = options.adapter === undefined
    ? await Promise.all(vectors.map((vector) => executeReferenceVector(vector, contract)))
    : await runAdapter(options.adapter, vectors, { ...contract.manifest, manifestSha256: contract.manifestSha256 }, options);
  const rows = vectors.map((vector, index) => ({
    id: vector.id,
    status: actual[index].result === vector.expected.result && actual[index].code === vector.expected.code ? 'passed' : 'failed',
    expectedCode: vector.expected.code,
    actualCode: actual[index].code,
  }));
  const failed = rows.filter(({ status }) => status === 'failed').length;
  return deepFreeze({
    schemaVersion: 'ogvcs.authorization/runner-report/v1',
    contractVersion: contract.manifest.contractVersion,
    manifestSha256: contract.manifestSha256,
    registrySetSha256: contract.manifest.registrySetSha256,
    adapter: options.adapter === undefined ? 'reference-fixture' : 'external-adapter',
    vectors: rows.length,
    passed: rows.length - failed,
    failed,
    resultsSha256: sha256(Buffer.from(canonicalJson(rows), 'utf8')),
    rows,
  });
}
