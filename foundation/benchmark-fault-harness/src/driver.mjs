import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';

import { canonicalDigest, canonicalJson, deepFreeze, parseJson } from './canonical.mjs';
import { validateBenchmarkValue } from './contract.mjs';
import { BenchmarkHarnessError, harnessFail } from './errors.mjs';
import { HARNESS_LIMITS, HarnessDeadline, boundedInteger, checkedAdd } from './limits.mjs';
import { snapshotOptions } from './input.mjs';

const REQUIRED_CAPABILITIES = Object.freeze(['cache-control', 'deterministic-faults', 'invariant-check', 'lifecycle', 'metrics', 'task-execution']);
const MAX_DRIVER_OUTPUT_NODES = 20_000;

function wireValue(contract, schema, value, label) {
  try { return validateBenchmarkValue(contract, schema, value); }
  catch (error) { harnessFail('HARNESS_PROTOCOL_MALFORMED', `driver ${label} violates its registered schema`, { cause: error }); }
}

function assertSafeDriverOutput(value) {
  const forbidden = /(?:authorization|credential|password|private.?key|secret|session.?token|access.?token|refresh.?token|partnerId|studioId)/iu;
  const stack = [value]; let nodes = 0;
  while (stack.length) {
    const current = stack.pop(); nodes += 1;
    if (nodes > MAX_DRIVER_OUTPUT_NODES) harnessFail('HARNESS_LIMIT_EXCEEDED', 'driver output inspection exceeds its bound');
    if (Array.isArray(current)) {
      if (stack.length + current.length > MAX_DRIVER_OUTPUT_NODES) harnessFail('HARNESS_LIMIT_EXCEEDED', 'driver output inspection exceeds its bound');
      for (let index = current.length - 1; index >= 0; index -= 1) stack.push(current[index]);
    }
    else if (current !== null && typeof current === 'object') {
      const entries = Object.entries(current);
      if (stack.length + entries.length > MAX_DRIVER_OUTPUT_NODES) harnessFail('HARNESS_LIMIT_EXCEEDED', 'driver output inspection exceeds its bound');
      for (const [key, child] of entries) { if (forbidden.test(key)) harnessFail('HARNESS_PROTOCOL_MALFORMED', 'driver output disclosed a protected field'); stack.push(child); }
    }
  }
}

function descriptor(input) {
  try { input = JSON.parse(canonicalJson(input, { maxBytes: 1_048_576, maxWorkingMemoryBytes: 8_388_608 })); }
  catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'driver descriptor must be inert bounded canonical data', { cause: error }); }
  if (Array.isArray(input)) input = { command: input[0], args: input.slice(1) };
  if (!input || typeof input !== 'object' || Array.isArray(input) || typeof input.command !== 'string' || input.command.length < 1 || input.command.length > 16_384 || input.command.includes('\0')) harnessFail('HARNESS_INPUT_INVALID', 'driver descriptor is invalid');
  const keys = Object.keys(input).sort(); if (keys.some((key) => !['args', 'command', 'cwd', 'env'].includes(key))) harnessFail('HARNESS_INPUT_INVALID', 'driver descriptor contains an unknown field');
  const args = input.args ?? []; const env = input.env ?? {};
  if (!Array.isArray(args) || args.length > 255 || args.some((value) => typeof value !== 'string' || value.length > 16_384 || value.includes('\0'))) harnessFail('HARNESS_INPUT_INVALID', 'driver arguments are invalid');
  if (!env || typeof env !== 'object' || Array.isArray(env) || Object.entries(env).length > 128 || Object.entries(env).some(([name, value]) => !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) || typeof value !== 'string' || value.length > 65_536 || value.includes('\0'))) harnessFail('HARNESS_INPUT_INVALID', 'driver environment is invalid');
  if (input.cwd !== undefined && (typeof input.cwd !== 'string' || input.cwd.length < 1 || input.cwd.length > 16_384 || input.cwd.includes('\0') || !isAbsolute(input.cwd))) harnessFail('HARNESS_INPUT_INVALID', 'driver working directory must be an absolute bounded path');
  return { command: input.command, args: [...args], env: { ...env }, cwd: input.cwd };
}

function minimalEnvironment(extra, contract) {
  const output = { ...extra, OGVCS_BENCHMARK_CONTRACT_MANIFEST: contract.manifestSha256 };
  for (const name of ['PATH', 'PATHEXT', 'SystemRoot', 'WINDIR', 'ComSpec', 'TMPDIR', 'TMP', 'TEMP']) if (process.env[name] !== undefined && output[name] === undefined) output[name] = process.env[name];
  return output;
}

async function terminate(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  if (process.platform === 'win32' && child.pid) {
    await new Promise((resolve) => { const killer = spawn('taskkill', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' }); killer.once('error', resolve); killer.once('close', resolve); });
  } else { try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch {} } }
}

async function* canonicalLines(stream, settings, state) {
  let pending = Buffer.alloc(0);
  for await (const raw of stream) {
    const chunk = Buffer.from(raw); state.stdoutBytes = checkedAdd(state.stdoutBytes, chunk.length, 'driver stdout bytes');
    if (state.stdoutBytes > settings.maxStreamBytes) { state.failure ??= new BenchmarkHarnessError('HARNESS_LIMIT_EXCEEDED', 'driver stdout exceeds its configured bound'); await terminate(state.child); throw state.failure; }
    pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk], pending.length + chunk.length);
    while (true) {
      const newline = pending.indexOf(0x0a); if (newline < 0) break;
      if (newline > settings.maxMessageBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'driver output line exceeds its configured bound');
      if (newline === 0 || pending[newline - 1] === 0x0d) harnessFail('HARNESS_PROTOCOL_MALFORMED', 'driver output line is empty or CRLF framed');
      const line = pending.subarray(0, newline); pending = pending.subarray(newline + 1);
      let value; try { value = parseJson(line, { requireCanonical: true, maxBytes: settings.maxMessageBytes }); } catch (error) { harnessFail('HARNESS_PROTOCOL_MALFORMED', 'driver output is not bounded canonical JSON', { cause: error }); }
      yield { bytes: line.length, value };
    }
    if (pending.length > settings.maxMessageBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'driver output line exceeds its configured bound');
  }
  if (pending.length !== 0) harnessFail('HARNESS_PROTOCOL_MALFORMED', 'driver output does not end with LF');
}

function writeLine(stream, value, settings, state) {
  const bytes = Buffer.from(`${canonicalJson(value, { maxBytes: settings.maxMessageBytes, maxWorkingMemoryBytes: Math.min(HARNESS_LIMITS.maxWorkingMemoryBytes, settings.maxMessageBytes * 8) })}\n`);
  if (bytes.length > settings.maxMessageBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'driver command exceeds its configured bound');
  state.stdinBytes = checkedAdd(state.stdinBytes, bytes.length, 'driver stdin bytes');
  if (state.stdinBytes > settings.maxStreamBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'driver input stream exceeds its configured bound');
  return new Promise((resolve, reject) => stream.write(bytes, (error) => error ? reject(error) : resolve()));
}

export class ExternalDriverSession {
  #child; #iterator; #deadline; #settings; #state; #sequence = 0; #closed = false; #traceEvents = 0; #lastTraceSequence = -1; #results = []; #retainedResultBytes;
  constructor(child, iterator, deadline, settings, state, contract, hello, helloBytes) { this.#child = child; this.#iterator = iterator; this.#deadline = deadline; this.#settings = settings; this.#state = state; this.contract = contract; this.hello = hello; this.#retainedResultBytes = helloBytes * 8 + 256; }
  get results() { return deepFreeze([...this.#results]); }
  async #next(label) {
    const row = await this.#deadline.race(this.#iterator.next(), label);
    if (row.done) harnessFail('HARNESS_PROTOCOL_MALFORMED', `driver closed before ${label}`);
    return row.value;
  }
  async command(operation, payload = {}, options = {}) {
    options = snapshotOptions(options, 'driver command options');
    if (this.#closed) harnessFail('HARNESS_DRIVER_FAILED', 'driver session is closed');
    const sequence = checkedAdd(this.#sequence, 1, 'driver command sequence');
    const id = `command-${String(sequence).padStart(6, '0')}`;
    const basis = { operation, payload, sequence };
    let idempotencyKey;
    try { idempotencyKey = `ik-${canonicalDigest(basis, 'ogvcs.benchmark/driver-command/v1')}`; }
    catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'driver command must be inert bounded canonical data', { cause: error }); }
    const command = validateBenchmarkValue(this.contract, 'DriverCommand.schema.json', { schemaVersion: 'ogvcs.benchmark/driver-command/v1', id, version: 1, operation, idempotencyKey, payload });
    this.#sequence = sequence;
    const maximumAttempts = options.retry === false ? 1 : 2;
    let result;
    try {
      for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
        try { await this.#deadline.race(writeLine(this.#child.stdin, command, this.#settings, this.#state), 'driver input write'); }
        catch (error) { if (error instanceof BenchmarkHarnessError) throw error; harnessFail('HARNESS_DRIVER_FAILED', 'driver input could not be written', { cause: error }); }
        const resultRow = await this.#next('driver result');
        result = wireValue(this.contract, 'DriverResult.schema.json', resultRow.value, 'result');
        if (result.id !== id) harnessFail('HARNESS_PROTOCOL_MALFORMED', 'driver result identity differs from its command');
        const errorAuthority = this.contract.registries.errors.entries.find(({ name }) => name === result.code);
        if (!errorAuthority || result.result !== (result.code === 'HARNESS_OK' ? 'accept' : 'reject') || result.preMutation !== (result.mutationCount === 0) || result.retryable !== errorAuthority.retryable) harnessFail('HARNESS_PROTOCOL_MALFORMED', 'driver result, mutation, or retry witness is inconsistent');
        let traceSequence = this.#lastTraceSequence;
        if (result.trace.length < 1 || result.trace.some((event) => { const invalid = event.operation !== operation || event.sequence <= traceSequence; traceSequence = event.sequence; return invalid; }) || result.trace.at(-1).code !== result.code || result.trace.at(-1).mutationCount !== result.mutationCount) harnessFail('HARNESS_PROTOCOL_MALFORMED', 'driver trace is missing, out of order, or inconsistent with its result');
        this.#traceEvents = checkedAdd(this.#traceEvents, result.trace.length, 'driver trace events');
        if (this.#traceEvents > HARNESS_LIMITS.maxTraceEvents) harnessFail('HARNESS_LIMIT_EXCEEDED', 'driver trace exceeds its configured aggregate bound');
        this.#lastTraceSequence = result.trace.at(-1).sequence;
        assertSafeDriverOutput(result);
        const retained = checkedAdd(this.#retainedResultBytes, resultRow.bytes * 8 + 256, 'driver retained result bytes');
        if (checkedAdd(retained, this.#settings.maxMessageBytes * 8 + 256, 'driver aggregate working bytes') > HARNESS_LIMITS.maxWorkingMemoryBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'driver retained results exceed the aggregate working-memory bound');
        this.#retainedResultBytes = retained;
        this.#results.push(deepFreeze(result));
        if (!(result.retryable && attempt < maximumAttempts)) break;
      }
      return result;
    } catch (error) {
      this.#closed = true;
      await terminate(this.#child);
      throw error;
    }
  }
  async close(options = {}) {
    options = snapshotOptions(options, 'driver close options');
    if (this.#closed) return;
    try {
      if (options.sendStop !== false) {
        const stopped = await this.command('stop', {});
        if (stopped.result !== 'accept') harnessFail('HARNESS_DRIVER_FAILED', 'driver rejected lifecycle stop');
      }
      this.#closed = true;
      this.#child.stdin.end();
      const status = await this.#deadline.race(this.#state.close, 'driver close');
      const tail = await this.#deadline.race(this.#iterator.next(), 'driver output completion');
      if (!tail.done || this.#state.stderrBytes !== 0 || status.code !== 0 || status.signal !== null || this.#state.failure) harnessFail('HARNESS_DRIVER_FAILED', 'driver process did not complete cleanly');
    } catch (error) {
      this.#closed = true;
      await terminate(this.#child);
      throw error;
    }
  }
  async abort() { this.#closed = true; await terminate(this.#child); }
}

export async function startExternalDriver(adapter, contract, options = {}) {
  options = snapshotOptions(options, 'external driver options');
  const spec = descriptor(adapter); const deadline = new HarnessDeadline(options);
  const settings = { maxMessageBytes: boundedInteger(options.maxMessageBytes, HARNESS_LIMITS.maxControlMessageBytes, HARNESS_LIMITS.maxControlMessageBytes, 'maxMessageBytes'), maxStreamBytes: boundedInteger(options.maxStreamBytes, HARNESS_LIMITS.maxStreamBytes, HARNESS_LIMITS.maxStreamBytes, 'maxStreamBytes') };
  deadline.checkpoint();
  const child = spawn(spec.command, spec.args, { cwd: spec.cwd, detached: process.platform !== 'win32', env: minimalEnvironment(spec.env, contract), shell: false, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  const state = { child, stdinBytes: 0, stdoutBytes: 0, stderrBytes: 0, failure: undefined };
  state.close = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); });
  child.stderr.on('data', (chunk) => { state.stderrBytes += chunk.length; if (state.stderrBytes > 0) { state.failure ??= new BenchmarkHarnessError('HARNESS_PROTOCOL_MALFORMED', 'successful driver emitted stderr'); void terminate(child); } });
  const iterator = canonicalLines(child.stdout, settings, state)[Symbol.asyncIterator]();
  try {
    const helloRow = await deadline.race(iterator.next(), 'driver hello');
    if (helloRow.done) harnessFail('HARNESS_PROTOCOL_MALFORMED', 'driver omitted its hello');
    const hello = wireValue(contract, 'DriverHello.schema.json', helloRow.value.value, 'hello');
    const capabilities = new Set(hello.capabilities);
    if (hello.contractManifestSha256 !== contract.manifestSha256 || !hello.versions.includes(1) || REQUIRED_CAPABILITIES.some((name) => !capabilities.has(name)) || hello.mutationCount !== 0 || hello.faultHooksEnabled !== false) harnessFail('HARNESS_NEGOTIATION_INCOMPATIBLE', 'driver is incompatible before mutation');
    settings.maxMessageBytes = Math.min(settings.maxMessageBytes, hello.maximumMessageBytes);
    const session = new ExternalDriverSession(child, iterator, deadline, settings, state, contract, hello, helloRow.value.bytes);
    const negotiated = await session.command('negotiate', { contractManifestSha256: contract.manifestSha256, version: 1, requiredCapabilities: REQUIRED_CAPABILITIES, testMode: true }, { retry: false });
    if (negotiated.result !== 'accept' || negotiated.code !== 'HARNESS_OK' || negotiated.preMutation !== true || negotiated.mutationCount !== 0) harnessFail('HARNESS_NEGOTIATION_INCOMPATIBLE', 'driver rejected negotiation before mutation');
    return session;
  } catch (error) { await terminate(child); throw error; }
}

export async function runExternalDriverConformance(adapter, contract, options = {}) {
  options = snapshotOptions(options, 'driver conformance options');
  const session = await startExternalDriver(adapter, contract, options);
  try {
    const configure = await session.command('configure', { cacheState: 'cold', networkProfile: 'loopback-simulated' });
    const reset = await session.command('reset-cache', { state: 'cold' });
    const start = await session.command('start', {});
    const task = await session.command('run-task', { taskId: 'setup', input: { idempotencyKey: 'external-driver-task-setup' } });
    const fault = await session.command('arm-fault', { seed: 'external-driver-fault-v1', faultPoint: 'branch.cas', action: 'error' });
    const faultedTask = await session.command('run-task', { taskId: 'submit', input: { idempotencyKey: 'external-driver-faulted-submit', expectedHead: 'root', actor: 'operator-a', authorized: true, fileId: '00000000000000000000000000000001', logicalBytes: 4096, uniqueBytes: 3072 } }, { retry: false });
    const invariants = await session.command('check-invariants', {});
    await session.close();
    const results = session.results;
    const faultObserved = fault.output?.armed === true && faultedTask.output?.status === 'incomplete' && faultedTask.output?.code === 'HARNESS_RETRYABLE' && faultedTask.output?.mutationCount === 0 && faultedTask.output?.output?.injectedFault?.faultPoint === 'branch.cas' && invariants.output?.passed === true;
    const failed = results.filter(({ result }) => result !== 'accept').length + (configure.output?.configured === true && reset.output?.state === 'cold' && start.output?.started === true && task.output?.status === 'success' && faultObserved ? 0 : 1);
    return deepFreeze({ hello: session.hello, results, failed, faultObserved, traceDigest: canonicalDigest(results.flatMap(({ trace }) => trace), 'ogvcs.benchmark/driver-trace/v1') });
  } catch (error) { await session.abort(); throw error; }
}
