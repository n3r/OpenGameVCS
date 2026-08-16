import { randomBytes, randomInt } from 'node:crypto';
import { spawn } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalBytes, canonicalJson, parseJson, sha256 } from './canonical.mjs';
import {
  assertNoProtectedAdapterOutput,
  collectProtocolScenarios,
  protectedAdapterOutputForms,
  PROTOCOL_OPERATIONS,
  runProtocolConformance,
  scenarioForAdapter,
} from './conformance.mjs';
import { RUNTIME_ERROR_CODES, ProtocolBaselineError, protocolError } from './errors.mjs';
import { executeReferenceProtocolCase } from './evaluator.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';
import { validateProtocolValue } from './schema.mjs';

function adapterDescriptor(input) {
  if (Array.isArray(input)) input = { command: input[0], args: input.slice(1) };
  if (!input || typeof input !== 'object' || Array.isArray(input)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'adapter descriptor must be an object or command array');
  const keys = Object.keys(input).sort();
  if (keys.some((key) => !['args', 'command', 'env'].includes(key)) || typeof input.command !== 'string' || input.command.length === 0 || input.command.length > 16_384 || input.command.includes('\0')) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'adapter command is invalid');
  const args = input.args ?? [];
  if (!Array.isArray(args) || args.length > 255 || args.some((item) => typeof item !== 'string' || item.length > 16_384 || item.includes('\0'))) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'adapter arguments are invalid');
  const env = input.env ?? {};
  if (env === null || typeof env !== 'object' || Array.isArray(env) || Object.entries(env).length > 128 || Object.entries(env).some(([name, value]) => !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) || typeof value !== 'string' || value.length > 65_536 || value.includes('\0'))) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'adapter environment is invalid');
  return { command: input.command, args: [...args], env };
}

function minimalEnvironment(extra, authorityRoot) {
  const output = { ...extra, OGVCS_PROTOCOL_AUTHORITY_ROOT: authorityRoot };
  for (const name of ['PATH', 'PATHEXT', 'SystemRoot', 'WINDIR', 'ComSpec', 'TMPDIR', 'TMP', 'TEMP']) if (process.env[name] !== undefined && output[name] === undefined) output[name] = process.env[name];
  return output;
}

async function terminate(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  if (process.platform === 'win32' && child.pid) {
    await new Promise((resolve) => {
      const killer = spawn('taskkill', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' });
      killer.once('error', resolve);
      killer.once('close', resolve);
    });
  } else {
    try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* already gone */ } }
  }
}

function writeBytes(writable, bytes) {
  return new Promise((resolve, reject) => {
    const onError = (error) => { cleanup(); reject(error); };
    const cleanup = () => writable.removeListener('error', onError);
    writable.once('error', onError);
    writable.write(bytes, (error) => { cleanup(); error ? reject(error) : resolve(); });
  });
}

function closeInput(writable) {
  return new Promise((resolve, reject) => {
    const onError = (error) => { cleanup(); reject(error); };
    const cleanup = () => writable.removeListener('error', onError);
    writable.once('error', onError);
    writable.end(() => { cleanup(); resolve(); });
  });
}

async function collectCanonicalLines(stream, settings, state) {
  const rows = [];
  let pending = Buffer.alloc(0);
  let totalBytes = 0;
  let retainedBytes = 0;
  try {
    for await (const rawChunk of stream) {
      const chunk = Buffer.from(rawChunk);
      totalBytes += chunk.length;
      if (!Number.isSafeInteger(totalBytes) || totalBytes > settings.maximumBytes) {
        state.failure ??= new ProtocolBaselineError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'adapter stdout ceiling exceeded');
        await terminate(state.child);
        throw state.failure;
      }
      if (pending.length + chunk.length > settings.maximumLineBytes + 1 && !chunk.includes(0x0a)) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter output line exceeds its ceiling');
      pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk], pending.length + chunk.length);
      while (true) {
        const newline = pending.indexOf(0x0a);
        if (newline === -1) break;
        if (newline === 0 || newline > settings.maximumLineBytes || pending[newline - 1] === 0x0d) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter output line is empty or oversized');
        const line = pending.subarray(0, newline);
        pending = pending.subarray(newline + 1);
        let text;
        try { text = new TextDecoder('utf-8', { fatal: true }).decode(line); } catch (error) { protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter output is not UTF-8', { cause: error }); }
        assertNoProtectedAdapterOutput(text, settings.protectedForms, settings.deadline);
        let value;
        try { value = parseJson(line, { requireCanonical: true, maxBytes: settings.maximumLineBytes, deadline: settings.deadline }); } catch (error) { protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter output is not canonical bounded JSON', { cause: error }); }
        retainedBytes += 1024 + line.length * 4;
        if (!Number.isSafeInteger(retainedBytes) || retainedBytes + pending.length > settings.maximumWorkingBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'adapter decoded-output working-memory ceiling exceeded');
        rows.push({ value, text });
        if (rows.length > settings.maximumLines) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter returned too many protocol lines');
      }
      if (pending.length > settings.maximumLineBytes) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter output line exceeds its ceiling');
    }
  } catch (error) {
    if (error?.code?.startsWith?.('PROTOCOL_')) {
      // A protocol violation discovered in authenticated stdout is the
      // primary failure. Killing a hostile writer may make Node emit an
      // incidental EPIPE stack on stderr; that secondary output must not
      // hide the disclosure/shape error that caused termination.
      state.failure = error;
      await terminate(state.child);
      throw state.failure;
    }
    if (state.failure) throw state.failure;
    protocolError(RUNTIME_ERROR_CODES.ADAPTER_FAILED, 'adapter stdout could not be read', { cause: error });
  }
  if (pending.length !== 0) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter output does not end with LF');
  return rows;
}

async function requireEmptyStderr(stream, maximum, state) {
  let total = 0;
  try {
    for await (const chunk of stream) {
      total += chunk.length;
      if (!Number.isSafeInteger(total) || total > maximum) state.failure ??= new ProtocolBaselineError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'adapter stderr ceiling exceeded');
      else if (chunk.length > 0) state.failure ??= new ProtocolBaselineError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'successful adapters must not emit stderr');
      await terminate(state.child);
    }
  } catch (error) {
    if (state.failure) throw state.failure;
    protocolError(RUNTIME_ERROR_CODES.ADAPTER_FAILED, 'adapter stderr could not be read', { cause: error });
  }
  return total;
}

function opaqueHandle(seen) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const value = `case-${randomBytes(16).toString('hex')}`;
    if (!seen.has(value)) { seen.add(value); return value; }
  }
  protocolError(RUNTIME_ERROR_CODES.IO, 'cannot allocate an opaque adapter case handle');
}

function shuffled(values) {
  const output = [...values];
  for (let index = output.length - 1; index > 0; index -= 1) {
    const selected = randomInt(index + 1);
    [output[index], output[selected]] = [output[selected], output[index]];
  }
  return output;
}

async function stageAuthority(contract) {
  if (typeof contract?.root !== 'string' || !contract.root.startsWith('file:')) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'external conformance requires a local authenticated contract');
  const sourceRoot = fileURLToPath(new URL('./', contract.root));
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-protocol-authority-'));
  const copy = async (path) => {
    if (typeof path !== 'string' || path.includes('..') || path.startsWith('/') || path.includes('\\')) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'adapter authority path is unsafe');
    const destination = join(root, path);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(join(sourceRoot, path), destination);
  };
  try {
    await copy('manifest.json');
    await copy('adapter-execution-view.json');
    const viewBytes = await readFile(join(root, 'adapter-execution-view.json'));
    const view = parseJson(viewBytes, { requireCanonical: true, maxBytes: HARD_LIMITS.jsonBytes });
    const binding = contract.manifest.adapterExecutionView;
    if (binding !== undefined && (binding?.path !== 'adapter-execution-view.json' || binding.bytes !== viewBytes.length || binding.sha256 !== sha256(viewBytes))) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'adapter execution view manifest binding is invalid');
    const expected = contract.manifest.artifacts
      .filter((entry) => /^(?:profiles|registries|schemas)\//u.test(entry.path))
      .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
    const supplied = Array.isArray(view.authorityArtifacts)
      ? [...view.authorityArtifacts].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
      : undefined;
    if (view.schemaVersion !== 'ogvcs.protocol/adapter-execution-view/v1'
        || view.contractManifestPath !== 'manifest.json'
        || view.contractVersion !== contract.manifest.contractVersion
        || view.license !== 'MIT'
        || canonicalJson(view.predecessorPins) !== canonicalJson(contract.manifest.predecessorPins)
        || supplied === undefined
        || canonicalJson(supplied) !== canonicalJson(expected)
        || view.authoritySetSha256 !== binding?.authoritySetSha256
        || canonicalJson(view.excludedNamespaces) !== '["docs/","vectors/"]') protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'adapter execution view does not bind the exact authority inventory');
    for (const entry of view.authorityArtifacts) await copy(entry.path);
    return await realpath(root);
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function isolatedDescriptor(descriptor, authorityRoot, options) {
  const args = [...descriptor.args];
  const marker = args.indexOf('--contract');
  if (marker !== -1) {
    if (marker + 1 >= args.length || args.indexOf('--contract', marker + 1) !== -1) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'adapter contract argument is invalid');
    args[marker + 1] = authorityRoot;
  }
  const executable = basename(descriptor.command).toLowerCase();
  const isNodeAdapter = executable === 'node' || executable === 'node.exe' || descriptor.command === process.execPath;
  if (options.nodeAdapterReadRoots === undefined) {
    return { ...descriptor, args: isNodeAdapter ? ['--no-warnings', ...args] : args };
  }
  if (!isNodeAdapter) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'nodeAdapterReadRoots requires a Node adapter command');
  }
  if (!Array.isArray(options.nodeAdapterReadRoots) || options.nodeAdapterReadRoots.length < 1 || options.nodeAdapterReadRoots.length > 8
      || options.nodeAdapterReadRoots.some((root) => typeof root !== 'string' || !isAbsolute(root) || root.length > 16_384 || root.includes('\0'))) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'nodeAdapterReadRoots is invalid');
  }
  let canonicalRoots;
  try {
    canonicalRoots = await Promise.all(options.nodeAdapterReadRoots.map((root) => realpath(root)));
  } catch (error) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'nodeAdapterReadRoots must identify existing accessible paths', { cause: error });
  }
  const canonicalArgs = await Promise.all(args.map(async (argument) => {
    if (!isAbsolute(argument)) return argument;
    try { return await realpath(argument); } catch { return argument; }
  }));
  const permissionArgs = [
    '--no-warnings',
    '--permission',
    ...[...new Set([...canonicalRoots, authorityRoot])].map((root) => `--allow-fs-read=${root}`),
  ];
  return { ...descriptor, args: [...permissionArgs, ...canonicalArgs] };
}

export async function runReferenceProtocolConformance(contract, options = {}) {
  return runProtocolConformance(contract, executeReferenceProtocolCase, { ...options, adapterId: options.adapterId ?? 'ogvcs.protocol/reference-js@1' });
}

export async function runExternalProtocolConformance(contract, adapter, options = {}) {
  const originalDescriptor = adapterDescriptor(adapter);
  const deadline = deadlineFrom(options);
  const scenarios = collectProtocolScenarios(contract, options);
  const handles = new Set();
  const executions = shuffled(scenarios.map((scenario) => {
    const opaqueId = opaqueHandle(handles);
    const runnerCase = { ...scenarioForAdapter(scenario, contract, { deadline }), id: opaqueId };
    return { opaqueId, runnerCase, scenario };
  }));
  const protectedForms = protectedAdapterOutputForms(contract, scenarios, deadline);
  const byOpaque = new Map(executions.map((value) => [value.opaqueId, value]));
  const maxStdoutBytes = boundedInteger(options.maxStdoutBytes, HARD_LIMITS.adapterStdoutBytes, HARD_LIMITS.adapterStdoutBytes, 'maxStdoutBytes');
  const maxStderrBytes = boundedInteger(options.maxStderrBytes, HARD_LIMITS.adapterStderrBytes, HARD_LIMITS.adapterStderrBytes, 'maxStderrBytes');
  const maxLineBytes = boundedInteger(options.maxLineBytes, HARD_LIMITS.jsonBytes, HARD_LIMITS.jsonBytes, 'maxLineBytes');
  const authorityRoot = await stageAuthority(contract);
  try {
    const descriptor = await isolatedDescriptor(originalDescriptor, authorityRoot, options);
    const child = spawn(descriptor.command, descriptor.args, {
      cwd: authorityRoot,
      detached: process.platform !== 'win32',
      env: minimalEnvironment(descriptor.env, authorityRoot),
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const state = { child, failure: undefined };
    child.stdin.on('error', () => {
      state.failure ??= new ProtocolBaselineError(RUNTIME_ERROR_CODES.ADAPTER_FAILED, 'adapter input could not be written');
    });
    const stdoutPromise = collectCanonicalLines(child.stdout, {
      deadline,
      maximumBytes: maxStdoutBytes,
      maximumLineBytes: maxLineBytes,
      maximumLines: executions.length + 1,
      maximumWorkingBytes: HARD_LIMITS.stateBytes,
      protectedForms,
    }, state);
    const stderrPromise = requireEmptyStderr(child.stderr, maxStderrBytes, state);
    const closePromise = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); });
    const writePromise = (async () => {
      for (const execution of executions) {
        deadline.checkpoint();
        const bytes = canonicalBytes(execution.runnerCase, { maxBytes: maxLineBytes, deadline });
        if (bytes.length + 1 > maxLineBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'adapter input line ceiling exceeded');
        await deadline.race(writeBytes(child.stdin, Buffer.concat([bytes, Buffer.from('\n')])), 'adapter input write');
      }
      await deadline.race(closeInput(child.stdin), 'adapter input close');
    })().catch(async (error) => {
      const failure = error?.code?.startsWith?.('PROTOCOL_')
        ? error
        : new ProtocolBaselineError(RUNTIME_ERROR_CODES.ADAPTER_FAILED, 'adapter input could not be written');
      state.failure ??= failure;
      await terminate(child);
      return undefined;
    });
    let status;
    let lines;
    let stderrBytes;
    try {
      [status, lines, stderrBytes] = await deadline.race(Promise.all([closePromise, stdoutPromise, stderrPromise, writePromise]).then(([closed, output, errorBytes]) => [closed, output, errorBytes]), 'adapter process');
    } catch (error) {
      await terminate(child);
      if (error?.code?.startsWith?.('PROTOCOL_')) throw error;
      protocolError(RUNTIME_ERROR_CODES.ADAPTER_FAILED, 'adapter process failed', { cause: error });
    }
    if (state.failure) throw state.failure;
    if (status.code !== 0 || status.signal !== null || stderrBytes !== 0) protocolError(RUNTIME_ERROR_CODES.ADAPTER_FAILED, 'adapter process exited unsuccessfully', { details: { exitCode: status.code ?? -1, stderrBytes } });
    if (lines.length !== executions.length + 1) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter returned the wrong number of protocol lines');
    let hello;
    try { hello = validateProtocolValue(contract, 'RunnerHello.schema.json', lines[0].value, { deadline }); } catch (error) { protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter handshake is invalid', { cause: error }); }
    if (hello.contractManifestSha256 !== contract.manifestSha256 || options.expectedAdapterId !== undefined && hello.adapterId !== options.expectedAdapterId) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter handshake does not bind the requested contract or identity');
    const supported = new Set(hello.operations);
    if (PROTOCOL_OPERATIONS.some((operation) => !supported.has(operation))) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter handshake omits a required operation');
    const byStableId = new Map();
    for (const line of lines.slice(1)) {
      let row;
      try { row = validateProtocolValue(contract, 'AdapterResult.schema.json', line.value, { deadline }); } catch (error) { protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter result is invalid', { cause: error }); }
      const execution = byOpaque.get(row.id);
      if (!execution || byStableId.has(execution.scenario.id)) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter results are missing, duplicated, or use an unknown opaque handle');
      byStableId.set(execution.scenario.id, { ...row, id: execution.scenario.id });
    }
    return runProtocolConformance(contract, async (runnerCase) => {
      const row = byStableId.get(runnerCase.id);
      if (!row) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter omitted a scenario result');
      return row;
    }, { ...options, adapterId: hello.adapterId });
  } finally {
    await rm(authorityRoot, { recursive: true, force: true });
  }
}
