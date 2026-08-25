import { canonicalDigest, canonicalJson, parseJson } from './canonical.mjs';
import { validateBenchmarkValue } from './contract.mjs';
import { BenchmarkHarnessError, asHarnessError } from './errors.mjs';
import { FakeRepositoryService, checkRepositoryInvariants } from './fake-service.mjs';
import { FaultScheduler, createFaultSchedule } from './faults.mjs';
import { HARNESS_LIMITS, checkedAdd } from './limits.mjs';
import { DeterministicCacheController } from './cache.mjs';
import { NetworkController } from './network.mjs';
import { snapshotOptions } from './input.mjs';

const CAPABILITIES = ['cache-control', 'deterministic-faults', 'invariant-check', 'lifecycle', 'metrics', 'task-execution'];

const RETRYABLE = new Set(['HARNESS_RETRYABLE', 'HARNESS_TASK_INCOMPLETE', 'HARNESS_DEADLINE_EXCEEDED', 'HARNESS_CANCELLED', 'HARNESS_IO']);

function result(id, code, output, mutationCount, trace) {
  return { schemaVersion: 'ogvcs.benchmark/driver-result/v1', id, result: code === 'HARNESS_OK' ? 'accept' : 'reject', code, preMutation: mutationCount === 0, mutationCount, retryable: RETRYABLE.has(code), output: output ?? null, trace };
}

function trace(sequence, operation, code, mutationCount, detail = {}) { return [{ schemaVersion: 'ogvcs.benchmark/driver-trace-event/v1', sequence, operation, phase: 'complete', code, preMutation: mutationCount === 0, mutationCount, detail }]; }

async function* lines(stream, maximum) {
  let pending = Buffer.alloc(0); let total = 0;
  for await (const raw of stream) {
    const chunk = Buffer.from(raw); total = checkedAdd(total, chunk.length, 'driver input stream bytes');
    if (total > HARNESS_LIMITS.maxStreamBytes) throw new BenchmarkHarnessError('HARNESS_LIMIT_EXCEEDED', 'driver input stream bound exceeded');
    pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
    while (true) {
      const newline = pending.indexOf(10); if (newline < 0) break;
      if (newline === 0 || newline > maximum || pending[newline - 1] === 13) throw new BenchmarkHarnessError('HARNESS_PROTOCOL_MALFORMED', 'driver input line framing is invalid');
      const line = pending.subarray(0, newline); pending = pending.subarray(newline + 1);
      yield parseJson(line, { requireCanonical: true, maxBytes: maximum });
    }
    if (pending.length > maximum) throw new BenchmarkHarnessError('HARNESS_LIMIT_EXCEEDED', 'driver input line bound exceeded');
  }
  if (pending.length) throw new BenchmarkHarnessError('HARNESS_PROTOCOL_MALFORMED', 'driver input lacks terminal LF');
}

export async function serveFakeDriver(contract, options = {}) {
  options = snapshotOptions(options, 'fake driver options');
  const input = options.input ?? process.stdin; const output = options.output ?? process.stdout;
  const incompatible = options.incompatible === true;
  const hello = {
    schemaVersion: 'ogvcs.benchmark/driver-hello/v1', driverId: 'ogvcs.benchmark/fake-driver@1', contractManifestSha256: contract.manifestSha256,
    protocolProfile: 'ogvcs.control.https-json@1', testProfile: 'ogvcs.benchmark-fault-driver.test@1', versions: incompatible ? [99] : [1],
    capabilities: incompatible ? CAPABILITIES.slice(0, -1) : CAPABILITIES, maximumMessageBytes: HARNESS_LIMITS.maxControlMessageBytes, mutationCount: 0, faultHooksEnabled: false,
  };
  if (options.malformedHello) output.write('{}\n'); else if (options.oversizedHello) output.write(`${'x'.repeat(HARNESS_LIMITS.maxControlMessageBytes + 1)}\n`); else output.write(`${canonicalJson(hello)}\n`);
  if (options.stderr) process.stderr.write('driver-stderr-forbidden\n');
  if (incompatible || options.malformedHello || options.oversizedHello || options.stderr) { for await (const _ of input) { /* drain until terminated */ } return; }
  let phase = 'hello'; let sequence = 0; let service = new FakeRepositoryService(); let cache = new DeterministicCacheController(); let network; let retried = false;
  const idempotency = new Map();
  for await (const raw of lines(input, HARNESS_LIMITS.maxControlMessageBytes)) {
    sequence += 1;
    let command; let response;
    try {
      command = validateBenchmarkValue(contract, 'DriverCommand.schema.json', raw);
      const requestDigest = canonicalDigest(command, 'ogvcs.benchmark/driver-command/v1');
      const prior = idempotency.get(command.idempotencyKey);
      if (prior) {
        if (prior.requestDigest !== requestDigest) throw new BenchmarkHarnessError('HARNESS_INPUT_INVALID', 'driver idempotency key was reused');
        response = prior.response;
      } else if (options.retryOnceOperation === command.operation && !retried) {
        retried = true; response = result(command.id, 'HARNESS_RETRYABLE', null, 0, trace(sequence, command.operation, 'HARNESS_RETRYABLE', 0));
      } else {
        let value = null; let mutations = 0;
        if (command.operation === 'negotiate') {
          if (phase !== 'hello' || command.payload.contractManifestSha256 !== contract.manifestSha256 || command.payload.version !== 1 || command.payload.testMode !== true || CAPABILITIES.some((name) => !command.payload.requiredCapabilities.includes(name))) throw new BenchmarkHarnessError('HARNESS_NEGOTIATION_INCOMPATIBLE', 'driver negotiation differs');
          phase = 'negotiated'; value = { selectedVersion: 1, testMode: true, capabilities: CAPABILITIES };
        } else {
          if (phase === 'hello') throw new BenchmarkHarnessError('HARNESS_NEGOTIATION_INCOMPATIBLE', 'driver command preceded negotiation');
          if (phase === 'stopped') throw new BenchmarkHarnessError('HARNESS_TASK_INCOMPLETE', 'driver command followed lifecycle stop');
          switch (command.operation) {
            case 'configure': {
              if (!['negotiated', 'configured'].includes(phase)) throw new BenchmarkHarnessError('HARNESS_TASK_INCOMPLETE', 'driver cannot be configured after start');
              const profile = contract.registries.networks.entries.find(({ id }) => id === command.payload.networkProfile);
              if (!profile || profile.mode === 'privileged') throw new BenchmarkHarnessError('HARNESS_INPUT_INVALID', 'fake driver configuration is invalid');
              cache.prepare(command.payload.cacheState); network = new NetworkController(profile); phase = 'configured'; value = { configured: true }; break;
            }
            case 'reset-cache': if (phase !== 'configured') throw new BenchmarkHarnessError('HARNESS_TASK_INCOMPLETE', 'cache reset requires configuration'); value = cache.prepare(command.payload.state); break;
            case 'start': if (phase !== 'configured') throw new BenchmarkHarnessError('HARNESS_TASK_INCOMPLETE', 'driver start requires configuration'); service = new FakeRepositoryService(); phase = 'started'; value = { started: true }; break;
            case 'run-task': {
              if (phase !== 'started') throw new BenchmarkHarnessError('HARNESS_TASK_INCOMPLETE', 'driver is not started');
              const taskInput = { ...(command.payload.input ?? {}), cache, network };
              const taskResult = await service.executeTask(command.payload.taskId, taskInput); mutations = taskResult.mutationCount; value = taskResult; break;
            }
            case 'arm-fault': {
              if (phase !== 'started') throw new BenchmarkHarnessError('HARNESS_TASK_INCOMPLETE', 'fault arming requires a started test session');
              const schedule = createFaultSchedule(command.payload.seed, [command.payload.faultPoint], { count: 1, actions: [command.payload.action], shuffle: false });
              service.setFaultScheduler(new FaultScheduler(schedule)); value = { scheduleDigest: schedule.scheduleDigest, armed: true }; break;
            }
            case 'check-invariants': if (phase !== 'started') throw new BenchmarkHarnessError('HARNESS_TASK_INCOMPLETE', 'invariant check requires a started test session'); value = checkRepositoryInvariants(service); break;
            case 'stop': phase = 'stopped'; value = { stopped: true }; break;
            default: throw new BenchmarkHarnessError('HARNESS_INPUT_INVALID', 'driver operation is unsupported');
          }
        }
        response = result(command.id, 'HARNESS_OK', value, mutations, trace(sequence, command.operation, 'HARNESS_OK', mutations));
        idempotency.set(command.idempotencyKey, { requestDigest, response });
      }
    } catch (error) {
      const failure = asHarnessError(error, 'HARNESS_DRIVER_FAILED');
      const id = command?.id ?? raw?.id ?? 'command-invalid';
      response = result(id, failure.code, null, 0, trace(sequence, command?.operation ?? 'negotiate', failure.code, 0));
    }
    output.write(`${canonicalJson(validateBenchmarkValue(contract, 'DriverResult.schema.json', response))}\n`);
  }
}
