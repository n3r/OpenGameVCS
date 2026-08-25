import { Writable } from 'node:stream';

import { verifyTransferGrant } from '@opengamevcs/authorization-contract';

import {
  base64urlDecode, canonicalBytes, cloneJson, inspectJson, parseJson,
} from './canonical.mjs';
import { CursorStore } from './cursors.mjs';
import { validateRequestEnvelope, validateResponseEnvelope } from './envelopes.mjs';
import { ProtocolBaselineError, ProtocolSemanticError, RUNTIME_ERROR_CODES, protocolSemanticError } from './errors.mjs';
import {
  loadAuthorizationGrantContract, validateCompactTransferGrant,
} from './grants.mjs';
import {
  IdempotencyReplayStore, requestIdempotencyProjection, semanticIdempotencyFingerprint,
  validateIdempotencyKeyBinding,
} from './idempotency.mjs';
import { HARD_LIMITS, PROTOCOL_LIMITS_BY_NAME, deadlineFrom } from './limits.mjs';
import { ProtocolNegotiator } from './negotiation.mjs';
import { validatePageEnvelope } from './pages.mjs';
import { ProtocolProblemCatalog } from './problems.mjs';
import { NegotiationReceiptCodec, validateNegotiationServerNonce } from './receipts.mjs';
import { validateReleasePreflight } from './release.mjs';
import { validateProtocolValue } from './schema.mjs';
import { parseCanonicalStream, writeCanonicalStream } from './streams.mjs';
import {
  validateTransferHttpRangeCarrier, validateTransferProbeResult,
} from './transfer.mjs';

const EMPTY_TRACE = Object.freeze({ responseBody: null, responseHeaders: [], streamFrames: [], logEntries: [], semanticOutput: null });
const AUTHORIZATION_SCHEMAS = { promise: undefined };
const TRANSFER_PROBE_SCHEMA_VERSION = 'ogvcs.protocol/transfer-probe/v1';
const TRANSFER_PROBE_NON_GRANT_SCHEMA_VERSION = 'ogvcs.protocol/transfer-probe-non-grant-input/v1';

class CaseReject extends Error {
  constructor(code, options = {}) {
    super('protocol conformance case rejected');
    this.code = code;
    this.mutationCount = options.mutationCount ?? 0;
    this.trace = options.trace;
  }
}

function reject(code, options) { throw new CaseReject(code, options); }

function adapterResult(id, code, options = {}) {
  const mutationCount = options.mutationCount ?? 0;
  return Object.freeze({
    schemaVersion: 'ogvcs.protocol/adapter-result/v1', id,
    result: code === 'NONE' ? 'accept' : 'reject', code,
    preMutation: mutationCount === 0, mutationCount,
    trace: options.trace ?? EMPTY_TRACE,
  });
}

function traceFor(code, tracker, overrides = {}) {
  return {
    responseBody: overrides.responseBody ?? null,
    responseHeaders: overrides.responseHeaders ?? [],
    streamFrames: overrides.streamFrames ?? [],
    logEntries: overrides.logEntries ?? [],
    semanticOutput: overrides.semanticOutput ?? { code, exercisedLimits: tracker.exercised() },
  };
}

class LimitTracker {
  #configured;
  #seen = new Set();

  constructor(configured) { this.#configured = configured ?? {}; }

  cap(name) { return this.#configured[name] ?? PROTOCOL_LIMITS_BY_NAME[name]; }

  observe(name, value) {
    if (!Object.hasOwn(PROTOCOL_LIMITS_BY_NAME, name) || !Number.isSafeInteger(value) || value < 0) reject('INTERNAL_ERROR');
    if (Object.hasOwn(this.#configured, name)) this.#seen.add(name);
    if (value > this.cap(name)) {
      const error = new ProtocolBaselineError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `${name} receiver ceiling exceeded`);
      error.limitTracker = this;
      throw error;
    }
    return value;
  }

  requireConfiguredRoutes() {
    for (const name of Object.keys(this.#configured)) if (!this.#seen.has(name)) reject('INTERNAL_ERROR');
  }

  route(name) { this.#seen.add(name); }

  exercised() { return [...this.#seen].sort(); }
}

function jsonSummary(value) {
  let nodes = 0;
  let collectionItems = 0;
  let depth = 0;
  let objectMembers = 0;
  let arrayItems = 0;
  let stringBytes = 0;
  let keyBytes = 0;
  const stack = [{ value, depth: 0 }];
  while (stack.length > 0) {
    const current = stack.pop();
    nodes += 1;
    depth = Math.max(depth, current.depth);
    if (typeof current.value === 'string') stringBytes = Math.max(stringBytes, Buffer.byteLength(current.value, 'utf8'));
    else if (Array.isArray(current.value)) {
      arrayItems = Math.max(arrayItems, current.value.length);
      collectionItems += current.value.length;
      for (const child of current.value) stack.push({ value: child, depth: current.depth + 1 });
    } else if (current.value && typeof current.value === 'object') {
      const entries = Object.entries(current.value);
      objectMembers = Math.max(objectMembers, entries.length);
      collectionItems += entries.length;
      for (const [key, child] of entries) {
        keyBytes = Math.max(keyBytes, Buffer.byteLength(key, 'utf8'));
        stack.push({ value: child, depth: current.depth + 1 });
      }
    }
  }
  return { nodes, collectionItems, depth, objectMembers, arrayItems, stringBytes, keyBytes };
}

function materializeConfigured(supplied, tracker, elapsedMs) {
  const names = Object.keys(supplied.configuredLimits ?? {});
  if (names.length === 0) return;
  const input = supplied.input;
  const document = input.document;
  const summary = document === undefined ? undefined : jsonSummary(document);
  for (const name of names) {
    switch (name) {
      case 'maxControlMessageBytes': tracker.observe(name, Buffer.byteLength(input.rawInput, 'utf8')); break;
      case 'maxCanonicalInputBytes': {
        const raw = input.rawInputs[0];
        tracker.observe(name, Buffer.byteLength(raw, 'utf8'));
        parseJson(raw, { maxBytes: tracker.cap(name) });
        break;
      }
      case 'maxJsonDepth': tracker.observe(name, summary.depth); inspectJson(document, { maxDepth: tracker.cap(name) }); break;
      case 'maxJsonNodes': tracker.observe(name, summary.nodes); inspectJson(document, { maxNodes: tracker.cap(name) }); break;
      case 'maxObjectMembers': tracker.observe(name, summary.objectMembers); inspectJson(document, { maxObjectMembers: tracker.cap(name) }); break;
      case 'maxArrayItems': tracker.observe(name, summary.arrayItems); inspectJson(document, { maxArrayItems: tracker.cap(name) }); break;
      case 'maxStringUtf8Bytes': tracker.observe(name, summary.stringBytes); inspectJson(document, { maxStringBytes: tracker.cap(name) }); break;
      case 'maxJsonKeyUtf8Bytes': tracker.observe(name, summary.keyBytes); inspectJson(document, { maxKeyBytes: tracker.cap(name) }); break;
      case 'maxJsonCollectionItems': tracker.observe(name, summary.collectionItems); inspectJson(document, { maxCollectionItems: tracker.cap(name) }); break;
      case 'maxWorkingMemoryBytes': tracker.observe(name, 128 + (4 * Buffer.byteLength(input.rawInput, 'utf8'))); break;
      case 'maxSchemaEvaluationSteps': tracker.route(name); break;
      case 'maxExtensionEntries': tracker.observe(name, Object.keys(document.extensions ?? {}).length); break;
      case 'maxCapabilityItems': tracker.observe(name, Math.max(...Object.values(input.offer.capabilities).map((axis) => axis.length))); break;
      case 'maxErrorParameters': tracker.observe(name, document.parameters?.length ?? 0); break;
      case 'maxPageItems': tracker.observe(name, document.items?.length ?? 0); break;
      case 'maxJsonlFrameBytes': {
        const lengths = input.jsonl.slice(0, -1).split('\n').map((line) => Buffer.byteLength(line, 'utf8'));
        tracker.observe(name, Math.max(...lengths)); break;
      }
      case 'maxJsonlFrames': tracker.observe(name, input.frames.length); break;
      case 'maxJsonlStreamBytes': tracker.observe(name, Buffer.byteLength(input.jsonl, 'utf8')); break;
      case 'maxCursorBytes': tracker.observe(name, Buffer.byteLength(input.suppliedToken, 'utf8')); break;
      case 'maxIdempotencyKeyBytes': tracker.observe(name, Buffer.byteLength(input.idempotencyKey, 'utf8')); break;
      case 'maxGrantBytes': tracker.observe(name, base64urlDecode(input.probe.grant.envelope, { maxBytes: HARD_LIMITS.grantBytes }).length); break;
      case 'maxTransferRangeBytes': tracker.observe(name, input.transportResponse.rangeBytes); break;
      case 'maxHeaderBytes': tracker.observe(name, input.headers.reduce((total, header) => total + Buffer.byteLength(header.name, 'utf8') + Buffer.byteLength(header.value, 'utf8') + 4, 0)); break;
      case 'maxCorrelationIdBytes': tracker.observe(name, Buffer.byteLength(document.correlationId, 'utf8')); break;
      case 'maxOperationBytes': tracker.observe(name, Buffer.byteLength(document.operation, 'utf8')); break;
      case 'maxRunnerCases': tracker.observe(name, input.cases.length); break;
      case 'maxSafeParameterBytes': tracker.observe(name, Buffer.byteLength(document.parameters[0].value, 'utf8')); break;
      case 'maxDeadlineHorizonMs': tracker.observe(name, document.deadlineUnixMs - input.atUnixMs); break;
      case 'maxReceiptLifetimeMs': tracker.observe(name, input.receiptLifetimeMs); break;
      case 'maxCursorLifetimeMs': tracker.observe(name, input.ttlMs); break;
      case 'maxRegistryEntries': tracker.observe(name, input.registryEntries.length); break;
      case 'maxOperationTimeMs': tracker.observe(name, elapsedMs); break;
      case 'maxContractArtifacts': tracker.observe(name, input.artifacts.length); break;
      case 'maxContractBytes': tracker.observe(name, input.artifacts.reduce((total, artifact) => total + artifact.bytesHex.length / 2, 0)); break;
      case 'maxReceiptBytes': tracker.route(name); break;
      default: reject('INTERNAL_ERROR');
    }
  }
}

function executionElapsed(control) {
  const samples = control?.clockSamplesUnixMs;
  if (!Array.isArray(samples) || samples.length === 0) reject('PROTOCOL_MALFORMED');
  let previous = samples[0];
  if (!Number.isSafeInteger(previous) || previous < 0) reject('PROTOCOL_MALFORMED');
  for (let index = 1; index < samples.length; index += 1) {
    const current = samples[index];
    if (!Number.isSafeInteger(current) || current < previous) reject('PROTOCOL_MALFORMED');
    previous = current;
  }
  const elapsedMs = previous - samples[0];
  if (!Number.isSafeInteger(elapsedMs) || elapsedMs < 0) reject('PROTOCOL_MALFORMED');
  return elapsedMs;
}

function controlFor(supplied) {
  const controller = new AbortController();
  if (supplied.control.cancellation === 'before-operation') controller.abort();
  const samples = supplied.control.clockSamplesUnixMs;
  const elapsedMs = executionElapsed(supplied.control);
  const origin = samples[0];
  let index = 0;
  const now = () => samples[Math.min(index++, samples.length - 1)] - origin;
  const timeoutMs = supplied.configuredLimits?.maxOperationTimeMs ?? HARD_LIMITS.timeoutMs;
  return { controller, deadline: deadlineFrom({ signal: controller.signal, timeoutMs, now }), elapsedMs };
}

function envelopeDocument(input, tracker, deadline) {
  const common = {
    maxBytes: tracker.cap('maxControlMessageBytes'), maxDepth: tracker.cap('maxJsonDepth'),
    maxNodes: tracker.cap('maxJsonNodes'), maxObjectMembers: tracker.cap('maxObjectMembers'),
    maxArrayItems: tracker.cap('maxArrayItems'), maxStringBytes: tracker.cap('maxStringUtf8Bytes'),
    maxKeyBytes: tracker.cap('maxJsonKeyUtf8Bytes'), maxCollectionItems: tracker.cap('maxJsonCollectionItems'),
    maxWorkingMemoryBytes: tracker.cap('maxWorkingMemoryBytes'), deadline,
  };
  if (input.encoding === 'semantic-json') return cloneJson(input.document, common);
  const bytes = input.encoding === 'raw-hex' ? Buffer.from(input.rawInput, 'hex') : input.rawInput;
  if (input.encoding === 'raw-hex' && Buffer.from(bytes).toString('hex') !== input.rawInput) reject('PROTOCOL_MALFORMED');
  return parseJson(bytes, common);
}

function validateEnvelope(contract, supplied, tracker, deadline) {
  const input = supplied.input;
  const document = envelopeDocument(input, tracker, deadline);
  const schemaOptions = { maxSteps: tracker.cap('maxSchemaEvaluationSteps'), deadline };
  if (input.targetSchema === 'JsonValue') {
    const definitions = contract.schemas['EnvelopeCaseInput.schema.json']?.$defs;
    if (!definitions?.JsonValue) reject('INTERNAL_ERROR');
    validateProtocolValue(contract, { ...definitions.JsonValue, $defs: definitions }, document, schemaOptions);
  }
  if (input.route === 'authorize') {
    validateRequestEnvelope(contract, document, { ...schemaOptions, atUnixMs: input.atUnixMs });
    // Protected server context is deliberately available to this policy path,
    // but only the registry-owned safe problem is made observable.
    inspectJson(supplied.serverContext ?? {}, { maxDepth: 8, maxNodes: 256, deadline });
    const catalog = new ProtocolProblemCatalog(contract);
    const code = input.authorizationDecision === 'error' ? 'INTERNAL_ERROR' : 'AUTHORIZATION_DENIED';
    const response = catalog.response(code, { correlationId: document.correlationId });
    reject(code, { trace: traceFor(code, tracker, { responseBody: response }) });
  }
  if (input.targetSchema === 'RequestEnvelope') {
    validateRequestEnvelope(contract, document, {
      ...schemaOptions, atUnixMs: input.atUnixMs, contentEncoding: input.contentEncoding,
      maxExtensionEntries: tracker.cap('maxExtensionEntries'),
      redirectStatus: input.redirectStatus ?? (input.originChanged ? 302 : undefined),
      allowSameOriginRedirect: input.allowSameOriginRedirect,
      selectedExtensions: input.selectedExtensions,
      originChanged: input.originChanged, mutation: input.method === 'POST',
    });
  } else if (input.targetSchema === 'ResponseEnvelope') {
    validateResponseEnvelope(contract, document, { ...schemaOptions, httpStatus: input.httpStatus, selectedExtensions: input.selectedExtensions });
  } else if (input.targetSchema === 'ProblemDetails') {
    new ProtocolProblemCatalog(contract).validate(document, {
      ...(input.httpStatus === undefined ? {} : { status: input.httpStatus }),
      headers: input.headers,
    }, schemaOptions);
  } else if (input.targetSchema === 'PageEnvelope') {
    validatePageEnvelope(contract, document, { ...schemaOptions, maxItems: tracker.cap('maxPageItems') });
  } else if (input.targetSchema === 'JsonValue') {
    inspectJson(document, { deadline });
  } else {
    validateProtocolValue(contract, `${input.targetSchema}.schema.json`, document, schemaOptions);
  }
  return traceFor('NONE', tracker, {
    semanticOutput: input.targetSchema === 'JsonValue'
      ? document
      : { targetSchema: input.targetSchema, validated: true },
  });
}

async function negotiate(contract, supplied, tracker, deadline) {
  const input = supplied.input;
  if (input.transportScheme !== 'https' || input.tlsVersion !== '1.3') reject('NEGOTIATION_DOWNGRADE_REJECTED');
  const key = base64urlDecode(input.receiptKeyBase64url, { maxBytes: 64 });
  const serverNonce = validateNegotiationServerNonce(input.serverNonce);
  const codec = new NegotiationReceiptCodec({
    contract, key, keyId: input.receiptKeyId, now: () => input.issueAtUnixMs,
    maxBytes: tracker.cap('maxReceiptBytes'), maxTtlMs: tracker.cap('maxReceiptLifetimeMs'),
  });
  if (input.route === 'verify-receipt') {
    const claims = {
      schemaVersion: 'ogvcs.protocol/negotiation-receipt-claims/v1', selection: input.serverSelection,
      ...input.principal, clientNonce: input.offer.clientNonce, serverNonce: input.serverNonce,
      issuedAtUnixMs: input.issueAtUnixMs, expiresAtUnixMs: input.issueAtUnixMs + input.receiptLifetimeMs,
    };
    let receipt = codec.issue(claims, { atUnixMs: input.issueAtUnixMs, deadline });
    if (input.receiptMacXor !== 0) {
      const mac = Buffer.from(receipt.mac, 'base64url');
      mac[0] ^= input.receiptMacXor;
      receipt = { ...receipt, mac: mac.toString('base64url') };
    }
    try {
      codec.verify(receipt, { ...input.verificationPrincipal, selection: input.verificationSelection }, { atUnixMs: input.verifyAtUnixMs, deadline });
    } catch (error) {
      if (error?.details?.reason === 'expired') reject('NEGOTIATION_RECEIPT_EXPIRED');
      reject('NEGOTIATION_RECEIPT_INVALID');
    }
    return traceFor('NONE', tracker, { semanticOutput: input.verificationSelection });
  }
  const order = [];
  const negotiator = new ProtocolNegotiator({
    contract, receiptCodec: codec, receiptTtlMs: input.receiptLifetimeMs,
    maxCapabilityItems: tracker.cap('maxCapabilityItems'),
    minimumCapabilities: input.minimumCapabilities, now: () => input.issueAtUnixMs,
    randomBytes: () => serverNonce,
    authenticate: async (_offer, _context) => { order.push('authenticate'); return input.principal; },
    repositoryRequirements: async () => { order.push('repository'); return { requiredCapabilities: [] }; },
  });
  const negotiated = await negotiator.negotiate(input.offer, {}, { deadline });
  if (order.join(',') !== 'authenticate,repository') reject('AUTHORIZATION_DENIED');
  if (Object.hasOwn(supplied.configuredLimits ?? {}, 'maxReceiptBytes')) tracker.observe('maxReceiptBytes', canonicalBytes(negotiated.receipt).length);
  return traceFor('NONE', tracker, { semanticOutput: negotiated.selection });
}

async function fingerprint(contract, supplied, tracker, deadline) {
  const input = supplied.input;
  if (input.algorithm !== 'OGVCS-SEMANTIC-JCS-SHA-256') reject('PROTOCOL_MALFORMED');
  for (const raw of input.rawInputs) parseJson(raw, { maxBytes: tracker.cap('maxCanonicalInputBytes'), deadline });
  const projections = input.projections.map((value) => validateProtocolValue(
    contract, 'IdempotencyProjectionInput.schema.json', value, { deadline },
  ));
  if (input.route === 'idempotency' && (input.retryableMutation !== true || input.idempotencyKey.length === 0)) reject('PROTOCOL_MALFORMED');
  if (input.retryableMutation && input.idempotencyKey.length === 0) reject('IDEMPOTENCY_KEY_REQUIRED');
  if (input.idempotencyKey.length > 0) {
    validateIdempotencyKeyBinding(input.idempotencyKey, input.idempotencyIssuedAtUnixMs, input.idempotencyExpiresAtUnixMs);
  }
  if (input.route === 'fingerprint') {
    const projected = projections.map((value) => requestIdempotencyProjection(value));
    const digests = projected.map((value) => semanticIdempotencyFingerprint(value, { deadline }));
    return { trace: traceFor('NONE', tracker, { semanticOutput: { fingerprints: digests } }), mutationCount: 0 };
  }
  if (input.attemptProjectionIndexes.some((index) => index >= projections.length)) reject('PROTOCOL_MALFORMED');
  const projected = input.attemptProjectionIndexes.map((index) => projections[index]);
  const fingerprints = projected.map((value) => semanticIdempotencyFingerprint(value, { deadline }));
  if (fingerprints.some((value) => value !== fingerprints[0])) reject('IDEMPOTENCY_KEY_REUSE');
  let now = input.idempotencyIssuedAtUnixMs;
  const store = new IdempotencyReplayStore({
    maxEntries: 4, maxBytes: 64 * 1024, maxOutcomeBytes: 1024,
    tombstoneTtlMs: input.tombstoneRetentionMs, now: () => now,
  });
  const scope = { operation: 'mutation', repository: 'repository', subject: 'subject', tenant: 'tenant' };
  let mutationCount = 0;
  if (Object.hasOwn(supplied.configuredLimits ?? {}, 'maxIdempotencyKeyBytes')) {
    // Exercise the public key parser/state preflight without publishing a
    // mutation reservation under this receiver-limit scenario.
    const first = store.begin({ scope, key: input.idempotencyKey, fingerprint: fingerprints[0] }, { deadline, atUnixMs: now });
    store.abort(first.lease);
    return { trace: traceFor('NONE', tracker, { semanticOutput: { keyPreflight: true } }), mutationCount: 0 };
  }
  const identity = { scope, key: input.idempotencyKey, fingerprint: fingerprints[0] };
  let firstExecution = false;
  try {
    if (input.attemptSchedule.includes('begin-mutation')) {
      if (input.attemptAuthorizationDecisions[0] !== 'allow') reject('AUTHORIZATION_DENIED');
      try {
        await store.execute(identity, async () => {
          mutationCount += 1;
          return { ok: true };
        }, {
          deadline,
          afterCommit: input.attemptSchedule.includes('lose-response') ? async () => { throw new Error('response lost'); } : undefined,
        });
      } catch (error) {
        if (!input.attemptSchedule.includes('lose-response')) throw error;
      }
    }
    if (input.attemptSchedule.includes('deadline')) {
      reject('DEADLINE_EXCEEDED', { mutationCount, trace: traceFor('DEADLINE_EXCEEDED', tracker) });
    }
    if (input.attemptSchedule.includes('retry')) {
      now = input.atUnixMs;
      const decision = input.attemptAuthorizationDecisions[1] ?? input.attemptAuthorizationDecisions[0];
      if (!input.attemptSchedule.includes('begin-mutation') && decision !== 'allow') reject('AUTHORIZATION_DENIED');
      const replay = await store.execute(identity, async () => {
        mutationCount += 1;
        firstExecution = true;
        return { ok: true };
      }, {
        deadline,
        atUnixMs: now,
        authorizeReplay: async (_binding, { signal }) => {
          if (signal.aborted || decision !== 'allow') protocolSemanticError('AUTHORIZATION_DENIED', 'idempotency replay authorization was denied');
          return { result: 'allow', code: 'ALLOW_EXPLICIT' };
        },
      });
      const expectedKind = input.attemptSchedule.includes('begin-mutation') ? 'replay' : 'committed';
      if (replay.kind !== expectedKind || mutationCount !== 1) reject('INTERNAL_ERROR');
    }
  } catch (error) {
    if (error instanceof ProtocolSemanticError) reject(error.code, { mutationCount, trace: traceFor(error.code, tracker) });
    if (error instanceof ProtocolBaselineError && error.code === RUNTIME_ERROR_CODES.STATE_CONFLICT) reject('INTERNAL_ERROR', { mutationCount });
    throw error;
  }
  return {
    trace: traceFor('NONE', tracker, {
      semanticOutput: firstExecution ? { firstExecution: true, replay: false } : { replay: true },
    }),
    mutationCount,
  };
}

function cursor(contract, supplied, tracker, deadline) {
  const input = supplied.input;
  if (input.route === 'validate-page') {
    validatePageEnvelope(contract, input.page, { maxItems: tracker.cap('maxPageItems'), deadline });
    return traceFor('NONE', tracker, { semanticOutput: { state: input.page.state, itemCount: input.page.items.length } });
  }
  if (input.route === 'validate-token') {
    tracker.observe('maxCursorBytes', Buffer.byteLength(input.suppliedToken, 'utf8'));
    validateProtocolValue(contract, 'Cursor.schema.json', { token: input.suppliedToken }, { deadline });
    return traceFor('NONE', tracker, { semanticOutput: { tokenAccepted: true } });
  }
  if (input.ttlMs > Number.MAX_SAFE_INTEGER - input.issuedAtUnixMs) reject('PROTOCOL_MALFORMED');
  validateProtocolValue(contract, 'CursorScopeInput.schema.json', input.issueScope, { deadline });
  validateProtocolValue(contract, 'CursorScopeInput.schema.json', input.readScope, { deadline });
  let random = 1;
  const store = new CursorStore({
    now: () => input.issuedAtUnixMs, ttlMs: input.ttlMs,
    tombstoneRetentionMs: input.tombstoneRetentionMs,
    randomBytes: () => Buffer.alloc(32, random++),
  });
  const issued = store.issue({ scope: input.issueScope, generation: input.generation, position: 0 }, { atUnixMs: input.issuedAtUnixMs });
  let token = input.tokenSource === 'supplied' ? input.suppliedToken : issued.token;
  if (input.tokenMutation === 'tamper') token = `${token.slice(0, -1)}${token.endsWith('A') ? 'B' : 'A'}`;
  if (input.tokenMutation === 'unknown') token = `c1.${Buffer.alloc(32, 99).toString('base64url')}`;
  if (supplied.serverContext !== undefined) inspectJson(supplied.serverContext, { maxDepth: 8, maxNodes: 256, deadline });
  if (input.minimumRetainedGeneration > input.generation) store.markGap(token, 'generation-changed');
  try {
    const output = store.read(token, input.readScope, { atUnixMs: input.readAtUnixMs });
    return traceFor('NONE', tracker, { semanticOutput: output });
  } catch (error) {
    if (error instanceof ProtocolSemanticError) reject(error.code);
    const reason = error?.details?.reason;
    if (reason === 'expired') reject('CURSOR_EXPIRED');
    if (reason === 'scope') reject('CURSOR_SCOPE_MISMATCH');
    if (reason === 'gap' || reason === 'generation') reject('CURSOR_GAP');
    reject('CURSOR_INVALID');
  }
}

async function stream(contract, supplied, tracker, deadline, controller) {
  const input = supplied.input;
  const options = {
    contract, maxLineBytes: tracker.cap('maxJsonlFrameBytes'), maxFrames: tracker.cap('maxJsonlFrames'),
    maxBytes: tracker.cap('maxJsonlStreamBytes'), maxWorkingMemoryBytes: tracker.cap('maxWorkingMemoryBytes'), deadline,
  };
  if (input.route === 'parse') {
    const parsed = parseCanonicalStream(input.jsonl, options);
    return traceFor('NONE', tracker, { streamFrames: parsed.frames, semanticOutput: parsed.summary });
  }
  const chunks = [];
  const destination = new Writable({ write(chunk, _encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); } });
  const frames = supplied.control.cancellation === 'after-first-stream-frame'
    ? {
        *[Symbol.iterator]() {
          for (let index = 0; index < input.frames.length; index += 1) {
            if (index === 1) controller.abort();
            yield input.frames[index];
          }
        },
      }
    : input.frames;
  for (const frame of input.frames) {
    const value = validateProtocolValue(contract, 'StreamFrame.schema.json', frame, { deadline });
    if (value.kind === 'gap' && value.problem?.code !== 'CURSOR_GAP') reject('PROTOCOL_MALFORMED');
  }
  try {
    await writeCanonicalStream(frames, destination, options);
  } catch (error) {
    if (error?.code === RUNTIME_ERROR_CODES.STREAM_INCOMPLETE) reject('STREAM_INCOMPLETE');
    if (error?.details?.reason === 'gapProblem') reject('PROTOCOL_MALFORMED');
    if (error?.code === RUNTIME_ERROR_CODES.INPUT_INVALID) reject('STREAM_SEQUENCE_INVALID');
    throw error;
  }
  const parsed = parseCanonicalStream(Buffer.concat(chunks), options);
  return traceFor('NONE', tracker, { streamFrames: parsed.frames, semanticOutput: parsed.summary });
}

async function authorizationSchemas(deadline) {
  AUTHORIZATION_SCHEMAS.promise ??= loadAuthorizationGrantContract();
  return deadline.race(AUTHORIZATION_SCHEMAS.promise, 'authorization grant schema load');
}

function transferProbeNonGrant(contract, input, deadline) {
  if (input?.schemaVersion !== TRANSFER_PROBE_SCHEMA_VERSION) reject('PROTOCOL_MALFORMED');
  const projection = { ...(input ?? {}) };
  delete projection.grant;
  projection.schemaVersion = TRANSFER_PROBE_NON_GRANT_SCHEMA_VERSION;
  return validateProtocolValue(contract, 'TransferProbeNonGrantInput.schema.json', projection, { deadline });
}

async function transfer(contract, supplied, tracker, deadline) {
  const input = supplied.input;
  if (!input.certificateValid || !input.hostnameMatches
      || input.proxyMode === 'connect' && (!input.proxyConfigured || input.connectResult !== 'success')
      || input.proxyMode === 'direct' && input.proxyConfigured && input.connectResult === 'bypassed') reject('PROTOCOL_UNSUPPORTED');
  if (typeof input.probe?.contentEncoding === 'string' && input.probe.contentEncoding !== 'identity') reject('COMPRESSION_FORBIDDEN');
  const probe = transferProbeNonGrant(contract, input.probe, deadline);
  if (input.responseStatus >= 300 && input.responseStatus < 400 && probe.operation === 'write') reject('REDIRECT_FORBIDDEN');
  if (probe.endOffsetExclusive !== undefined && probe.endOffsetExclusive <= probe.startOffset) reject('TRANSFER_RANGE_INVALID');
  if (input.route === 'probe' && probe.startOffset > 0 && probe.validatorTag === undefined) reject('TRANSFER_VALIDATOR_MISMATCH');
  if (input.route === 'http-range'
      && (!input.transportResponse || typeof input.transportResponse !== 'object' || Array.isArray(input.transportResponse)
        || !Number.isSafeInteger(input.transportResponse.totalBytes) || input.transportResponse.totalBytes < 0
        || !Number.isSafeInteger(input.transportResponse.rangeBytes) || input.transportResponse.rangeBytes < 0)) {
    reject('PROTOCOL_MALFORMED');
  }
  const requestedBytes = probe.endOffsetExclusive === undefined
    ? input.transportResponse.rangeBytes
    : probe.endOffsetExclusive - probe.startOffset;
  tracker.observe('maxTransferRangeBytes', requestedBytes);
  tracker.observe('maxTransferRangeBytes', input.transportResponse.rangeBytes);
  if (input.grantLocation !== 'header' || input.logGrant) reject('TRANSFER_GRANT_INVALID');
  if (!input.probe.grant || typeof input.probe.grant !== 'object' || Array.isArray(input.probe.grant)
      || !Number.isSafeInteger(input.probe.grant.explicitObjectCount)
      || input.probe.grant.explicitObjectCount !== 0) reject('TRANSFER_GRANT_INVALID');
  try {
    const schemas = await authorizationSchemas(deadline);
    const verify = (envelope, context) => verifyTransferGrant(envelope, context, input.authorizationPublicJwk);
    await validateCompactTransferGrant(contract, schemas, input.probe.grant, verify, input.authorizationContext, { deadline });
  } catch (error) {
    if (error?.code === RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED
        || error?.code === RUNTIME_ERROR_CODES.CANCELLED
        || error?.code === RUNTIME_ERROR_CODES.LIMIT_EXCEEDED) throw error;
    reject('TRANSFER_GRANT_INVALID');
  }
  if (input.route === 'validate-result') {
    const value = validateTransferProbeResult(contract, input.probeResult, { deadline });
    return traceFor('NONE', tracker, { semanticOutput: value });
  }
  if (input.route === 'http-range') {
    const value = validateTransferHttpRangeCarrier(contract, {
      probe: input.probe,
      requestHeaders: input.requestHeaders,
      responseHeaders: input.responseHeaders,
      responseStatus: input.responseStatus,
      responseBodyHex: input.responseBodyHex,
      transportResponse: input.transportResponse,
    }, {
      deadline,
      maxHeaderBytes: tracker.cap('maxHeaderBytes'),
      maxRangeBytes: tracker.cap('maxTransferRangeBytes'),
      maxWorkingMemoryBytes: tracker.cap('maxWorkingMemoryBytes'),
    });
    return traceFor('NONE', tracker, { semanticOutput: value });
  }
  let headerValidator;
  if (input.transportResponse.etagHeader !== undefined) {
    const match = /^"([A-Za-z0-9._~-]{16,256})"$/u.exec(input.transportResponse.etagHeader);
    if (!match) reject('TRANSFER_VALIDATOR_MISMATCH');
    headerValidator = match[1];
  }
  let headerDigest;
  if (input.transportResponse.contentDigestHeader !== undefined) {
    const match = /^sha-256=:([A-Za-z0-9+/]{43}=):$/u.exec(input.transportResponse.contentDigestHeader);
    if (!match) reject('TRANSFER_VALIDATOR_MISMATCH');
    const bytes = Buffer.from(match[1], 'base64');
    if (bytes.length !== 32 || bytes.toString('base64') !== match[1]) reject('TRANSFER_VALIDATOR_MISMATCH');
    headerDigest = bytes.toString('hex');
  }
  if (input.digestMatches === false
      || input.probe.startOffset === 0 && input.probe.validatorTag !== undefined && headerValidator === undefined
      || headerValidator !== undefined && input.probe.validatorTag !== headerValidator
      || headerDigest !== undefined && input.probe.expectedSha256 !== headerDigest) reject('TRANSFER_VALIDATOR_MISMATCH');
  if (input.transportResponse.interruptedAt !== undefined && input.transportResponse.resumeAt !== input.transportResponse.interruptedAt) reject('TRANSFER_RANGE_INVALID');
  return traceFor('NONE', tracker, { semanticOutput: { acceptedStart: input.probe.startOffset, rangeBytes: input.transportResponse.rangeBytes } });
}

function contractLoad(input, tracker) {
  if (input.route === 'inventory') {
    let total = 0;
    for (const artifact of input.artifacts) {
      const bytes = Buffer.from(artifact.bytesHex, 'hex');
      if (bytes.toString('hex') !== artifact.bytesHex) reject('PROTOCOL_MALFORMED');
      total += bytes.length;
      if (!Number.isSafeInteger(total)) reject('PROTOCOL_LIMIT_EXCEEDED');
    }
    return traceFor('NONE', tracker, { semanticOutput: { artifacts: input.artifacts.length, bytes: total } });
  }
  for (const entry of input.registryEntries) inspectJson(entry);
  return traceFor('NONE', tracker, { semanticOutput: { registryEntries: input.registryEntries.length } });
}

function runnerBatch(input, tracker) {
  const ids = new Set();
  for (const row of input.cases) {
    if (ids.has(row.id)) reject('PROTOCOL_MALFORMED');
    ids.add(row.id);
  }
  return traceFor('NONE', tracker, { semanticOutput: { cases: input.cases.length } });
}

function releasePreflight(contract, input, tracker, deadline) {
  const result = validateReleasePreflight(contract, input, { deadline });
  return traceFor('NONE', tracker, { semanticOutput: result });
}

function wireCode(error) {
  if (error instanceof CaseReject || error instanceof ProtocolSemanticError) return error.code;
  if (!(error instanceof ProtocolBaselineError)) return 'INTERNAL_ERROR';
  switch (error.code) {
    case RUNTIME_ERROR_CODES.INPUT_INVALID: return 'PROTOCOL_MALFORMED';
    case RUNTIME_ERROR_CODES.LIMIT_EXCEEDED: return 'PROTOCOL_LIMIT_EXCEEDED';
    case RUNTIME_ERROR_CODES.STREAM_INCOMPLETE: return 'STREAM_INCOMPLETE';
    case RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED: return 'DEADLINE_EXCEEDED';
    case RUNTIME_ERROR_CODES.CANCELLED: return 'CANCELLED';
    default: return 'INTERNAL_ERROR';
  }
}

export async function executeReferenceProtocolCase(supplied, context = {}) {
  const contract = context.contract;
  let tracker;
  let caseId = 'case-00000000000000000000000000000000';
  let trace = EMPTY_TRACE;
  let mutationCount = 0;
  let code = 'NONE';
  try {
    supplied = validateProtocolValue(contract, 'RunnerCase.schema.json', supplied, context);
    caseId = supplied.id;
    tracker = new LimitTracker(supplied.configuredLimits);
    const control = controlFor(supplied);
    if (control.controller.signal.aborted) control.deadline.checkpoint();
    if (!Object.hasOwn(supplied.configuredLimits ?? {}, 'maxOperationTimeMs')
        && control.elapsedMs >= HARD_LIMITS.timeoutMs) reject('DEADLINE_EXCEEDED');
    materializeConfigured(supplied, tracker, control.elapsedMs);
    control.deadline.checkpoint();
    switch (supplied.operation) {
      case 'negotiate': trace = await negotiate(contract, supplied, tracker, control.deadline); break;
      case 'validate-envelope': trace = validateEnvelope(contract, supplied, tracker, control.deadline); break;
      case 'fingerprint': ({ trace, mutationCount } = await fingerprint(contract, supplied, tracker, control.deadline)); break;
      case 'validate-cursor': trace = cursor(contract, supplied, tracker, control.deadline); break;
      case 'validate-stream': trace = await stream(contract, supplied, tracker, control.deadline, control.controller); break;
      case 'transfer-probe': trace = await transfer(contract, supplied, tracker, control.deadline); break;
      case 'contract-load': trace = contractLoad(supplied.input, tracker); break;
      case 'runner-batch': trace = runnerBatch(supplied.input, tracker); break;
      case 'release-preflight': trace = releasePreflight(contract, supplied.input, tracker, control.deadline); break;
      default: reject('PROTOCOL_UNSUPPORTED');
    }
    control.deadline.checkpoint();
    tracker.requireConfiguredRoutes();
  } catch (error) {
    tracker ??= new LimitTracker();
    code = wireCode(error);
    if (code === 'DEADLINE_EXCEEDED' && Object.hasOwn(supplied.configuredLimits ?? {}, 'maxOperationTimeMs')) code = 'PROTOCOL_LIMIT_EXCEEDED';
    mutationCount = error?.mutationCount ?? mutationCount;
    trace = error?.trace ?? traceFor(code, error?.limitTracker ?? tracker);
  }
  return adapterResult(caseId, code, { mutationCount, trace });
}
