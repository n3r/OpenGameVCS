import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { verifyTransferGrant } from '@opengamevcs/authorization-contract';

import {
  AdapterFault,
  FROZEN_LIMITS,
  canonicalJson,
  configuredLimits,
  fail,
  inspectJson,
  parseCanonical,
  parseJson,
} from './core.mjs';

export const OPERATIONS = Object.freeze([
  'negotiate', 'validate-envelope', 'fingerprint', 'validate-cursor',
  'validate-stream', 'transfer-probe', 'contract-load', 'runner-batch',
  'release-preflight',
]);

const AXES = Object.freeze([
  ['protocolVersions', 'protocolVersion'],
  ['schemaVersions', 'messageSchemaVersion'],
  ['repositoryFormats', 'repositoryFormat'],
  ['authorizationContracts', 'authorizationContract'],
  ['pathContracts', 'pathContract'],
  ['pathProfiles', 'pathProfile'],
  ['eventVersions', 'eventVersion'],
  ['transferProfiles', 'transferProfile'],
]);
const NEW_SESSION_STATES = new Set(['candidate', 'ratified']);
const TERMINAL = new Set(['terminal', 'gap', 'cancelled', 'error']);
const RECEIPT_DOMAIN = Buffer.from('OGVCS-PROTOCOL-NEGOTIATION-RECEIPT-V1\0', 'ascii');
const FINGERPRINT_DOMAIN = Buffer.from('ogvcs.protocol/idempotency/v1\0', 'ascii');
const TRANSFER_PROBE_SCHEMA_VERSION = 'ogvcs.protocol/transfer-probe/v1';
const TRANSFER_PROBE_NON_GRANT_SCHEMA_VERSION = 'ogvcs.protocol/transfer-probe-non-grant-input/v1';
const EMPTY_TRACE = Object.freeze({
  responseBody: null,
  responseHeaders: [],
  streamFrames: [],
  logEntries: [],
  semanticOutput: null,
});
const SELECTION_FIELDS = Object.freeze([
  'protocolVersion', 'messageSchemaVersion', 'repositoryFormat',
  'authorizationContract', 'authorizationRegistrySha256', 'pathContract',
  'pathProfile', 'pathRegistrySha256', 'eventVersion', 'transferProfile',
  'protocolRegistrySetSha256', 'repositoryRegistrySha256',
]);

class SemanticReject extends Error {
  constructor(code, options = {}) {
    super('independent protocol evaluation rejected the case');
    this.code = code;
    this.mutationCount = options.mutationCount ?? 0;
    this.trace = options.trace;
  }
}

function reject(code, options) { throw new SemanticReject(code, options); }

function trace(code, tracker, options = {}) {
  return {
    responseBody: options.responseBody ?? null,
    responseHeaders: options.responseHeaders ?? [],
    streamFrames: options.streamFrames ?? [],
    logEntries: options.logEntries ?? [],
    semanticOutput: options.semanticOutput ?? { code, exercisedLimits: tracker.exercised() },
  };
}

function result(id, code, mutationCount, value) {
  return {
    schemaVersion: 'ogvcs.protocol/adapter-result/v1',
    id,
    result: code === 'NONE' ? 'accept' : 'reject',
    code,
    preMutation: mutationCount === 0,
    mutationCount,
    trace: value ?? EMPTY_TRACE,
  };
}

function bytesBase64url(value, maximum) {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(maximum * 4 / 3) + 4 || !/^[A-Za-z0-9_-]+$/u.test(value)) fail('invalid', 'base64url value is invalid');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length > maximum || bytes.toString('base64url') !== value) fail('invalid', 'base64url value is invalid');
  return bytes;
}

function same(left, right) { return canonicalJson(left) === canonicalJson(right); }
function sameSet(left, right) { return left.length === right.length && left.every((item) => right.includes(item)); }

class LimitTracker {
  #configured;
  #seen = new Set();

  constructor(value) { this.#configured = value ?? {}; }
  cap(name) { return this.#configured[name] ?? FROZEN_LIMITS[name]; }
  observe(name, value) {
    if (!Object.hasOwn(FROZEN_LIMITS, name) || !Number.isSafeInteger(value) || value < 0) fail('contract', 'invalid resource observation');
    if (Object.hasOwn(this.#configured, name)) this.#seen.add(name);
    if (value > this.cap(name)) fail('limit', `${name} ceiling exceeded`);
    return value;
  }
  route(name) { this.#seen.add(name); }
  finish() {
    for (const name of Object.keys(this.#configured)) if (!this.#seen.has(name)) fail('contract', `configured resource route was not exercised: ${name}`);
  }
  exercised() { return [...this.#seen].sort(); }
}

function jsonSummary(value) {
  const output = { depth: 0, nodes: 0, objectMembers: 0, arrayItems: 0, stringBytes: 0, keyBytes: 0, collectionItems: 0 };
  const pending = [{ value, depth: 0 }];
  while (pending.length > 0) {
    const current = pending.pop();
    output.nodes += 1;
    output.depth = Math.max(output.depth, current.depth);
    if (typeof current.value === 'string') output.stringBytes = Math.max(output.stringBytes, Buffer.byteLength(current.value, 'utf8'));
    else if (Array.isArray(current.value)) {
      output.arrayItems = Math.max(output.arrayItems, current.value.length);
      output.collectionItems += current.value.length;
      for (const child of current.value) pending.push({ value: child, depth: current.depth + 1 });
    } else if (current.value && typeof current.value === 'object') {
      const entries = Object.entries(current.value);
      output.objectMembers = Math.max(output.objectMembers, entries.length);
      output.collectionItems += entries.length;
      for (const [name, child] of entries) {
        output.keyBytes = Math.max(output.keyBytes, Buffer.byteLength(name, 'utf8'));
        pending.push({ value: child, depth: current.depth + 1 });
      }
    }
  }
  return output;
}

function configuredResourceRoutes(supplied, tracker, authority, elapsedMs) {
  const names = Object.keys(supplied.configuredLimits ?? {});
  if (names.length === 0) return;
  const input = supplied.input;
  const document = input.document;
  const summary = document === undefined ? undefined : jsonSummary(document);
  for (const name of names) {
    switch (name) {
      case 'maxControlMessageBytes': tracker.observe(name, Buffer.byteLength(input.rawInput, 'utf8')); parseJson(input.rawInput, { maxControlMessageBytes: tracker.cap(name) }); break;
      case 'maxCanonicalInputBytes': tracker.observe(name, Buffer.byteLength(input.rawInputs[0], 'utf8')); parseCanonical(input.rawInputs[0], { maxCanonicalInputBytes: tracker.cap(name) }); break;
      case 'maxJsonDepth': tracker.observe(name, summary.depth); inspectJson(document, { maxJsonDepth: tracker.cap(name) }); break;
      case 'maxJsonNodes': tracker.observe(name, summary.nodes); inspectJson(document, { maxJsonNodes: tracker.cap(name) }); break;
      case 'maxObjectMembers': tracker.observe(name, summary.objectMembers); inspectJson(document, { maxObjectMembers: tracker.cap(name) }); break;
      case 'maxArrayItems': tracker.observe(name, summary.arrayItems); inspectJson(document, { maxArrayItems: tracker.cap(name) }); break;
      case 'maxStringUtf8Bytes': tracker.observe(name, summary.stringBytes); inspectJson(document, { maxStringUtf8Bytes: tracker.cap(name) }); break;
      case 'maxJsonKeyUtf8Bytes': tracker.observe(name, summary.keyBytes); inspectJson(document, { maxJsonKeyUtf8Bytes: tracker.cap(name) }); break;
      case 'maxJsonCollectionItems': tracker.observe(name, summary.collectionItems); inspectJson(document, { maxJsonCollectionItems: tracker.cap(name) }); break;
      case 'maxWorkingMemoryBytes': {
        const measured = 128 + 4 * Buffer.byteLength(input.rawInput, 'utf8');
        tracker.observe(name, measured);
        parseJson(input.rawInput, { maxControlMessageBytes: tracker.cap('maxControlMessageBytes'), maxWorkingMemoryBytes: tracker.cap(name) });
        break;
      }
      case 'maxSchemaEvaluationSteps': {
        tracker.route(name);
        const definitions = authority.schemas['EnvelopeCaseInput.schema.json']?.$defs;
        authority.validator.validate(document, { ...definitions.JsonValue, $defs: definitions }, { configuredLimits: { maxSchemaEvaluationSteps: tracker.cap(name) } });
        break;
      }
      case 'maxExtensionEntries': tracker.observe(name, Object.keys(document.extensions ?? {}).length); break;
      case 'maxCapabilityItems': tracker.observe(name, Math.max(...Object.values(input.offer.capabilities).map((axis) => axis.length))); authority.validator.validate(input.offer, 'NegotiationOffer.schema.json'); break;
      case 'maxErrorParameters': tracker.observe(name, document.parameters?.length ?? 0); authority.validator.validate(document, 'ProblemDetails.schema.json'); break;
      case 'maxPageItems': tracker.observe(name, document.items?.length ?? 0); authority.validator.validate(document, 'PageEnvelope.schema.json'); break;
      case 'maxJsonlFrameBytes': tracker.observe(name, Math.max(...input.jsonl.slice(0, -1).split('\n').map((line) => Buffer.byteLength(line, 'utf8')))); break;
      case 'maxJsonlFrames': tracker.observe(name, input.frames.length); break;
      case 'maxJsonlStreamBytes': tracker.observe(name, Buffer.byteLength(input.jsonl, 'utf8')); break;
      case 'maxCursorBytes': tracker.observe(name, Buffer.byteLength(input.suppliedToken, 'utf8')); authority.validator.validate({ token: input.suppliedToken }, 'Cursor.schema.json'); break;
      case 'maxIdempotencyKeyBytes': tracker.observe(name, Buffer.byteLength(input.idempotencyKey, 'utf8')); break;
      case 'maxReceiptBytes': tracker.route(name); break;
      case 'maxGrantBytes':
        // This configured-resource preflight measures only the opaque encoded
        // predecessor envelope. Carrier shape and semantics belong to the
        // transfer grant stage below, so they must not be selected here.
        tracker.observe(name, bytesBase64url(input.probe.grant.envelope, FROZEN_LIMITS.maxGrantBytes).length);
        break;
      case 'maxTransferRangeBytes': tracker.observe(name, input.transportResponse.rangeBytes); break;
      case 'maxHeaderBytes': tracker.observe(name, input.headers.reduce((sum, header) => sum + Buffer.byteLength(header.name, 'utf8') + Buffer.byteLength(header.value, 'utf8') + 4, 0)); break;
      case 'maxCorrelationIdBytes': tracker.observe(name, Buffer.byteLength(document.correlationId, 'utf8')); break;
      case 'maxOperationBytes': tracker.observe(name, Buffer.byteLength(document.operation, 'utf8')); break;
      case 'maxRunnerCases': tracker.observe(name, input.cases.length); break;
      case 'maxSafeParameterBytes': tracker.observe(name, Buffer.byteLength(document.parameters[0].value, 'utf8')); break;
      case 'maxDeadlineHorizonMs': tracker.observe(name, document.deadlineUnixMs - input.atUnixMs); break;
      case 'maxReceiptLifetimeMs': tracker.observe(name, input.receiptLifetimeMs); break;
      case 'maxCursorLifetimeMs': tracker.observe(name, input.ttlMs); break;
      case 'maxRegistryEntries': tracker.observe(name, input.registryEntries.length); break;
      case 'maxOperationTimeMs': {
        tracker.route(name);
        if (elapsedMs >= tracker.cap(name)) fail('limit', 'operation time ceiling exceeded');
        break;
      }
      case 'maxContractArtifacts': tracker.observe(name, input.artifacts.length); break;
      case 'maxContractBytes': tracker.observe(name, input.artifacts.reduce((sum, item) => sum + item.bytesHex.length / 2, 0)); break;
      default: fail('contract', `no independent route for configured limit ${name}`);
    }
  }
}

function executionElapsed(control) {
  const samples = control?.clockSamplesUnixMs;
  if (!Array.isArray(samples) || samples.length === 0) fail('invalid', 'execution clock samples are invalid');
  let previous = samples[0];
  if (!Number.isSafeInteger(previous) || previous < 0) fail('invalid', 'execution clock samples are invalid');
  for (let index = 1; index < samples.length; index += 1) {
    const current = samples[index];
    if (!Number.isSafeInteger(current) || current < previous) fail('invalid', 'execution clock samples must be nondecreasing');
    previous = current;
  }
  const elapsedMs = previous - samples[0];
  if (!Number.isSafeInteger(elapsedMs) || elapsedMs < 0) fail('invalid', 'execution clock elapsed time is invalid');
  return elapsedMs;
}

function receiptMac(key, keyId, claims) {
  return createHmac('sha256', key)
    .update(RECEIPT_DOMAIN)
    .update(Buffer.from(keyId, 'ascii'))
    .update(Buffer.from([0]))
    .update(Buffer.from(canonicalJson(claims)))
    .digest();
}

function selectedTokens(selection) {
  return new Set([
    selection.protocolVersion, selection.messageSchemaVersion, selection.repositoryFormat,
    selection.authorizationContract, selection.pathContract, selection.pathProfile,
    selection.eventVersion, selection.transferProfile, ...selection.extensions,
  ]);
}

function negotiate(authority, supplied, tracker) {
  const input = supplied.input;
  if (input.transportScheme !== 'https' || input.tlsVersion !== '1.3') reject('NEGOTIATION_DOWNGRADE_REJECTED');
  if (!Number.isSafeInteger(input.receiptLifetimeMs) || input.receiptLifetimeMs < 1
      || input.receiptLifetimeMs > FROZEN_LIMITS.maxReceiptLifetimeMs) fail('invalid', 'receipt lifetime is outside the supported range');
  const key = bytesBase64url(input.receiptKeyBase64url, 64);
  if (key.length < 32) fail('invalid', 'receipt key is too short');
  const serverNonce = bytesBase64url(input.serverNonce, 64);
  if (serverNonce.length < 16) fail('invalid', 'server nonce is too short');
  if (input.route === 'verify-receipt') {
    const claims = {
      schemaVersion: 'ogvcs.protocol/negotiation-receipt-claims/v1',
      selection: input.serverSelection,
      ...input.principal,
      clientNonce: input.offer.clientNonce,
      serverNonce: input.serverNonce,
      issuedAtUnixMs: input.issueAtUnixMs,
      expiresAtUnixMs: input.issueAtUnixMs + input.receiptLifetimeMs,
    };
    authority.validator.validate(claims, 'NegotiationReceiptClaims.schema.json');
    const expectedMac = receiptMac(key, input.receiptKeyId, claims);
    const suppliedMac = Buffer.from(expectedMac);
    suppliedMac[0] ^= input.receiptMacXor;
    if (!timingSafeEqual(expectedMac, suppliedMac)
        || !same(input.verificationSelection, claims.selection)
        || ['subjectDigest', 'tenantDigest', 'authorityEpoch', 'sessionId'].some((name) => input.verificationPrincipal[name] !== claims[name])) reject('NEGOTIATION_RECEIPT_INVALID');
    if (input.verifyAtUnixMs < claims.issuedAtUnixMs || input.verifyAtUnixMs >= claims.expiresAtUnixMs) reject('NEGOTIATION_RECEIPT_EXPIRED');
    return trace('NONE', tracker, { semanticOutput: input.verificationSelection });
  }
  authority.validator.validate(input.offer, 'NegotiationOffer.schema.json');
  const capabilityRows = authority.registries.capabilities.entries;
  const known = new Map(capabilityRows.map((entry) => [entry.id, entry]));
  for (const required of input.offer.capabilities.requiredCapabilities) if (!known.has(required)) reject('NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN');
  for (const minimum of input.minimumCapabilities) if (!known.has(minimum) || !input.offer.capabilities.requiredCapabilities.includes(minimum)) reject('NEGOTIATION_DOWNGRADE_REJECTED');
  let selection;
  for (const row of [...authority.registries.compatibility.entries].sort((left, right) => left.code - right.code)) {
    if (!NEW_SESSION_STATES.has(row.state)) continue;
    if (AXES.some(([offered, selected]) => !input.offer.capabilities[offered].includes(row.selection[selected]))) continue;
    const offeredExtensions = new Set(input.offer.capabilities.extensions);
    const candidate = { ...row.selection, extensions: row.selection.extensions.filter((id) => offeredExtensions.has(id)) };
    const tokens = selectedTokens(candidate);
    const okay = [...row.requiredCapabilities, ...input.offer.capabilities.requiredCapabilities].every((required) => {
      const assignment = known.get(required);
      return assignment?.axis === 'feature'
        ? input.offer.capabilities.requiredCapabilities.includes(required) && row.requiredCapabilities.includes(required)
        : tokens.has(required);
    });
    if (okay) { selection = authority.validator.validate(candidate, 'NegotiationSelection.schema.json'); break; }
  }
  if (selection === undefined) reject('NEGOTIATION_NO_COMMON_VERSION');
  const claims = {
    schemaVersion: 'ogvcs.protocol/negotiation-receipt-claims/v1', selection,
    ...input.principal, clientNonce: input.offer.clientNonce, serverNonce: input.serverNonce,
    issuedAtUnixMs: input.issueAtUnixMs, expiresAtUnixMs: input.issueAtUnixMs + input.receiptLifetimeMs,
  };
  authority.validator.validate(claims, 'NegotiationReceiptClaims.schema.json');
  const receipt = authority.validator.validate({
    algorithm: 'HMAC-SHA-256', keyId: input.receiptKeyId, claims,
    mac: receiptMac(key, input.receiptKeyId, claims).toString('base64url'),
  }, 'NegotiationReceipt.schema.json');
  if (Object.hasOwn(supplied.configuredLimits ?? {}, 'maxReceiptBytes')) tracker.observe('maxReceiptBytes', Buffer.byteLength(canonicalJson(receipt), 'utf8'));
  return trace('NONE', tracker, { semanticOutput: selection });
}

function problemEntry(authority, code) {
  const value = authority.registries['error-codes'].entries.find((entry) => entry.name === code);
  if (!value) fail('contract', 'wire error assignment is unavailable');
  return value;
}

function safeProblem(authority, code, correlationId, parameters = []) {
  const entry = problemEntry(authority, code);
  if (parameters.length > FROZEN_LIMITS.maxErrorParameters) fail('limit', 'problem parameter ceiling exceeded');
  const allowed = new Set(entry.safeParameters);
  const names = new Set();
  for (const parameter of parameters) {
    if (!allowed.has(parameter.name) || names.has(parameter.name) || typeof parameter.value !== 'string') fail('invalid', 'problem parameter is not registered');
    names.add(parameter.name);
    if (parameter.name === 'gapClass' && !['retention-gap', 'generation-changed'].includes(parameter.value)) fail('invalid', 'gap class is not public');
    if (parameter.name === 'conflictClass' && parameter.value !== 'idempotency-input-mismatch') fail('invalid', 'conflict class is not public');
    if (parameter.name === 'retryAfterMs' && !/^(?:0|[1-9][0-9]{0,6}|[1-7][0-9]{7}|8[0-5][0-9]{6}|86[0-3][0-9]{5}|86400000)$/u.test(parameter.value)) fail('invalid', 'retry delay is outside its closed domain');
  }
  return authority.validator.validate({
    type: entry.type, title: entry.title, status: entry.status, code: entry.name,
    retryable: entry.retryable, correlationId,
    ...(parameters.length === 0 ? {} : { parameters: [...parameters].sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0) }),
  }, 'ProblemDetails.schema.json');
}

function validateRetryHeaders(headers, problem) {
  if (!Array.isArray(headers)) fail('invalid', 'HTTP headers must be an array');
  const retry = problem.parameters?.find(({ name }) => name === 'retryAfterMs')?.value;
  const supplied = headers.filter((header) => header.name.toLowerCase() === 'retry-after').map((header) => header.value);
  if (retry === undefined) {
    if (supplied.length !== 0) fail('invalid', 'Retry-After has no registered safe parameter');
    return;
  }
  if (supplied.length !== 1 || !/^(?:0|[1-9][0-9]{0,4})$/u.test(supplied[0]) || Number(supplied[0]) > 86_400
      || Number(supplied[0]) !== Math.ceil(Number(retry) / 1000)) fail('invalid', 'Retry-After does not match retryAfterMs');
}

function validateProblem(authority, value, httpStatus, headers) {
  authority.validator.validate(value, 'ProblemDetails.schema.json');
  const row = problemEntry(authority, value.code);
  if (value.type !== row.type || value.title !== row.title || value.status !== row.status || value.retryable !== row.retryable || httpStatus !== undefined && value.status !== httpStatus) fail('invalid', 'problem does not match its registry assignment');
  safeProblem(authority, value.code, value.correlationId, value.parameters ?? []);
  if (headers !== undefined) validateRetryHeaders(headers, value);
}

function extensionPolicy(authority, document, schemaName, selectedExtensions, maximum) {
  const entries = Object.keys(document.extensions ?? {});
  if (entries.length > maximum) fail('limit', 'extension entry ceiling exceeded');
  const selected = new Set(selectedExtensions);
  const registry = new Map(authority.registries.extensions.entries.map((entry) => [entry.id, entry]));
  for (const id of entries) {
    const row = registry.get(id);
    if (!row || !selected.has(id) || !['candidate', 'ratified'].includes(row.state)
        || !row.affectedSchemas.includes(schemaName) || row.requirement !== 'optional'
        || !['ignore', 'reject'].includes(row.fallback)) reject('PROTOCOL_UNSUPPORTED');
  }
}

function envelopeDocument(input, tracker) {
  if (input.rawInputUtf16CodeUnits !== undefined) return parseJson(String.fromCharCode(...input.rawInputUtf16CodeUnits), { maxControlMessageBytes: tracker.cap('maxControlMessageBytes') });
  if (input.encoding === 'semantic-json') { inspectJson(input.document); return input.document; }
  if (input.encoding === 'raw-hex') {
    if (typeof input.rawInput !== 'string' || input.rawInput.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(input.rawInput)) fail('invalid', 'raw hex input is invalid');
    return parseJson(Buffer.from(input.rawInput, 'hex'), { maxControlMessageBytes: tracker.cap('maxControlMessageBytes') });
  }
  return parseJson(input.rawInput, { maxControlMessageBytes: tracker.cap('maxControlMessageBytes') });
}

function envelope(authority, supplied, tracker) {
  const input = supplied.input;
  const document = envelopeDocument(input, tracker);
  if (input.targetSchema === 'JsonValue') {
    const definitions = authority.schemas['EnvelopeCaseInput.schema.json'].$defs;
    authority.validator.validate(document, { ...definitions.JsonValue, $defs: definitions }, { configuredLimits: supplied.configuredLimits });
    return trace('NONE', tracker, { semanticOutput: document });
  }
  authority.validator.validate(document, `${input.targetSchema}.schema.json`, { configuredLimits: supplied.configuredLimits });
  if (input.route === 'authorize') {
    inspectJson(supplied.serverContext ?? {}, { maxJsonDepth: 8, maxJsonNodes: 256 });
    const code = input.authorizationDecision === 'error' ? 'INTERNAL_ERROR' : 'AUTHORIZATION_DENIED';
    const problem = safeProblem(authority, code, document.correlationId);
    const body = authority.validator.validate({
      schemaVersion: 'ogvcs.protocol/response-envelope/v1', correlationId: problem.correlationId,
      success: false, problem,
    }, 'ResponseEnvelope.schema.json');
    reject(code, { trace: trace(code, tracker, { responseBody: body }) });
  }
  if (input.targetSchema === 'RequestEnvelope') {
    extensionPolicy(authority, document, 'RequestEnvelope', input.selectedExtensions, tracker.cap('maxExtensionEntries'));
    if (document.deadlineUnixMs !== undefined) {
      if (document.deadlineUnixMs <= input.atUnixMs) reject('DEADLINE_EXCEEDED');
      tracker.observe('maxDeadlineHorizonMs', document.deadlineUnixMs - input.atUnixMs);
    }
    if (input.contentEncoding !== 'identity') reject('COMPRESSION_FORBIDDEN');
    if (input.redirectStatus !== undefined || input.originChanged) {
      const safe = input.allowSameOriginRedirect === true && input.originChanged === false && input.method !== 'POST' && document.idempotency === undefined;
      if (!safe) reject('REDIRECT_FORBIDDEN');
    }
  } else if (input.targetSchema === 'ResponseEnvelope') {
    extensionPolicy(authority, document, 'ResponseEnvelope', input.selectedExtensions, tracker.cap('maxExtensionEntries'));
    if (document.success === true && (!Object.hasOwn(document, 'body') || Object.hasOwn(document, 'problem'))) fail('invalid', 'response outcome is invalid');
    if (document.success === false) {
      if (!Object.hasOwn(document, 'problem') || Object.hasOwn(document, 'body')) fail('invalid', 'response outcome is invalid');
      validateProblem(authority, document.problem, input.httpStatus, input.headers);
    }
  } else if (input.targetSchema === 'ProblemDetails') validateProblem(authority, document, input.httpStatus, input.headers);
  else if (input.targetSchema === 'PageEnvelope') validatePage(document);
  return trace('NONE', tracker, { semanticOutput: { targetSchema: input.targetSchema, validated: true } });
}

function projectRequest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.operation !== 'string' || !Object.hasOwn(value, 'body')) fail('invalid', 'request projection is invalid');
  return {
    ...(value.schemaVersion === undefined ? {} : { schemaVersion: value.schemaVersion }),
    operation: value.operation,
    body: value.body,
    extensions: value.extensions ?? {},
  };
}

function fingerprintOf(value) {
  return createHash('sha256').update(FINGERPRINT_DOMAIN).update(Buffer.from(canonicalJson(value))).digest('hex');
}

function selfDatingKey(input) {
  if (input.idempotencyKey === '') return false;
  const match = /^ik1\.(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})\.([A-Za-z0-9_-]{22,218})$/u.exec(input.idempotencyKey);
  if (!match) fail('invalid', 'idempotency key is malformed');
  const issued = Number(match[1]);
  const expires = Number(match[2]);
  if (!Number.isSafeInteger(issued) || !Number.isSafeInteger(expires)
      || issued !== input.idempotencyIssuedAtUnixMs || expires !== input.idempotencyExpiresAtUnixMs
      || expires <= issued || expires - issued > 86_400_000) fail('invalid', 'idempotency key lifetime is invalid');
  return true;
}

function fingerprint(authority, supplied, tracker) {
  const input = supplied.input;
  if (input.algorithm !== 'OGVCS-SEMANTIC-JCS-SHA-256') reject('PROTOCOL_MALFORMED');
  for (const raw of input.rawInputs) parseJson(raw, { maxControlMessageBytes: tracker.cap('maxCanonicalInputBytes') });
  const projections = input.projections.map((value) => authority.validator.validate(
    value, 'IdempotencyProjectionInput.schema.json', { configuredLimits: supplied.configuredLimits },
  ));
  if (input.route === 'idempotency' && (input.retryableMutation !== true || input.idempotencyKey === '')) reject('PROTOCOL_MALFORMED');
  if (input.retryableMutation && input.idempotencyKey === '') reject('IDEMPOTENCY_KEY_REQUIRED');
  if (input.idempotencyKey !== '') selfDatingKey(input);
  const projected = projections.map(projectRequest);
  const digests = projected.map(fingerprintOf);
  if (input.route === 'fingerprint') return { trace: trace('NONE', tracker, { semanticOutput: { fingerprints: digests } }), mutationCount: 0 };
  if (input.attemptProjectionIndexes.some((index) => index >= digests.length)) reject('PROTOCOL_MALFORMED');
  if (Object.hasOwn(supplied.configuredLimits ?? {}, 'maxIdempotencyKeyBytes')) return { trace: trace('NONE', tracker, { semanticOutput: { keyPreflight: true } }), mutationCount: 0 };
  const attempts = input.attemptProjectionIndexes.map((index) => digests[index]);
  if (attempts.length > 1 && attempts.some((value) => value !== attempts[0])) reject('IDEMPOTENCY_KEY_REUSE');
  let mutationCount = 0;
  let firstExecution = false;
  const beginsMutation = input.attemptSchedule.includes('begin-mutation');
  if (beginsMutation && input.attemptAuthorizationDecisions[0] !== 'allow') {
    reject('AUTHORIZATION_DENIED', { mutationCount, trace: trace('AUTHORIZATION_DENIED', tracker) });
  }
  if (beginsMutation) mutationCount = 1;
  if (input.idempotencyIssuedAtUnixMs > input.atUnixMs
      || input.idempotencyExpiresAtUnixMs <= input.atUnixMs) {
    reject('IDEMPOTENCY_KEY_REQUIRED', { mutationCount, trace: trace('IDEMPOTENCY_KEY_REQUIRED', tracker) });
  }
  if (input.attemptSchedule.includes('deadline')) reject('DEADLINE_EXCEEDED', { mutationCount, trace: trace('DEADLINE_EXCEEDED', tracker) });
  if (input.attemptSchedule.includes('retry')) {
    const authorization = input.attemptAuthorizationDecisions[1] ?? input.attemptAuthorizationDecisions[0];
    if (authorization !== 'allow') reject('AUTHORIZATION_DENIED', { mutationCount, trace: trace('AUTHORIZATION_DENIED', tracker) });
    if (mutationCount === 0) {
      mutationCount = 1;
      firstExecution = true;
    }
  }
  return {
    trace: trace('NONE', tracker, {
      semanticOutput: firstExecution ? { firstExecution: true, replay: false } : { replay: true },
    }),
    mutationCount,
  };
}

function validatePage(page) {
  if (page.state === 'complete' && Object.hasOwn(page, 'nextCursor') || page.state === 'more' && !Object.hasOwn(page, 'nextCursor')) fail('invalid', 'page terminal state is invalid');
}

function scopeEqual(left, right) {
  return ['subject', 'tenant', 'repository', 'operation', 'queryDigest'].every((name) => left[name] === right[name]);
}

function cursor(authority, supplied, tracker) {
  const input = supplied.input;
  if (!Number.isSafeInteger(input.ttlMs) || input.ttlMs < 1
      || input.ttlMs > FROZEN_LIMITS.maxCursorLifetimeMs) fail('invalid', 'cursor lifetime is outside the supported range');
  if (input.route === 'validate-page') {
    authority.validator.validate(input.page, 'PageEnvelope.schema.json');
    validatePage(input.page);
    return trace('NONE', tracker, { semanticOutput: { state: input.page.state, itemCount: input.page.items.length } });
  }
  if (input.route === 'validate-token' || input.route === 'token-byte-preflight') {
    tracker.observe('maxCursorBytes', Buffer.byteLength(input.suppliedToken, 'utf8'));
    authority.validator.validate({ token: input.suppliedToken }, 'Cursor.schema.json');
    return trace('NONE', tracker, { semanticOutput: { tokenAccepted: true } });
  }
  if (input.ttlMs > Number.MAX_SAFE_INTEGER - input.issuedAtUnixMs) fail('invalid', 'cursor expiry overflows the time domain');
  authority.validator.validate(input.issueScope, 'CursorScopeInput.schema.json');
  authority.validator.validate(input.readScope, 'CursorScopeInput.schema.json');
  const issuedToken = `c1.${Buffer.alloc(32, 1).toString('base64url')}`;
  let token = input.tokenSource === 'issued' ? issuedToken : input.suppliedToken;
  if (input.tokenMutation === 'tamper') token = `${token.slice(0, -1)}${token.endsWith('A') ? 'B' : 'A'}`;
  if (input.tokenMutation === 'unknown') token = `c1.${Buffer.alloc(32, 99).toString('base64url')}`;
  inspectJson(supplied.serverContext ?? {}, { maxJsonDepth: 8, maxJsonNodes: 256 });
  if (token !== issuedToken) reject('CURSOR_INVALID');
  if (!scopeEqual(input.issueScope, input.readScope)) reject('CURSOR_SCOPE_MISMATCH');
  if (input.minimumRetainedGeneration > input.generation) reject('CURSOR_GAP');
  if (input.readAtUnixMs >= input.issuedAtUnixMs + input.ttlMs) reject('CURSOR_EXPIRED');
  return trace('NONE', tracker, { semanticOutput: { generation: input.generation, position: 0, issuedAt: input.issuedAtUnixMs, expiresAt: input.issuedAtUnixMs + input.ttlMs } });
}

function acceptFrame(authority, state, frame, tracker) {
  authority.validator.validate(frame, 'StreamFrame.schema.json');
  if (frame.kind === 'gap' && frame.problem?.code !== 'CURSOR_GAP') fail('invalid', 'gap stream frame requires CURSOR_GAP');
  if (state.terminal || frame.sequence !== state.count || state.streamId !== undefined && frame.streamId !== state.streamId) reject('STREAM_SEQUENCE_INVALID');
  state.streamId ??= frame.streamId;
  state.count += 1;
  if (TERMINAL.has(frame.kind)) state.terminal = frame.kind;
  tracker.observe('maxJsonlFrames', state.count);
}

function stream(authority, supplied, tracker) {
  const input = supplied.input;
  const state = { count: 0, streamId: undefined, terminal: undefined };
  const frames = [];
  let totalBytes = 0;
  if (input.route === 'parse') {
    tracker.observe('maxJsonlStreamBytes', Buffer.byteLength(input.jsonl, 'utf8'));
    if (input.jsonl.length === 0 || !input.jsonl.endsWith('\n')) reject('STREAM_INCOMPLETE');
    if (input.jsonl.endsWith('\r\n')) fail('invalid', 'JSONL framing is invalid');
    for (const line of input.jsonl.slice(0, -1).split('\n')) {
      tracker.observe('maxJsonlFrameBytes', Buffer.byteLength(line, 'utf8'));
      const frame = parseCanonical(line, { maxControlMessageBytes: tracker.cap('maxJsonlFrameBytes'), maxCanonicalInputBytes: tracker.cap('maxJsonlFrameBytes') });
      acceptFrame(authority, state, frame, tracker);
      frames.push(frame);
    }
  } else {
    for (let index = 0; index < input.frames.length; index += 1) {
      if (supplied.control.cancellation === 'after-first-stream-frame' && index === 1) reject('CANCELLED');
      const frame = input.frames[index];
      acceptFrame(authority, state, frame, tracker);
      const lineBytes = Buffer.byteLength(canonicalJson(frame), 'utf8');
      tracker.observe('maxJsonlFrameBytes', lineBytes);
      totalBytes += lineBytes + 1;
      tracker.observe('maxJsonlStreamBytes', totalBytes);
      frames.push(frame);
    }
  }
  if (state.terminal === undefined) reject('STREAM_INCOMPLETE');
  const retained = frames.reduce((sum, frame) => sum + 512 + 4 * Buffer.byteLength(canonicalJson(frame), 'utf8'), 0);
  const inputBytes = input.route === 'parse' ? Buffer.byteLength(input.jsonl, 'utf8') : 0;
  tracker.observe('maxWorkingMemoryBytes', 1024 + inputBytes + retained);
  return trace('NONE', tracker, { streamFrames: frames, semanticOutput: { streamId: state.streamId, frames: state.count, terminalKind: state.terminal } });
}

async function verifyGrant(authority, input) {
  const pin = authority.manifest.predecessorPins.authorization;
  const carrier = authority.validator.validate(input.probe.grant, 'CompactTransferGrant.schema.json');
  if (carrier.authorizationManifestSha256 !== pin.manifestSha256 || carrier.representation !== 'request-root' || carrier.explicitObjectCount !== 0) reject('TRANSFER_GRANT_INVALID');
  const envelope = parseCanonical(bytesBase64url(carrier.envelope, FROZEN_LIMITS.maxGrantBytes));
  if (!Array.isArray(envelope.claims?.objectIds) || envelope.claims.objectIds.length !== 0 || !/^sha256:[0-9a-f]{64}$/u.test(envelope.claims.requestRoot ?? '')) reject('TRANSFER_GRANT_INVALID');
  const decision = await verifyTransferGrant(envelope, input.authorizationContext, input.authorizationPublicJwk);
  if (!decision || typeof decision !== 'object' || Array.isArray(decision)
      || Object.keys(decision).sort().join('\0') !== 'code\0result'
      || decision.result !== 'allow' || decision.code !== 'ALLOW_EXPLICIT') reject('TRANSFER_GRANT_INVALID');
}

function nonGrantProbe(authority, input, configuredLimits) {
  if (input?.schemaVersion !== TRANSFER_PROBE_SCHEMA_VERSION) reject('PROTOCOL_MALFORMED');
  const projection = { ...(input ?? {}) };
  delete projection.grant;
  projection.schemaVersion = TRANSFER_PROBE_NON_GRANT_SCHEMA_VERSION;
  return authority.validator.validate(projection, 'TransferProbeNonGrantInput.schema.json', { configuredLimits });
}

function digestHeader(value) {
  const match = /^sha-256=:([A-Za-z0-9+/]{43}=):$/u.exec(value);
  if (!match) reject('TRANSFER_VALIDATOR_MISMATCH');
  const bytes = Buffer.from(match[1], 'base64');
  if (bytes.length !== 32 || bytes.toString('base64') !== match[1]) reject('TRANSFER_VALIDATOR_MISMATCH');
  return bytes.toString('hex');
}

function transportHeaders(input, label, maximum) {
  if (!Array.isArray(input)) fail('invalid', `${label} headers must be an array`);
  const output = new Map();
  let bytes = 0;
  for (const header of input) {
    if (!header || typeof header !== 'object' || Array.isArray(header)
        || Object.keys(header).sort().join('\0') !== 'name\0value'
        || typeof header.name !== 'string' || !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u.test(header.name)
        || typeof header.value !== 'string' || /[\r\n\0]/u.test(header.value)) fail('invalid', `${label} header is malformed`);
    bytes += Buffer.byteLength(header.name, 'utf8') + Buffer.byteLength(header.value, 'utf8') + 4;
    if (!Number.isSafeInteger(bytes) || bytes > maximum) fail('limit', `${label} header ceiling exceeded`);
    const name = header.name.toLowerCase();
    if (output.has(name)) fail('invalid', `${label} header is duplicated`);
    output.set(name, header.value);
  }
  return { map: output, bytes };
}

function decimalHeader(value, label) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,15})$/u.test(value) || !Number.isSafeInteger(Number(value))) fail('invalid', `${label} is not a canonical decimal`);
  return Number(value);
}

function strongEtag(value, label) {
  const match = typeof value === 'string' ? /^"([A-Za-z0-9._~-]{16,256})"$/u.exec(value) : null;
  if (!match) reject('TRANSFER_VALIDATOR_MISMATCH');
  return match[1];
}

function requiredStrongEtag(value, label) {
  const match = typeof value === 'string' ? /^"([A-Za-z0-9._~-]{16,256})"$/u.exec(value) : null;
  if (!match) fail('invalid', `${label} is not a canonical strong ETag`);
  return match[1];
}

function requiredDigestHeader(value) {
  const match = typeof value === 'string' ? /^sha-256=:([A-Za-z0-9+/]{43}=):$/u.exec(value) : null;
  if (!match) fail('invalid', 'Content-Digest is not canonical RFC 9530 SHA-256');
  const bytes = Buffer.from(match[1], 'base64');
  if (bytes.length !== 32 || bytes.toString('base64') !== match[1]) fail('invalid', 'Content-Digest is not canonical RFC 9530 SHA-256');
  return bytes.toString('hex');
}

function responseBody(input, tracker) {
  const value = input.responseBodyHex;
  if (typeof value !== 'string' || value.length > Math.min(FROZEN_LIMITS.maxControlMessageBytes, tracker.cap('maxTransferRangeBytes') * 2)
      || value.length % 2 !== 0 || !/^(?:[0-9a-f]{2})*$/u.test(value)) fail('invalid', 'response body is not lowercase even-length hex');
  const byteLength = value.length / 2;
  if (byteLength > tracker.cap('maxTransferRangeBytes')) fail('limit', 'response body exceeds transfer range ceiling');
  const liveBytes = value.length * 2 + byteLength + 1024;
  tracker.observe('maxWorkingMemoryBytes', liveBytes);
  const bytes = Buffer.from(value, 'hex');
  if (bytes.length !== byteLength || bytes.toString('hex') !== value) fail('invalid', 'response body hex is not canonical');
  return bytes;
}

function validateHttpRange(authority, input, tracker) {
  if (![200, 206, 416].includes(input.responseStatus)) fail('invalid', 'HTTP range status is unsupported');
  const request = transportHeaders(input.requestHeaders, 'request', tracker.cap('maxHeaderBytes'));
  const response = transportHeaders(input.responseHeaders, 'response', tracker.cap('maxHeaderBytes'));
  if (request.bytes + response.bytes > tracker.cap('maxHeaderBytes')) fail('limit', 'combined header ceiling exceeded');
  const responseEncoding = response.map.get('content-encoding');
  if (responseEncoding !== undefined && responseEncoding !== 'identity') reject('COMPRESSION_FORBIDDEN');
  const body = responseBody(input, tracker);
  const lengthText = response.map.get('content-length');
  if (lengthText === undefined) fail('invalid', 'Content-Length is missing');
  const length = decimalHeader(lengthText, 'Content-Length');
  if (length !== body.length || length !== input.transportResponse.rangeBytes) reject('TRANSFER_RANGE_INVALID');
  const rangeText = request.map.get('range');
  const ifRangeText = request.map.get('if-range');
  const contentRangeText = response.map.get('content-range');
  const responseEtag = response.map.get('etag');
  const responseDigest = response.map.get('content-digest');
  let validatorTag;
  let contentSha256;
  if (input.responseStatus === 200 || input.responseStatus === 206) {
    validatorTag = requiredStrongEtag(responseEtag, 'ETag');
    contentSha256 = requiredDigestHeader(responseDigest);
    const actualSha256 = createHash('sha256').update(body).digest('hex');
    if (contentSha256 !== actualSha256
        || input.probe.expectedSha256 !== undefined && contentSha256 !== input.probe.expectedSha256
        || input.probe.validatorTag !== undefined && validatorTag !== input.probe.validatorTag) reject('TRANSFER_VALIDATOR_MISMATCH');
  } else if (responseDigest !== undefined) fail('invalid', 'unsatisfied Range response carries Content-Digest');
  else if (responseEtag !== undefined) fail('invalid', 'unsatisfied Range response carries ETag');
  if (rangeText === undefined) {
    if (ifRangeText !== undefined) reject('TRANSFER_VALIDATOR_MISMATCH');
    if (input.responseStatus !== 200 || contentRangeText !== undefined
        || input.probe.startOffset !== 0
        || input.probe.endOffsetExclusive !== undefined && input.probe.endOffsetExclusive !== input.transportResponse.totalBytes
        || body.length !== input.transportResponse.totalBytes) reject('TRANSFER_RANGE_INVALID');
    return { status: 200, acceptedStart: 0, acceptedEndExclusive: body.length, totalBytes: input.transportResponse.totalBytes, validatorTag, contentSha256 };
  }
  const match = /^bytes=(0|[1-9][0-9]{0,15})-(?:(0|[1-9][0-9]{0,15}))?$/u.exec(rangeText);
  if (!match) fail('invalid', 'Range is malformed');
  const start = decimalHeader(match[1], 'Range start');
  const endInclusive = match[2] === undefined ? undefined : decimalHeader(match[2], 'Range end');
  if (endInclusive !== undefined && endInclusive < start) reject('TRANSFER_RANGE_INVALID');
  if (start !== input.probe.startOffset
      || input.probe.endOffsetExclusive === undefined && endInclusive !== undefined
      || input.probe.endOffsetExclusive !== undefined && endInclusive !== input.probe.endOffsetExclusive - 1) reject('TRANSFER_RANGE_INVALID');
  if (input.probe.validatorTag !== undefined) {
    if (ifRangeText === undefined || strongEtag(ifRangeText, 'If-Range') !== input.probe.validatorTag) reject('TRANSFER_VALIDATOR_MISMATCH');
  } else if (ifRangeText !== undefined) reject('TRANSFER_VALIDATOR_MISMATCH');
  const total = input.transportResponse.totalBytes;
  if (start >= total) {
    if (input.responseStatus !== 416 || contentRangeText !== `bytes */${total}` || body.length !== 0) reject('TRANSFER_RANGE_INVALID');
    reject('TRANSFER_RANGE_INVALID');
  }
  const end = input.probe.endOffsetExclusive ?? total;
  if (end <= start || end > total) reject('TRANSFER_RANGE_INVALID');
  const span = end - start;
  tracker.observe('maxTransferRangeBytes', span);
  if (input.responseStatus !== 206 || contentRangeText !== `bytes ${start}-${end - 1}/${total}`
      || body.length !== span || input.transportResponse.rangeBytes !== span) reject('TRANSFER_RANGE_INVALID');
  return { status: 206, acceptedStart: start, acceptedEndExclusive: end, totalBytes: total, validatorTag, contentSha256 };
}

function validateProbeResult(authority, value) {
  authority.validator.validate(value, 'TransferProbeResult.schema.json');
  if (value.acceptedStart > value.acceptedEndExclusive || value.acceptedEndExclusive > value.totalBytes) fail('invalid', 'transfer result range is invalid');
  if (value.status === 'complete' && (!value.terminal || value.acceptedEndExclusive !== value.totalBytes)) fail('invalid', 'complete result is not terminal');
  if (value.status !== 'complete' && value.terminal) fail('invalid', 'non-complete result is terminal');
  if (value.status === 'partial'
      && (value.acceptedEndExclusive <= value.acceptedStart || value.acceptedEndExclusive >= value.totalBytes)) fail('invalid', 'partial result progress is invalid');
  if (value.status === 'interrupted'
      && (value.acceptedEndExclusive < value.acceptedStart || value.acceptedEndExclusive >= value.totalBytes)) fail('invalid', 'interrupted result progress is invalid');
  if (value.status === 'rejected' && (value.acceptedStart !== value.acceptedEndExclusive || value.problem === undefined)) fail('invalid', 'rejected result shape is invalid');
  if (value.status !== 'rejected' && value.problem !== undefined) fail('invalid', 'successful result carries a problem');
  if (value.status === 'rejected') validateProblem(authority, value.problem);
  return value;
}

async function transfer(authority, supplied, tracker) {
  const input = supplied.input;
  if (!input.certificateValid || !input.hostnameMatches
      || input.proxyMode === 'connect' && (!input.proxyConfigured || input.connectResult !== 'success')
      || input.proxyMode === 'direct' && input.proxyConfigured && input.connectResult === 'bypassed') reject('PROTOCOL_UNSUPPORTED');
  if (typeof input.probe?.contentEncoding === 'string' && input.probe.contentEncoding !== 'identity') reject('COMPRESSION_FORBIDDEN');
  const probe = nonGrantProbe(authority, input.probe, supplied.configuredLimits);
  if (input.responseStatus >= 300 && input.responseStatus < 400 && probe.operation === 'write') reject('REDIRECT_FORBIDDEN');
  if (probe.endOffsetExclusive !== undefined && probe.endOffsetExclusive <= probe.startOffset) reject('TRANSFER_RANGE_INVALID');
  if (input.route === 'probe' && probe.startOffset > 0 && probe.validatorTag === undefined) reject('TRANSFER_VALIDATOR_MISMATCH');
  if (input.route === 'http-range'
      && (!input.transportResponse || typeof input.transportResponse !== 'object' || Array.isArray(input.transportResponse)
        || !Number.isSafeInteger(input.transportResponse.totalBytes) || input.transportResponse.totalBytes < 0
        || !Number.isSafeInteger(input.transportResponse.rangeBytes) || input.transportResponse.rangeBytes < 0)) {
    fail('invalid', 'HTTP range carrier accounting is invalid');
  }
  tracker.observe('maxTransferRangeBytes', probe.endOffsetExclusive === undefined
    ? input.transportResponse.rangeBytes
    : probe.endOffsetExclusive - probe.startOffset);
  tracker.observe('maxTransferRangeBytes', input.transportResponse.rangeBytes);
  if (input.grantLocation !== 'header' || input.logGrant) reject('TRANSFER_GRANT_INVALID');
  if (!input.probe.grant || typeof input.probe.grant !== 'object' || Array.isArray(input.probe.grant)
      || !Number.isSafeInteger(input.probe.grant.explicitObjectCount)
      || input.probe.grant.explicitObjectCount !== 0) reject('TRANSFER_GRANT_INVALID');
  try {
    await verifyGrant(authority, input);
  } catch (error) {
    if (error instanceof SemanticReject && error.code === 'TRANSFER_GRANT_INVALID') throw error;
    if (error instanceof AdapterFault && error.kind === 'limit') throw error;
    reject('TRANSFER_GRANT_INVALID');
  }
  if (input.route === 'validate-result') return trace('NONE', tracker, { semanticOutput: validateProbeResult(authority, input.probeResult) });
  if (input.route === 'http-range') return trace('NONE', tracker, { semanticOutput: validateHttpRange(authority, input, tracker) });
  let headerTag;
  if (input.transportResponse.etagHeader !== undefined) {
    const match = /^"([A-Za-z0-9._~-]{16,256})"$/u.exec(input.transportResponse.etagHeader);
    if (!match) reject('TRANSFER_VALIDATOR_MISMATCH');
    headerTag = match[1];
  }
  const headerSha = input.transportResponse.contentDigestHeader === undefined ? undefined : digestHeader(input.transportResponse.contentDigestHeader);
  if (input.digestMatches === false
      || input.probe.startOffset === 0 && input.probe.validatorTag !== undefined && headerTag === undefined
      || headerTag !== undefined && headerTag !== input.probe.validatorTag
      || headerSha !== undefined && headerSha !== input.probe.expectedSha256) reject('TRANSFER_VALIDATOR_MISMATCH');
  if (input.transportResponse.interruptedAt !== undefined && input.transportResponse.resumeAt !== input.transportResponse.interruptedAt) reject('TRANSFER_RANGE_INVALID');
  return trace('NONE', tracker, { semanticOutput: { acceptedStart: input.probe.startOffset, rangeBytes: input.transportResponse.rangeBytes } });
}

function contractLoad(input, tracker) {
  if (input.route === 'inventory') {
    let total = 0;
    for (const artifact of input.artifacts) {
      if (artifact.bytesHex.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(artifact.bytesHex)) fail('invalid', 'contract artifact bytes are invalid');
      total += artifact.bytesHex.length / 2;
      if (!Number.isSafeInteger(total)) fail('limit', 'contract byte accounting overflowed');
    }
    return trace('NONE', tracker, { semanticOutput: { artifacts: input.artifacts.length, bytes: total } });
  }
  for (const entry of input.registryEntries) inspectJson(entry);
  return trace('NONE', tracker, { semanticOutput: { registryEntries: input.registryEntries.length } });
}

function runnerBatch(input, tracker) {
  const ids = new Set();
  for (const row of input.cases) {
    if (ids.has(row.id)) fail('invalid', 'runner case identifier is duplicated');
    ids.add(row.id);
  }
  return trace('NONE', tracker, { semanticOutput: { cases: input.cases.length } });
}

function assignmentKey(value) { return `${value.kind}\0${value.scope}\0${value.code}`; }
function assignmentName(value) { return `${value.kind}\0${value.scope}\0${value.name}`; }

function release(authority, input, tracker) {
  authority.validator.validate(input, 'ReleasePreflightCaseInput.schema.json');
  const known = new Set(authority.registries.capabilities.entries.map((entry) => entry.id));
  for (const required of input.requiredCapabilities) if (!known.has(required)) reject('NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN');
  const compatibility = authority.registries.compatibility;
  const pins = compatibility.predecessorPins;
  if (input.authorizationManifestSha256 !== pins.authorization.manifestSha256
      || input.pathManifestSha256 !== pins.path.manifestSha256
      || input.repositoryManifestSha256 !== pins.repository.manifestSha256) reject('PROTOCOL_UNSUPPORTED');
  const extensionRows = new Map(authority.registries.extensions.entries.map((entry) => [entry.id, entry]));
  const tuple = compatibility.entries.some((row) => {
    if (!['candidate', 'ratified'].includes(row.state)
        || input.authorizationManifestSha256 !== row.authorizationManifestSha256
        || input.pathManifestSha256 !== row.pathManifestSha256
        || input.repositoryManifestSha256 !== row.repositoryManifestSha256
        || SELECTION_FIELDS.some((field) => input.proposedSelection[field] !== row.selection[field])
        || !sameSet(input.proposedSelection.extensions, row.selection.extensions)
        || !sameSet(input.requiredCapabilities, row.requiredCapabilities)) return false;
    return input.proposedSelection.extensions.every((id) => ['candidate', 'ratified'].includes(extensionRows.get(id)?.state));
  });
  if (!tuple) reject('PROTOCOL_UNSUPPORTED');
  const frozen = authority.registries['release-assignments'];
  if (frozen.compatibilityPolicy !== 'immutable-code-name-scope-semantics-no-removal-unique-registered-optional-candidate-additions'
      || !Array.isArray(frozen.allowedAdditions)
      || input.priorAssignmentSnapshotSha256 !== frozen.snapshotSha256) reject('PROTOCOL_UNSUPPORTED');
  const byCode = new Map();
  const byName = new Map();
  for (const value of input.proposedAssignments) {
    const codeKey = assignmentKey(value);
    const nameKey = assignmentName(value);
    const codeMatch = byCode.get(codeKey);
    const nameMatch = byName.get(nameKey);
    if (codeMatch && !same(codeMatch, value) || nameMatch && !same(nameMatch, value)) reject('PROTOCOL_UNSUPPORTED');
    byCode.set(codeKey, value);
    byName.set(nameKey, value);
  }
  const priorCodes = new Set(frozen.entries.map(assignmentKey));
  const priorNames = new Set(frozen.entries.map(assignmentName));
  for (const prior of frozen.entries) {
    const codeMatch = byCode.get(assignmentKey(prior));
    const nameMatch = byName.get(assignmentName(prior));
    if (codeMatch === undefined || nameMatch === undefined || !same(codeMatch, prior) || !same(nameMatch, prior)) reject('PROTOCOL_UNSUPPORTED');
  }
  const allowed = new Set();
  for (const row of frozen.allowedAdditions) {
    if (row?.state !== 'candidate' || row?.requirement !== 'optional' || row?.major !== 1 || !row.assignment) reject('PROTOCOL_UNSUPPORTED');
    const registration = authority.registries[row.registry]?.entries?.find?.((entry) => entry.code === row.assignment.code
      && (entry.id ?? entry.name) === row.assignment.name && entry.state === row.state && entry.requirement === row.requirement);
    if (!registration) reject('PROTOCOL_UNSUPPORTED');
    allowed.add(canonicalJson(row.assignment));
  }
  for (const value of input.proposedAssignments) {
    if (priorCodes.has(assignmentKey(value))) continue;
    if (priorNames.has(assignmentName(value)) || !allowed.has(canonicalJson(value))) reject('PROTOCOL_UNSUPPORTED');
  }
  return trace('NONE', tracker, { semanticOutput: { compatible: true, assignmentCount: input.proposedAssignments.length, priorAssignmentSnapshotSha256: input.priorAssignmentSnapshotSha256 } });
}

function mapped(error) {
  if (error instanceof SemanticReject) return error.code;
  if (!(error instanceof AdapterFault)) return 'INTERNAL_ERROR';
  if (error.kind === 'limit') return 'PROTOCOL_LIMIT_EXCEEDED';
  if (error.kind === 'invalid') return 'PROTOCOL_MALFORMED';
  return 'INTERNAL_ERROR';
}

export async function evaluateIndependentCase(authority, supplied) {
  let tracker = new LimitTracker();
  let outputTrace = EMPTY_TRACE;
  let mutationCount = 0;
  let code = 'NONE';
  try {
    authority.validator.validate(supplied, 'RunnerCase.schema.json');
    const reduced = supplied.configuredLimits === undefined ? {} : configuredLimits(supplied.configuredLimits);
    tracker = new LimitTracker(reduced);
    const elapsedMs = executionElapsed(supplied.control);
    if (supplied.control.cancellation === 'before-operation') reject('CANCELLED');
    if (!Object.hasOwn(supplied.configuredLimits ?? {}, 'maxOperationTimeMs')
        && elapsedMs >= FROZEN_LIMITS.maxOperationTimeMs) reject('DEADLINE_EXCEEDED');
    configuredResourceRoutes(supplied, tracker, authority, elapsedMs);
    switch (supplied.operation) {
      case 'negotiate': outputTrace = negotiate(authority, supplied, tracker); break;
      case 'validate-envelope': outputTrace = envelope(authority, supplied, tracker); break;
      case 'fingerprint': ({ trace: outputTrace, mutationCount } = fingerprint(authority, supplied, tracker)); break;
      case 'validate-cursor': outputTrace = cursor(authority, supplied, tracker); break;
      case 'validate-stream': outputTrace = stream(authority, supplied, tracker); break;
      case 'transfer-probe': outputTrace = await transfer(authority, supplied, tracker); break;
      case 'contract-load': outputTrace = contractLoad(supplied.input, tracker); break;
      case 'runner-batch': outputTrace = runnerBatch(supplied.input, tracker); break;
      case 'release-preflight': outputTrace = release(authority, supplied.input, tracker); break;
      default: reject('PROTOCOL_UNSUPPORTED');
    }
    tracker.finish();
  } catch (error) {
    code = mapped(error);
    mutationCount = error?.mutationCount ?? mutationCount;
    outputTrace = error?.trace ?? trace(code, tracker);
  }
  const value = result(supplied.id, code, mutationCount, outputTrace);
  authority.validator.validate(value, 'AdapterResult.schema.json');
  return value;
}
