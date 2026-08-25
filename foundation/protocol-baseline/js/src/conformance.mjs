import {
  canonicalBytes, canonicalJson, cloneJson, deepFreeze, inspectJson, parseJson, sha256, sha256Bytes,
} from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError } from './errors.mjs';
import { HARD_LIMITS, PROTOCOL_LIMITS_BY_NAME, boundedInteger, deadlineFrom } from './limits.mjs';
import { validateProtocolValue } from './schema.mjs';

const CASE_FIELDS = new Set([
  'category', 'configuredLimits', 'control', 'expected', 'forbiddenResponseFields',
  'hiddenMarkerValues', 'hiddenServerInputs', 'id', 'input', 'inputKind', 'operation',
  'predecessorCase', 'requirementIds', 'resourceWitness', 'schemaVersion',
]);
const EXPECTED_FIELDS = new Set(['code', 'mutationCount', 'preMutation', 'result', 'semanticDigest', 'traceDigest']);
const OPERATIONS = Object.freeze([
  'negotiate', 'validate-envelope', 'fingerprint', 'validate-cursor',
  'validate-stream', 'transfer-probe', 'contract-load', 'runner-batch',
  'release-preflight',
]);
const OPERATION_INPUT_SCHEMAS = Object.freeze({
  negotiate: 'NegotiationCaseInput.schema.json',
  'validate-envelope': 'EnvelopeCaseInput.schema.json',
  fingerprint: 'FingerprintCaseInput.schema.json',
  'validate-cursor': 'CursorCaseInput.schema.json',
  'validate-stream': 'StreamCaseInput.schema.json',
  'transfer-probe': 'TransferCaseInput.schema.json',
  'contract-load': 'ContractLoadCaseInput.schema.json',
  'runner-batch': 'RunnerBatchCaseInput.schema.json',
  'release-preflight': 'ReleasePreflightCaseInput.schema.json',
});
const MIN_DERIVED_CANARY_BYTES = 12;
const MAX_DERIVED_CANARIES = 8192;
const MAX_DERIVED_CANARY_BYTES = 2 * HARD_LIMITS.jsonBytes;

function boundedText(value, label, maximum = 256) {
  const bytes = typeof value === 'string' ? Buffer.byteLength(value, 'utf8') : 0;
  if (bytes < 1 || bytes > maximum) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `${label} is invalid`);
  return value;
}

function checkClosed(value, fields, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some((key) => !fields.has(key))) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `${label} is not a closed object`);
}

function validateExpected(value) {
  checkClosed(value, EXPECTED_FIELDS, 'scenario expected result');
  if (!['accept', 'reject'].includes(value.result)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario expected result is invalid');
  boundedText(value.code, 'scenario expected code', 128);
  if (value.semanticDigest !== undefined && !/^[0-9a-f]{64}$/u.test(value.semanticDigest)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario expected semantic digest is invalid');
  if (!/^[0-9a-f]{64}$/u.test(value.traceDigest ?? '')) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario expected trace digest is invalid');
  if (typeof value.preMutation !== 'boolean' || !Number.isSafeInteger(value.mutationCount) || value.mutationCount < 0 || value.preMutation !== (value.mutationCount === 0)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario mutation witness is invalid');
}

function configuredLimitObject(value) {
  if (value === undefined) return;
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length < 1) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario configured limits are invalid');
  for (const [name, maximum] of Object.entries(value)) {
    const minimum = name === 'maxErrorParameters' ? 0 : 1;
    if (!Object.hasOwn(PROTOCOL_LIMITS_BY_NAME, name) || !Number.isSafeInteger(maximum) || maximum < minimum || maximum > PROTOCOL_LIMITS_BY_NAME[name]) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario configured limit is invalid');
  }
}

function validateScenario(value, options = {}) {
  checkClosed(value, CASE_FIELDS, 'protocol scenario');
  if (value.schemaVersion !== 'ogvcs.protocol/scenario/v1') protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario schemaVersion is invalid');
  boundedText(value.id, 'scenario id', 256);
  boundedText(value.category, 'scenario category', 128);
  if (!OPERATIONS.includes(value.operation)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario operation is invalid');
  if (!['semantic-value', 'raw-json', 'raw-bytes', 'jsonl'].includes(value.inputKind)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario inputKind is invalid');
  cloneJson(value.input, { ...options, maxBytes: HARD_LIMITS.jsonBytes });
  validateExpected(value.expected);
  configuredLimitObject(value.configuredLimits);
  cloneJson(value.control, { ...options, maxBytes: 16 * 1024, maxDepth: 4, maxNodes: 64, maxStringBytes: 256, maxCollectionItems: 32 });
  if (!Array.isArray(value.requirementIds) || value.requirementIds.length === 0 || value.requirementIds.length > 64 || value.requirementIds.some((item) => typeof item !== 'string' || item.length === 0 || item.length > 128)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario requirement IDs are invalid');
  if (!Array.isArray(value.forbiddenResponseFields) || value.forbiddenResponseFields.length > 64 || value.forbiddenResponseFields.some((item) => typeof item !== 'string' || !/^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)*$/u.test(item))) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario forbidden response fields are invalid');
  if (value.hiddenMarkerValues !== undefined) {
    if (!Array.isArray(value.hiddenMarkerValues) || value.hiddenMarkerValues.length < 1 || value.hiddenMarkerValues.length > 32 || value.hiddenMarkerValues.some((item) => typeof item !== 'string' || Buffer.byteLength(item, 'utf8') < 1 || Buffer.byteLength(item, 'utf8') > 1024)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario hidden marker inventory is invalid');
    if (value.hiddenServerInputs === undefined) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario hidden marker has no protected server input');
    const protectedText = canonicalJson(value.hiddenServerInputs, { ...options, maxBytes: 64 * 1024, maxDepth: 8, maxNodes: 256 });
    const publicText = canonicalJson({ input: value.input, control: value.control, configuredLimits: value.configuredLimits ?? null }, options);
    for (const marker of value.hiddenMarkerValues) {
      if (!protectedText.includes(marker) || publicText.includes(marker)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'scenario hidden marker isolation is invalid');
    }
  }
  if (value.hiddenServerInputs !== undefined) cloneJson(value.hiddenServerInputs, { ...options, maxBytes: 64 * 1024, maxDepth: 8, maxNodes: 256, maxStringBytes: 4096, maxCollectionItems: 256 });
  if (value.resourceWitness !== undefined) cloneJson(value.resourceWitness, { ...options, maxBytes: 16 * 1024, maxDepth: 4, maxNodes: 64, maxStringBytes: 512, maxCollectionItems: 32 });
  if (value.predecessorCase !== undefined) cloneJson(value.predecessorCase, { ...options, maxBytes: 16 * 1024, maxDepth: 4, maxNodes: 64, maxStringBytes: 512, maxCollectionItems: 32 });
}

export function protocolJsonRetentionBytes(value, options = {}) {
  const summary = inspectJson(value, { ...options, maxBytes: HARD_LIMITS.jsonBytes });
  const reservation = 128 + (4 * summary.encodedBytes);
  if (!Number.isSafeInteger(reservation)) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol retained JSON reservation overflows');
  return reservation;
}

export function collectProtocolScenarioPlan(contract, options = {}) {
  if (!contract?.vectors || typeof contract.vectors !== 'object') protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol contract has no vectors');
  const maximum = boundedInteger(options.maxCases, HARD_LIMITS.adapterCases, HARD_LIMITS.adapterCases, 'maxCases');
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  const deadline = deadlineFrom(options);
  const cases = [];
  const ids = new Set();
  let retainedBytes = 0;
  for (const [name, document] of Object.entries(contract.vectors).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)) {
    if (name === 'manifest') continue;
    if (!Array.isArray(document?.cases)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `protocol vector document has no cases: ${name}`);
    for (const supplied of document.cases) {
      if (cases.length >= maximum) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol scenario ceiling exceeded');
      const reservation = protocolJsonRetentionBytes(supplied, { deadline });
      if (retainedBytes + reservation > maximumWorking) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol scenario working-memory ceiling exceeded');
      const scenario = cloneJson(supplied, {
        maxBytes: HARD_LIMITS.jsonBytes,
        maxWorkingMemoryBytes: maximumWorking - retainedBytes,
        deadline,
      });
      validateScenario(scenario, {
        maxWorkingMemoryBytes: Math.max(1, maximumWorking - retainedBytes - reservation),
        deadline,
      });
      if (ids.has(scenario.id)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol scenario identifier is duplicated');
      ids.add(scenario.id);
      cases.push(scenario);
      retainedBytes += reservation;
    }
  }
  cases.sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
  return deepFreeze({ scenarios: deepFreeze(cases), retainedBytes });
}

export function collectProtocolScenarios(contract, options = {}) {
  return collectProtocolScenarioPlan(contract, options).scenarios;
}

export function scenarioForAdapter(scenario, contract, options = {}) {
  scenario = cloneJson(scenario, { ...options, maxBytes: HARD_LIMITS.jsonBytes });
  validateScenario(scenario, options);
  const output = {
    schemaVersion: 'ogvcs.protocol/runner-case/v1',
    id: scenario.id,
    operation: scenario.operation,
    input: scenario.input,
    inputKind: scenario.inputKind,
    control: scenario.control,
    ...(scenario.configuredLimits === undefined ? {} : { configuredLimits: scenario.configuredLimits }),
    ...(scenario.hiddenServerInputs === undefined ? {} : { serverContext: scenario.hiddenServerInputs }),
  };
  return contract === undefined
    ? cloneJson(output, { maxBytes: HARD_LIMITS.jsonBytes })
    : validateProtocolValue(contract, 'RunnerCase.schema.json', output, options);
}

function visitEncodedMarkerForms(marker, visit) {
  const bytes = Buffer.from(marker, 'utf8');
  const forms = [
    marker,
    bytes.toString('hex'),
    bytes.toString('base64'),
    bytes.toString('base64url'),
    [...bytes].map((value) => `%${value.toString(16).padStart(2, '0')}`).join(''),
    [...bytes].map((value) => `%${value.toString(16).padStart(2, '0').toUpperCase()}`).join(''),
  ];
  const digestDomains = [
    Buffer.alloc(0),
    Buffer.from('ogvcs.protocol/idempotency/v1\0', 'ascii'),
    Buffer.from('OGVCS-PROTOCOL-IDEMPOTENCY-KEY-V1\0', 'ascii'),
    Buffer.from('OGVCS-PROTOCOL-CURSOR-TOKEN-V1\0', 'ascii'),
    Buffer.from('OGVCS-PROTOCOL-NEGOTIATION-RECEIPT-V1\0', 'ascii'),
  ];
  for (const domain of digestDomains) {
    const digest = sha256Bytes(Buffer.concat([domain, bytes]));
    forms.push(digest.toString('hex'));
    forms.push(digest.toString('base64'));
    forms.push(digest.toString('base64url'));
  }
  for (const value of forms) {
    visit(value);
    if (value.length < 24) continue;
    const width = Math.min(48, Math.max(16, Math.floor(value.length / 2)));
    // The suffix carries each seeded canary's unique portion. Scanning every
    // short interior window would collide with legitimate public code names
    // such as NEGOTIATION_* and create a disclosure oracle of its own.
    visit(value.slice(-width));
    if (value !== marker) visit(value.slice(0, width));
  }
}

function scanText(value, forms, deadline) {
  if (typeof value !== 'string' || value.length === 0) return;
  let inspected = 0;
  for (const form of forms) {
    if (value.includes(form)) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter output disclosed protected material');
    inspected += 1;
    if ((inspected & 1023) === 0) deadline?.checkpoint();
  }
}

function schemaPointer(root, fragment) {
  let value = root;
  for (const token of fragment.split('/').slice(1)) {
    const key = token.replaceAll('~1', '/').replaceAll('~0', '~');
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, key)) return undefined;
    value = value[key];
  }
  return value;
}

function resolveSchemaRef(contract, root, ref) {
  if (typeof ref !== 'string' || ref.length === 0) return undefined;
  if (ref.startsWith('#')) return { schema: schemaPointer(root, ref.slice(1)), root };
  const [path, fragment = ''] = ref.split('#', 2);
  const name = path.slice(path.lastIndexOf('/') + 1);
  const external = contract.schemas[name];
  if (external === undefined) return undefined;
  return { schema: fragment === '' ? external : schemaPointer(external, fragment), root: external };
}

export function protocolStringSetRetentionBytes(values) {
  let retainedBytes = 0;
  for (const value of values) {
    const reservation = 128 + (2 * value.length);
    retainedBytes += reservation;
    if (!Number.isSafeInteger(retainedBytes)) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protected-canary reservation overflows');
  }
  return retainedBytes;
}

function derivedCanaryCollector(options = {}) {
  const values = new Set();
  let totalBytes = 0;
  let retainedBytes = 0;
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  const add = (value) => {
    if (typeof value !== 'string') return;
    const bytes = Buffer.byteLength(value, 'utf8');
    if (bytes < MIN_DERIVED_CANARY_BYTES || values.has(value)) return;
    if (values.size >= MAX_DERIVED_CANARIES || totalBytes + bytes > MAX_DERIVED_CANARY_BYTES) {
      protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'derived protected-canary ceiling exceeded');
    }
    const reservation = 128 + (2 * value.length);
    if (!Number.isSafeInteger(reservation) || retainedBytes + reservation > maximumWorking) {
      protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'derived protected-canary working-memory ceiling exceeded');
    }
    values.add(value);
    totalBytes += bytes;
    retainedBytes += reservation;
  };
  const addValue = (value, descendants = false) => {
    if (typeof value === 'string') { add(value); return; }
    if (value === null || typeof value !== 'object') return;
    if (retainedBytes >= maximumWorking) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'derived protected-canary working-memory ceiling exceeded');
    const canonical = canonicalJson(value, {
      ...options,
      maxBytes: HARD_LIMITS.jsonBytes,
      maxWorkingMemoryBytes: maximumWorking - retainedBytes,
    });
    add(canonical);
    if (!descendants) return;
    const pending = [value];
    while (pending.length > 0) {
      const current = pending.pop();
      if (typeof current === 'string') add(current);
      else if (Array.isArray(current)) pending.push(...current);
      else if (current && typeof current === 'object') pending.push(...Object.values(current));
    }
  };
  return { add, addValue, values };
}

function walkSensitiveSchema(contract, value, schema, root, collector, state) {
  if (schema === null || typeof schema !== 'object') return;
  if (value && typeof value === 'object') {
    let visited = state.seen.get(value);
    if (visited === undefined) { visited = new WeakSet(); state.seen.set(value, visited); }
    if (visited.has(schema)) return;
    visited.add(schema);
  }
  if (schema['x-ogvcs-sensitive'] === true) collector.addValue(value, schema.$ref?.endsWith('#/$defs/JsonValue') === true);
  if (schema.$ref !== undefined) {
    const resolved = resolveSchemaRef(contract, root, schema.$ref);
    if (resolved?.schema !== undefined) walkSensitiveSchema(contract, value, resolved.schema, resolved.root, collector, state);
  }
  for (const keyword of ['allOf', 'anyOf', 'oneOf']) {
    if (Array.isArray(schema[keyword])) for (const branch of schema[keyword]) walkSensitiveSchema(contract, value, branch, root, collector, state);
  }
  for (const keyword of ['if', 'then', 'else', 'not']) {
    if (schema[keyword] !== undefined) walkSensitiveSchema(contract, value, schema[keyword], root, collector, state);
  }
  if (Array.isArray(value) && schema.items !== undefined) {
    for (const item of value) walkSensitiveSchema(contract, item, schema.items, root, collector, state);
  } else if (value && typeof value === 'object' && !Array.isArray(value)) {
    const properties = schema.properties ?? {};
    for (const [name, childSchema] of Object.entries(properties)) {
      if (Object.hasOwn(value, name)) walkSensitiveSchema(contract, value[name], childSchema, root, collector, state);
    }
    if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
      for (const [name, child] of Object.entries(value)) {
        if (!Object.hasOwn(properties, name)) walkSensitiveSchema(contract, child, schema.additionalProperties, root, collector, state);
      }
    }
  }
}

function decodedEnvelopeDocument(input) {
  try {
    if (input.encoding === 'semantic-json') return input.document;
    if (Array.isArray(input.rawInputUtf16CodeUnits)) return parseJson(String.fromCharCode(...input.rawInputUtf16CodeUnits), { maxBytes: HARD_LIMITS.jsonBytes });
    if (input.encoding === 'raw-hex') {
      if (typeof input.rawInput !== 'string' || input.rawInput.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(input.rawInput)) return undefined;
      return parseJson(Buffer.from(input.rawInput, 'hex'), { maxBytes: HARD_LIMITS.jsonBytes });
    }
    return parseJson(input.rawInput, { maxBytes: HARD_LIMITS.jsonBytes });
  } catch { return undefined; }
}

function derivedSensitiveCanaries(contract, scenario, options = {}) {
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  const supplied = scenarioForAdapter(scenario, contract, options);
  const suppliedReservation = protocolJsonRetentionBytes(supplied, { deadline: options.deadline });
  if (suppliedReservation >= maximumWorking) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'derived protected-canary working-memory ceiling exceeded');
  const collector = derivedCanaryCollector({
    ...options,
    maxWorkingMemoryBytes: maximumWorking - suppliedReservation,
  });
  const state = { seen: new WeakMap() };
  const inputSchema = contract.schemas[OPERATION_INPUT_SCHEMAS[supplied.operation]];
  if (inputSchema !== undefined) walkSensitiveSchema(contract, supplied.input, inputSchema, inputSchema, collector, state);
  if (supplied.serverContext !== undefined) collector.addValue(supplied.serverContext, true);
  if (supplied.operation === 'validate-envelope') {
    const document = decodedEnvelopeDocument(supplied.input);
    const schema = supplied.input.targetSchema === 'JsonValue' ? undefined : contract.schemas[`${supplied.input.targetSchema}.schema.json`];
    if (document !== undefined && schema !== undefined) walkSensitiveSchema(contract, document, schema, schema, collector, state);
  } else if (supplied.operation === 'transfer-probe') {
    const schema = contract.schemas['TransferProbe.schema.json'];
    if (schema !== undefined) walkSensitiveSchema(contract, supplied.input.probe, schema, schema, collector, state);
  } else if (supplied.operation === 'validate-cursor') {
    const pageSchema = contract.schemas['PageEnvelope.schema.json'];
    if (pageSchema !== undefined) walkSensitiveSchema(contract, supplied.input.page, pageSchema, pageSchema, collector, state);
    if (typeof supplied.input.suppliedToken === 'string') collector.add(supplied.input.suppliedToken);
  } else if (supplied.operation === 'fingerprint' && typeof supplied.input.idempotencyKey === 'string') {
    collector.add(supplied.input.idempotencyKey);
  }
  return collector.values;
}

function compileProtectedForms(contract, scenarios, options = {}) {
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  const deadline = deadlineFrom(options);
  const markers = new Set();
  const forms = new Set();
  let retainedBytes = 0;
  const addRetained = (set, value, temporaryBytes = 0) => {
    if (set.has(value)) return;
    const reservation = 128 + (2 * value.length);
    if (!Number.isSafeInteger(reservation) || retainedBytes + temporaryBytes + reservation > maximumWorking) {
      protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protected-canary working-memory ceiling exceeded');
    }
    set.add(value);
    retainedBytes += reservation;
  };
  const addMarker = (marker, temporaryBytes = 0) => {
    if (markers.has(marker)) return;
    addRetained(markers, marker, temporaryBytes);
    visitEncodedMarkerForms(marker, (form) => addRetained(forms, form, temporaryBytes));
  };
  for (const scenario of scenarios) {
    for (const marker of scenario.hiddenMarkerValues ?? []) addMarker(marker);
    const derived = derivedSensitiveCanaries(contract, scenario, {
      deadline,
      maxWorkingMemoryBytes: Math.max(1, maximumWorking - retainedBytes),
    });
    const temporaryBytes = protocolStringSetRetentionBytes(derived);
    for (const marker of derived) addMarker(marker, temporaryBytes);
    deadline.checkpoint();
  }
  return forms;
}

function inspectTrace(trace, scenario, contract, options) {
  const deadline = deadlineFrom(options);
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  const forbidden = new Set(scenario.forbiddenResponseFields);
  const forms = compileProtectedForms(contract, [scenario], options);
  const fixedReservation = protocolStringSetRetentionBytes(forms) + (128 * forbidden.size);
  if (!Number.isSafeInteger(fixedReservation) || fixedReservation >= maximumWorking) {
    protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'adapter trace-audit working-memory ceiling exceeded');
  }
  const stack = [{ value: trace, path: '' }];
  const stringFragments = [];
  let fragmentUnits = 0;
  const checkFragments = () => {
    const fragmentReservation = (32 * stringFragments.length) + (2 * fragmentUnits);
    if (!Number.isSafeInteger(fragmentReservation) || fixedReservation + fragmentReservation > maximumWorking) {
      protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'adapter trace-audit working-memory ceiling exceeded');
    }
  };
  let nodes = 0;
  while (stack.length > 0) {
    const { value, path } = stack.pop();
    nodes += 1;
    if ((nodes & 1023) === 0) deadline.checkpoint();
    if (typeof value === 'string') {
      scanText(value, forms, deadline);
      stringFragments.push(value);
      fragmentUnits += value.length;
      checkFragments();
    }
    if (value === null || typeof value !== 'object') continue;
    if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index -= 1) stack.push({ value: value[index], path: `${path}/${index}` });
      continue;
    }
    for (const [key, child] of Object.entries(value)) {
      const dotted = path.length === 0 ? key : `${path}.${key}`;
      if (forbidden.has(key) || forbidden.has(dotted) || [...forbidden].some((candidate) => dotted.endsWith(`.${candidate}`))) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, 'adapter trace disclosed a forbidden response field');
      scanText(key, forms, deadline);
      stringFragments.push(key);
      fragmentUnits += key.length;
      checkFragments();
      stack.push({ value: child, path: dotted });
    }
  }
  scanText(stringFragments.join(''), forms, deadline);
  const retainedAuditBytes = fixedReservation + (32 * stringFragments.length);
  scanText(canonicalJson(trace, {
    ...options,
    maxBytes: HARD_LIMITS.jsonBytes,
    maxWorkingMemoryBytes: maximumWorking - retainedAuditBytes,
    deadline,
  }), forms, deadline);
  deadline.checkpoint();
}

export function protectedAdapterOutputForms(contract, scenarios, deadline, options = {}) {
  const forms = compileProtectedForms(contract, scenarios, { ...options, deadline });
  deadline.checkpoint();
  return forms;
}

export function assertNoProtectedAdapterOutput(text, forms, deadline) {
  scanText(text, forms, deadline);
  deadline.checkpoint();
}

function normalizeResult(contract, scenario, value, options) {
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  let adapterResult;
  try {
    adapterResult = validateProtocolValue(contract, 'AdapterResult.schema.json', value, options);
  } catch (error) {
    protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, `adapter returned an invalid result: ${scenario.id}`, { cause: error });
  }
  if (adapterResult.id !== scenario.id) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, `adapter result identity is out of order: ${scenario.id}`);
  const adapterReservation = protocolJsonRetentionBytes(adapterResult, { deadline: options.deadline });
  if (adapterReservation >= maximumWorking) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'adapter normalized-result working-memory ceiling exceeded');
  const remainingOptions = { ...options, maxWorkingMemoryBytes: maximumWorking - adapterReservation };
  try {
    inspectTrace(adapterResult.trace, scenario, contract, remainingOptions);
  } catch (error) {
    if (error?.code === RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL) protocolError(RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL, `adapter trace failed disclosure audit: ${scenario.id}`, { cause: error });
    throw error;
  }
  const projected = {
    schemaVersion: 'ogvcs.protocol/runner-result/v1', id: adapterResult.id,
    result: adapterResult.result, code: adapterResult.code,
    preMutation: adapterResult.preMutation, mutationCount: adapterResult.mutationCount,
    traceDigest: sha256(canonicalBytes(adapterResult.trace, remainingOptions)),
    ...(scenario.expected.semanticDigest === undefined ? {} : { semanticDigest: sha256(canonicalBytes(adapterResult.trace.semanticOutput, remainingOptions)) }),
  };
  return validateProtocolValue(contract, 'RunnerResult.schema.json', projected, remainingOptions);
}

function sameOutcome(expected, actual) {
  return expected.result === actual.result
    && expected.code === actual.code
    && expected.preMutation === actual.preMutation
    && expected.mutationCount === actual.mutationCount
    && expected.traceDigest === actual.traceDigest
    && (expected.semanticDigest === undefined || expected.semanticDigest === actual.semanticDigest);
}

export function createRunnerHello(contract, adapterId, options = {}) {
  return validateProtocolValue(contract, 'RunnerHello.schema.json', {
    schemaVersion: 'ogvcs.protocol/runner-hello/v1',
    adapterId: boundedText(adapterId, 'adapterId'),
    contractManifestSha256: contract.manifestSha256,
    operations: [...OPERATIONS],
  }, options);
}

export async function runProtocolConformanceWithPlan(contract, evaluator, options, plan, baseRetainedBytes = 0) {
  if (typeof evaluator !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol scenario evaluator must be callable');
  const adapterId = boundedText(options.adapterId ?? options.implementation, 'adapterId');
  const deadline = deadlineFrom(options);
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  if (!plan || !Array.isArray(plan.scenarios) || !Number.isSafeInteger(plan.retainedBytes) || plan.retainedBytes < 0
      || !Number.isSafeInteger(baseRetainedBytes) || baseRetainedBytes < 0
      || plan.retainedBytes + baseRetainedBytes > maximumWorking) {
    protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol runner retained working-memory ceiling exceeded');
  }
  const scenarios = plan.scenarios;
  const results = [];
  let retainedBytes = plan.retainedBytes + baseRetainedBytes;
  let passed = 0;
  for (const scenario of scenarios) {
    deadline.checkpoint();
    let supplied = scenarioForAdapter(scenario, contract, {
      deadline,
      maxWorkingMemoryBytes: Math.max(1, maximumWorking - retainedBytes),
    });
    const suppliedReservation = protocolJsonRetentionBytes(supplied, { deadline });
    if (retainedBytes + suppliedReservation > maximumWorking) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol runner-case working-memory ceiling exceeded');
    let actualValue;
    try {
      actualValue = await deadline.race(Promise.resolve(evaluator(supplied, {
        contract,
        deadline,
        maxWorkingMemoryBytes: Math.max(1, maximumWorking - retainedBytes - suppliedReservation),
      })), `scenario ${scenario.id}`);
    } catch (error) {
      if (error?.code?.startsWith?.('PROTOCOL_')) throw error;
      protocolError(RUNTIME_ERROR_CODES.ADAPTER_FAILED, `scenario evaluator failed: ${scenario.id}`, { cause: error });
    }
    const actualValueReservation = protocolJsonRetentionBytes(actualValue, { deadline });
    if (retainedBytes + suppliedReservation + (2 * actualValueReservation) > maximumWorking) {
      protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol runner-result working-memory ceiling exceeded');
    }
    const actual = normalizeResult(contract, scenario, actualValue, {
      deadline,
      maxBytes: HARD_LIMITS.jsonBytes,
      maxWorkingMemoryBytes: maximumWorking - retainedBytes - suppliedReservation - actualValueReservation,
    });
    actualValue = undefined;
    supplied = undefined;
    if (sameOutcome(scenario.expected, actual)) passed += 1;
    results.push(actual);
    retainedBytes += protocolJsonRetentionBytes(actual, { deadline });
  }
  const frozenReservation = protocolJsonRetentionBytes(results, { deadline });
  if (retainedBytes + frozenReservation > maximumWorking) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol report working-memory ceiling exceeded');
  const frozenResults = cloneJson(results, {
    maxBytes: HARD_LIMITS.jsonBytes,
    maxWorkingMemoryBytes: maximumWorking - retainedBytes,
    deadline,
  });
  const resultCount = results.length;
  results.length = 0;
  retainedBytes = plan.retainedBytes + baseRetainedBytes + frozenReservation;
  if (retainedBytes + 512 > maximumWorking) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol report working-memory ceiling exceeded');
  const report = {
    schemaVersion: 'ogvcs.protocol/runner-report/v1',
    adapterId,
    contractManifestSha256: contract.manifestSha256,
    results: frozenResults,
    passed,
    failed: resultCount - passed,
    reportDigest: sha256(canonicalBytes(frozenResults, {
      maxBytes: HARD_LIMITS.jsonBytes,
      maxWorkingMemoryBytes: maximumWorking - retainedBytes,
      deadline,
    })),
  };
  const reportReservation = protocolJsonRetentionBytes(report, { deadline });
  if (retainedBytes + 512 + reportReservation > maximumWorking) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol report working-memory ceiling exceeded');
  return deepFreeze(validateProtocolValue(contract, 'RunnerReport.schema.json', report, {
    maxBytes: HARD_LIMITS.jsonBytes,
    maxWorkingMemoryBytes: maximumWorking - retainedBytes - 512,
    deadline,
  }));
}

export async function runProtocolConformance(contract, evaluator, options = {}) {
  const plan = collectProtocolScenarioPlan(contract, options);
  return runProtocolConformanceWithPlan(contract, evaluator, options, plan);
}

export { OPERATIONS as PROTOCOL_OPERATIONS };
