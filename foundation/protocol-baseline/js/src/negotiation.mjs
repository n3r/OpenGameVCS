import { randomBytes } from 'node:crypto';

import { base64urlEncode, cloneJson, deepFreeze } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError, protocolSemanticError } from './errors.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';
import { validateProtocolValue } from './schema.mjs';

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

function timeValue(value) {
  if (!Number.isSafeInteger(value) || value < 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'negotiation time is invalid');
  return value;
}

function capabilityRegistry(contract) {
  const registry = contract?.registries?.capabilities;
  if (registry?.registry !== 'capabilities' || !Array.isArray(registry.entries)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'capability registry is invalid');
  return registry.entries;
}

function compatibilityRegistry(contract) {
  const registry = contract?.registries?.compatibility;
  if (registry?.registry !== 'compatibility' || !Array.isArray(registry.entries) || registry.entries.length === 0) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'compatibility registry is invalid');
  return registry.entries;
}

function semanticFailure(code) {
  protocolSemanticError(code, 'protocol negotiation failed before mutation');
}

function principalValue(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).sort().join('\0') !== ['authorityEpoch', 'sessionId', 'subjectDigest', 'tenantDigest'].join('\0') || !/^[0-9a-f]{64}$/u.test(input.subjectDigest ?? '') || !/^[0-9a-f]{64}$/u.test(input.tenantDigest ?? '') || !Number.isSafeInteger(input.authorityEpoch) || input.authorityEpoch < 0 || typeof input.sessionId !== 'string' || Buffer.byteLength(input.sessionId, 'utf8') < 16 || Buffer.byteLength(input.sessionId, 'utf8') > 256 || !/^[A-Za-z0-9._~-]+$/u.test(input.sessionId)) {
    semanticFailure('AUTHORIZATION_DENIED');
  }
  return cloneJson(input, { maxBytes: 2048, maxDepth: 2, maxNodes: 16, maxStringBytes: 256, maxCollectionItems: 8 });
}

function selectedTokens(selection) {
  return new Set([
    selection.protocolVersion, selection.messageSchemaVersion, selection.repositoryFormat,
    selection.authorizationContract, selection.pathContract, selection.pathProfile,
    selection.eventVersion, selection.transferProfile, ...selection.extensions,
  ]);
}

export function buildBaselineOffer(contract, options = {}) {
  const row = compatibilityRegistry(contract)
    .filter((entry) => NEW_SESSION_STATES.has(entry.state))
    .sort((left, right) => left.code - right.code)[0];
  if (row === undefined) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'compatibility registry has no tuple eligible for a new session');
  const selection = row.selection;
  return validateProtocolValue(contract, 'NegotiationOffer.schema.json', {
    schemaVersion: 'ogvcs.protocol/negotiation-offer/v1',
    clientNonce: options.clientNonce ?? base64urlEncode(randomBytes(16)),
    correlationId: options.correlationId ?? 'correlation-default',
    capabilities: {
      protocolVersions: [selection.protocolVersion],
      schemaVersions: [selection.messageSchemaVersion],
      repositoryFormats: [selection.repositoryFormat],
      authorizationContracts: [selection.authorizationContract],
      pathContracts: [selection.pathContract],
      pathProfiles: [selection.pathProfile],
      eventVersions: [selection.eventVersion],
      transferProfiles: [selection.transferProfile],
      extensions: [...selection.extensions],
      requiredCapabilities: [...row.requiredCapabilities],
    },
    ...(options.deadlineUnixMs === undefined ? {} : { deadlineUnixMs: options.deadlineUnixMs }),
  }, options);
}

export class ProtocolNegotiator {
  #authenticate;
  #contract;
  #minimumCapabilities;
  #maxCapabilityItems;
  #now;
  #random;
  #receiptCodec;
  #repositoryRequirements;
  #ttlMs;

  constructor(options = {}) {
    this.#contract = options.contract;
    this.#receiptCodec = options.receiptCodec;
    this.#authenticate = options.authenticate;
    this.#repositoryRequirements = options.repositoryRequirements ?? (async () => ({ requiredCapabilities: [] }));
    this.#minimumCapabilities = new Set(options.minimumCapabilities ?? []);
    this.#maxCapabilityItems = boundedInteger(options.maxCapabilityItems, HARD_LIMITS.capabilityItems, HARD_LIMITS.capabilityItems, 'maxCapabilityItems');
    this.#ttlMs = boundedInteger(options.receiptTtlMs, HARD_LIMITS.receiptLifetimeMs, HARD_LIMITS.receiptLifetimeMs, 'receiptTtlMs');
    this.#now = options.now ?? (() => Date.now());
    this.#random = options.randomBytes ?? randomBytes;
    if (!this.#contract?.validator || typeof this.#receiptCodec?.issue !== 'function' || typeof this.#receiptCodec?.verify !== 'function') protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'negotiator requires a contract and receipt codec');
    if (typeof this.#authenticate !== 'function' || typeof this.#repositoryRequirements !== 'function' || typeof this.#now !== 'function' || typeof this.#random !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'negotiator callbacks are invalid');
  }

  #time() { return timeValue(this.#now()); }

  async negotiate(offerInput, context = {}, options = {}) {
    const deadline = deadlineFrom(options);
    const offer = validateProtocolValue(this.#contract, 'NegotiationOffer.schema.json', offerInput, { maxBytes: HARD_LIMITS.controlMessageBytes, deadline });
    for (const [name, values] of Object.entries(offer.capabilities)) {
      if (!Array.isArray(values) || values.length > this.#maxCapabilityItems) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `negotiation capability-axis ceiling exceeded: ${name}`);
    }
    if (offer.deadlineUnixMs !== undefined && offer.deadlineUnixMs <= this.#time()) semanticFailure('DEADLINE_EXCEEDED');
    let principal;
    try { principal = principalValue(await deadline.race(this.#authenticate(offer, cloneJson(context, { maxBytes: 16 * 1024, deadline }), { deadline, signal: deadline.signal }), 'negotiation authentication')); } catch (error) {
      if (error?.code) throw error;
      semanticFailure('AUTHORIZATION_DENIED');
    }
    // Repository-specific state is deliberately unavailable until the
    // principal/session callback has succeeded.
    let requirements;
    try { requirements = await deadline.race(this.#repositoryRequirements(cloneJson(principal), cloneJson(context, { maxBytes: 16 * 1024, deadline }), { deadline, signal: deadline.signal }), 'repository capability lookup'); } catch (error) {
      if (error?.code) throw error;
      semanticFailure('AUTHORIZATION_DENIED');
    }
    const known = new Map(capabilityRegistry(this.#contract).map((entry) => [entry.id, entry]));
    for (const required of offer.capabilities.requiredCapabilities) if (!known.has(required)) semanticFailure('NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN');
    for (const minimum of this.#minimumCapabilities) {
      if (!known.has(minimum) || !offer.capabilities.requiredCapabilities.includes(minimum)) semanticFailure('NEGOTIATION_DOWNGRADE_REJECTED');
    }
    const repositoryRequired = requirements?.requiredCapabilities ?? [];
    if (!Array.isArray(repositoryRequired) || repositoryRequired.length > this.#maxCapabilityItems || repositoryRequired.some((item) => typeof item !== 'string')) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'repository capability requirements are invalid');
    for (const required of repositoryRequired) if (!known.has(required)) semanticFailure('NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN');

    let chosen;
    for (const row of compatibilityRegistry(this.#contract).slice().sort((left, right) => left.code - right.code)) {
      deadline.checkpoint();
      if (!NEW_SESSION_STATES.has(row.state)) continue;
      if (AXES.some(([offerField, selectionField]) => !offer.capabilities[offerField].includes(row.selection[selectionField]))) continue;
      const offeredExtensions = new Set(offer.capabilities.extensions);
      const extensions = row.selection.extensions.filter((id) => offeredExtensions.has(id));
      const selection = validateProtocolValue(this.#contract, 'NegotiationSelection.schema.json', { ...row.selection, extensions }, { deadline });
      const tokens = selectedTokens(selection);
      const requirementsSatisfied = [...row.requiredCapabilities, ...repositoryRequired, ...offer.capabilities.requiredCapabilities].every((required) => {
        const assignment = known.get(required);
        if (assignment?.axis === 'feature') return offer.capabilities.requiredCapabilities.includes(required) && row.requiredCapabilities.includes(required);
        return tokens.has(required);
      });
      if (!requirementsSatisfied) continue;
      chosen = selection;
      break;
    }
    if (!chosen) semanticFailure('NEGOTIATION_NO_COMMON_VERSION');
    const now = this.#time();
    if (this.#ttlMs > Number.MAX_SAFE_INTEGER - now) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'negotiation receipt expiry overflows');
    let nonce;
    try { nonce = Buffer.from(this.#random(16)); } catch (error) { protocolError(RUNTIME_ERROR_CODES.IO, 'negotiation nonce source failed', { cause: error }); }
    if (nonce.length < 16 || nonce.length > 64) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'negotiation nonce source returned a value outside the 16 to 64 byte range');
    const claims = {
      schemaVersion: 'ogvcs.protocol/negotiation-receipt-claims/v1', selection: chosen,
      subjectDigest: principal?.subjectDigest, tenantDigest: principal?.tenantDigest,
      authorityEpoch: principal?.authorityEpoch, sessionId: principal?.sessionId,
      clientNonce: offer.clientNonce, serverNonce: base64urlEncode(nonce),
      issuedAtUnixMs: now, expiresAtUnixMs: now + this.#ttlMs,
    };
    const receipt = this.#receiptCodec.issue(claims, { ...options, deadline, atUnixMs: now });
    return deepFreeze({ selection: chosen, receipt });
  }

  verifyMutationReceipt(receipt, principal, options = {}) {
    if (options.selection === undefined) {
      protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'negotiation receipt requires the current authenticated selection');
    }
    const selection = validateProtocolValue(this.#contract, 'NegotiationSelection.schema.json', options.selection, options);
    const bindings = {
      subjectDigest: principal?.subjectDigest,
      tenantDigest: principal?.tenantDigest,
      authorityEpoch: principal?.authorityEpoch,
      sessionId: principal?.sessionId,
      selection,
    };
    return this.#receiptCodec.verify(receipt, bindings, options);
  }
}

export { AXES as NEGOTIATION_AXES };
