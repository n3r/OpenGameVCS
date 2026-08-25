import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { cloneJson, deepFreeze, sha256 } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError, protocolSemanticError } from './errors.mjs';
import { validateCompactTransferGrant } from './grants.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';
import { ProtocolProblemCatalog } from './problems.mjs';
import { validateProtocolValue } from './schema.mjs';

const HTTP_FIELD_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const CANONICAL_DECIMAL = /^(?:0|[1-9][0-9]{0,15})$/u;
const STRONG_ETAG = /^"([A-Za-z0-9._~-]{16,256})"$/u;

function semanticRange(message) {
  protocolSemanticError('TRANSFER_RANGE_INVALID', message);
}

function semanticValidator(message) {
  protocolSemanticError('TRANSFER_VALIDATOR_MISMATCH', message);
}

function exactInertRecord(input, label, expectedKeys) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || utilTypes.isProxy(input)) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} must be an inert object`);
  }
  let prototype;
  let keys;
  let descriptors;
  try {
    prototype = Object.getPrototypeOf(input);
    keys = Reflect.ownKeys(input);
    descriptors = Object.getOwnPropertyDescriptors(input);
  } catch (error) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} cannot be inspected safely`, { cause: error });
  }
  if (prototype !== Object.prototype && prototype !== null
      || keys.some((key) => typeof key !== 'string')
      || keys.length !== expectedKeys.length
      || expectedKeys.some((key) => !keys.includes(key))) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} fields are invalid`);
  }
  const output = Object.create(null);
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} contains an accessor or hidden field`);
    }
    output[key] = descriptor.value;
  }
  return Object.freeze(output);
}

function headerMap(input, label, maximum, options) {
  const deadline = deadlineFrom(options);
  const headers = cloneJson(input, {
    ...options,
    deadline,
    maxBytes: maximum,
    maxDepth: 3,
    maxNodes: 1024,
    maxStringBytes: maximum,
    maxCollectionItems: 1024,
  });
  if (!Array.isArray(headers)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} headers must be an array`);
  const output = new Map();
  let bytes = 0;
  for (const header of headers) {
    if (!header || typeof header !== 'object' || Array.isArray(header)
        || Object.keys(header).sort().join('\0') !== 'name\0value'
        || typeof header.name !== 'string' || !HTTP_FIELD_NAME.test(header.name)
        || typeof header.value !== 'string' || /[\r\n\0]/u.test(header.value)) {
      protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} header is malformed`);
    }
    bytes += Buffer.byteLength(header.name, 'utf8') + Buffer.byteLength(header.value, 'utf8') + 4;
    if (!Number.isSafeInteger(bytes) || bytes > maximum) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `${label} header ceiling exceeded`);
    const name = header.name.toLowerCase();
    if (output.has(name)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} contains a duplicate case-insensitive header`);
    output.set(name, header.value);
  }
  return Object.freeze({ headers, map: output, bytes });
}

function decimalField(value, label) {
  if (typeof value !== 'string' || !CANONICAL_DECIMAL.test(value)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} is not a canonical decimal`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} is outside the safe integer domain`);
  return parsed;
}

function quotedValidator(value, label) {
  const match = typeof value === 'string' ? STRONG_ETAG.exec(value) : null;
  if (!match) semanticValidator(`${label} is not a quoted strong validator`);
  return match[1];
}

function requiredStrongValidator(value, label) {
  const match = typeof value === 'string' ? STRONG_ETAG.exec(value) : null;
  if (!match) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} is not a canonical quoted strong validator`);
  return match[1];
}

function requiredContentDigest(value) {
  const match = typeof value === 'string' ? /^sha-256=:([A-Za-z0-9+/]{43}=):$/u.exec(value) : null;
  if (!match) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'Content-Digest is not canonical RFC 9530 SHA-256');
  const bytes = Buffer.from(match[1], 'base64');
  if (bytes.length !== 32 || bytes.toString('base64') !== match[1]) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'Content-Digest is not canonical RFC 9530 SHA-256');
  }
  return bytes.toString('hex');
}

function decodeResponseBodyHex(value, maximumBytes, maximumWorkingBytes, deadline) {
  if (typeof value !== 'string' || value.length % 2 !== 0) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'HTTP response body is not lowercase even-length hex');
  }
  const byteLength = value.length / 2;
  if (byteLength > maximumBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'HTTP response body exceeds the receiver range ceiling');
  const liveBytes = value.length * 2 + byteLength + 1024;
  if (!Number.isSafeInteger(liveBytes) || liveBytes > maximumWorkingBytes) {
    protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'HTTP response body exceeds the working-memory ceiling');
  }
  if (!/^(?:[0-9a-f]{2})*$/u.test(value)) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'HTTP response body is not lowercase even-length hex');
  }
  deadline.checkpoint();
  const output = Buffer.from(value, 'hex');
  deadline.checkpoint();
  if (output.length !== byteLength || output.toString('hex') !== value) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'HTTP response body hex is not canonical');
  return output;
}

function bytesValue(value, maximum, maximumWorking, label, deadline) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} must be bytes`);
  if (value.byteLength > maximum) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `${label} byte ceiling exceeded`);
  if (value.byteLength + 1024 > maximumWorking) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `${label} working-memory ceiling exceeded`);
  deadline.checkpoint();
  const bytes = Buffer.from(value);
  deadline.checkpoint();
  return bytes;
}

function digestField(bytes, deadline) {
  deadline.checkpoint();
  const digest = createHash('sha256').update(bytes).digest('base64');
  deadline.checkpoint();
  return `sha-256=:${digest}:`;
}

function hexadecimalDigest(bytes, deadline) {
  deadline.checkpoint();
  const digest = sha256(bytes);
  deadline.checkpoint();
  return digest;
}

function validatorForTrustedBytes(bytes, deadline) {
  return `"sha256-${hexadecimalDigest(bytes, deadline)}"`;
}

export function strongRepresentationValidator(bytes, options = {}) {
  const deadline = deadlineFrom(options);
  const maximum = boundedInteger(options.maxRepresentationBytes, HARD_LIMITS.assetBytes, HARD_LIMITS.contractBytes, 'maxRepresentationBytes');
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  const value = bytesValue(bytes, maximum, maximumWorking, 'representation', deadline);
  return validatorForTrustedBytes(value, deadline);
}

export function rfc9530Sha256(bytes, options = {}) {
  const deadline = deadlineFrom(options);
  const maximum = boundedInteger(options.maxBytes, HARD_LIMITS.assetBytes, HARD_LIMITS.contractBytes, 'digest maxBytes');
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  return digestField(bytesValue(bytes, maximum, maximumWorking, 'digest input', deadline), deadline);
}

export class SyntheticTransferProbe {
  #bytes;
  #contentDigest;
  #contentSha256;
  #maxRangeBytes;
  #representationDigest;
  #publicValidator;
  #validator;

  constructor(representation, options = {}) {
    const deadline = deadlineFrom(options);
    const maxRepresentationBytes = boundedInteger(options.maxRepresentationBytes, HARD_LIMITS.assetBytes, HARD_LIMITS.contractBytes, 'maxRepresentationBytes');
    const maxWorkingMemoryBytes = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
    if (!(Buffer.isBuffer(representation) || representation instanceof Uint8Array)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer representation must be bytes');
    if (representation.byteLength + 2048 > maxWorkingMemoryBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'transfer constructor working-memory ceiling exceeded');
    this.#maxRangeBytes = boundedInteger(options.maxRangeBytes, Math.min(1024 * 1024, maxRepresentationBytes), maxRepresentationBytes, 'maxRangeBytes');
    this.#bytes = bytesValue(representation, maxRepresentationBytes, maxWorkingMemoryBytes, 'transfer representation', deadline);
    if (this.#bytes.length === 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer representation must not be empty');
    this.#validator = validatorForTrustedBytes(this.#bytes, deadline);
    this.#representationDigest = digestField(this.#bytes, deadline);
    this.#contentDigest = this.#representationDigest;
    this.#contentSha256 = hexadecimalDigest(this.#bytes, deadline);
    this.#publicValidator = `sha256-${this.#contentSha256}`;
  }

  descriptor() {
    return Object.freeze({
      contentEncoding: 'identity',
      length: this.#bytes.length,
      validatorTag: this.#publicValidator,
      contentSha256: this.#contentSha256,
      etagHeader: `"${this.#publicValidator}"`,
      contentDigestHeader: this.#representationDigest,
    });
  }

  read(request, options = {}) {
    const deadline = deadlineFrom(options);
    const maxWorkingMemoryBytes = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
    const value = cloneJson(request, { ...options, maxBytes: 16 * 1024, maxDepth: 4, maxNodes: 64, maxStringBytes: 512, maxCollectionItems: 32, deadline });
    const keys = Object.keys(value).sort();
    const permitted = ['contentEncoding', 'length', 'offset', 'validator'];
    if (keys.some((key) => !permitted.includes(key)) || !keys.includes('contentEncoding') || !keys.includes('length') || !keys.includes('offset') || !keys.includes('validator')) {
      protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer range request fields are invalid');
    }
    if (value.contentEncoding !== 'identity') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer content encoding must be identity');
    if (!Number.isSafeInteger(value.offset) || value.offset < 0 || value.offset >= this.#bytes.length) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer offset is outside the representation');
    if (!Number.isSafeInteger(value.length) || value.length < 1 || value.length > this.#maxRangeBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'transfer range length ceiling exceeded');
    if (!(value.validator === null || typeof value.validator === 'string')) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer validator is invalid');
    if (value.offset > 0 && value.validator !== this.#validator) protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'transfer resume validator is stale or missing');
    if (value.offset === 0 && value.validator !== null && value.validator !== this.#validator) protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'transfer validator does not match the representation');
    const end = Math.min(this.#bytes.length, value.offset + value.length);
    const part = this.#bytes.subarray(value.offset, end);
    const encodedBytes = Math.ceil(part.length / 3) * 4;
    if (this.#bytes.length + encodedBytes + 1024 > maxWorkingMemoryBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'transfer read working-memory ceiling exceeded');
    deadline.checkpoint();
    return Object.freeze({
      contentBase64: part.toString('base64'),
      contentDigest: digestField(part, deadline),
      representationDigest: this.#representationDigest,
      validator: this.#validator,
      offset: value.offset,
      nextOffset: end,
      totalLength: this.#bytes.length,
      complete: end === this.#bytes.length,
      contentEncoding: 'identity',
    });
  }

  verifyComplete(parts, options = {}) {
    if (!Array.isArray(parts) || parts.length === 0 || parts.length > HARD_LIMITS.collectionItems) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer parts are invalid');
    const deadline = deadlineFrom(options);
    const maxWorkingMemoryBytes = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
    const retainedBytes = this.#bytes.length + 512;
    if (retainedBytes > maxWorkingMemoryBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'transfer verification working-memory ceiling exceeded');
    const digest = createHash('sha256');
    let total = 0;
    for (const part of parts) {
      deadline.checkpoint();
      if (typeof part !== 'string' || part.length > Math.ceil(this.#maxRangeBytes * 4 / 3) + 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(part)) {
        protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer part is not canonical base64');
      }
      const padding = part.endsWith('==') ? 2 : part.endsWith('=') ? 1 : 0;
      const decodedLength = part.length / 4 * 3 - padding;
      if (retainedBytes + decodedLength > maxWorkingMemoryBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'transfer verification working-memory ceiling exceeded');
      const bytes = Buffer.from(part, 'base64');
      if (bytes.toString('base64') !== part) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer part is not canonical base64');
      total += bytes.length;
      if (!Number.isSafeInteger(total) || total > this.#bytes.length) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'transfer assembly ceiling exceeded');
      digest.update(bytes);
    }
    const assembledDigest = `sha-256=:${digest.digest('base64')}:`;
    if (total !== this.#bytes.length || assembledDigest !== this.#contentDigest) protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'transfer assembly is incomplete or corrupt');
    return Object.freeze({ complete: true, length: total, representationDigest: this.#representationDigest, validator: this.#validator });
  }

  async execute(contract, probeInput, options = {}) {
    const deadline = deadlineFrom(options);
    const maxRangeBytes = boundedInteger(options.maxRangeBytes, this.#maxRangeBytes, this.#maxRangeBytes, 'maxRangeBytes');
    const probe = validateTransferProbe(contract, probeInput, { ...options, deadline, maxRangeBytes });
    await validateCompactTransferGrant(
      contract,
      options.authorizationContract,
      probe.grant,
      options.verifyGrant,
      options.authorizationContext,
      { ...options, deadline },
    );
    if (options.resourceTag !== undefined && probe.resourceTag !== options.resourceTag) protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'transfer resource tag does not match');
    if (probe.startOffset > this.#bytes.length) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer start offset is outside the representation');
    if (probe.startOffset > 0 && probe.validatorTag !== this.#publicValidator) protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'transfer resume validator is stale or missing');
    if (probe.startOffset === 0 && probe.validatorTag !== undefined && probe.validatorTag !== this.#publicValidator) protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'transfer validator does not match the representation');
    if (probe.expectedSha256 !== undefined && probe.expectedSha256 !== this.#contentSha256) protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'transfer representation digest does not match');
    const end = probe.endOffsetExclusive ?? this.#bytes.length;
    if (end > this.#bytes.length) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer end offset is outside the representation');
    if (end - probe.startOffset > maxRangeBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'transfer requested range ceiling exceeded');
    const part = this.#bytes.subarray(probe.startOffset, end);
    const interruptAfterBytes = options.interruptAfterBytes === undefined
      ? undefined
      : boundedInteger(options.interruptAfterBytes, 1, Math.max(1, part.length), 'interruptAfterBytes');
    const accepted = interruptAfterBytes === undefined ? part : part.subarray(0, interruptAfterBytes);
    const acceptedEndExclusive = probe.startOffset + accepted.length;
    const interrupted = interruptAfterBytes !== undefined && accepted.length < part.length;
    const terminal = !interrupted && acceptedEndExclusive === this.#bytes.length;
    const status = interrupted ? 'interrupted' : terminal ? 'complete' : 'partial';
    deadline.checkpoint();
    return deepFreeze(validateTransferProbeResult(contract, {
      schemaVersion: 'ogvcs.protocol/transfer-probe-result/v1',
      status,
      acceptedStart: probe.startOffset,
      acceptedEndExclusive,
      totalBytes: this.#bytes.length,
      validatorTag: this.#publicValidator,
      contentSha256: sha256(accepted),
      terminal,
    }, { ...options, deadline }));
  }
}

export function validateTransferProbe(contract, input, options = {}) {
  const value = validateProtocolValue(contract, 'TransferProbe.schema.json', input, { ...options, maxBytes: HARD_LIMITS.controlMessageBytes });
  const maxRangeBytes = boundedInteger(options.maxRangeBytes, HARD_LIMITS.transferRangeBytes, HARD_LIMITS.transferRangeBytes, 'maxRangeBytes');
  const end = value.endOffsetExclusive;
  if (end !== undefined && end <= value.startOffset) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer range is empty or reversed');
  if (end !== undefined && end - value.startOffset > maxRangeBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'transfer range ceiling exceeded');
  if (end === undefined && options.remainingBytes !== undefined) {
    if (!Number.isSafeInteger(options.remainingBytes) || options.remainingBytes < 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer remaining-byte authority is invalid');
    if (options.remainingBytes > maxRangeBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'transfer open-ended range ceiling exceeded');
  }
  if (value.startOffset > 0 && value.validatorTag === undefined) protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'transfer resume requires a strong validator');
  return value;
}

export function validateTransferHttpRangeCarrier(contract, input, options = {}) {
  const deadline = deadlineFrom(options);
  const maximumHeaders = boundedInteger(options.maxHeaderBytes, HARD_LIMITS.headerBytes, HARD_LIMITS.headerBytes, 'maxHeaderBytes');
  const maximumRange = boundedInteger(options.maxRangeBytes, HARD_LIMITS.transferRangeBytes, HARD_LIMITS.transferRangeBytes, 'maxRangeBytes');
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  input = exactInertRecord(input, 'HTTP range carrier', [
    'probe',
    'requestHeaders',
    'responseBodyHex',
    'responseHeaders',
    'responseStatus',
    'transportResponse',
  ]);
  const transportResponse = cloneJson(input.transportResponse, {
    deadline,
    maxBytes: 16 * 1024,
    maxDepth: 4,
    maxNodes: 64,
    maxStringBytes: 1024,
    maxArrayItems: 16,
    maxCollectionItems: 32,
    maxWorkingMemoryBytes: maximumWorking,
  });
  if (!Number.isSafeInteger(input.responseStatus)
      || !transportResponse || typeof transportResponse !== 'object' || Array.isArray(transportResponse)
      || !Number.isSafeInteger(transportResponse.totalBytes) || transportResponse.totalBytes < 0
      || !Number.isSafeInteger(transportResponse.rangeBytes) || transportResponse.rangeBytes < 0) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'HTTP range carrier accounting is invalid');
  }
  if (![200, 206, 416].includes(input.responseStatus)) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'HTTP range carrier status is unsupported');
  }
  const probe = validateProtocolValue(contract, 'TransferProbe.schema.json', input.probe, { ...options, deadline, maxBytes: HARD_LIMITS.controlMessageBytes });
  if (probe.endOffsetExclusive !== undefined && probe.endOffsetExclusive <= probe.startOffset) semanticRange('transfer range is empty or reversed');
  if (probe.endOffsetExclusive !== undefined && probe.endOffsetExclusive - probe.startOffset > maximumRange) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'HTTP requested range exceeds the receiver ceiling');
  if (transportResponse.rangeBytes > maximumRange) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'HTTP response range exceeds the receiver ceiling');
  const request = headerMap(input.requestHeaders, 'HTTP request', maximumHeaders, { ...options, deadline });
  const response = headerMap(input.responseHeaders, 'HTTP response', maximumHeaders, { ...options, deadline });
  if (request.bytes + response.bytes > maximumHeaders) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'combined HTTP header ceiling exceeded');
  const body = decodeResponseBodyHex(input.responseBodyHex, maximumRange, maximumWorking, deadline);

  const contentEncoding = response.map.get('content-encoding');
  if (contentEncoding !== undefined && contentEncoding !== 'identity') protocolSemanticError('COMPRESSION_FORBIDDEN', 'HTTP range response content coding is forbidden');
  const responseLengthText = response.map.get('content-length');
  if (responseLengthText === undefined) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'HTTP range response requires Content-Length');
  const responseLength = decimalField(responseLengthText, 'Content-Length');
  if (responseLength !== body.length || responseLength !== transportResponse.rangeBytes) semanticRange('HTTP response byte accounting does not match Content-Length');

  const rangeText = request.map.get('range');
  const ifRangeText = request.map.get('if-range');
  const contentRangeText = response.map.get('content-range');
  const responseEtag = response.map.get('etag');
  const responseDigest = response.map.get('content-digest');
  let validatorTag;
  let contentSha256;
  if (input.responseStatus === 200 || input.responseStatus === 206) {
    validatorTag = requiredStrongValidator(responseEtag, 'ETag');
    contentSha256 = requiredContentDigest(responseDigest);
    const actualSha256 = hexadecimalDigest(body, deadline);
    if (contentSha256 !== actualSha256 || probe.expectedSha256 !== undefined && contentSha256 !== probe.expectedSha256) {
      semanticValidator('Content-Digest does not match the response body');
    }
    if (probe.validatorTag !== undefined && validatorTag !== probe.validatorTag) semanticValidator('ETag does not match the semantic validator');
  } else if (responseDigest !== undefined) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'unsatisfied Range response must not carry Content-Digest');
  } else if (responseEtag !== undefined) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'unsatisfied Range response must not carry ETag');
  }
  if (rangeText === undefined) {
    if (ifRangeText !== undefined) semanticValidator('If-Range cannot be sent without Range');
    if (input.responseStatus !== 200 || contentRangeText !== undefined) semanticRange('request without Range requires a 200 response without Content-Range');
    if (probe.startOffset !== 0 || probe.endOffsetExclusive !== undefined && probe.endOffsetExclusive !== transportResponse.totalBytes
        || body.length !== transportResponse.totalBytes) semanticRange('full response does not match the semantic probe');
    deadline.checkpoint();
    return deepFreeze({ status: 200, acceptedStart: 0, acceptedEndExclusive: body.length, totalBytes: transportResponse.totalBytes, validatorTag, contentSha256 });
  }

  const rangeMatch = /^bytes=(0|[1-9][0-9]{0,15})-(?:(0|[1-9][0-9]{0,15}))?$/u.exec(rangeText);
  if (!rangeMatch) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'Range is malformed');
  const requestedStart = decimalField(rangeMatch[1], 'Range start');
  const requestedEndInclusive = rangeMatch[2] === undefined ? undefined : decimalField(rangeMatch[2], 'Range end');
  if (requestedEndInclusive !== undefined && requestedEndInclusive < requestedStart) semanticRange('Range is empty or reversed');
  const semanticEnd = probe.endOffsetExclusive;
  if (requestedStart !== probe.startOffset
      || semanticEnd === undefined && requestedEndInclusive !== undefined
      || semanticEnd !== undefined && requestedEndInclusive !== semanticEnd - 1) semanticRange('Range does not match the half-open semantic probe');

  if (probe.validatorTag !== undefined) {
    if (ifRangeText === undefined) semanticValidator('resume request requires If-Range');
    if (quotedValidator(ifRangeText, 'If-Range') !== probe.validatorTag) semanticValidator('If-Range does not match the semantic validator');
  } else if (ifRangeText !== undefined) semanticValidator('If-Range has no semantic validator authority');

  const total = transportResponse.totalBytes;
  if (requestedStart >= total) {
    if (input.responseStatus !== 416 || contentRangeText !== `bytes */${total}` || body.length !== 0) semanticRange('unsatisfied Range response is invalid');
    semanticRange('requested Range is unsatisfied');
  }
  const acceptedEndExclusive = semanticEnd ?? total;
  if (acceptedEndExclusive > total || acceptedEndExclusive <= requestedStart) semanticRange('requested Range is outside the representation');
  const expectedBytes = acceptedEndExclusive - requestedStart;
  if (expectedBytes > maximumRange) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'HTTP requested range exceeds the receiver ceiling');
  const expectedContentRange = `bytes ${requestedStart}-${acceptedEndExclusive - 1}/${total}`;
  if (input.responseStatus !== 206 || contentRangeText !== expectedContentRange
      || body.length !== expectedBytes || transportResponse.rangeBytes !== expectedBytes) semanticRange('satisfiable Range response does not match the semantic range');
  deadline.checkpoint();
  return deepFreeze({ status: 206, acceptedStart: requestedStart, acceptedEndExclusive, totalBytes: total, validatorTag, contentSha256 });
}

export function validateTransferProbeResult(contract, input, options = {}) {
  const value = validateProtocolValue(contract, 'TransferProbeResult.schema.json', input, { ...options, maxBytes: HARD_LIMITS.controlMessageBytes });
  if (value.acceptedStart > value.acceptedEndExclusive || value.acceptedEndExclusive > value.totalBytes) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer result range is invalid');
  if (value.status === 'complete' && (!value.terminal || value.acceptedEndExclusive !== value.totalBytes)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'complete transfer result is not terminal');
  if (value.status !== 'complete' && value.terminal) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'non-complete transfer result cannot be terminal');
  if (value.status === 'partial'
      && (value.acceptedEndExclusive <= value.acceptedStart || value.acceptedEndExclusive >= value.totalBytes)) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'partial transfer progress must be nonempty and strictly before total');
  }
  if (value.status === 'interrupted'
      && (value.acceptedEndExclusive < value.acceptedStart || value.acceptedEndExclusive >= value.totalBytes)) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'interrupted transfer progress must not reverse and must remain before total');
  }
  if (value.status === 'rejected' && value.acceptedStart !== value.acceptedEndExclusive) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'rejected transfer result cannot accept bytes');
  if (value.status === 'rejected' && value.problem === undefined) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'rejected transfer result requires a problem');
  if (value.status !== 'rejected' && value.problem !== undefined) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'successful transfer result cannot carry a problem');
  if (value.status === 'rejected') new ProtocolProblemCatalog(contract).validate(value.problem, {}, options);
  return value;
}
