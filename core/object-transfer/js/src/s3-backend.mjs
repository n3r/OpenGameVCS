import { createHash, createHmac } from 'node:crypto';
import {
  ObjectRef,
  Sha256Writer,
  createObjectHashWriter,
  decodeCanonical,
  equalBytes,
  validateKnownSchema,
} from '@opengamevcs/object-model';
import { canonicalBytes, rfc9530Sha256 } from '@opengamevcs/protocol-baseline';
import { captureTrustedBackend, validateOpaqueBackendKey } from './backend-port.mjs';
import { consumeDeletePermit, consumeReuploadPermit } from './delete-permit.mjs';
import { transferError } from './errors.mjs';

const SHA = /^[0-9a-f]{64}$/u;
const BUCKET = /^(?!.*\.\.)(?!.*\.-)(?!.*-\.)(?!\d+\.\d+\.\d+\.\d+$)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u;
const PREFIX = /^[a-z0-9][a-z0-9/_-]{0,127}$/u;
const FENCE_BYTES_MAXIMUM = 1024 * 1024;
const DELETION_HISTORY_MAXIMUM = 64;
const METADATA_WORKING_BYTES = 67_108_864;
const OBJECT_METADATA = Object.freeze({
  schema: 'x-amz-meta-ogvcs-schema',
  objectId: 'x-amz-meta-ogvcs-object-id',
  length: 'x-amz-meta-ogvcs-length',
  payloadSha256: 'x-amz-meta-ogvcs-payload-sha256',
});

export const S3_LIMITS = Object.freeze({
  objectBytesMaximum: 67_108_864,
  rangeBytesMaximum: 8_388_608,
  listMaximum: 4096,
  responseBytesMaximum: 68_157_440,
  retriesMaximum: 4,
  deadlineMillisecondsMaximum: 60_000,
});

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const hmac = (key, value, encoding = undefined) => createHmac('sha256', key).update(value).digest(encoding);
let S3_BACKEND_DEFINITION;
const S3_BACKEND_RECORDS = new WeakMap();

function failInput(condition, message) {
  if (!condition) transferError('TRANSFER_INPUT_INVALID', message);
}

function boundedInteger(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    transferError('TRANSFER_INPUT_INVALID', `${label} is outside the configured bound`);
  }
  return value;
}

function canonicalObjectId(value, code = 'TRANSFER_INPUT_INVALID') {
  try {
    const parsed = ObjectRef.parse(value);
    if (parsed.toString() !== value) throw new TypeError('ObjectID is not canonical');
    return parsed;
  } catch (error) {
    transferError(code, 'stored object identity is invalid', { cause: error });
  }
}

function sourceOf(value) {
  if (value instanceof Uint8Array) return (async function* () { if (value.byteLength > 0) yield value; })();
  if (value?.[Symbol.asyncIterator]) return value;
  transferError('TRANSFER_INPUT_INVALID', 'object source must be bytes or an async iterable');
}

async function collectSource(source, length, maximum) {
  boundedInteger(length, 0, maximum, 'object length');
  const output = Buffer.alloc(length);
  let consumed = 0;
  for await (const value of sourceOf(source)) {
    if (!(value instanceof Uint8Array) || value.byteLength < 1 || value.byteLength > length - consumed) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'object source length differs from its declaration');
    }
    Buffer.from(value.buffer, value.byteOffset, value.byteLength).copy(output, consumed);
    consumed += value.byteLength;
  }
  if (consumed !== length) transferError('TRANSFER_BACKEND_CORRUPT', 'object source length differs from its declaration');
  return output;
}

function validateMetadata(reference, payload, maximum) {
  if (reference.kind === 1) return;
  try {
    const value = decodeCanonical(payload, { maxBytes: maximum, maxWorkingBytes: METADATA_WORKING_BYTES });
    validateKnownSchema(value, reference.kind, { semantic: false, maxWorkingBytes: METADATA_WORKING_BYTES });
  } catch (error) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'stored metadata is not canonical OGVCS-002 content', { cause: error });
  }
}

function verifyObjectBytes(objectId, payload, maximum) {
  const reference = canonicalObjectId(objectId, 'TRANSFER_BACKEND_CORRUPT');
  const writer = createObjectHashWriter(reference.kind, {
    maxChunkBytes: maximum,
    maxMetadataBytes: maximum,
  });
  writer.update(payload);
  const actual = writer.finish();
  if (!equalBytes(actual.digest, reference.digest)) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'stored payload verification failed');
  }
  validateMetadata(reference, payload, maximum);
  return reference;
}

function receipt(metadata) {
  const body = Object.freeze({
    schemaVersion: 'ogvcs.object-transfer/backend-receipt/v1',
    opaqueKey: metadata.opaqueKey,
    objectId: metadata.objectId,
    length: metadata.length,
    payloadSha256: metadata.payloadSha256,
    durable: true,
  });
  return Object.freeze({ ...body, receiptSha256: sha256(canonicalBytes(body)) });
}

function deletionReceipt(binding) {
  const body = Object.freeze({
    schemaVersion: 'ogvcs.object-transfer/backend-delete-receipt/v1',
    opaqueKey: binding.opaqueKey,
    priorReceiptSha256: binding.priorReceiptSha256,
    expectedGeneration: binding.expectedGeneration,
    authorityBindingSha256: binding.authorityBindingSha256,
    deleted: true,
  });
  return Object.freeze({ ...body, receiptSha256: sha256(canonicalBytes(body)) });
}

function reopenReceipt(binding) {
  const body = Object.freeze({
    schemaVersion: 'ogvcs.object-transfer/backend-reopen-receipt/v1',
    opaqueKey: binding.opaqueKey,
    objectId: binding.objectId,
    length: binding.length,
    expectedDeletedGeneration: binding.expectedDeletedGeneration,
    stagedGeneration: binding.expectedDeletedGeneration + 1,
    deletionReceiptSha256: binding.deletionReceiptSha256,
    authorityBindingSha256: binding.nextAuthorityBindingSha256,
    reopened: true,
  });
  return Object.freeze({ ...body, receiptSha256: sha256(canonicalBytes(body)) });
}

function deletionEntry(binding) {
  const deleted = deletionReceipt(binding);
  return Object.freeze({
    objectId: binding.objectId,
    length: binding.length,
    expectedDeletingGeneration: binding.expectedGeneration,
    deletedGeneration: binding.expectedGeneration + 1,
    priorReceiptSha256: binding.priorReceiptSha256,
    authorityBindingSha256: binding.authorityBindingSha256,
    deletionReceiptSha256: deleted.receiptSha256,
    reopenedStagedGeneration: null,
    reopenAuthorityBindingSha256: null,
    reopenReceiptSha256: null,
  });
}

function validateDeletionEntry(value, opaqueKey) {
  const keys = [
    'authorityBindingSha256', 'deletedGeneration', 'deletionReceiptSha256',
    'expectedDeletingGeneration', 'length', 'objectId', 'priorReceiptSha256',
    'reopenAuthorityBindingSha256', 'reopenReceiptSha256', 'reopenedStagedGeneration',
  ].sort().join('\0');
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== keys
      || !SHA.test(value.priorReceiptSha256 ?? '') || !SHA.test(value.authorityBindingSha256 ?? '')
      || !SHA.test(value.deletionReceiptSha256 ?? '')
      || !Number.isSafeInteger(value.expectedDeletingGeneration) || value.expectedDeletingGeneration < 1
      || value.deletedGeneration !== value.expectedDeletingGeneration + 1
      || !Number.isSafeInteger(value.length) || value.length < 0
      || value.length > S3_LIMITS.objectBytesMaximum) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle fence is invalid');
  }
  canonicalObjectId(value.objectId, 'TRANSFER_BACKEND_CORRUPT');
  const expected = deletionReceipt({
    opaqueKey,
    priorReceiptSha256: value.priorReceiptSha256,
    expectedGeneration: value.expectedDeletingGeneration,
    authorityBindingSha256: value.authorityBindingSha256,
  });
  if (expected.receiptSha256 !== value.deletionReceiptSha256) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle fence receipt differs');
  }
  const hasReopen = value.reopenedStagedGeneration !== null
    || value.reopenAuthorityBindingSha256 !== null || value.reopenReceiptSha256 !== null;
  if (hasReopen && (value.reopenedStagedGeneration !== value.deletedGeneration + 1
      || !SHA.test(value.reopenAuthorityBindingSha256 ?? '') || !SHA.test(value.reopenReceiptSha256 ?? ''))) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle reopen fence is invalid');
  }
  if (!hasReopen && !(value.reopenedStagedGeneration === null
      && value.reopenAuthorityBindingSha256 === null && value.reopenReceiptSha256 === null)) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle reopen fence is partial');
  }
  return Object.freeze(value);
}

function validateFence(value, opaqueKey) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== 'deletions\0opaqueKey\0schemaVersion'
      || value.schemaVersion !== 'ogvcs.object-transfer/backend-lifecycle-fence/v1'
      || value.opaqueKey !== opaqueKey || !Array.isArray(value.deletions)
      || value.deletions.length < 1 || value.deletions.length > DELETION_HISTORY_MAXIMUM) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle fence is invalid');
  }
  const deletions = value.deletions.map((entry) => validateDeletionEntry(entry, opaqueKey));
  for (let index = 1; index < deletions.length; index += 1) {
    const prior = deletions[index - 1];
    const current = deletions[index];
    if (prior.reopenedStagedGeneration === null
        || current.expectedDeletingGeneration <= prior.reopenedStagedGeneration) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle fence generations are not monotonic');
    }
  }
  return Object.freeze({ ...value, deletions: Object.freeze(deletions) });
}

function rfc3986(value) {
  return encodeURIComponent(value).replace(/[!'()*]/gu, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

function canonicalQuery(entries) {
  const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
  return [...entries]
    .map(([key, value]) => [rfc3986(String(key)), rfc3986(String(value))])
    .sort(([leftKey, leftValue], [rightKey, rightValue]) => compare(leftKey, rightKey) || compare(leftValue, rightValue))
    .map(([key, value]) => `${key}=${value}`)
    .join('&');
}

function normalizedHeaderValue(value) {
  return String(value).trim().replace(/[\t ]+/gu, ' ');
}

function amzDate(value) {
  if (!Number.isFinite(value)) transferError('TRANSFER_BACKEND_IO', 'backend clock is invalid');
  return new Date(value).toISOString().replace(/[:-]|\.\d{3}/gu, '');
}

export function signS3RequestV4({
  url: inputUrl,
  method,
  headers = {},
  payloadSha256,
  accessKeyId,
  secretAccessKey,
  region,
  date,
  sessionToken = null,
}) {
  const url = inputUrl instanceof URL ? inputUrl : new URL(inputUrl);
  const normalized = {};
  for (const [name, value] of Object.entries(headers)) normalized[name.toLowerCase()] = normalizedHeaderValue(value);
  normalized.host = url.host;
  normalized['x-amz-content-sha256'] = payloadSha256;
  normalized['x-amz-date'] = date;
  if (sessionToken !== null) normalized['x-amz-security-token'] = sessionToken;
  const names = Object.keys(normalized).sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
  const canonicalHeaders = names.map((name) => `${name}:${normalized[name]}\n`).join('');
  const signedNames = names.join(';');
  const canonicalRequest = [method, url.pathname, url.search.slice(1), canonicalHeaders, signedNames, payloadSha256].join('\n');
  const dateStamp = date.slice(0, 8);
  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${date}\n${scope}\n${sha256(canonicalRequest)}`;
  const dateKey = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const regionKey = hmac(dateKey, region);
  const serviceKey = hmac(regionKey, 's3');
  const signingKey = hmac(serviceKey, 'aws4_request');
  const signature = hmac(signingKey, stringToSign, 'hex');
  normalized.authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope},SignedHeaders=${signedNames},Signature=${signature}`;
  return Object.freeze({
    headers: Object.freeze(normalized),
    canonicalRequestSha256: sha256(canonicalRequest),
    signature,
  });
}

async function readBoundedBody(response, maximum) {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximum) {
        await reader.cancel().catch(() => {});
        transferError('TRANSFER_LIMIT_EXCEEDED', 'backend response exceeds its configured bound');
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } catch (error) {
    if (error?.code?.startsWith?.('TRANSFER_')) throw error;
    transferError('TRANSFER_BACKEND_IO', 'backend response could not be read');
  }
  return Buffer.concat(chunks, total);
}

function xmlText(value) {
  return value.replace(/&lt;/gu, '<').replace(/&gt;/gu, '>').replace(/&quot;/gu, '"')
    .replace(/&apos;/gu, "'").replace(/&amp;/gu, '&');
}

function parseListXml(bytes, maximum) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { transferError('TRANSFER_BACKEND_CORRUPT', 'backend list response is invalid'); }
  const keys = [...text.matchAll(/<Key>([\s\S]*?)<\/Key>/gu)].map((match) => xmlText(match[1]));
  if (keys.length > maximum) transferError('TRANSFER_LIMIT_EXCEEDED', 'backend list exceeds its bound');
  const truncated = /<IsTruncated>true<\/IsTruncated>/u.test(text);
  const tokenMatch = /<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/u.exec(text);
  const token = tokenMatch ? xmlText(tokenMatch[1]) : null;
  if (truncated && (token === null || token.length < 1 || token.length > 4096)) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend list cursor is invalid');
  }
  return Object.freeze({ keys: Object.freeze(keys), truncated, token });
}

export class S3ObjectBackend {
  #fetch;
  #secretAccessKey;
  #sessionToken;
  #sleep;
  #telemetry;

  constructor({
    endpoint,
    bucket,
    region,
    accessKeyId,
    secretAccessKey,
    sessionToken = null,
    prefix = 'ogvcs-v1',
    allowInsecureLoopback = false,
    createBucketForTests = false,
    fetch: fetchImplementation = globalThis.fetch,
    now = () => Date.now(),
    sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
    deadlineMilliseconds = 15_000,
    retries = 3,
    maxObjectBytes = S3_LIMITS.objectBytesMaximum,
    maxRangeBytes = S3_LIMITS.rangeBytesMaximum,
    telemetry = null,
  } = {}) {
    if (new.target !== S3ObjectBackend) {
      transferError('TRANSFER_INPUT_INVALID', 'S3 backend subclasses are not trusted adapters');
    }
    let parsed;
    try { parsed = new URL(endpoint); } catch { transferError('TRANSFER_INPUT_INVALID', 'S3 endpoint is invalid'); }
    const loopback = ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(parsed.hostname);
    failInput(parsed.username === '' && parsed.password === '' && parsed.search === '' && parsed.hash === ''
      && (parsed.pathname === '' || parsed.pathname === '/'), 'S3 endpoint is invalid');
    failInput(parsed.protocol === 'https:' || (parsed.protocol === 'http:' && loopback && allowInsecureLoopback),
      'S3 endpoint must use HTTPS unless loopback HTTP is explicitly enabled');
    failInput(BUCKET.test(bucket ?? '') && typeof region === 'string' && /^[a-z0-9-]{1,64}$/u.test(region)
      && typeof accessKeyId === 'string' && accessKeyId.length >= 3 && accessKeyId.length <= 128
      && typeof secretAccessKey === 'string' && secretAccessKey.length >= 16 && secretAccessKey.length <= 4096
      && (sessionToken === null || (typeof sessionToken === 'string' && sessionToken.length >= 1 && sessionToken.length <= 4096))
      && PREFIX.test(prefix) && typeof fetchImplementation === 'function' && typeof now === 'function'
      && typeof sleep === 'function' && (telemetry === null || typeof telemetry.observe === 'function'),
    'S3 backend configuration is invalid');
    failInput(createBucketForTests === false || (loopback && allowInsecureLoopback),
      'automatic S3 bucket creation is test-only and requires explicit loopback HTTP');
    this.endpoint = parsed;
    this.bucket = bucket;
    this.region = region;
    this.accessKeyId = accessKeyId;
    this.prefix = prefix.replace(/\/$/u, '');
    this.now = now;
    this.deadlineMilliseconds = boundedInteger(deadlineMilliseconds, 100, S3_LIMITS.deadlineMillisecondsMaximum, 'S3 deadline');
    this.retries = boundedInteger(retries, 0, S3_LIMITS.retriesMaximum, 'S3 retry count');
    this.maxObjectBytes = boundedInteger(maxObjectBytes, 1, S3_LIMITS.objectBytesMaximum, 'maxObjectBytes');
    this.maxRangeBytes = boundedInteger(maxRangeBytes, 1, Math.min(this.maxObjectBytes, S3_LIMITS.rangeBytesMaximum), 'maxRangeBytes');
    this.createBucketForTests = createBucketForTests;
    this.#fetch = fetchImplementation;
    this.#secretAccessKey = secretAccessKey;
    this.#sessionToken = sessionToken;
    this.#sleep = sleep;
    this.#telemetry = telemetry;
    S3_BACKEND_RECORDS.set(this, captureTrustedBackend(this, {
      schemaVersion: 'ogvcs.object-transfer/backend-capabilities/v1',
      backendKind: 's3-compatible',
      profile: 'storage.opengamevcs/s3-compatible@1',
      objectBytesMaximum: this.maxObjectBytes,
      rangeBytesMaximum: this.maxRangeBytes,
      createIfAbsent: true,
      exactMetadata: true,
      wholeObjectVerification: true,
      verifiedRanges: true,
      boundedPrefixList: true,
      generationFencedDelete: true,
      multipartEtagIsDigest: false,
    }, S3_BACKEND_DEFINITION));
  }

  async initialize() {
    const result = await this.#request({ method: 'HEAD', accepted: [200, 404], maximum: 0 });
    if (result.status === 404 && this.createBucketForTests) {
      const created = await this.#request({ method: 'PUT', accepted: [200, 201, 409], maximum: 1024 });
      if (![200, 201, 409].includes(created.status)) transferError('TRANSFER_BACKEND_IO', 'S3 test bucket could not be created');
    } else if (result.status !== 200) {
      transferError('TRANSFER_BACKEND_IO', 'S3 bucket is unavailable');
    }
    return this;
  }

  #path(kind, key) {
    const value = validateOpaqueBackendKey(key);
    return `${this.prefix}/${kind}/${value.slice(0, 2)}/${value.slice(2, 4)}/${value}`;
  }

  #url(key = null, query = []) {
    const segments = [this.bucket, ...(key === null ? [] : key.split('/'))].map(rfc3986);
    const url = new URL(this.endpoint);
    url.pathname = `/${segments.join('/')}`;
    url.search = canonicalQuery(query);
    return url;
  }

  #observe(value) {
    try { this.#telemetry?.observe(value); } catch {
      // Metrics cannot become a storage acknowledgement or alter a backend
      // outcome. Invalid/unavailable sinks are isolated from the data plane.
    }
  }

  #signed({ method, key, query, headers, bodySha256 }) {
    const url = this.#url(key, query);
    const date = amzDate(this.now());
    const signed = signS3RequestV4({
      url,
      method,
      headers,
      payloadSha256: bodySha256,
      accessKeyId: this.accessKeyId,
      secretAccessKey: this.#secretAccessKey,
      region: this.region,
      date,
      sessionToken: this.#sessionToken,
    });
    const requestHeaders = { ...signed.headers };
    delete requestHeaders.host;
    return Object.freeze({ url, headers: requestHeaders });
  }

  async #request({ method, key = null, query = [], headers = {}, body = null, accepted, maximum, retrySafe = true }) {
    const payload = body === null ? Buffer.alloc(0) : Buffer.from(body);
    const bodySha256 = sha256(payload);
    let lastRetry = 0;
    for (let attempt = 0; attempt <= this.retries; attempt += 1) {
      const signed = this.#signed({ method, key, query, headers, bodySha256 });
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.deadlineMilliseconds);
      const started = this.now();
      try {
        const response = await this.#fetch(signed.url, {
          method,
          headers: signed.headers,
          body: body === null ? undefined : payload,
          signal: controller.signal,
          redirect: 'error',
        });
        const retryableStatus = [408, 425, 429, 500, 502, 503, 504].includes(response.status);
        if (retryableStatus && retrySafe && attempt < this.retries) {
          await response.body?.cancel().catch(() => {});
          lastRetry = attempt + 1;
          this.#observe({ operation: 'backend-request', backend: 's3-compatible', outcome: 'retry', bytes: payload.length, durationMs: Math.max(0, this.now() - started), retries: 1, resume: 0, parts: 0, quota: 'none', integrity: 'none' });
          await this.#sleep(Math.min(25 * (2 ** attempt), 200));
          continue;
        }
        const responseBody = await readBoundedBody(response, maximum);
        if (!accepted.includes(response.status)) {
          transferError('TRANSFER_BACKEND_IO', 'S3 backend request failed');
        }
        this.#observe({ operation: 'backend-request', backend: 's3-compatible', outcome: 'success', bytes: payload.length + responseBody.length, durationMs: Math.max(0, this.now() - started), retries: lastRetry, resume: 0, parts: 0, quota: 'none', integrity: 'none' });
        return Object.freeze({ status: response.status, headers: response.headers, body: responseBody, retries: lastRetry });
      } catch (error) {
        if (error?.code?.startsWith?.('TRANSFER_')) throw error;
        if (retrySafe && attempt < this.retries) {
          lastRetry = attempt + 1;
          this.#observe({ operation: 'backend-request', backend: 's3-compatible', outcome: 'retry', bytes: payload.length, durationMs: Math.max(0, this.now() - started), retries: 1, resume: 0, parts: 0, quota: 'none', integrity: 'none' });
          await this.#sleep(Math.min(25 * (2 ** attempt), 200));
          continue;
        }
        transferError('TRANSFER_BACKEND_IO', 'S3 backend request failed or exceeded its deadline');
      } finally {
        clearTimeout(timer);
      }
    }
    transferError('TRANSFER_BACKEND_IO', 'S3 backend retry bound was exhausted');
  }

  #metadataFromResponse(key, response) {
    const objectId = response.headers.get(OBJECT_METADATA.objectId);
    const lengthText = response.headers.get(OBJECT_METADATA.length);
    const payloadSha256 = response.headers.get(OBJECT_METADATA.payloadSha256);
    const schema = response.headers.get(OBJECT_METADATA.schema);
    const contentLength = response.headers.get('content-length');
    const length = Number(lengthText);
    if (schema !== 'ogvcs.object-transfer/s3-object/v1' || !SHA.test(payloadSha256 ?? '')
        || !Number.isSafeInteger(length) || length < 0 || length > this.maxObjectBytes
        || (contentLength !== null && Number(contentLength) !== length)) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'S3 object metadata is invalid');
    }
    canonicalObjectId(objectId, 'TRANSFER_BACKEND_CORRUPT');
    return Object.freeze({ opaqueKey: key, objectId, length, payloadSha256 });
  }

  async head(opaqueKey) {
    const key = validateOpaqueBackendKey(opaqueKey);
    const response = await this.#request({ method: 'HEAD', key: this.#path('objects', key), accepted: [200, 404], maximum: 0 });
    return response.status === 404 ? null : this.#metadataFromResponse(key, response);
  }

  async #getVerified(key) {
    const response = await this.#request({
      method: 'GET', key: this.#path('objects', key), accepted: [200, 404], maximum: this.maxObjectBytes,
    });
    if (response.status === 404) transferError('TRANSFER_BACKEND_CONFLICT', 'backend object is absent');
    const metadata = this.#metadataFromResponse(key, response);
    if (response.body.length !== metadata.length || sha256(response.body) !== metadata.payloadSha256) {
      this.#observe({ operation: 'backend-verify', backend: 's3-compatible', outcome: 'integrity', bytes: response.body.length, durationMs: 0, retries: response.retries, resume: 0, parts: 0, quota: 'none', integrity: 'failed' });
      transferError('TRANSFER_BACKEND_CORRUPT', 'stored payload verification failed');
    }
    const checksum = response.headers.get('x-amz-checksum-sha256');
    if (checksum !== null && checksum !== Buffer.from(metadata.payloadSha256, 'hex').toString('base64')) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'stored checksum metadata differs');
    }
    verifyObjectBytes(metadata.objectId, response.body, this.maxObjectBytes);
    return Object.freeze({ metadata, bytes: response.body, receipt: receipt(metadata) });
  }

  async verify(opaqueKey) {
    const verified = await this.#getVerified(validateOpaqueBackendKey(opaqueKey));
    return Object.freeze({ ...verified.receipt, validatorTag: `sha256-${verified.metadata.payloadSha256}` });
  }

  async readVerifiedRange(opaqueKey, start, endExclusive) {
    const key = validateOpaqueBackendKey(opaqueKey);
    boundedInteger(start, 0, this.maxObjectBytes, 'range start');
    boundedInteger(endExclusive, start + 1, this.maxObjectBytes, 'range end');
    if (endExclusive - start > this.maxRangeBytes) transferError('TRANSFER_INPUT_INVALID', 'range exceeds its configured bound');
    // S3 range checksums are not uniformly available across compatible stores.
    // Read and verify the complete canonical object first, then disclose only
    // the requested bounded slice. This never treats an ETag as a digest.
    const verified = await this.#getVerified(key);
    if (endExclusive > verified.metadata.length) transferError('TRANSFER_INPUT_INVALID', 'range exceeds the stored object');
    const bytes = Buffer.from(verified.bytes.subarray(start, endExclusive));
    return Object.freeze({
      ...verified.receipt,
      validatorTag: `sha256-${verified.metadata.payloadSha256}`,
      bytes,
      start,
      endExclusive,
      totalLength: verified.metadata.length,
      contentSha256: sha256(bytes),
      contentDigest: rfc9530Sha256(bytes, {
        maxBytes: this.maxRangeBytes,
        maxWorkingMemoryBytes: this.maxRangeBytes * 2,
      }),
    });
  }

  async readRange(opaqueKey, start, endExclusive) {
    return this.readVerifiedRange(opaqueKey, start, endExclusive);
  }

  async #readFence(key) {
    const response = await this.#request({
      method: 'GET', key: this.#path('fences', key), accepted: [200, 404], maximum: FENCE_BYTES_MAXIMUM,
    });
    if (response.status === 404) return null;
    let value;
    try { value = JSON.parse(response.body); }
    catch { transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle fence is invalid'); }
    const expected = Buffer.from(canonicalBytes(value));
    if (!response.body.equals(expected)) transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle fence is not canonical');
    const etag = response.headers.get('etag');
    if (etag === null || etag.length < 3 || etag.length > 256) transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle fence version is invalid');
    return Object.freeze({ value: validateFence(value, key), etag });
  }

  async #writeFence(key, value, priorEtag) {
    const body = Buffer.from(canonicalBytes(value));
    const headers = {
      'content-length': String(body.length),
      'content-type': 'application/json',
      [priorEtag === null ? 'if-none-match' : 'if-match']: priorEtag ?? '*',
    };
    const response = await this.#request({
      method: 'PUT', key: this.#path('fences', key), headers, body,
      accepted: [200, 201, 412], maximum: 1024,
    });
    return response.status !== 412;
  }

  async createIfAbsent({ opaqueKey, objectId, length, source, reuploadPermit = null }) {
    const key = validateOpaqueBackendKey(opaqueKey);
    const reference = canonicalObjectId(objectId);
    const payload = await collectSource(source, length, this.maxObjectBytes);
    verifyObjectBytes(reference.toString(), payload, this.maxObjectBytes);
    const payloadSha256 = sha256(payload);
    const reupload = reuploadPermit === null ? null : consumeReuploadPermit(reuploadPermit);
    const beforeFence = await this.#readFence(key);
    let reopen = null;
    if (beforeFence) {
      const latest = beforeFence.value.deletions.at(-1);
      if (latest.objectId !== reference.toString() || latest.length !== length) {
        transferError('TRANSFER_BACKEND_CONFLICT', 'backend object has an active deletion fence');
      }
      if (latest.reopenedStagedGeneration === null) {
        if (!reupload || reupload.opaqueKey !== key || reupload.objectId !== reference.toString()
            || reupload.length !== length || reupload.expectedDeletedGeneration !== latest.deletedGeneration
            || reupload.deletionReceiptSha256 !== latest.deletionReceiptSha256
            || reupload.priorAuthorityBindingSha256 !== latest.authorityBindingSha256) {
          transferError('TRANSFER_BACKEND_CONFLICT', 'backend object has an active deletion fence');
        }
      } else {
        reopen = reopenReceipt({
          opaqueKey: key,
          objectId: latest.objectId,
          length: latest.length,
          expectedDeletedGeneration: latest.deletedGeneration,
          deletionReceiptSha256: latest.deletionReceiptSha256,
          nextAuthorityBindingSha256: latest.reopenAuthorityBindingSha256,
        });
        if (reopen.receiptSha256 !== latest.reopenReceiptSha256) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle reopen receipt differs');
        }
      }
    } else if (reupload) {
      transferError('TRANSFER_LIFECYCLE_STALE', 'deleted-generation reupload permit is stale');
    }
    const headers = {
      'content-length': String(payload.length),
      'content-type': 'application/octet-stream',
      'if-none-match': '*',
      'x-amz-checksum-sha256': Buffer.from(payloadSha256, 'hex').toString('base64'),
      [OBJECT_METADATA.schema]: 'ogvcs.object-transfer/s3-object/v1',
      [OBJECT_METADATA.objectId]: reference.toString(),
      [OBJECT_METADATA.length]: String(length),
      [OBJECT_METADATA.payloadSha256]: payloadSha256,
    };
    const put = await this.#request({
      method: 'PUT', key: this.#path('objects', key), headers, body: payload,
      accepted: [200, 201, 412], maximum: 1024,
    });
    const verified = await this.#getVerified(key);
    if (verified.metadata.objectId !== reference.toString() || verified.metadata.length !== length
        || verified.metadata.payloadSha256 !== payloadSha256) {
      transferError('TRANSFER_BACKEND_CONFLICT', 'existing backend object differs');
    }
    const afterFence = await this.#readFence(key);
    if (reupload && reopen === null) {
      if (!afterFence || afterFence.etag !== beforeFence.etag) {
        transferError('TRANSFER_BACKEND_CONFLICT', 'backend lifecycle fence changed during reupload');
      }
      const latest = afterFence.value.deletions.at(-1);
      const next = reopenReceipt(reupload);
      const updated = {
        ...afterFence.value,
        deletions: [
          ...afterFence.value.deletions.slice(0, -1),
          {
            ...latest,
            reopenedStagedGeneration: latest.deletedGeneration + 1,
            reopenAuthorityBindingSha256: reupload.nextAuthorityBindingSha256,
            reopenReceiptSha256: next.receiptSha256,
          },
        ],
      };
      if (!await this.#writeFence(key, updated, afterFence.etag)) {
        transferError('TRANSFER_BACKEND_CONFLICT', 'backend lifecycle fence changed during reupload');
      }
      reopen = next;
    } else if (!reupload && afterFence && (!beforeFence || afterFence.etag !== beforeFence.etag)) {
      transferError('TRANSFER_BACKEND_CONFLICT', 'backend deletion raced object creation');
    }
    return Object.freeze({
      ...verified.receipt,
      validatorTag: `sha256-${payloadSha256}`,
      created: put.status !== 412,
      reopenReceipt: reopen,
    });
  }

  async safeDelete({ permit } = {}) {
    const binding = consumeDeletePermit(permit);
    const key = validateOpaqueBackendKey(binding.opaqueKey);
    canonicalObjectId(binding.objectId, 'TRANSFER_LIFECYCLE_STALE');
    boundedInteger(binding.expectedGeneration, 1, Number.MAX_SAFE_INTEGER, 'delete generation');
    if (!SHA.test(binding.priorReceiptSha256 ?? '') || !SHA.test(binding.authorityBindingSha256 ?? '')) {
      transferError('TRANSFER_LIFECYCLE_STALE', 'authoritative deleting-generation permit binding is invalid');
    }
    let exactFence = null;
    let fenceWasExistingSame = false;
    for (let attempt = 0; attempt <= this.retries; attempt += 1) {
      const persisted = await this.#readFence(key);
      const latest = persisted?.value.deletions.at(-1) ?? null;
      const same = latest !== null && latest.objectId === binding.objectId && latest.length === binding.length
        && latest.expectedDeletingGeneration === binding.expectedGeneration
        && latest.priorReceiptSha256 === binding.priorReceiptSha256
        && latest.authorityBindingSha256 === binding.authorityBindingSha256;
      if (latest && !same && latest.reopenedStagedGeneration === null) {
        transferError('TRANSFER_BACKEND_CONFLICT', 'backend object has an active deletion fence');
      }
      if (same && latest.reopenedStagedGeneration !== null) {
        transferError('TRANSFER_BACKEND_CONFLICT', 'backend deletion permit is stale');
      }
      if (same) { exactFence = persisted; fenceWasExistingSame = true; break; }
      if (persisted && persisted.value.deletions.length >= DELETION_HISTORY_MAXIMUM) {
        transferError('TRANSFER_LIMIT_EXCEEDED', 'backend lifecycle fence history is full');
      }
      const next = {
        schemaVersion: 'ogvcs.object-transfer/backend-lifecycle-fence/v1',
        opaqueKey: key,
        deletions: [...(persisted?.value.deletions ?? []), deletionEntry(binding)],
      };
      if (await this.#writeFence(key, next, persisted?.etag ?? null)) {
        exactFence = await this.#readFence(key);
        break;
      }
    }
    if (!exactFence) transferError('TRANSFER_BACKEND_CONFLICT', 'backend lifecycle fence update conflicted');
    let verified = null;
    try { verified = await this.verify(key); }
    catch (error) {
      if (error?.code !== 'TRANSFER_BACKEND_CONFLICT') throw error;
      if (!fenceWasExistingSame) {
        transferError('TRANSFER_BACKEND_CONFLICT', 'backend object disappeared before deletion');
      }
    }
    if (verified && verified.receiptSha256 !== binding.priorReceiptSha256) {
      transferError('TRANSFER_BACKEND_CONFLICT', 'delete receipt is stale');
    }
    if (verified) {
      await this.#request({
        method: 'DELETE', key: this.#path('objects', key), accepted: [200, 202, 204, 404], maximum: 1024,
      });
      const absent = await this.head(key);
      if (absent !== null) transferError('TRANSFER_BACKEND_IO', 'S3 deletion was not observable before acknowledgement');
    }
    return deletionReceipt(binding);
  }

  async listByInternalPrefix(prefix = '', maximum = S3_LIMITS.listMaximum) {
    if (typeof prefix !== 'string' || !/^[0-9a-f]{0,64}$/u.test(prefix)) {
      transferError('TRANSFER_INPUT_INVALID', 'internal prefix is invalid');
    }
    boundedInteger(maximum, 0, S3_LIMITS.listMaximum, 'list maximum');
    const base = `${this.prefix}/objects/`;
    const internal = prefix.length <= 2 ? `${base}${prefix}`
      : prefix.length <= 4 ? `${base}${prefix.slice(0, 2)}/${prefix.slice(2)}`
        : `${base}${prefix.slice(0, 2)}/${prefix.slice(2, 4)}/${prefix}`;
    const collected = [];
    let token = null;
    let pages = 0;
    const pageMaximum = maximum + 1;
    do {
      pages += 1;
      if (pages > pageMaximum) transferError('TRANSFER_LIMIT_EXCEEDED', 'backend list pagination exceeds its bound');
      const query = [['list-type', '2'], ['prefix', internal], ['max-keys', String(Math.min(1000, maximum + 1 - collected.length))]];
      if (token !== null) query.push(['continuation-token', token]);
      const response = await this.#request({ method: 'GET', query, accepted: [200], maximum: FENCE_BYTES_MAXIMUM });
      const page = parseListXml(response.body, maximum + 1 - collected.length);
      for (const storageKey of page.keys) {
        if (!storageKey.startsWith(internal)) transferError('TRANSFER_BACKEND_CORRUPT', 'backend list escaped its internal prefix');
        const match = new RegExp(`^${this.prefix}/objects/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{64})$`, 'u').exec(storageKey);
        if (!match || match[1] !== match[3].slice(0, 2) || match[2] !== match[3].slice(2, 4)
            || !match[3].startsWith(prefix)) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'backend list returned an invalid sharded key');
        }
        collected.push(match[3]);
        if (collected.length > maximum) transferError('TRANSFER_LIMIT_EXCEEDED', 'internal list exceeds its bound');
      }
      token = page.truncated ? page.token : null;
    } while (token !== null);
    return Object.freeze(collected.sort());
  }
}

export function s3BackendRecord(instance) {
  return S3_BACKEND_RECORDS.get(instance) ?? null;
}

const S3_BACKEND_METHOD_NAMES = [
  'createIfAbsent', 'head', 'initialize', 'listByInternalPrefix', 'readRange',
  'readVerifiedRange', 'safeDelete', 'verify',
];
Object.freeze(S3ObjectBackend.prototype);
S3_BACKEND_DEFINITION = Object.freeze({
  constructor: S3ObjectBackend,
  prototype: S3ObjectBackend.prototype,
  methods: Object.freeze(Object.fromEntries(S3_BACKEND_METHOD_NAMES.map((method) => [
    method,
    Object.getOwnPropertyDescriptor(S3ObjectBackend.prototype, method).value,
  ]))),
});
