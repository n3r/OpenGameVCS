import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { types } from 'node:util';

const DIGEST = /^[0-9a-f]{64}$/u;
const ID = /^[A-Za-z0-9._:-]{1,128}$/u;
const BASE64URL_SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const REFERENCE_JOB_KEYS = Object.freeze([
  'actorDigest',
  'deadlineUnixMs',
  'idempotencyKey',
  'inputDigest',
  'jobId',
  'manifestDigest',
  'optionsDigest',
  'outputSchema',
  'purpose',
  'resourcePolicyDigest',
  'runtimeDigest',
  'schemaVersion',
  'toolDigest',
]);
const ACQUISITION_KEYS = Object.freeze([
  'maximumBytes',
  'objectIdDigest',
  'schemaVersion',
  'sourceId',
]);
const MANIFEST_KEYS = Object.freeze([
  'expiresAtUnixMs',
  'generation',
  'issuedAtUnixMs',
  'manifestId',
  'outputPolicy',
  'resourcePolicy',
  'runtimeContractSha256',
  'runtimeDigest',
  'runtimeImage',
  'schemaVersion',
  'signatureEd25519',
  'signingKeyId',
  'toolClass',
  'toolDigest',
]);
const RESOURCE_KEYS = Object.freeze([
  'cpuMilliseconds',
  'elapsedMilliseconds',
  'fanout',
  'memoryBytes',
  'outputBytes',
  'processes',
  'profileId',
  'scratchBytes',
]);
const OUTPUT_POLICY_KEYS = Object.freeze(['allowedTypes', 'maximumFileBytes', 'schemaVersion']);
const TOOL_CLASSES = Object.freeze(['converter', 'import-parser']);

export const LINUX_RUNTIME_CONTRACT_SHA256 = '930be8bc4d5afb79830736fc1ef4c553dc5ef63e8a38766551cf28047752189d';

export const REFERENCE_LIMITS = Object.freeze({
  cpuMilliseconds: 30_000,
  elapsedMilliseconds: 60_000,
  fanout: 10_000,
  memoryBytes: 512 * 1024 * 1024,
  outputBytes: 256 * 1024 * 1024,
  processes: 8,
  scratchBytes: 1024 * 1024 * 1024,
});

const hasValidUnicode = (value) => {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
};

export const canonicalJson = (value) => {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') {
    if (!hasValidUnicode(value)) throw new TypeError('canonical JSON contains invalid Unicode');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonical JSON contains a non-finite number');
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value !== 'object' || types.isProxy(value)) throw new TypeError('canonical JSON contains an unsupported value');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('canonical JSON contains a non-record');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).sort();
  if (keys.some((key) => !hasValidUnicode(key))) throw new TypeError('canonical JSON contains an invalid key');
  const fields = keys.map((key) => {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || Object.hasOwn(descriptor, 'get') || Object.hasOwn(descriptor, 'set') || descriptor.value === undefined) throw new TypeError('canonical JSON contains an active or undefined field');
    return `${JSON.stringify(key)}:${canonicalJson(descriptor.value)}`;
  });
  return `{${fields.join(',')}}`;
};

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const exactRecord = (source, keys) => {
  if (source === null || typeof source !== 'object' || Array.isArray(source) || types.isProxy(source)) return null;
  try {
    const prototype = Object.getPrototypeOf(source);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(source);
    if (Object.keys(descriptors).sort().join('\0') !== keys.join('\0')) return null;
    if (Object.values(descriptors).some((descriptor) => !descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || Object.hasOwn(descriptor, 'get') || Object.hasOwn(descriptor, 'set'))) return null;
    return Object.freeze(Object.fromEntries(keys.map((key) => [key, descriptors[key].value])));
  } catch {
    return null;
  }
};

const exactInteger = (value, minimum, maximum) => Number.isSafeInteger(value) && value >= minimum && value <= maximum;
const exactDigest = (value) => typeof value === 'string' && DIGEST.test(value);
const exactId = (value) => typeof value === 'string' && ID.test(value);

const snapshotResourcePolicy = (source) => {
  const policy = exactRecord(source, RESOURCE_KEYS);
  if (!policy || policy.profileId !== 'linux-reference-v1') return null;
  for (const key of Object.keys(REFERENCE_LIMITS)) {
    if (!exactInteger(policy[key], 1, REFERENCE_LIMITS[key])) return null;
  }
  return Object.freeze({ ...policy });
};

const snapshotOutputPolicy = (source, resourcePolicy) => {
  const policy = exactRecord(source, OUTPUT_POLICY_KEYS);
  if (!policy || policy.schemaVersion !== 'ogvcs.untrusted-sandbox/parser-output/v1' || !exactInteger(policy.maximumFileBytes, 1, resourcePolicy.outputBytes) || !Array.isArray(policy.allowedTypes) || policy.allowedTypes.length !== 1) return null;
  const allowedTypes = [];
  for (const value of policy.allowedTypes) {
    if (typeof value !== 'string' || !/^[a-z][a-z0-9.-]{0,63}$/u.test(value)) return null;
    allowedTypes.push(value);
  }
  if (allowedTypes.some((value, index) => index > 0 && value <= allowedTypes[index - 1])) return null;
  return Object.freeze({ allowedTypes: Object.freeze(allowedTypes), maximumFileBytes: policy.maximumFileBytes, schemaVersion: policy.schemaVersion });
};

const parseCanonicalDocument = (source, maximumBytes) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : typeof source === 'string' ? Buffer.from(source, 'utf8') : null;
  if (!bytes || bytes.length < 2 || bytes.length > maximumBytes) return null;
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) return null;
  try {
    const value = JSON.parse(text);
    if (canonicalJson(value) !== text) return null;
    return Object.freeze({ bytes, value });
  } catch {
    return null;
  }
};

const publicKeyMap = (source) => {
  if (source === null || typeof source !== 'object' || Array.isArray(source) || types.isProxy(source)) return null;
  try {
    const descriptors = Object.getOwnPropertyDescriptors(source);
    const entries = [];
    for (const key of Object.keys(descriptors).sort()) {
      const descriptor = descriptors[key];
      if (!exactId(key) || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || Object.hasOwn(descriptor, 'get') || Object.hasOwn(descriptor, 'set')) return null;
      const candidate = descriptor.value;
      const publicKey = candidate?.type === 'public' && candidate?.asymmetricKeyType === 'ed25519'
        ? candidate
        : createPublicKey(candidate);
      if (publicKey.asymmetricKeyType !== 'ed25519') return null;
      entries.push([key, publicKey]);
    }
    return entries.length > 0 ? new Map(entries) : null;
  } catch {
    return null;
  }
};

export const snapshotTrustedManifestKeys = (source) => {
  const keys = publicKeyMap(source);
  if (!keys) throw new TypeError('trusted manifest keys are invalid');
  return keys;
};

export const parseAndVerifyToolManifest = ({ manifestBytes, trustedKeys, nowUnixMs }) => {
  const document = parseCanonicalDocument(manifestBytes, 64 * 1024);
  const manifest = document && exactRecord(document.value, MANIFEST_KEYS);
  if (!manifest || manifest.schemaVersion !== 'ogvcs.untrusted-sandbox/tool-runtime-manifest/v1' || !exactId(manifest.manifestId) || !exactId(manifest.signingKeyId) || !TOOL_CLASSES.includes(manifest.toolClass) || !exactDigest(manifest.toolDigest) || !exactDigest(manifest.runtimeDigest) || manifest.runtimeImage !== `sha256:${manifest.runtimeDigest}` || manifest.runtimeContractSha256 !== LINUX_RUNTIME_CONTRACT_SHA256 || !exactInteger(manifest.generation, 1, 0xffff_ffff) || !exactInteger(manifest.issuedAtUnixMs, 0, Number.MAX_SAFE_INTEGER) || !exactInteger(manifest.expiresAtUnixMs, manifest.issuedAtUnixMs + 1, Number.MAX_SAFE_INTEGER) || typeof manifest.signatureEd25519 !== 'string' || !BASE64URL_SIGNATURE.test(manifest.signatureEd25519)) return null;
  const resourcePolicy = snapshotResourcePolicy(manifest.resourcePolicy);
  const outputPolicy = resourcePolicy && snapshotOutputPolicy(manifest.outputPolicy, resourcePolicy);
  if (!resourcePolicy || !outputPolicy) return null;
  const publicKey = trustedKeys.get(manifest.signingKeyId);
  if (!publicKey) return null;
  const unsigned = Object.fromEntries(MANIFEST_KEYS.filter((key) => key !== 'signatureEd25519').map((key) => [key, key === 'resourcePolicy' ? resourcePolicy : key === 'outputPolicy' ? outputPolicy : manifest[key]]));
  let signature;
  try { signature = Buffer.from(manifest.signatureEd25519, 'base64url'); } catch { return null; }
  if (signature.length !== 64 || !verifySignature(null, Buffer.from(canonicalJson(unsigned), 'utf8'), publicKey, signature)) return null;
  if (!exactInteger(nowUnixMs, 0, Number.MAX_SAFE_INTEGER) || nowUnixMs < manifest.issuedAtUnixMs || nowUnixMs >= manifest.expiresAtUnixMs) return null;
  const policyDigest = sha256(Buffer.from(canonicalJson(resourcePolicy), 'utf8'));
  return Object.freeze({
    ...unsigned,
    manifestDigest: sha256(document.bytes),
    outputPolicy,
    resourcePolicy,
    resourcePolicyDigest: policyDigest,
    signatureEd25519: manifest.signatureEd25519,
  });
};

export const snapshotReferenceJob = (source, nowUnixMs) => {
  const job = exactRecord(source, REFERENCE_JOB_KEYS);
  if (!job || job.schemaVersion !== 'ogvcs.untrusted-sandbox/reference-job/v1' || !exactId(job.jobId) || !exactId(job.idempotencyKey) || !exactDigest(job.actorDigest) || !exactDigest(job.inputDigest) || !exactDigest(job.manifestDigest) || !exactDigest(job.optionsDigest) || !exactDigest(job.resourcePolicyDigest) || !exactDigest(job.runtimeDigest) || !exactDigest(job.toolDigest) || job.outputSchema !== 'ogvcs.untrusted-sandbox/parser-output/v1' || typeof job.purpose !== 'string' || [...job.purpose].length < 1 || [...job.purpose].length > 128 || !hasValidUnicode(job.purpose) || !exactInteger(job.deadlineUnixMs, nowUnixMs + 1, nowUnixMs + REFERENCE_LIMITS.elapsedMilliseconds)) return null;
  return Object.freeze({ ...job });
};

export const snapshotAcquisitionRequest = (source, inputMaximum) => {
  const request = exactRecord(source, ACQUISITION_KEYS);
  if (!request || request.schemaVersion !== 'ogvcs.untrusted-sandbox/acquisition-request/v1' || !exactId(request.sourceId) || !exactDigest(request.objectIdDigest) || !exactInteger(request.maximumBytes, 1, inputMaximum)) return null;
  return Object.freeze({ ...request });
};

export const validateJobManifestBinding = (job, manifest) => job.manifestDigest === manifest.manifestDigest
  && job.toolDigest === manifest.toolDigest
  && job.runtimeDigest === manifest.runtimeDigest
  && job.resourcePolicyDigest === manifest.resourcePolicyDigest;

export const referenceJobFingerprint = (job, acquisition) => sha256(Buffer.from(canonicalJson({ acquisition, job }), 'utf8'));

export const safeResult = ({ jobId, code, outputDigest = null, provenanceDigest = null, cleanupReceiptDigest = null }) => Object.freeze({
  schemaVersion: 'ogvcs.untrusted-sandbox/reference-result/v1',
  jobId,
  status: code === 'VALIDATED' ? 'validated' : 'denied',
  code,
  outputDigest: code === 'VALIDATED' ? outputDigest : null,
  provenanceDigest,
  cleanupReceiptDigest,
});

export const isDigest = exactDigest;
export const isId = exactId;
