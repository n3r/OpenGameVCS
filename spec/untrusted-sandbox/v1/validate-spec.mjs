import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateSandboxManifest } from './scripts/generate.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const assert = (value, message) => { if (!value) throw new Error(message); };
const json = async (path) => JSON.parse(await readFile(resolve(root, path)));
const sha = (value) => createHash('sha256').update(value).digest('hex');
const canonical = (value) => value === null || typeof value !== 'object'
  ? JSON.stringify(value)
  : Array.isArray(value)
    ? `[${value.map(canonical).join(',')}]`
    : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
const exactDocument = (actual, expected, label) => assert(canonical(actual) === canonical(expected), `${label} semantic constraints differ`);

const EXPECTED_JOB = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  additionalProperties: false,
  properties: {
    schemaVersion: { const: 'ogvcs.untrusted-sandbox/parser-job/v1' },
    jobId: { pattern: '^[A-Za-z0-9._:-]{1,128}$', type: 'string' },
    toolDigest: { pattern: '^[0-9a-f]{64}$', type: 'string' },
    runtimeDigest: { pattern: '^[0-9a-f]{64}$', type: 'string' },
    inputDigest: { pattern: '^[0-9a-f]{64}$', type: 'string' },
    resourceClass: { enum: ['parser-default'] },
    outputSchema: { const: 'ogvcs.untrusted-sandbox/parser-output/v1' },
    idempotencyKey: { pattern: '^[A-Za-z0-9._:-]{1,128}$', type: 'string' },
    purpose: { maxLength: 128, minLength: 1, type: 'string' },
  },
  required: ['schemaVersion', 'jobId', 'toolDigest', 'runtimeDigest', 'inputDigest', 'resourceClass', 'outputSchema', 'idempotencyKey', 'purpose'],
  type: 'object',
  'x-ogvcs-license': 'MIT',
  'x-ogvcs-boundary': 'parser receives only this declared metadata and broker-owned immutable input handle',
});
const EXPECTED_OUTPUT = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  additionalProperties: false,
  properties: {
    outputs: {
      items: {
        additionalProperties: false,
        properties: {
          digest: { pattern: '^[0-9a-f]{64}$', type: 'string' },
          path: { minLength: 1, type: 'string', 'x-ogvcs-path-profile': 'path.opengamevcs/portable@1' },
          type: { maxLength: 64, minLength: 1, type: 'string' },
        },
        required: ['digest', 'path', 'type'],
        type: 'object',
      },
      maxItems: 10_000,
      type: 'array',
    },
    schemaVersion: { const: 'ogvcs.untrusted-sandbox/parser-output/v1' },
  },
  required: ['outputs', 'schemaVersion'],
  type: 'object',
  'x-ogvcs-canonical-json': 'keys sorted by UTF-16 code units with no insignificant whitespace or terminal LF',
  'x-ogvcs-path-profile': 'path.opengamevcs/portable@1',
});
const DENIAL_CODES = Object.freeze(['SANDBOX_UNAVAILABLE', 'SANDBOX_TIMEOUT', 'SANDBOX_OUTPUT_LIMIT', 'SANDBOX_PROTOCOL_INVALID', 'SANDBOX_VALIDATION_FAILED']);
const ALL_CODES = Object.freeze(['VALIDATED', ...DENIAL_CODES]);
const EXPECTED_VECTOR_SEMANTIC_SHA256 = '4752ca2540f5639a7f635d5caabcf3f4378076100ebc353429dc5cfda0603614';
const EXPECTED_RESULT = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  additionalProperties: false,
  oneOf: [
    { properties: { code: { const: 'VALIDATED' }, outputDigest: { pattern: '^[0-9a-f]{64}$', type: 'string' }, status: { const: 'validated' } }, required: ['code', 'outputDigest', 'status'] },
    { properties: { code: { enum: DENIAL_CODES }, outputDigest: { type: 'null' }, status: { const: 'denied' } }, required: ['code', 'outputDigest', 'status'] },
  ],
  properties: {
    schemaVersion: { const: 'ogvcs.untrusted-sandbox/parser-result/v1' },
    jobId: { pattern: '^[A-Za-z0-9._:-]{1,128}$', type: 'string' },
    status: { enum: ['validated', 'denied'] },
    code: { enum: ALL_CODES },
    outputDigest: { oneOf: [{ type: 'null' }, { pattern: '^[0-9a-f]{64}$', type: 'string' }] },
  },
  required: ['schemaVersion', 'jobId', 'status', 'code', 'outputDigest'],
  type: 'object',
  'x-ogvcs-fatal-error-codes': ['SANDBOX_SETTLEMENT_UNCONFIRMED'],
  'x-ogvcs-privacy': 'safe code only; no paths, stderr, environment, credentials, or input content',
});

export function validateSandboxDocuments({ job, output, result, vectors }) {
  exactDocument(job, EXPECTED_JOB, 'ParserJob');
  exactDocument(output, EXPECTED_OUTPUT, 'ParserOutput');
  exactDocument(result, EXPECTED_RESULT, 'ParserResult');
  assert(vectors !== null && typeof vectors === 'object' && !Array.isArray(vectors) && Object.keys(vectors).sort().join(',') === 'cases,schemaVersion', 'canary inventory shape differs');
  assert(vectors.schemaVersion === 'ogvcs.untrusted-sandbox/vectors/v1' && Array.isArray(vectors.cases) && vectors.cases.length >= 10, 'canary inventory differs');
  assert(new Set(vectors.cases.map((item) => item.id)).size === vectors.cases.length, 'canary identifiers repeat');
  assert(new Set(vectors.cases.map((item) => item.scenario)).size === vectors.cases.length, 'canary scenarios repeat instead of dispatching independently');
  assert(vectors.cases.every((item) => Array.isArray(item.requirementIds) && item.requirementIds.length > 0 && new Set(item.requirementIds).size === item.requirementIds.length && item.requirementIds.every((id) => /^OGVCS-045-(?:FR|AC)-\d{2}$/u.test(id))), 'canary traceability differs');
  assert(vectors.cases.every((item) => Object.keys(item).sort().join(',') === 'expectedCode,id,requirementIds,scenario' && typeof item.id === 'string' && item.id.length > 0 && item.id.length <= 128 && typeof item.scenario === 'string' && item.scenario.length > 0 && ALL_CODES.includes(item.expectedCode)), 'canary shape or expected outcome differs');
  assert(sha(canonical(vectors)) === EXPECTED_VECTOR_SEMANTIC_SHA256, 'canary semantics differ');
  return Object.freeze({ schemaDigest: sha(canonical([job, output, result])), vectors: vectors.cases.length });
}

export async function validateSandboxContract() {
  const manifest = await validateSandboxManifest();
  const [job, output, result, vectors] = await Promise.all([
    json('schemas/ParserJob.schema.json'), json('schemas/ParserOutput.schema.json'), json('schemas/ParserResult.schema.json'), json('vectors/canaries.json'),
  ]);
  const semantics = validateSandboxDocuments({ job, output, result, vectors });
  return Object.freeze({ manifest, ...semantics });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) console.log(await validateSandboxContract());
