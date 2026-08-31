import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateSandboxManifest } from './scripts/generate.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const assert = (value, message) => { if (!value) throw new Error(message); };
const json = async (path) => JSON.parse(await readFile(resolve(root, path)));
const sha = (value) => createHash('sha256').update(value).digest('hex');

export async function validateSandboxContract() {
  const manifest = await validateSandboxManifest();
  const [job, output, result, vectors] = await Promise.all([
    json('schemas/ParserJob.schema.json'), json('schemas/ParserOutput.schema.json'), json('schemas/ParserResult.schema.json'), json('vectors/canaries.json'),
  ]);
  assert(job.additionalProperties === false && output.additionalProperties === false && output.properties.outputs.items.additionalProperties === false && result.additionalProperties === false, 'sandbox schemas must be closed');
  assert(job.properties.schemaVersion.const === 'ogvcs.untrusted-sandbox/parser-job/v1', 'job version differs');
  assert(job['x-ogvcs-boundary'].includes('broker-owned immutable input'), 'broker boundary differs');
  assert(output.properties.schemaVersion.const === job.properties.outputSchema.const && output.properties.outputs.maxItems === 10_000, 'output schema or record ceiling differs');
  assert(output['x-ogvcs-canonical-json'].includes('keys sorted') && output['x-ogvcs-path-profile'] === 'path.opengamevcs/portable@1', 'output canonical/path profile differs');
  assert(result.properties.code.enum.join(',') === 'VALIDATED,SANDBOX_UNAVAILABLE,SANDBOX_TIMEOUT,SANDBOX_OUTPUT_LIMIT,SANDBOX_PROTOCOL_INVALID,SANDBOX_VALIDATION_FAILED', 'safe result codes differ');
  assert(result['x-ogvcs-fatal-error-codes'].join(',') === 'SANDBOX_SETTLEMENT_UNCONFIRMED', 'fatal containment error allowlist differs');
  assert(result['x-ogvcs-privacy'].includes('credentials'), 'safe error boundary differs');
  assert(vectors.schemaVersion === 'ogvcs.untrusted-sandbox/vectors/v1' && vectors.cases.length >= 10, 'canary inventory differs');
  assert(new Set(vectors.cases.map((item) => item.id)).size === vectors.cases.length, 'canary identifiers repeat');
  assert(new Set(vectors.cases.map((item) => item.scenario)).size === vectors.cases.length, 'canary scenarios repeat instead of dispatching independently');
  assert(vectors.cases.every((item) => item.requirementIds.every((id) => /^OGVCS-045-(?:FR|AC)-\d{2}$/u.test(id))), 'canary traceability differs');
  assert(vectors.cases.every((item) => Object.keys(item).sort().join(',') === 'expectedCode,id,requirementIds,scenario' && typeof item.scenario === 'string' && result.properties.code.enum.includes(item.expectedCode)), 'canary shape or expected outcome differs');
  return Object.freeze({ manifest, schemaDigest: sha(JSON.stringify([job, output, result])), vectors: vectors.cases.length });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) console.log(await validateSandboxContract());
