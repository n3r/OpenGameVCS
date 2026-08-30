import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

import { identityFail } from './errors.mjs';

const require = createRequire(import.meta.url);
const readPackageJson = (specifier) => {
  const bytes = readFileSync(require.resolve(specifier));
  return { bytes, value: JSON.parse(bytes) };
};
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

const identity = readPackageJson('@opengamevcs/identity-policy-audit-contract-v1/manifest.json');
const metadata = readPackageJson('@opengamevcs/repository-metadata-contract-v1/manifest.json');
const metadataOperations = readPackageJson('@opengamevcs/repository-metadata-contract-v1/registries/operations.json').value;
const predecessorManifests = {
  authorization: readPackageJson('@opengamevcs/authorization-contract-v1/manifest.json').bytes,
  path: readPackageJson('@opengamevcs/path-contract-v1/manifest.json').bytes,
  protocol: readPackageJson('@opengamevcs/protocol-contract-v1/manifest.json').bytes,
  metadata: metadata.bytes,
};
if (identity.value.schemaVersion !== 'ogvcs.identity-policy/contract-manifest/v1'
    || identity.value.contractVersion !== '0.1.0' || identity.value.state !== 'candidate'
    || Object.entries(predecessorManifests).some(([name, bytes]) => identity.value.predecessorPins[name]?.manifestSha256 !== digest(bytes))) {
  identityFail('POLICY_UNAVAILABLE', 'identity-policy contract authority is invalid');
}
if (metadata.value.contractVersion !== '0.1.0' || metadataOperations.registry !== 'operations') {
  identityFail('POLICY_UNAVAILABLE', 'metadata contract authority is invalid');
}

const operations = new Map(metadataOperations.entries.map((entry) => [entry.name, Object.freeze(structuredClone(entry))]));

export const identityPolicyContract = Object.freeze({
  contractVersion: identity.value.contractVersion,
  manifestSha256: digest(identity.bytes),
  predecessorPins: Object.freeze(structuredClone(identity.value.predecessorPins)),
});

export function metadataOperationAuthority(name) {
  const operation = operations.get(name);
  if (!operation) identityFail('INPUT_INVALID', 'metadata operation is not assigned');
  if (operation.permission === 'service-internal') identityFail('INPUT_INVALID', 'internal metadata operation has no public authorization request');
  return operation;
}
