import { inspectJson } from './canonical.mjs';
import { ERROR_CODES, contractError } from './errors.mjs';
import { validateAuthorizationRequest } from './validate.mjs';

const PERMISSION = Object.freeze({
  branch: 'submit',
  'branch-update': 'submit',
  'ci-materialize': 'content.materialize',
  copy: 'submit',
  create: 'submit',
  delete: 'submit',
  edit: 'submit',
  interrupt: 'submit',
  'lock-acquire': 'lock.create',
  'lock-conflict': 'lock.create',
  'lock-loss': 'lock.create',
  merge: 'submit',
  move: 'submit',
  'network-condition': 'metadata.read',
  rename: 'submit',
  review: 'review',
  'selective-sync': 'metadata.read',
  submit: 'submit',
});

function resourceType(kind) {
  if (kind.startsWith('lock-')) return 'lock';
  if (['branch', 'branch-update', 'merge'].includes(kind)) return 'reference';
  if (kind === 'review') return 'review';
  if (kind === 'ci-materialize') return 'content';
  return 'path';
}

export function authorizationRequestFromFixtureOperation(operation, bindings = {}) {
  inspectJson(operation);
  inspectJson(bindings);
  if (!operation || typeof operation !== 'object' || !Number.isSafeInteger(operation.sequence) || operation.sequence < 0 || typeof operation.kind !== 'string' || typeof operation.actor !== 'string' || typeof operation.target !== 'string' || !operation.authorization || operation.authorization.decision !== 'allow') {
    contractError(ERROR_CODES.INPUT_INVALID, 'fixture operation is not an OperationScenario v2 record');
  }
  const permission = PERMISSION[operation.kind];
  if (!permission) contractError(ERROR_CODES.INPUT_INVALID, 'fixture operation kind is not mapped to authorization v1');
  const authorityEpoch = bindings.authorityEpoch ?? 1;
  const fileId = operation.fileId?.result ?? operation.fileId?.source ?? null;
  const request = {
    schemaVersion: 'ogvcs.authorization/request/v1',
    requestId: bindings.requestId ?? `fixture-${String(operation.sequence).padStart(8, '0')}`,
    actor: {
      id: operation.actor,
      class: bindings.actorClass ?? (operation.kind === 'ci-materialize' ? 'service' : 'human'),
      groups: [operation.authorization.matchedPrincipal],
      credentialClass: bindings.credentialClass ?? (operation.kind === 'ci-materialize' ? 'service-token' : 'session'),
      credentialGeneration: bindings.credentialGeneration ?? 1,
      credentialStatus: bindings.credentialStatus ?? 'active',
      authorityEpoch,
    },
    tenant: bindings.tenant ?? 'fixture-tenant',
    repository: bindings.repository ?? 'fixture-repository',
    permission,
    reason: null,
    resource: {
      type: resourceType(operation.kind),
      path: operation.target,
      fileId,
      objectId: null,
      name: null,
    },
    context: {
      reference: bindings.reference ?? 'main',
      snapshot: bindings.snapshot ?? null,
      policyGeneration: bindings.policyGeneration ?? 1,
      authorityEpoch,
    },
  };
  return validateAuthorizationRequest(request);
}
