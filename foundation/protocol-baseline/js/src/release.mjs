import { deepFreeze } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError, protocolSemanticError } from './errors.mjs';
import { deadlineFrom } from './limits.mjs';
import { validateProtocolValue } from './schema.mjs';

const SELECTION_FIELDS = Object.freeze([
  'protocolVersion', 'messageSchemaVersion', 'repositoryFormat',
  'authorizationContract', 'authorizationRegistrySha256', 'pathContract',
  'pathProfile', 'pathRegistrySha256', 'eventVersion', 'transferProfile',
  'protocolRegistrySetSha256', 'repositoryRegistrySha256',
]);

function registry(contract, name) {
  const value = contract?.registries?.[name];
  if (value?.registry !== name || !Array.isArray(value.entries)) {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `protocol ${name} registry is invalid`);
  }
  return value;
}

function reject(code) {
  protocolSemanticError(code, 'protocol release preflight rejected the candidate before publication');
}

function sameSet(left, right) {
  return left.length === right.length && left.every((value) => right.includes(value));
}

function tupleMatches(candidate, row, extensionRegistry) {
  if (SELECTION_FIELDS.some((field) => candidate[field] !== row.selection[field])) return false;
  const selected = new Set(candidate.extensions);
  if (selected.size !== candidate.extensions.length) return false;
  for (const id of selected) {
    const registration = extensionRegistry.get(id);
    if (!registration || !['candidate', 'ratified'].includes(registration.state)) return false;
  }
  return sameSet(candidate.extensions, row.selection.extensions);
}

function assignmentKey(value) {
  return `${value.kind}\0${value.scope}\0${value.code}`;
}

function assignmentNameKey(value) {
  return `${value.kind}\0${value.scope}\0${value.name}`;
}

function sameAssignment(left, right) {
  return left?.kind === right?.kind
    && left?.scope === right?.scope
    && left?.name === right?.name
    && left?.code === right?.code
    && left?.semanticSha256 === right?.semanticSha256;
}

/**
 * Deterministically checks a proposed release against the authenticated
 * compatibility, capability, predecessor-pin, and immutable-assignment
 * authorities carried by the protocol contract.
 */
export function validateReleasePreflight(contract, candidateInput, options = {}) {
  const deadline = deadlineFrom(options);
  const candidate = validateProtocolValue(contract, 'ReleasePreflightCaseInput.schema.json', candidateInput, { ...options, deadline });
  const capabilities = registry(contract, 'capabilities');
  const compatibility = registry(contract, 'compatibility');
  const extensions = registry(contract, 'extensions');
  const assignments = registry(contract, 'release-assignments');

  const knownCapabilities = new Set(capabilities.entries.map((entry) => entry.id));
  for (const required of candidate.requiredCapabilities) {
    deadline.checkpoint();
    if (!knownCapabilities.has(required)) reject('NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN');
  }

  const pins = compatibility.predecessorPins;
  if (candidate.authorizationManifestSha256 !== pins?.authorization?.manifestSha256
      || candidate.pathManifestSha256 !== pins?.path?.manifestSha256
      || candidate.repositoryManifestSha256 !== pins?.repository?.manifestSha256) {
    reject('PROTOCOL_UNSUPPORTED');
  }

  const extensionById = new Map(extensions.entries.map((entry) => [entry.id, entry]));
  const matchingTuple = compatibility.entries.some((row) => {
    deadline.checkpoint();
    if (!['candidate', 'ratified'].includes(row.state)) return false;
    if (candidate.authorizationManifestSha256 !== row.authorizationManifestSha256
        || candidate.pathManifestSha256 !== row.pathManifestSha256
        || candidate.repositoryManifestSha256 !== row.repositoryManifestSha256) return false;
    if (!tupleMatches(candidate.proposedSelection, row, extensionById)) return false;
    return sameSet(candidate.requiredCapabilities, row.requiredCapabilities);
  });
  if (!matchingTuple) reject('PROTOCOL_UNSUPPORTED');

  if (assignments.compatibilityPolicy !== 'immutable-code-name-scope-semantics-no-removal-unique-registered-optional-candidate-additions'
      || typeof assignments.snapshotSha256 !== 'string'
      || !Array.isArray(assignments.allowedAdditions)
      || candidate.priorAssignmentSnapshotSha256 !== assignments.snapshotSha256) {
    reject('PROTOCOL_UNSUPPORTED');
  }

  const priorByCode = new Map();
  const priorByName = new Map();
  for (const value of assignments.entries) {
    deadline.checkpoint();
    priorByCode.set(assignmentKey(value), value);
    priorByName.set(assignmentNameKey(value), value);
  }
  const allowed = new Map();
  for (const row of assignments.allowedAdditions) {
    deadline.checkpoint();
    if (row?.state !== 'candidate' || row?.requirement !== 'optional' || row?.major !== 1
        || !row.assignment || typeof row.registry !== 'string') reject('PROTOCOL_UNSUPPORTED');
    const registration = contract.registries?.[row.registry]?.entries?.find?.((entry) => (
      entry.code === row.assignment.code
      && (entry.id ?? entry.name) === row.assignment.name
      && entry.state === row.state
      && entry.requirement === row.requirement
    ));
    if (!registration) reject('PROTOCOL_UNSUPPORTED');
    allowed.set(assignmentKey(row.assignment), row.assignment);
  }
  const proposedByCode = new Map();
  const proposedByName = new Map();
  for (const value of candidate.proposedAssignments) {
    deadline.checkpoint();
    const codeKey = assignmentKey(value);
    const nameKey = assignmentNameKey(value);
    const byCode = proposedByCode.get(codeKey);
    const byName = proposedByName.get(nameKey);
    if (byCode && !sameAssignment(byCode, value)
        || byName && !sameAssignment(byName, value)) reject('PROTOCOL_UNSUPPORTED');
    proposedByCode.set(codeKey, value);
    proposedByName.set(nameKey, value);
  }
  for (const value of assignments.entries) {
    deadline.checkpoint();
    const byCode = proposedByCode.get(assignmentKey(value));
    const byName = proposedByName.get(assignmentNameKey(value));
    if (byCode === undefined || byName === undefined
        || !sameAssignment(byCode, value)
        || !sameAssignment(byName, value)) {
      reject('PROTOCOL_UNSUPPORTED');
    }
  }
  for (const value of candidate.proposedAssignments) {
    deadline.checkpoint();
    if (priorByCode.has(assignmentKey(value))) continue;
    if (!sameAssignment(allowed.get(assignmentKey(value)), value)) reject('PROTOCOL_UNSUPPORTED');
    if (priorByName.has(assignmentNameKey(value))) reject('PROTOCOL_UNSUPPORTED');
  }
  deadline.checkpoint();
  return deepFreeze({
    compatible: true,
    assignmentCount: candidate.proposedAssignments.length,
    priorAssignmentSnapshotSha256: candidate.priorAssignmentSnapshotSha256,
  });
}
