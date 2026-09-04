import { types } from 'node:util';
import { snapshotSourceEvidence } from './conformance-evidence.mjs';
import { isDigest } from './reference-contract.mjs';

const RESULT_CODES = Object.freeze([
  'SANDBOX_CANCELLED',
  'SANDBOX_OUTPUT_LIMIT',
  'SANDBOX_PROTOCOL_INVALID',
  'SANDBOX_RESOURCE_LIMIT',
  'SANDBOX_REVOKED',
  'SANDBOX_TIMEOUT',
  'SANDBOX_UNAVAILABLE',
  'SANDBOX_VALIDATION_FAILED',
  'VALIDATED',
]);
const FAILURE_STAGES = Object.freeze(['CONTROL', 'DENIED_OUTPUT', 'OPEN', 'RESOURCE_ENVELOPE', 'RESULT_CODE', 'VALIDATED_OUTPUT']);
const REPORT_COMMANDS = Object.freeze([
  'bomb', 'cancel', 'clone-namespace', 'clone3-namespace', 'converter', 'cpu', 'crash', 'credential', 'device', 'disk', 'fork', 'hang', 'host', 'importer', 'memory', 'namespace', 'network', 'recursion', 'restart', 'revoke-new', 'revoke-prior', 'sibling', 'stdout', 'symlink', 'traversal', 'undeclared',
]);
const PRESTART_IMAGE_DIAGNOSTICS = Object.freeze([
  'PRESTART_IMAGE_CONFIG_COMMAND', 'PRESTART_IMAGE_CONFIG_ENV', 'PRESTART_IMAGE_CONFIG_HEALTH', 'PRESTART_IMAGE_CONFIG_LABELS', 'PRESTART_IMAGE_CONFIG_USER_WORKDIR', 'PRESTART_IMAGE_CONFIG_VOLUME', 'PRESTART_IMAGE_IDENTITY', 'PRESTART_IMAGE_INSPECT_SHAPE', 'PRESTART_IMAGE_PLATFORM', 'PRESTART_IMAGE_ROOTFS', 'PRESTART_IMAGE_SIZE',
]);
const RESULT_DIAGNOSTICS = Object.freeze([
  'none',
  'OUTPUT_FRAME_INVALID',
  'TRUSTED_OUTPUT_SHIM_REJECTED',
  'VALIDATED_EMPTY_OUTPUT',
  ...PRESTART_IMAGE_DIAGNOSTICS,
  ...[
    'anchor-running', 'config-content', 'config-image', 'config-io', 'config-labels', 'config-process', 'effective-mounts', 'host-capabilities', 'host-devices', 'host-lifecycle', 'host-logging', 'host-mounts', 'host-namespaces', 'host-network', 'host-resources', 'host-root', 'host-runtime', 'host-security', 'host-security-apparmor', 'host-security-init', 'host-security-nnp', 'host-security-oom', 'host-security-options-shape', 'host-security-privileged', 'host-security-seccomp', 'host-tmpfs', 'host-ulimits', 'identity', 'inspect-response', 'inspect-shape', 'network-attachment', 'output-volume', 'state',
  ].map((value) => `PRESTART_INSPECT_${value.replaceAll('-', '_').toUpperCase()}`),
  ...['ACTIVATION_CONTROL', 'CONTROL', 'ENTRYPOINT', 'INPUT_READ', 'NONZERO', 'OUTPUT_WRITE', 'STDERR', 'STDOUT', 'TOOL_EXITED'].map((value) => `WORKER_FAILED:${value}`),
]);
const CONTROL_KEYS = Object.freeze([
  'architecture',
  'availableControllers',
  'cgroupNamespace',
  'cgroupVersion',
  'operatingSystem',
  'rootless',
  'runtimeBinaryBinding',
  'runtimeCommit',
  'runtimeName',
  'runtimePathKind',
  'runtimeVersion',
  'seccomp',
]);
const KNOWN_CONTROLLERS = Object.freeze(['cpu', 'cpuset', 'dmem', 'hugetlb', 'io', 'memory', 'misc', 'pids', 'rdma']);
const SANITIZED_RUNTIME_COMPONENT = /^[A-Za-z0-9._+-]{1,128}$/u;

const exactRecord = (source, keys) => {
  try {
    if (source === null || typeof source !== 'object' || Array.isArray(source) || types.isProxy(source)) return null;
    const prototype = Object.getPrototypeOf(source);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(source);
    if (Reflect.ownKeys(descriptors).length !== keys.length
      || Object.keys(descriptors).sort().join('\0') !== [...keys].sort().join('\0')
      || Object.values(descriptors).some((descriptor) => !descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || Object.hasOwn(descriptor, 'get') || Object.hasOwn(descriptor, 'set'))) return null;
    return Object.fromEntries(keys.map((key) => [key, descriptors[key].value]));
  } catch { return null; }
};

const exactArray = (source, minimum, maximum) => {
  try {
    if (!Array.isArray(source)
      || types.isProxy(source)
      || Object.getPrototypeOf(source) !== Array.prototype
      || !Number.isSafeInteger(source.length)
      || source.length < minimum
      || source.length > maximum) return null;
    const descriptors = Object.getOwnPropertyDescriptors(source);
    const expectedKeys = [];
    for (let index = 0; index < source.length; index += 1) expectedKeys.push(String(index));
    expectedKeys.push('length');
    if (Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string')
      || Reflect.ownKeys(descriptors).join('\0') !== expectedKeys.join('\0')) return null;
    const values = [];
    for (let index = 0; index < source.length; index += 1) {
      const descriptor = descriptors[index];
      if (!descriptor
        || !descriptor.enumerable
        || !Object.hasOwn(descriptor, 'value')
        || Object.hasOwn(descriptor, 'get')
        || Object.hasOwn(descriptor, 'set')) return null;
      values.push(descriptor.value);
    }
    return values;
  } catch { return null; }
};

export const closeLinuxConformanceFailure = (source) => {
  const value = exactRecord(source, ['actualCode', 'command', 'diagnostic', 'expectedCode', 'stage']) ?? {};
  return Object.freeze({
    actualCode: RESULT_CODES.includes(value.actualCode) ? value.actualCode : 'UNKNOWN',
    command: REPORT_COMMANDS.includes(value.command) ? value.command : 'harness',
    diagnostic: RESULT_DIAGNOSTICS.includes(value.diagnostic) ? value.diagnostic : 'none',
    expectedCode: RESULT_CODES.includes(value.expectedCode) ? value.expectedCode : 'UNKNOWN',
    stage: FAILURE_STAGES.includes(value.stage) ? value.stage : 'CONTROL',
  });
};

const closeCase = (source) => {
  const value = exactRecord(source, ['command', 'elapsedMilliseconds', 'resultCode']);
  if (!value
    || !REPORT_COMMANDS.includes(value.command)
    || !Number.isSafeInteger(value.elapsedMilliseconds)
    || value.elapsedMilliseconds < 0
    || value.elapsedMilliseconds > 60_000
    || !RESULT_CODES.includes(value.resultCode)) return null;
  return Object.freeze(value);
};

export const buildLinuxConformanceReport = (source) => {
  const value = exactRecord(source, ['cases', 'failure', 'outcome', 'runtimeDigest', 'seccompProfileSha256']);
  if (!value
    || !Array.isArray(value.cases)
    || value.cases.length > 128
    || !['failed', 'passed'].includes(value.outcome)
    || (value.runtimeDigest !== null && !isDigest(value.runtimeDigest))
    || (value.seccompProfileSha256 !== null && !isDigest(value.seccompProfileSha256))) throw new TypeError('Linux conformance report input is invalid');
  const cases = value.cases.map(closeCase);
  if (cases.some((entry) => entry === null)) throw new TypeError('Linux conformance report case is invalid');
  const failure = value.outcome === 'failed' ? closeLinuxConformanceFailure(value.failure) : null;
  return Object.freeze({
    cases: Object.freeze(cases),
    failure,
    outcome: value.outcome,
    profile: 'linux-reference-v1',
    runtimeDigest: value.runtimeDigest,
    schemaVersion: 'ogvcs.untrusted-sandbox/linux-conformance-report/v1',
    seccompProfileSha256: value.seccompProfileSha256,
  });
};

const closeControls = (source) => {
  const value = exactRecord(source, CONTROL_KEYS);
  const availableControllers = value && exactArray(value.availableControllers, 3, KNOWN_CONTROLLERS.length);
  if (!value
    || value.architecture !== 'amd64'
    || value.operatingSystem !== 'linux'
    || value.cgroupVersion !== 2
    || value.cgroupNamespace !== true
    || value.seccomp !== true
    || value.rootless !== false
    || value.runtimeName !== 'runc'
    || !['absolute-path', 'relative-name'].includes(value.runtimePathKind)
    || value.runtimeBinaryBinding !== 'unproven'
    || !SANITIZED_RUNTIME_COMPONENT.test(value.runtimeVersion ?? '')
    || !SANITIZED_RUNTIME_COMPONENT.test(value.runtimeCommit ?? '')
    || !availableControllers
    || availableControllers.some((controller) => typeof controller !== 'string' || !KNOWN_CONTROLLERS.includes(controller))
    || new Set(availableControllers).size !== availableControllers.length
    || availableControllers.join('\0') !== [...availableControllers].sort().join('\0')
    || !['cpu', 'memory', 'pids'].every((controller) => availableControllers.includes(controller))) return null;
  return Object.freeze({
    ...value,
    availableControllers: Object.freeze(availableControllers),
  });
};

export const buildLinuxConformanceReportV2 = (source) => {
  const value = exactRecord(source, ['cases', 'controls', 'failure', 'outcome', 'runtimeDigest', 'seccompProfileSha256', 'sourceFiles', 'sourceRevision']);
  const controls = value && closeControls(value.controls);
  const cases = value && exactArray(value.cases, 0, 128);
  if (!value || !controls || !cases) throw new TypeError('Linux conformance report v2 input is invalid');
  const legacy = buildLinuxConformanceReport({
    cases,
    failure: value.failure,
    outcome: value.outcome,
    runtimeDigest: value.runtimeDigest,
    seccompProfileSha256: value.seccompProfileSha256,
  });
  const sourceEvidence = snapshotSourceEvidence({ sourceFiles: value.sourceFiles, sourceRevision: value.sourceRevision });
  return Object.freeze({
    cases: legacy.cases,
    controls,
    failure: legacy.failure,
    outcome: legacy.outcome,
    profile: legacy.profile,
    runtimeDigest: legacy.runtimeDigest,
    schemaVersion: 'ogvcs.untrusted-sandbox/linux-conformance-report/v2',
    seccompProfileSha256: legacy.seccompProfileSha256,
    ...sourceEvidence,
  });
};

export const isLinuxConformanceResultDiagnostic = (value) => typeof value === 'string' && RESULT_DIAGNOSTICS.includes(value);
export const isLinuxConformanceResultCode = (value) => typeof value === 'string' && RESULT_CODES.includes(value);
