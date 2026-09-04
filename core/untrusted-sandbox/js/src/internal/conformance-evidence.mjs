import { execFile } from 'node:child_process';
import { types } from 'node:util';
import { promisify } from 'node:util';

import { CandidateCredentialBroker, CandidateSandboxSupervisor } from '../index.mjs';
import { candidateLauncherParts, createTestingLauncherCapability } from './capability.mjs';
import { canonicalJson, isDigest, sha256 } from './reference-contract.mjs';

const execFileAsync = promisify(execFile);
const GIT_REVISION = /^[0-9a-f]{40}$/u;
const SOURCE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.?(?:\/|$))(?!.*[\\\0\r\n])[A-Za-z0-9._/-]{1,512}$/u;
const SOURCE_FILE_KEYS = Object.freeze(['bytes', 'path', 'sha256']);
const PORTABLE_REQUEST_KEYS = Object.freeze(['platform', 'sourceFiles', 'sourceRevision']);
const PORTABLE_PLATFORMS = Object.freeze(['linux', 'macos', 'windows']);
const PORTABLE_CASES = Object.freeze([
  Object.freeze({ outputPath: 'import/result', toolClass: 'importer' }),
  Object.freeze({ outputPath: 'preview/result', toolClass: 'converter' }),
]);
const LAUNCH_REQUEST_KEYS = Object.freeze(['arguments', 'environment', 'job', 'limits', 'stdin']);
const MAXIMUM_SOURCE_FILES = 128;
const MAXIMUM_SOURCE_FILE_BYTES = 16 * 1024 * 1024;
const MAXIMUM_SOURCE_SET_BYTES = 128 * 1024 * 1024;

export const SANDBOX_CONFORMANCE_SOURCE_PATHS = Object.freeze([
  '.github/workflows/untrusted-sandbox.yml',
  'core/untrusted-sandbox/js/linux/runtime-contract.json',
  'core/untrusted-sandbox/js/linux/seccomp-linux-reference-v1.json',
  'core/untrusted-sandbox/js/package.json',
  'core/untrusted-sandbox/js/scripts/kill-boundary-conformance.mjs',
  'core/untrusted-sandbox/js/scripts/linux-conformance.mjs',
  'core/untrusted-sandbox/js/scripts/portable-conformance.mjs',
  'core/untrusted-sandbox/js/scripts/source-model-conformance.mjs',
  'core/untrusted-sandbox/js/src/index.mjs',
  'core/untrusted-sandbox/js/src/internal/capability.mjs',
  'core/untrusted-sandbox/js/src/internal/conformance-evidence.mjs',
  'core/untrusted-sandbox/js/src/internal/docker-reference.mjs',
  'core/untrusted-sandbox/js/src/internal/linux-conformance-report.mjs',
  'core/untrusted-sandbox/js/src/internal/output-frame.mjs',
  'core/untrusted-sandbox/js/src/internal/reference-contract.mjs',
  'core/untrusted-sandbox/js/src/internal/reference-service.mjs',
  'core/untrusted-sandbox/js/src/internal/reference-state.mjs',
  'core/untrusted-sandbox/js/src/linux.mjs',
  'core/untrusted-sandbox/js/src/testing.mjs',
  'core/untrusted-sandbox/js/test/conformance-evidence.test.mjs',
  'core/untrusted-sandbox/js/test/fixtures/kill-boundary-child.mjs',
  'core/untrusted-sandbox/js/test/reference-worker.test.mjs',
  'tools/compare-untrusted-sandbox-conformance.mjs',
  'tools/untrusted-sandbox-conformance-evidence.test.mjs',
  'tools/untrusted-sandbox-workflow-policy.test.mjs',
]);

const exactRecord = (source, keys) => {
  try {
    if (source === null || typeof source !== 'object' || Array.isArray(source) || types.isProxy(source)) return null;
    const prototype = Object.getPrototypeOf(source);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(source);
    if (Reflect.ownKeys(descriptors).length !== keys.length
      || Object.keys(descriptors).sort().join('\0') !== keys.join('\0')
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
    const length = descriptors.length;
    if (!length
      || !Object.hasOwn(length, 'value')
      || length.value !== source.length
      || length.enumerable
      || Object.hasOwn(length, 'get')
      || Object.hasOwn(length, 'set')) return null;
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

export const sourceSetSha256 = (sourceFiles) => sha256(Buffer.from(`OGVCS-SANDBOX-SOURCE-SET-V1\0${canonicalJson(sourceFiles)}`, 'utf8'));

export const snapshotSourceEvidence = (sourceValue) => {
  const request = exactRecord(sourceValue, ['sourceFiles', 'sourceRevision']);
  if (!request) throw new TypeError('sandbox conformance source evidence is invalid');
  const { sourceFiles, sourceRevision } = request;
  const sourceEntries = exactArray(sourceFiles, 1, MAXIMUM_SOURCE_FILES);
  if (!GIT_REVISION.test(sourceRevision ?? '') || !sourceEntries) throw new TypeError('sandbox conformance source evidence is invalid');
  const files = [];
  let totalBytes = 0;
  for (const source of sourceEntries) {
    const file = exactRecord(source, SOURCE_FILE_KEYS);
    if (!file
      || !SOURCE_PATH.test(file.path ?? '')
      || !Number.isSafeInteger(file.bytes)
      || file.bytes < 0
      || file.bytes > MAXIMUM_SOURCE_FILE_BYTES
      || !isDigest(file.sha256)) throw new TypeError('sandbox conformance source file is invalid');
    totalBytes += file.bytes;
    if (totalBytes > MAXIMUM_SOURCE_SET_BYTES) throw new TypeError('sandbox conformance source evidence is too large');
    files.push(Object.freeze({ bytes: file.bytes, path: file.path, sha256: file.sha256 }));
  }
  const paths = files.map(({ path }) => path);
  if (new Set(paths).size !== paths.length || paths.join('\0') !== [...paths].sort().join('\0')) throw new TypeError('sandbox conformance source files are not uniquely sorted');
  const frozen = Object.freeze(files);
  return Object.freeze({
    sourceFiles: frozen,
    sourceRevision,
    sourceSetSha256: sourceSetSha256(frozen),
  });
};

export const readGitSourceEvidence = async (requestSource) => {
  const request = exactRecord(requestSource, ['repositoryRoot', 'sourceRevision']);
  if (!request || typeof request.repositoryRoot !== 'string' || !GIT_REVISION.test(request.sourceRevision ?? '')) throw new TypeError('sandbox git source evidence request is invalid');
  const { repositoryRoot, sourceRevision } = request;
  const sourcePaths = SANDBOX_CONFORMANCE_SOURCE_PATHS;
  const { stdout: headOutput } = await execFileAsync('git', ['rev-parse', '--verify', 'HEAD'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    maxBuffer: 1024,
    windowsHide: true,
  });
  if (headOutput !== `${sourceRevision}\n`) throw new Error('sandbox conformance source revision is not the checked-out HEAD');
  await execFileAsync('git', ['diff', '--quiet', '--no-ext-diff', sourceRevision, '--', ...sourcePaths], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    maxBuffer: 1024,
    windowsHide: true,
  }).catch(() => { throw new Error('sandbox conformance executing source differs from the checked-out revision'); });
  const sourceFiles = [];
  for (const path of sourcePaths) {
    const { stdout } = await execFileAsync('git', ['show', `${sourceRevision}:${path}`], {
      cwd: repositoryRoot,
      encoding: null,
      maxBuffer: MAXIMUM_SOURCE_FILE_BYTES,
      windowsHide: true,
    });
    const bytes = Buffer.from(stdout);
    sourceFiles.push(Object.freeze({ bytes: bytes.length, path, sha256: sha256(bytes) }));
  }
  return snapshotSourceEvidence({ sourceFiles, sourceRevision });
};

const iterable = (chunks) => (async function* () { for (const chunk of chunks) yield Buffer.from(chunk); }());

const portableLauncher = (requests, outputPath, toolClass) => createTestingLauncherCapability({
  assertedControls: Object.freeze({
    cpuLimited: true,
    credentialFree: true,
    isolatedScratch: true,
    memoryLimited: true,
    networkDenied: true,
    processLimited: true,
    readOnlyInput: true,
  }),
  launch: async (request) => {
    requests.push(request);
    const output = Buffer.from(canonicalJson({
      outputs: Object.freeze([Object.freeze({
        digest: sha256(Buffer.from(`portable-${toolClass}`, 'utf8')),
        path: outputPath,
        type: 'conformance.record',
      })]),
      schemaVersion: 'ogvcs.untrusted-sandbox/parser-output/v1',
    }), 'utf8');
    return Object.freeze({
      exit: Promise.resolve(Object.freeze({ code: 0, signal: null })),
      kill: async () => {},
      stderr: iterable([]),
      stdout: iterable([output]),
      terminate: async () => {},
    });
  },
});

const portableJob = ({ index, inputDigest, toolClass }) => Object.freeze({
  idempotencyKey: `portable.${toolClass}.${index}`,
  inputDigest,
  jobId: `portable.${toolClass}.${index}`,
  outputSchema: 'ogvcs.untrusted-sandbox/parser-output/v1',
  purpose: 'private-portable-conformance',
  resourceClass: 'parser-default',
  runtimeDigest: sha256(Buffer.from('portable-private-runtime-v1', 'utf8')),
  schemaVersion: 'ogvcs.untrusted-sandbox/parser-job/v1',
  toolDigest: sha256(Buffer.from(`portable-private-${toolClass}-v1`, 'utf8')),
});

export const runPrivatePortableConformance = async (requestSource) => {
  const request = exactRecord(requestSource, PORTABLE_REQUEST_KEYS);
  if (!request || !PORTABLE_PLATFORMS.includes(request.platform)) throw new TypeError('portable sandbox conformance request is invalid');
  const source = snapshotSourceEvidence({ sourceFiles: request.sourceFiles, sourceRevision: request.sourceRevision });
  const canary = 'portable-broker-secret-canary';
  const cases = [];
  for (const [index, definition] of PORTABLE_CASES.entries()) {
    const inputDigest = sha256(Buffer.from(`portable-${definition.toolClass}-input`, 'utf8'));
    const job = portableJob({ index, inputDigest, toolClass: definition.toolClass });
    const requests = [];
    const broker = new CandidateCredentialBroker({
      acquire: async ({ credential }) => Object.freeze({
        handle: credential === canary ? `opaque.${definition.toolClass}.input` : 'denied',
        inputDigest,
      }),
      credential: canary,
    });
    const launcher = portableLauncher(requests, definition.outputPath, definition.toolClass);
    if (candidateLauncherParts(launcher) === null) throw new Error('portable sandbox launcher capability is unavailable');
    const supervisor = new CandidateSandboxSupervisor({ candidateLauncher: launcher });
    const staged = await broker.stage(job);
    const result = await supervisor.run(job, staged);
    if (requests.length !== 1) throw new Error('portable sandbox conformance launch count differs');
    const launch = requests[0];
    const requestKeys = Object.keys(launch).sort();
    const credentialCanaryAbsent = !JSON.stringify(launch).includes(canary);
    const publicationCapabilityPresent = Reflect.ownKeys(launch).some((key) => typeof key === 'string' && /publish|commit|repository/iu.test(key));
    cases.push(Object.freeze({
      credentialCanaryAbsent,
      publicationCapabilityPresent,
      requestKeys: Object.freeze(requestKeys),
      resultCode: result.code,
      toolClass: definition.toolClass,
    }));
  }
  const outcome = cases.length === 2
    && cases.every((entry) => entry.resultCode === 'VALIDATED'
      && entry.credentialCanaryAbsent
      && !entry.publicationCapabilityPresent
      && entry.requestKeys.join('\0') === LAUNCH_REQUEST_KEYS.join('\0')) ? 'passed' : 'failed';
  return Object.freeze({
    cases: Object.freeze(cases),
    claimBoundary: Object.freeze({
      hostIsolation: false,
      productionBroker: false,
      publicAdmission: false,
      repositoryPublication: false,
    }),
    evidenceKind: 'source-only-model',
    executionMode: 'source-only-private-model',
    nodeMajor: Number.parseInt(process.versions.node.split('.')[0], 10),
    outcome,
    platform: request.platform,
    platformBinding: 'declared-target-only',
    profile: 'portable-private-v1',
    retentionStatus: 'not-hosted',
    schemaVersion: 'ogvcs.untrusted-sandbox/portable-conformance-report/v1',
    ...source,
  });
};

export const comparePortableConformanceReports = (reportSources) => {
  const reportEntries = exactArray(reportSources, 3, 3);
  if (!reportEntries) throw new TypeError('portable sandbox comparison input is invalid');
  const rank = Object.freeze({ linux: 0, macos: 1, windows: 2 });
  const reports = [];
  for (const source of reportEntries) {
    const report = exactRecord(source, [
      'cases',
      'claimBoundary',
      'evidenceKind',
      'executionMode',
      'nodeMajor',
      'outcome',
      'platform',
      'platformBinding',
      'profile',
      'retentionStatus',
      'schemaVersion',
      'sourceFiles',
      'sourceRevision',
      'sourceSetSha256',
    ]);
    const claimBoundary = report && exactRecord(report.claimBoundary, ['hostIsolation', 'productionBroker', 'publicAdmission', 'repositoryPublication']);
    const caseEntries = report && exactArray(report.cases, 2, 2);
    if (!report
      || !Object.hasOwn(rank, report.platform)
      || report.schemaVersion !== 'ogvcs.untrusted-sandbox/portable-conformance-report/v1'
      || report.profile !== 'portable-private-v1'
      || report.evidenceKind !== 'source-only-model'
      || report.retentionStatus !== 'not-hosted'
      || report.platformBinding !== 'declared-target-only'
      || report.executionMode !== 'source-only-private-model'
      || report.outcome !== 'passed'
      || report.nodeMajor !== 24
      || !claimBoundary
      || Object.values(claimBoundary).some((value) => value !== false)
      || !caseEntries) throw new Error('portable sandbox conformance report is invalid');
    const sourceEvidence = snapshotSourceEvidence({ sourceFiles: report.sourceFiles, sourceRevision: report.sourceRevision });
    if (report.sourceSetSha256 !== sourceEvidence.sourceSetSha256) throw new Error('portable sandbox conformance source binding differs');
    const cases = [];
    for (const [index, caseSource] of caseEntries.entries()) {
      const entry = exactRecord(caseSource, ['credentialCanaryAbsent', 'publicationCapabilityPresent', 'requestKeys', 'resultCode', 'toolClass']);
      const requestKeys = entry && exactArray(entry.requestKeys, LAUNCH_REQUEST_KEYS.length, LAUNCH_REQUEST_KEYS.length);
      if (!entry
        || entry.toolClass !== PORTABLE_CASES[index].toolClass
        || entry.resultCode !== 'VALIDATED'
        || entry.credentialCanaryAbsent !== true
        || entry.publicationCapabilityPresent !== false
        || !requestKeys
        || requestKeys.some((key) => typeof key !== 'string')
        || requestKeys.join('\0') !== LAUNCH_REQUEST_KEYS.join('\0')) throw new Error('portable sandbox conformance case is invalid');
      cases.push(Object.freeze({ ...entry, requestKeys: Object.freeze(requestKeys) }));
    }
    reports.push(Object.freeze({ ...report, cases: Object.freeze(cases), claimBoundary: Object.freeze(claimBoundary), ...sourceEvidence }));
  }
  reports.sort((left, right) => rank[left.platform] - rank[right.platform]);
  const platforms = reports.map((report) => report?.platform);
  const expectedPlatforms = ['linux', 'macos', 'windows'];
  const reference = reports[0];
  if (platforms.join('\0') !== expectedPlatforms.join('\0')
    || reports.some((report) => report.sourceRevision !== reference.sourceRevision
      || report.sourceSetSha256 !== reference.sourceSetSha256
      || canonicalJson(report.sourceFiles) !== canonicalJson(reference.sourceFiles)
      || canonicalJson(report.cases) !== canonicalJson(reference.cases)
      || canonicalJson(report.claimBoundary) !== canonicalJson(reference.claimBoundary))) throw new Error('portable sandbox conformance reports differ');
  return Object.freeze({
    caseSetSha256: sha256(Buffer.from(canonicalJson(reference.cases), 'utf8')),
    platforms: Object.freeze(expectedPlatforms),
    reports: 3,
    result: 'equal',
    schemaVersion: 'ogvcs.untrusted-sandbox/portable-conformance-comparison/v1',
    sourceRevision: reference.sourceRevision,
    sourceSetSha256: reference.sourceSetSha256,
  });
};
