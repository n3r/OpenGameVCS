import { types } from 'node:util';
import { fileURLToPath } from 'node:url';
import { DockerReferenceAdapter } from './internal/docker-reference.mjs';
import { ReferenceSandboxService } from './internal/reference-service.mjs';

export const LINUX_REFERENCE_SECCOMP_SHA256 = 'd25dfdd48dbfccb7fcb30e1468f0f2adb4974d26e3bd205231abac0bd062f1f0';
const SECCOMP_PATH = fileURLToPath(new URL('../linux/seccomp-linux-reference-v1.json', import.meta.url));
const CONFIGURATION_KEYS = Object.freeze([
  'acquisitionSources',
  'dockerBinary',
  'evidenceHmacKey',
  'evidenceHmacKeyId',
  'manifestCatalog',
  'stateRoot',
  'trustedManifestKeys',
]);

const snapshotConfiguration = (source) => {
  if (source === null || typeof source !== 'object' || Array.isArray(source) || types.isProxy(source)) return null;
  try {
    const prototype = Object.getPrototypeOf(source);
    const descriptors = Object.getOwnPropertyDescriptors(source);
    if ((prototype !== Object.prototype && prototype !== null) || Object.keys(descriptors).sort().join('\0') !== CONFIGURATION_KEYS.join('\0') || Object.values(descriptors).some((descriptor) => !descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || Object.hasOwn(descriptor, 'get') || Object.hasOwn(descriptor, 'set'))) return null;
    return Object.freeze(Object.fromEntries(CONFIGURATION_KEYS.map((key) => [key, descriptors[key].value])));
  } catch { return null; }
};

export class LinuxReferenceUnavailableError extends Error {
  constructor() {
    super('required Linux reference sandbox controls are unavailable');
    this.name = 'LinuxReferenceUnavailableError';
    this.code = 'SANDBOX_UNAVAILABLE';
    this.stack = `${this.name}: ${this.message}`;
    Object.freeze(this);
  }
}

const openAdapter = async (dockerBinary) => DockerReferenceAdapter.open({
  dockerBinary,
  expectedSeccompSha256: LINUX_REFERENCE_SECCOMP_SHA256,
  seccompProfilePath: SECCOMP_PATH,
});

export async function probeLinuxReferenceSandbox({ dockerBinary } = {}) {
  if (process.platform !== 'linux' || process.arch !== 'x64' || typeof dockerBinary !== 'string') return Object.freeze({ available: false, code: 'SANDBOX_UNAVAILABLE', profile: 'linux-reference-v1' });
  try {
    const adapter = await openAdapter(dockerBinary);
    return Object.freeze({ available: true, code: 'AVAILABLE', profile: 'linux-reference-v1', seccompProfileSha256: adapter.seccompDigest });
  } catch {
    return Object.freeze({ available: false, code: 'SANDBOX_UNAVAILABLE', profile: 'linux-reference-v1' });
  }
}

export async function openLinuxReferenceSandboxCandidate(configurationSource) {
  const configuration = snapshotConfiguration(configurationSource);
  if (!configuration || process.platform !== 'linux' || process.arch !== 'x64') throw new LinuxReferenceUnavailableError();
  let adapter;
  try {
    adapter = await openAdapter(configuration.dockerBinary);
    const service = await ReferenceSandboxService.open({ adapter, ...configuration });
    return Object.freeze(service);
  } catch {
    throw new LinuxReferenceUnavailableError();
  }
}
