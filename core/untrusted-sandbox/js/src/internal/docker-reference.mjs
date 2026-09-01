import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { LINUX_RUNTIME_CONTRACT_SHA256, canonicalJson, isDigest, sha256 } from './reference-contract.mjs';

const SAFE_COMMAND_ENVIRONMENT = Object.freeze({ LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' });
const COMMAND_OUTPUT_MAXIMUM = 256 * 1024;
const CONTROL_TIMEOUT_MILLISECONDS = 10_000;
const OCI_RUNTIME = 'runc';
const ROLE_LABEL = 'org.opengamevcs.sandbox.role';
const JOB_LABEL = 'org.opengamevcs.sandbox.job';
const REQUIRED_MASKED_PATHS = Object.freeze(['/proc/acpi', '/proc/asound', '/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats', '/proc/sched_debug', '/proc/scsi', '/proc/timer_list', '/proc/timer_stats', '/sys/firmware']);
const REQUIRED_READONLY_PATHS = Object.freeze(['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger']);
const RUNTIME_IMAGE_MISMATCHES = Object.freeze([
  'config-command',
  'config-env',
  'config-health',
  'config-labels',
  'config-user-workdir',
  'config-volume',
  'identity',
  'inspect-shape',
  'platform',
  'rootfs',
  'size',
]);
const runtimeImageAdmissionDiagnostics = new WeakMap();
const adapters = new WeakSet();

const containerName = () => `ogvcs-sandbox-${randomBytes(12).toString('hex')}`;
const volumeName = () => `ogvcs-sandbox-${randomBytes(12).toString('hex')}`;
const procDescriptorPath = (handle) => `/proc/${process.pid}/fd/${handle.fd}`;

const appendBounded = (chunks, chunk, state, maximum) => {
  const copy = Buffer.from(chunk);
  state.bytes += copy.length;
  if (state.bytes > maximum) { state.overflow = true; return; }
  chunks.push(copy);
};

const execute = ({ binary, args, stdin = null, stdoutPath = null, maximumStdout = COMMAND_OUTPUT_MAXIMUM, maximumStderr = COMMAND_OUTPUT_MAXIMUM, timeoutMilliseconds = CONTROL_TIMEOUT_MILLISECONDS, signal = null }) => new Promise((resolve) => {
  let child;
  try {
    child = spawn(binary, args, { env: SAFE_COMMAND_ENVIRONMENT, shell: false, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  } catch {
    resolve(Object.freeze({ kind: 'spawn-failed' })); return;
  }
  const stdoutChunks = [];
  const stderrChunks = [];
  const stdoutState = { bytes: 0, overflow: false };
  const stderrState = { bytes: 0, overflow: false };
  let outputHandle = null;
  let outputChain = Promise.resolve();
  let settled = false;
  let timedOut = false;
  let aborted = false;
  const stop = () => { try { child.kill('SIGKILL'); } catch {} };
  const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMilliseconds);
  const abort = () => { aborted = true; stop(); };
  if (signal) {
    if (signal.aborted) abort(); else signal.addEventListener('abort', abort, { once: true });
  }
  const finish = async (code, processSignal) => {
    if (settled) return;
    settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
    try { await outputChain; } catch { stdoutState.overflow = true; }
    if (outputHandle) await outputHandle.close().catch(() => {});
    resolve(Object.freeze({
      code,
      kind: aborted ? 'aborted' : timedOut ? 'timeout' : stdoutState.overflow || stderrState.overflow ? 'overflow' : 'exit',
      signal: processSignal,
      stderr: Buffer.concat(stderrChunks),
      stdout: stdoutPath ? Buffer.alloc(0) : Buffer.concat(stdoutChunks),
      stdoutBytes: stdoutState.bytes,
    }));
  };
  if (stdoutPath) {
    outputChain = open(stdoutPath, 'wx', 0o600).then((handle) => { outputHandle = handle; });
    child.stdout.on('data', (chunk) => {
      const copy = Buffer.from(chunk);
      stdoutState.bytes += copy.length;
      if (stdoutState.bytes > maximumStdout) { stdoutState.overflow = true; stop(); return; }
      outputChain = outputChain.then(() => outputHandle.write(copy));
    });
  } else child.stdout.on('data', (chunk) => { appendBounded(stdoutChunks, chunk, stdoutState, maximumStdout); if (stdoutState.overflow) stop(); });
  child.stderr.on('data', (chunk) => { appendBounded(stderrChunks, chunk, stderrState, maximumStderr); if (stderrState.overflow) stop(); });
  child.on('error', () => finish(null, null));
  child.on('close', finish);
  if (stdin === null) child.stdin.end();
  else child.stdin.end(stdin);
});

const safeExecutable = async (source) => {
  if (typeof source !== 'string' || !isAbsolute(source) || source.length > 4096) throw new TypeError('docker binary path is invalid');
  const path = await realpath(source);
  const details = await lstat(path);
  const owner = typeof process.geteuid === 'function' ? process.geteuid() : details.uid;
  if (!details.isFile() || details.isSymbolicLink() || (details.mode & 0o111) === 0 || (details.mode & 0o022) !== 0 || ![0, owner].includes(details.uid)) throw new Error('docker binary ownership or mode is unsafe');
  return path;
};

const hardeningArguments = ({ jobId, name, policy, role, seccompPath }) => [
  '--name', name,
  '--pull=never',
  `--runtime=${OCI_RUNTIME}`,
  `--label=${JOB_LABEL}=${jobId}`,
  `--label=${ROLE_LABEL}=${role}`,
  '--network=none',
  '--read-only',
  '--cap-drop=ALL',
  '--security-opt=no-new-privileges=true',
  `--security-opt=seccomp=${seccompPath}`,
  '--cgroupns=private',
  '--ipc=none',
  '--hostname=ogvcs-worker',
  '--log-driver=none',
  `--pids-limit=${policy.processes}`,
  `--memory=${policy.memoryBytes}b`,
  `--memory-swap=${policy.memoryBytes}b`,
  '--cpus=1.0',
  `--ulimit=cpu=${policy.cpuMilliseconds / 1000}:${policy.cpuMilliseconds / 1000}`,
  `--ulimit=fsize=${policy.outputBytes}:${policy.outputBytes}`,
  '--ulimit=nofile=64:64',
  '--stop-timeout=1',
  '--restart=no',
  '--user=65532:65532',
  '--workdir=/scratch',
  `--tmpfs=/scratch:rw,nosuid,nodev,noexec,size=${policy.scratchBytes},uid=65532,gid=65532,mode=0700`,
];

const mountFile = (handle, target) => `type=bind,src=${procDescriptorPath(handle)},dst=${target},readonly,bind-propagation=rprivate,bind-recursive=disabled`;

const emptyCollection = (value) => value == null
  || (Array.isArray(value) && value.length === 0)
  || (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0);

const exactSecurityOptions = (source, seccompCanonical) => {
  if (!Array.isArray(source) || source.length !== 2 || source.filter((value) => value === 'no-new-privileges=true').length !== 1) return false;
  const encoded = source.find((value) => typeof value === 'string' && value.startsWith('seccomp='));
  if (!encoded) return false;
  try { return canonicalJson(JSON.parse(encoded.slice('seccomp='.length))) === seccompCanonical; } catch { return false; }
};

const exactUlimits = (source, policy) => {
  if (!Array.isArray(source) || source.length !== 3) return false;
  const actual = [...source].sort((left, right) => String(left?.Name).localeCompare(String(right?.Name)));
  const expected = [
    { Hard: policy.cpuMilliseconds / 1000, Name: 'cpu', Soft: policy.cpuMilliseconds / 1000 },
    { Hard: policy.outputBytes, Name: 'fsize', Soft: policy.outputBytes },
    { Hard: 64, Name: 'nofile', Soft: 64 },
  ].sort((left, right) => left.Name.localeCompare(right.Name));
  return canonicalJson(actual) === canonicalJson(expected);
};

const exactHostMounts = (source, expected) => {
  if (!Array.isArray(source) || source.length !== expected.fileMounts.length + 1) return false;
  const byTarget = new Map(source.map((mount) => [mount?.Target, mount]));
  if (byTarget.size !== source.length) return false;
  for (const file of expected.fileMounts) {
    const mount = byTarget.get(file.target);
    if (!mount || mount.Type !== 'bind' || mount.Source !== file.source || mount.ReadOnly !== true || !['', 'default'].includes(mount.Consistency ?? '') || mount.BindOptions?.Propagation !== 'rprivate' || mount.BindOptions?.NonRecursive !== true || (mount.BindOptions?.CreateMountpoint ?? false) !== false || (mount.BindOptions?.ReadOnlyNonRecursive ?? false) !== false || (mount.BindOptions?.ReadOnlyForceRecursive ?? false) !== false) return false;
  }
  const output = byTarget.get('/output');
  return output?.Type === 'volume'
    && output.Source === expected.volume
    && output.ReadOnly === expected.outputReadonly
    && ['', 'default'].includes(output.Consistency ?? '')
    && output.VolumeOptions?.NoCopy === true
    && (output.VolumeOptions?.Subpath ?? '') === ''
    && emptyCollection(output.VolumeOptions?.Labels)
    && emptyCollection(output.VolumeOptions?.DriverConfig);
};

const exactEffectiveMounts = (source, expected) => {
  if (!Array.isArray(source) || source.length !== expected.fileMounts.length + 1) return false;
  const byDestination = new Map(source.map((mount) => [mount?.Destination, mount]));
  if (byDestination.size !== source.length) return false;
  for (const file of expected.fileMounts) {
    const mount = byDestination.get(file.target);
    if (!mount || mount.Type !== 'bind' || mount.Source !== file.source || mount.RW !== false || mount.Propagation !== 'rprivate' || (mount.Mode ?? '') !== '') return false;
  }
  const output = byDestination.get('/output');
  return output?.Type === 'volume'
    && output.Name === expected.volume
    && output.Driver === 'local'
    && output.Source === expected.volumeMountpoint
    && output.RW === !expected.outputReadonly
    && (output.Mode ?? '') === ''
    && (output.Propagation ?? '') === '';
};

const containsRequiredPaths = (source, required) => Array.isArray(source)
  && source.every((value) => typeof value === 'string')
  && new Set(source).size === source.length
  && required.every((value) => source.includes(value));

export const createdContainerInspectMismatch = (container, expected) => {
  try {
    const config = container?.Config;
    const host = container?.HostConfig;
    const state = container?.State;
    const labels = config?.Labels;
    const expectedLabels = {
      [JOB_LABEL]: expected.jobId,
      [ROLE_LABEL]: expected.role,
      'org.opengamevcs.sandbox.runtime': 'linux-reference-v1',
      'org.opengamevcs.sandbox.runtime-contract-sha256': expected.runtimeContractSha256,
    };
    const tmpfs = `rw,nosuid,nodev,noexec,size=${expected.policy.scratchBytes},uid=65532,gid=65532,mode=0700`;
    const networks = container?.NetworkSettings?.Networks;
    const networkNames = networks && typeof networks === 'object' && !Array.isArray(networks) ? Object.keys(networks).sort() : null;
    const checks = [
      ['identity', container?.Id === expected.id && container?.Name === `/${expected.name}` && container?.Path === expected.entrypoint && emptyCollection(container?.Args)],
      ['state', state?.Status === 'created' && state?.Running === false && state?.Paused === false && state?.Restarting === false && state?.Pid === 0],
      ['config-image', config?.Image === expected.runtimeImage],
      ['config-process', config?.Hostname === 'ogvcs-worker' && config?.Domainname === '' && config?.User === '65532:65532' && Array.isArray(config?.Entrypoint) && config.Entrypoint.length === 1 && config.Entrypoint[0] === expected.entrypoint && config.WorkingDir === '/scratch'],
      ['config-content', emptyCollection(config?.Cmd) && emptyCollection(config?.Env) && emptyCollection(config?.Volumes) && emptyCollection(config?.ExposedPorts) && config?.Healthcheck == null],
      ['config-io', config?.OpenStdin === false && config?.StdinOnce === false && config?.Tty === false && config?.NetworkDisabled === false && config?.StopTimeout === 1],
      ['config-labels', canonicalJson(labels) === canonicalJson(expectedLabels)],
      ['host-network', host?.NetworkMode === 'none' && emptyCollection(host?.PortBindings) && emptyCollection(host?.Links) && emptyCollection(host?.Dns) && emptyCollection(host?.DnsOptions) && emptyCollection(host?.DnsSearch) && emptyCollection(host?.ExtraHosts)],
      ['host-runtime', host?.Runtime === OCI_RUNTIME],
      ['host-root', host?.ReadonlyRootfs === true && containsRequiredPaths(host?.MaskedPaths, REQUIRED_MASKED_PATHS) && containsRequiredPaths(host?.ReadonlyPaths, REQUIRED_READONLY_PATHS)],
      ['host-capabilities', canonicalJson(host?.CapDrop) === '["ALL"]' && emptyCollection(host?.CapAdd) && emptyCollection(host?.GroupAdd)],
      ['host-security', exactSecurityOptions(host?.SecurityOpt, expected.seccompCanonical) && host?.Privileged === false && host?.OomKillDisable === false && (host?.Init == null || host.Init === false)],
      // Moby represents its private PID namespace with an empty PidMode and
      // rejects the otherwise intuitive literal `private` as invalid.
      ['host-namespaces', host?.CgroupnsMode === 'private' && host?.PidMode === '' && host?.IpcMode === 'none' && (host?.UTSMode ?? '') === '' && (host?.UsernsMode ?? '') === ''],
      ['host-lifecycle', host?.AutoRemove === false && host?.PublishAllPorts === false && host?.RestartPolicy?.Name === 'no' && host?.RestartPolicy?.MaximumRetryCount === 0],
      ['host-devices', emptyCollection(host?.Binds) && emptyCollection(host?.VolumesFrom) && emptyCollection(host?.Devices) && emptyCollection(host?.DeviceCgroupRules) && emptyCollection(host?.DeviceRequests) && emptyCollection(host?.Sysctls)],
      ['host-resources', host?.Memory === expected.policy.memoryBytes && host?.MemorySwap === expected.policy.memoryBytes && (host?.MemoryReservation ?? 0) === 0 && host?.PidsLimit === expected.policy.processes && host?.NanoCpus === 1_000_000_000 && (host?.CpuPeriod ?? 0) === 0 && (host?.CpuQuota ?? 0) === 0 && (host?.CpuShares ?? 0) === 0],
      ['host-ulimits', exactUlimits(host?.Ulimits, expected.policy)],
      ['host-tmpfs', Object.keys(host?.Tmpfs ?? {}).length === 1 && host?.Tmpfs?.['/scratch'] === tmpfs],
      ['host-logging', host?.LogConfig?.Type === 'none' && emptyCollection(host?.LogConfig?.Config)],
      ['host-mounts', exactHostMounts(host?.Mounts, expected)],
      ['effective-mounts', exactEffectiveMounts(container?.Mounts, expected)],
      ['network-attachment', networkNames?.length === 0 || networkNames?.join(',') === 'none'],
    ];
    return checks.find(([, valid]) => !valid)?.[0] ?? null;
  } catch { return 'inspect-shape'; }
};

export const validateCreatedContainerInspect = (container, expected) => createdContainerInspectMismatch(container, expected) === null;

export const validateOutputVolumeInspect = (volume, name, options, jobId) => volume?.Name === name
  && volume?.Driver === 'local'
  && volume?.Scope === 'local'
  && typeof volume?.Mountpoint === 'string'
  && volume.Mountpoint.length > 0
  && canonicalJson(volume?.Labels) === canonicalJson({ [JOB_LABEL]: jobId, [ROLE_LABEL]: 'output-volume', 'org.opengamevcs.sandbox': 'reference-v1' })
  && canonicalJson(volume?.Options) === canonicalJson({ device: 'tmpfs', o: options, type: 'tmpfs' });

const runtimeImageEvent = (mismatch) => RUNTIME_IMAGE_MISMATCHES.includes(mismatch)
  ? `PRESTART_IMAGE_${mismatch.replaceAll('-', '_').toUpperCase()}`
  : null;

const runtimeImageAdmissionError = (mismatch) => {
  const diagnostic = runtimeImageEvent(mismatch);
  const error = new Error('runtime image admission failed');
  if (diagnostic !== null) runtimeImageAdmissionDiagnostics.set(error, diagnostic);
  return error;
};

export const prestartImageDiagnostic = (error) => {
  try { return runtimeImageAdmissionDiagnostics.get(error) ?? null; } catch { return null; }
};

export const isPrestartImageDiagnostic = (value) => typeof value === 'string'
  && RUNTIME_IMAGE_MISMATCHES.some((mismatch) => value === runtimeImageEvent(mismatch));

export const runtimeImageInspectMismatch = (image, runtimeImage, runtimeContractSha256) => {
  try {
    const empty = (candidate) => candidate == null || (Array.isArray(candidate) && candidate.length === 0);
    const emptyRecord = (candidate) => candidate == null || (candidate && typeof candidate === 'object' && !Array.isArray(candidate) && Object.keys(candidate).length === 0);
    if (image === null || typeof image !== 'object' || Array.isArray(image)) return 'inspect-shape';
    if (image.Id !== runtimeImage) return 'identity';
    if (image.Os !== 'linux' || image.Architecture !== 'amd64') return 'platform';
    if (image.RootFS?.Type !== 'layers' || !Array.isArray(image.RootFS?.Layers) || image.RootFS.Layers.length !== 1) return 'rootfs';
    if (!Number.isSafeInteger(image.Size) || image.Size <= 0 || image.Size > 32 * 1024 * 1024) return 'size';
    const config = image.Config;
    if (config === null || typeof config !== 'object' || Array.isArray(config)) return 'inspect-shape';
    if (!empty(config.Env)) return 'config-env';
    if (!empty(config.Cmd) || !empty(config.Entrypoint) || !emptyRecord(config.ExposedPorts)) return 'config-command';
    if (!emptyRecord(config.Volumes)) return 'config-volume';
    if (config.Healthcheck != null) return 'config-health';
    if (config.User !== '' || config.WorkingDir !== '') return 'config-user-workdir';
    const labels = config.Labels;
    if (Object.keys(labels ?? {}).sort().join(',') !== 'org.opengamevcs.sandbox.runtime,org.opengamevcs.sandbox.runtime-contract-sha256'
      || labels['org.opengamevcs.sandbox.runtime'] !== 'linux-reference-v1'
      || labels['org.opengamevcs.sandbox.runtime-contract-sha256'] !== runtimeContractSha256) return 'config-labels';
    return null;
  } catch { return 'inspect-shape'; }
};

export const validateRuntimeImageInspect = (image, runtimeImage, runtimeContractSha256) => runtimeImageInspectMismatch(image, runtimeImage, runtimeContractSha256) === null;

export class DockerReferenceAdapter {
  #binary;
  #seccompPath;
  #seccompDigest;
  #seccompCanonical;
  #poisoned = false;

  static async open({ dockerBinary, seccompProfilePath, expectedSeccompSha256 }) {
    if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('Linux reference worker requires Linux x86_64');
    const [binary, seccompPath] = await Promise.all([safeExecutable(dockerBinary), realpath(seccompProfilePath)]);
    const seccompBytes = await readFile(seccompPath);
    if (!isDigest(expectedSeccompSha256) || sha256(seccompBytes) !== expectedSeccompSha256) throw new Error('owned seccomp profile digest differs');
    let seccompCanonical;
    try { seccompCanonical = canonicalJson(JSON.parse(seccompBytes)); } catch { throw new Error('owned seccomp profile is malformed'); }
    const details = await lstat(seccompPath);
    if (!details.isFile() || details.isSymbolicLink() || (details.mode & 0o022) !== 0) throw new Error('owned seccomp profile mode is unsafe');
    const adapter = new DockerReferenceAdapter(binary, seccompPath, expectedSeccompSha256, seccompCanonical);
    await adapter.#probeHost();
    adapters.add(adapter);
    return adapter;
  }

  constructor(binary, seccompPath, seccompDigest, seccompCanonical) {
    this.#binary = binary;
    this.#seccompPath = seccompPath;
    this.#seccompDigest = seccompDigest;
    this.#seccompCanonical = seccompCanonical;
  }

  get seccompDigest() { return this.#seccompDigest; }

  async #control(args, options = {}) {
    const value = await execute({ binary: this.#binary, args, ...options });
    return value;
  }

  async #probeHost() {
    const [version, info, controllers] = await Promise.all([
      this.#control(['version', '--format', '{{json .Server}}']),
      this.#control(['info', '--format', '{{json .}}']),
      readFile('/sys/fs/cgroup/cgroup.controllers', 'utf8').catch(() => ''),
    ]);
    if (version.kind !== 'exit' || version.code !== 0 || info.kind !== 'exit' || info.code !== 0 || controllers.trim().length === 0) throw new Error('Docker or cgroup v2 reference controls are unavailable');
    let server; let details;
    try { server = JSON.parse(version.stdout.toString('utf8')); details = JSON.parse(info.stdout.toString('utf8')); } catch { throw new Error('Docker control report is malformed'); }
    const security = Array.isArray(details.SecurityOptions) ? details.SecurityOptions.join('\n') : '';
    const availableControllers = new Set(controllers.trim().split(/\s+/u));
    const runtimes = details?.Runtimes;
    if (server?.Os !== 'linux' || server?.Arch !== 'amd64' || details?.OSType !== 'linux' || String(details?.CgroupVersion) !== '2' || !['cpu', 'memory', 'pids'].every((controller) => availableControllers.has(controller)) || !security.includes('name=seccomp') || !security.includes('name=cgroupns') || security.includes('name=rootless') || runtimes === null || typeof runtimes !== 'object' || Array.isArray(runtimes) || !Object.hasOwn(runtimes, OCI_RUNTIME)) throw new Error('Docker required Linux security controls are unavailable');
  }

  async verifyRuntimeImage(runtimeImage, runtimeContractSha256) {
    const value = await this.#control(['image', 'inspect', runtimeImage]);
    if (value.kind !== 'exit' || value.code !== 0) throw new Error('runtime image admission failed');
    let images;
    try { images = JSON.parse(value.stdout.toString('utf8')); } catch { throw runtimeImageAdmissionError('inspect-shape'); }
    if (!Array.isArray(images) || images.length !== 1) throw runtimeImageAdmissionError('inspect-shape');
    const mismatch = runtimeImageInspectMismatch(images[0], runtimeImage, runtimeContractSha256);
    if (mismatch !== null) throw runtimeImageAdmissionError(mismatch);
    return true;
  }

  async #createOutputVolume(policy, jobId) {
    const name = volumeName();
    const options = `size=${policy.outputBytes},uid=65532,gid=65532,mode=0700,nosuid,nodev,noexec`;
    const value = await this.#control(['volume', 'create', '--driver=local', '--opt=type=tmpfs', '--opt=device=tmpfs', `--opt=o=${options}`, '--label=org.opengamevcs.sandbox=reference-v1', `--label=${JOB_LABEL}=${jobId}`, `--label=${ROLE_LABEL}=output-volume`, name]);
    if (value.kind !== 'exit') {
      await this.#cleanupVolume(name).catch(() => false);
      this.#poisoned = true;
      throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    }
    if (value.code !== 0 || value.stdout.toString('utf8').trim() !== name) {
      if (!await this.#cleanupVolume(name)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      throw new Error('bounded output volume is unavailable');
    }
    const inspected = await this.#control(['volume', 'inspect', name]);
    let volumes;
    try { volumes = inspected.kind === 'exit' && inspected.code === 0 ? JSON.parse(inspected.stdout.toString('utf8')) : null; } catch { volumes = null; }
    if (!Array.isArray(volumes) || volumes.length !== 1 || !validateOutputVolumeInspect(volumes[0], name, options, jobId)) {
      if (!await this.#cleanupVolume(name)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      throw new Error('SANDBOX_INSPECT_MISMATCH:output-volume');
    }
    return Object.freeze({ mountpoint: volumes[0].Mountpoint, name });
  }

  async #createContainer(name, argumentsAfterCreate, expected) {
    const created = await this.#control(['create', ...argumentsAfterCreate]);
    if (created.kind !== 'exit') {
      await this.#cleanupContainer(name, name).catch(() => false);
      this.#poisoned = true;
      throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    }
    if (created.code !== 0) {
      if (!await this.#cleanupContainer(name, name)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      return null;
    }
    const id = created.stdout.toString('utf8').trim();
    if (!/^[0-9a-f]{64}$/u.test(id)) {
      await this.#cleanupContainer(name, name).catch(() => false);
      this.#poisoned = true;
      throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    }
    const inspected = await this.#control(['container', 'inspect', id]);
    let containers;
    try { containers = inspected.kind === 'exit' && inspected.code === 0 ? JSON.parse(inspected.stdout.toString('utf8')) : null; } catch { containers = null; }
    const inspectUncertain = inspected.kind !== 'exit' || inspected.code !== 0;
    const mismatch = Array.isArray(containers) && containers.length === 1
      ? createdContainerInspectMismatch(containers[0], { ...expected, id, name, seccompCanonical: this.#seccompCanonical })
      : 'inspect-response';
    if (mismatch !== null) {
      const removed = await this.#cleanupContainer(id, name).catch(() => false);
      if (!removed || inspectUncertain) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      throw new Error(`SANDBOX_INSPECT_MISMATCH:${mismatch}`);
    }
    return id;
  }

  async #cleanupContainer(id, name) {
    await this.#control(['kill', id], { timeoutMilliseconds: 2_000 }).catch(() => null);
    await this.#control(['rm', '--force', '--volumes', id], { timeoutMilliseconds: 5_000 }).catch(() => null);
    const [byId, byName] = await Promise.all([
      this.#control(['container', 'inspect', id], { timeoutMilliseconds: 2_000 }),
      this.#control(['container', 'inspect', name], { timeoutMilliseconds: 2_000 }),
    ]);
    return byId.kind === 'exit' && byId.code !== 0 && byName.kind === 'exit' && byName.code !== 0;
  }

  async #cleanupVolume(name) {
    await this.#control(['volume', 'rm', '--force', name], { timeoutMilliseconds: 5_000 }).catch(() => null);
    const inspect = await this.#control(['volume', 'inspect', name], { timeoutMilliseconds: 2_000 });
    return inspect.kind === 'exit' && inspect.code !== 0;
  }

  async #settle(id, name, volume) {
    const containerGone = await this.#cleanupContainer(id, name);
    const volumeGone = containerGone && await this.#cleanupVolume(volume.name);
    if (!containerGone || !volumeGone) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
  }

  async runTool({ runtimeImage, policy, inputHandle, jobHandle, jobId, toolHandle, signal }) {
    if (this.#poisoned) throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    const volume = await this.#createOutputVolume(policy, jobId);
    const name = containerName();
    const fileMounts = [
      { source: procDescriptorPath(inputHandle), target: '/input/payload' },
      { source: procDescriptorPath(jobHandle), target: '/input/job' },
      { source: procDescriptorPath(toolHandle), target: '/tool/program' },
    ];
    const args = [
      ...hardeningArguments({ jobId, name, policy, role: 'parser', seccompPath: this.#seccompPath }),
      '--mount', mountFile(inputHandle, '/input/payload'),
      '--mount', mountFile(jobHandle, '/input/job'),
      '--mount', mountFile(toolHandle, '/tool/program'),
      '--mount', `type=volume,src=${volume.name},dst=/output,volume-nocopy`,
      '--entrypoint=/tool/program',
      runtimeImage,
    ];
    let id;
    try {
      id = await this.#createContainer(name, args, { entrypoint: '/tool/program', fileMounts, jobId, outputReadonly: false, policy, role: 'parser', runtimeContractSha256: LINUX_RUNTIME_CONTRACT_SHA256, runtimeImage, volume: volume.name, volumeMountpoint: volume.mountpoint });
    } catch (error) {
      if (!await this.#cleanupVolume(volume.name).catch(() => false)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      throw error;
    }
    if (!id) {
      if (!await this.#cleanupVolume(volume.name)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      return Object.freeze({ kind: 'unavailable', volume: null });
    }
    const deadline = Math.min(policy.elapsedMilliseconds, 60_000);
    const value = await execute({ binary: this.#binary, args: ['start', '--attach', id], maximumStdout: 64 * 1024, maximumStderr: 64 * 1024, timeoutMilliseconds: deadline, signal });
    const containerGone = await this.#cleanupContainer(id, name);
    if (!containerGone) { await this.#cleanupVolume(volume.name); this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
    const kind = value.kind === 'timeout' ? 'timeout' : value.kind === 'aborted' ? 'cancelled' : value.kind === 'overflow' ? 'output-limit' : value.kind === 'exit' && [137, 152].includes(value.code) ? 'resource-limit' : value.kind !== 'exit' || value.code !== 0 || value.stdoutBytes !== 0 || value.stderr.length !== 0 ? 'failed' : 'success';
    return Object.freeze({ kind, volume });
  }

  async collectOutput({ runtimeImage, policy, volume, bindingHandle, framePath, jobId, maximumFrameBytes }) {
    if (this.#poisoned) throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    const name = containerName();
    const fileMounts = [{ source: procDescriptorPath(bindingHandle), target: '/input/binding' }];
    const args = [
      ...hardeningArguments({ jobId, name, policy, role: 'output-shim', seccompPath: this.#seccompPath }),
      '--mount', mountFile(bindingHandle, '/input/binding'),
      '--mount', `type=volume,src=${volume.name},dst=/output,readonly,volume-nocopy`,
      '--entrypoint=/ogvcs-output-shim',
      runtimeImage,
    ];
    let id;
    try {
      id = await this.#createContainer(name, args, { entrypoint: '/ogvcs-output-shim', fileMounts, jobId, outputReadonly: true, policy, role: 'output-shim', runtimeContractSha256: LINUX_RUNTIME_CONTRACT_SHA256, runtimeImage, volume: volume.name, volumeMountpoint: volume.mountpoint });
    } catch (error) {
      if (!await this.#cleanupVolume(volume.name).catch(() => false)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      throw error;
    }
    if (!id) {
      if (!await this.#cleanupVolume(volume.name)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      return Object.freeze({ kind: 'failed', frameBytes: 0 });
    }
    const value = await execute({ binary: this.#binary, args: ['start', '--attach', id], stdoutPath: framePath, maximumStdout: maximumFrameBytes, maximumStderr: 64 * 1024, timeoutMilliseconds: Math.min(policy.elapsedMilliseconds, 60_000) });
    await this.#settle(id, name, volume);
    return Object.freeze({ kind: value.kind === 'overflow' ? 'output-limit' : value.kind !== 'exit' || value.code !== 0 || value.stderr.length !== 0 ? 'failed' : 'success', frameBytes: value.stdoutBytes });
  }

  async discardVolume(volume) {
    if (!await this.#cleanupVolume(volume.name)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
  }
}

export const isDockerReferenceAdapter = (value) => adapters.has(value);

export const executeDockerForTesting = execute;
