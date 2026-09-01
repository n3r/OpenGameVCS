import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fstatSync } from 'node:fs';
import { lstat, open, readFile, readlink, realpath } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { types } from 'node:util';
import { LINUX_RUNTIME_CONTRACT_SHA256, canonicalJson, isDigest, sha256 } from './reference-contract.mjs';
import { validateStatePinnedAliasForAdapter } from './reference-state.mjs';

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
const adapterTestExecutors = new WeakMap();
const adapterTestFaults = new WeakMap();
const anchoredOutputVolumes = new WeakMap();
const settledOutputVolumes = new WeakMap();

const containerName = () => `ogvcs-sandbox-${randomBytes(12).toString('hex')}`;
const volumeName = () => `ogvcs-sandbox-${randomBytes(12).toString('hex')}`;

const statePinnedFileSource = async (handle, { executable = false } = {}) => {
  try {
    if (handle === null || typeof handle !== 'object' || types.isProxy(handle)) throw new TypeError('invalid handle');
    const descriptor = handle.fd;
    if (!Number.isSafeInteger(descriptor) || descriptor < 0) throw new TypeError('invalid descriptor');
    const heldDetails = fstatSync(descriptor, { bigint: true });
    const descriptorPath = `/proc/self/fd/${descriptor}`;
    const path = await readlink(descriptorPath);
    if (!isAbsolute(path)
      || path.length > 4096
      || path.endsWith(' (deleted)')
      || /^\/(?:dev|proc|sys)(?:\/|$)/u.test(path)
      || /[,\0\r\n]/u.test(path)
      || await realpath(path) !== path) throw new TypeError('invalid alias path');
    const pathDetails = await lstat(path, { bigint: true });
    const owner = typeof process.geteuid === 'function' ? BigInt(process.geteuid()) : pathDetails.uid;
    if (!heldDetails.isFile()
      || !pathDetails.isFile()
      || pathDetails.isSymbolicLink()
      || (pathDetails.mode & 0o777n) !== (executable ? 0o555n : 0o444n)
      || (pathDetails.uid !== 0n && pathDetails.uid !== owner)
      || !validateStatePinnedAliasForAdapter(handle, path, heldDetails, pathDetails, { executable })) throw new TypeError('invalid alias identity');
    return Object.freeze({ executable, handle, source: path });
  } catch { throw new Error('held mount source is not a state-pinned immutable alias'); }
};

const revalidateStatePinnedFileSources = async (sources) => {
  for (const expected of sources) {
    const current = await statePinnedFileSource(expected.handle, { executable: expected.executable });
    if (current.source !== expected.source) throw new Error('held mount alias identity changed');
  }
};

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

const mountFile = (source, target) => `type=bind,src=${source},dst=${target},readonly,bind-propagation=rprivate,bind-recursive=writable`;

const WORKER_EXECUTE_RESULT_KEYS = Object.freeze(['code', 'kind', 'signal', 'stderr', 'stdout', 'stdoutBytes']);

const exactWorkerExecuteResult = (source) => {
  try {
    if (source === null || typeof source !== 'object' || types.isProxy(source) || !Object.isFrozen(source) || Object.getPrototypeOf(source) !== Object.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(source);
    if (Reflect.ownKeys(source).sort().join('\0') !== WORKER_EXECUTE_RESULT_KEYS.join('\0')
      || Object.values(descriptors).some((descriptor) => !descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || Object.hasOwn(descriptor, 'get') || Object.hasOwn(descriptor, 'set'))) return null;
    const value = Object.fromEntries(WORKER_EXECUTE_RESULT_KEYS.map((key) => [key, descriptors[key].value]));
    if (value.kind !== 'exit'
      || value.signal !== null
      || !Number.isSafeInteger(value.code)
      || value.code < 0
      || value.code > 255
      || !Number.isSafeInteger(value.stdoutBytes)
      || value.stdoutBytes < 0
      || value.stdoutBytes > 64 * 1024
      || !Buffer.isBuffer(value.stdout)
      || Object.getPrototypeOf(value.stdout) !== Buffer.prototype
      || value.stdout.length !== value.stdoutBytes
      || !Buffer.isBuffer(value.stderr)
      || Object.getPrototypeOf(value.stderr) !== Buffer.prototype
      || value.stderr.length > 64 * 1024) return null;
    return value;
  } catch { return null; }
};

const workerFailureClass = (source) => {
  try {
    const value = exactWorkerExecuteResult(source);
    if (!value) return 'CONTROL';
    const stderrBytes = value.stderr.length;
    if (value.code === 63 && value.stdoutBytes === 0 && stderrBytes === 0) return 'INPUT_READ';
    if (value.code === 64 && value.stdoutBytes === 0 && stderrBytes === 0) return 'OUTPUT_WRITE';
    if ([126, 127].includes(value.code)) return 'ENTRYPOINT';
    if (value.code !== 0) return 'NONZERO';
    if (value.stdoutBytes > 0 && stderrBytes === 0) return 'STDOUT';
    if (stderrBytes > 0 && value.stdoutBytes === 0) return 'STDERR';
    return 'CONTROL';
  } catch { return 'CONTROL'; }
};

const detachedStartResultMatches = (source, expectedId) => {
  try {
    return typeof expectedId === 'string'
      && /^[0-9a-f]{64}$/u.test(expectedId)
      && source?.kind === 'exit'
      && source.code === 0
      && source.signal === null
      && Buffer.isBuffer(source.stderr)
      && source.stderr.length === 0
      && Buffer.isBuffer(source.stdout)
      && source.stdoutBytes === expectedId.length + 1
      && source.stdout.equals(Buffer.from(`${expectedId}\n`, 'ascii'));
  } catch { return false; }
};

const POST_NONZERO_CONTROL = Object.freeze({ failureClass: 'CONTROL', kind: 'failed', poison: true });
const POST_NONZERO_ACTIVATION_CONTROL = Object.freeze({ failureClass: 'ACTIVATION_CONTROL', kind: 'failed', poison: false });
const POST_NONZERO_TOOL_EXITED = Object.freeze({ failureClass: 'TOOL_EXITED', kind: 'failed', poison: false });
const POST_NONZERO_RESOURCE_LIMIT = Object.freeze({ failureClass: null, kind: 'resource-limit', poison: false });

const postNonzeroFailureDisposition = (startSource, inspectSource, expectedId, expectedName) => {
  try {
    const start = exactWorkerExecuteResult(startSource);
    const inspected = exactWorkerExecuteResult(inspectSource);
    if (!start
      || workerFailureClass(startSource) !== 'NONZERO'
      || !inspected
      || inspected.code !== 0
      || inspected.stderr.length !== 0
      || inspected.stdoutBytes === 0
      || typeof expectedId !== 'string'
      || !/^[0-9a-f]{64}$/u.test(expectedId)
      || typeof expectedName !== 'string'
      || !/^ogvcs-sandbox-[0-9a-f]{24}$/u.test(expectedName)) return POST_NONZERO_CONTROL;
    let containers;
    try { containers = JSON.parse(inspected.stdout.toString('utf8')); } catch { return POST_NONZERO_CONTROL; }
    if (!Array.isArray(containers) || containers.length !== 1) return POST_NONZERO_CONTROL;
    const container = containers[0];
    if (container === null
      || typeof container !== 'object'
      || Array.isArray(container)
      || container.Id !== expectedId
      || container.Name !== `/${expectedName}`) return POST_NONZERO_CONTROL;
    const state = container.State;
    if (state === null
      || typeof state !== 'object'
      || Array.isArray(state)
      || !['created', 'exited'].includes(state.Status)
      || !Number.isSafeInteger(state.ExitCode)
      || state.ExitCode < 0
      || state.ExitCode > 255
      || typeof state.OOMKilled !== 'boolean'
      || typeof state.Error !== 'string'
      || state.Running !== false
      || state.Paused !== false
      || state.Restarting !== false
      || state.Dead !== false
      || state.Pid !== 0) return POST_NONZERO_CONTROL;
    const stateErrorPresent = state.Error.length !== 0;
    const stdoutPresent = start.stdoutBytes !== 0;
    const stderrPresent = start.stderr.length !== 0;
    if (state.Status === 'created') return start.code === 1
      && !stdoutPresent
      && stderrPresent
      && state.ExitCode !== 0
      && !state.OOMKilled
      && stateErrorPresent ? POST_NONZERO_ACTIVATION_CONTROL : POST_NONZERO_CONTROL;
    if (state.ExitCode !== start.code || stateErrorPresent || stdoutPresent || stderrPresent) return POST_NONZERO_CONTROL;
    if (state.OOMKilled && start.code !== 137) return POST_NONZERO_CONTROL;
    if (state.OOMKilled || [137, 152].includes(start.code)) return POST_NONZERO_RESOURCE_LIMIT;
    return POST_NONZERO_TOOL_EXITED;
  } catch { return POST_NONZERO_CONTROL; }
};

const emptyCollection = (value) => value == null
  || (Array.isArray(value) && value.length === 0)
  || (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0);

const securityOptionsMismatch = (source, seccompCanonical, appArmorProfile) => {
  if (!Array.isArray(source) || ![2, 3].includes(source.length) || new Set(source).size !== source.length) return 'host-security-options-shape';
  if (source.filter((value) => value === 'no-new-privileges=true').length !== 1) return 'host-security-nnp';
  const seccomp = source.filter((value) => typeof value === 'string' && value.startsWith('seccomp='));
  if (seccomp.length !== 1) return 'host-security-seccomp';
  try {
    if (canonicalJson(JSON.parse(seccomp[0].slice('seccomp='.length))) !== seccompCanonical) return 'host-security-seccomp';
  } catch { return 'host-security-seccomp'; }
  const appArmor = source.filter((value) => typeof value === 'string' && value.startsWith('apparmor='));
  if (appArmor.length > 1
    || source.some((value) => value !== 'no-new-privileges=true' && value !== seccomp[0] && value !== appArmor[0])) return 'host-security-options-shape';
  if ((appArmor.length === 1 && appArmor[0] !== 'apparmor=docker-default')
    || ![undefined, '', 'docker-default'].includes(appArmorProfile)
    || (appArmor.length === 1 && appArmorProfile !== 'docker-default')) return 'host-security-apparmor';
  return null;
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

const omittedOrFalse = (source, field) => !Object.hasOwn(source, field) || source[field] === false;

const exactHostMounts = (source, expected) => {
  if (!Array.isArray(source) || source.length !== expected.fileMounts.length + 1) return false;
  const byTarget = new Map(source.map((mount) => [mount?.Target, mount]));
  if (byTarget.size !== source.length) return false;
  for (const file of expected.fileMounts) {
    const mount = byTarget.get(file.target);
    if (!mount || mount.Type !== 'bind' || mount.Source !== file.source || mount.ReadOnly !== true || !['', 'default'].includes(mount.Consistency ?? '') || mount.BindOptions?.Propagation !== 'rprivate' || !omittedOrFalse(mount.BindOptions, 'NonRecursive') || !omittedOrFalse(mount.BindOptions, 'CreateMountpoint') || mount.BindOptions?.ReadOnlyNonRecursive !== true || !omittedOrFalse(mount.BindOptions, 'ReadOnlyForceRecursive')) return false;
  }
  const output = byTarget.get('/output');
  const outputReadOnly = expected.outputReadonly
    ? output?.ReadOnly === true
    : output != null && (!Object.hasOwn(output, 'ReadOnly') || output.ReadOnly === false);
  return output?.Type === 'volume'
    && output.Source === expected.volume
    && outputReadOnly
    && ['', 'default'].includes(output.Consistency ?? '')
    && output.VolumeOptions?.NoCopy === true
    && (output.VolumeOptions?.Subpath ?? '') === ''
    && emptyCollection(output.VolumeOptions?.Labels)
    && emptyCollection(output.VolumeOptions?.DriverConfig);
};

const omittedOrEmptyReportedMountField = (mount, field) => !Object.hasOwn(mount, field) || mount[field] === '';

const exactReportedMountMode = (mount, currentMode) => mount.Mode === currentMode
  || omittedOrEmptyReportedMountField(mount, 'Mode');

const exactEffectiveMounts = (source, expected) => {
  if (!Array.isArray(source) || source.length !== expected.fileMounts.length + 1) return false;
  const byDestination = new Map(source.map((mount) => [mount?.Destination, mount]));
  if (byDestination.size !== source.length) return false;
  for (const file of expected.fileMounts) {
    const mount = byDestination.get(file.target);
    if (!mount
      || mount.Type !== 'bind'
      || mount.Source !== file.source
      || mount.RW !== false
      || mount.Propagation !== 'rprivate'
      || !exactReportedMountMode(mount, 'ro')
      || !omittedOrEmptyReportedMountField(mount, 'Name')
      || !omittedOrEmptyReportedMountField(mount, 'Driver')) return false;
  }
  const output = byDestination.get('/output');
  return output?.Type === 'volume'
    && output.Name === expected.volume
    && output.Driver === 'local'
    && output.Source === expected.volumeMountpoint
    && output.RW === !expected.outputReadonly
    && exactReportedMountMode(output, 'z')
    && omittedOrEmptyReportedMountField(output, 'Propagation');
};

const containsRequiredPaths = (source, required) => Array.isArray(source)
  && source.every((value) => typeof value === 'string')
  && new Set(source).size === source.length
  && required.every((value) => source.includes(value));

const containerInspectMismatch = (container, expected, expectedState) => {
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
    const securityMismatch = securityOptionsMismatch(host?.SecurityOpt, expected.seccompCanonical, container?.AppArmorProfile);
    const stateMatches = expectedState === 'running'
      ? state?.Status === 'running'
        && state?.Running === true
        && state?.Paused === false
        && state?.Restarting === false
        && state?.Dead === false
        && state?.OOMKilled === false
        && state?.Error === ''
        && state?.ExitCode === 0
        && Number.isSafeInteger(state?.Pid)
        && state.Pid > 0
      : expectedState === 'created'
        && state?.Status === 'created'
        && state?.Running === false
        && state?.Paused === false
        && state?.Restarting === false
        && state?.Pid === 0;
    const checks = [
      ['identity', container?.Id === expected.id && container?.Name === `/${expected.name}` && container?.Path === expected.entrypoint && emptyCollection(container?.Args)],
      ['state', stateMatches],
      ['config-image', config?.Image === expected.runtimeImage],
      ['config-process', config?.Hostname === 'ogvcs-worker' && config?.Domainname === '' && config?.User === '65532:65532' && Array.isArray(config?.Entrypoint) && config.Entrypoint.length === 1 && config.Entrypoint[0] === expected.entrypoint && config.WorkingDir === '/scratch'],
      ['config-content', emptyCollection(config?.Cmd) && emptyCollection(config?.Env) && emptyCollection(config?.Volumes) && emptyCollection(config?.ExposedPorts) && config?.Healthcheck == null],
      // NetworkDisabled is a deprecated omitempty field. Current Moby omits
      // its false value; older inspect projections can still return false.
      ['config-io', config?.OpenStdin === false && config?.StdinOnce === false && config?.Tty === false && (!Object.hasOwn(config, 'NetworkDisabled') || config.NetworkDisabled === false) && config?.StopTimeout === 1],
      ['config-labels', canonicalJson(labels) === canonicalJson(expectedLabels)],
      ['host-network', host?.NetworkMode === 'none' && emptyCollection(host?.PortBindings) && emptyCollection(host?.Links) && emptyCollection(host?.Dns) && emptyCollection(host?.DnsOptions) && emptyCollection(host?.DnsSearch) && emptyCollection(host?.ExtraHosts)],
      ['host-runtime', host?.Runtime === OCI_RUNTIME],
      ['host-root', host?.ReadonlyRootfs === true && containsRequiredPaths(host?.MaskedPaths, REQUIRED_MASKED_PATHS) && containsRequiredPaths(host?.ReadonlyPaths, REQUIRED_READONLY_PATHS)],
      ['host-capabilities', canonicalJson(host?.CapDrop) === '["ALL"]' && emptyCollection(host?.CapAdd) && emptyCollection(host?.GroupAdd)],
      [securityMismatch ?? 'host-security', securityMismatch === null],
      ['host-security-privileged', host?.Privileged === false],
      ['host-security-oom', host?.OomKillDisable === false],
      ['host-security-init', host?.Init == null || host.Init === false],
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

export const createdContainerInspectMismatch = (container, expected) => containerInspectMismatch(container, expected, 'created');
export const validateCreatedContainerInspect = (container, expected) => createdContainerInspectMismatch(container, expected) === null;
export const runningContainerInspectMismatch = (container, expected) => containerInspectMismatch(container, expected, 'running');
export const validateRunningContainerInspect = (container, expected) => runningContainerInspectMismatch(container, expected) === null;

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
    const testExecutor = adapterTestExecutors.get(this);
    const value = testExecutor
      ? await testExecutor(Object.freeze([...args]), Object.freeze({ ...options }))
      : await execute({ binary: this.#binary, args, ...options });
    return value;
  }

  #testFault(name) {
    const faults = adapterTestFaults.get(this);
    if (faults?.has(name)) { faults.delete(name); throw new Error(`TEST_FAULT:${name}`); }
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

  async #createVolumeAnchor(volume, runtimeImage, policy, jobId) {
    let id = null;
    let name = null;
    let transferred = false;
    try {
      this.#testFault('before-anchor-create');
      name = containerName();
      const expected = {
        entrypoint: '/ogvcs-volume-anchor',
        fileMounts: [],
        jobId,
        outputReadonly: true,
        policy,
        role: 'volume-anchor',
        runtimeContractSha256: LINUX_RUNTIME_CONTRACT_SHA256,
        runtimeImage,
        volume: volume.name,
        volumeMountpoint: volume.mountpoint,
      };
      const args = [
        ...hardeningArguments({ jobId, name, policy, role: 'volume-anchor', seccompPath: this.#seccompPath }),
        '--mount', `type=volume,src=${volume.name},dst=/output,readonly,volume-nocopy`,
        '--entrypoint=/ogvcs-volume-anchor',
        runtimeImage,
      ];
      id = await this.#createContainer(name, args, expected);
      if (!id) {
        if (!await this.#cleanupVolume(volume.name)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
        return null;
      }
      const started = await this.#control(['start', id], { timeoutMilliseconds: 5_000 });
      const startValid = detachedStartResultMatches(started, id);
      let mismatch = 'anchor-running';
      if (startValid) {
        const inspected = await this.#control(['container', 'inspect', id], { timeoutMilliseconds: 2_000 });
        let containers;
        try { containers = inspected.kind === 'exit' && inspected.code === 0 ? JSON.parse(inspected.stdout.toString('utf8')) : null; } catch { containers = null; }
        mismatch = Array.isArray(containers) && containers.length === 1
          ? runningContainerInspectMismatch(containers[0], { ...expected, id, name, seccompCanonical: this.#seccompCanonical })
          : 'anchor-running';
      }
      if (!startValid || mismatch !== null) {
        const anchorGone = await this.#cleanupContainer(id, name).catch(() => false);
        const volumeGone = await this.#cleanupVolume(volume.name).catch(() => false);
        if (!anchorGone || !volumeGone) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
        if (startValid) throw new Error(`SANDBOX_INSPECT_MISMATCH:${mismatch}`);
        return null;
      }
      anchoredOutputVolumes.set(volume, Object.freeze({ adapter: this, expected: Object.freeze({ ...expected, id, name, seccompCanonical: this.#seccompCanonical }), id, name }));
      transferred = true;
      return volume;
    } catch (error) {
      if (!transferred) {
        const anchorGone = name === null ? true : await this.#cleanupContainer(id ?? name, name).catch(() => false);
        const volumeGone = await this.#cleanupVolume(volume.name).catch(() => false);
        if (!anchorGone || !volumeGone) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      }
      throw error;
    }
  }

  async #volumeAnchorMismatch(volume) {
    const anchor = anchoredOutputVolumes.get(volume);
    if (anchor?.adapter !== this) return 'anchor-running';
    let inspected;
    try { inspected = await this.#control(['container', 'inspect', anchor.id], { timeoutMilliseconds: 2_000 }); } catch { return 'inspect-response'; }
    let containers;
    try { containers = inspected.kind === 'exit' && inspected.code === 0 ? JSON.parse(inspected.stdout.toString('utf8')) : null; } catch { containers = null; }
    return Array.isArray(containers) && containers.length === 1
      ? runningContainerInspectMismatch(containers[0], anchor.expected)
      : 'inspect-response';
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

  async #cleanupAnchoredOutputVolume(volume) {
    if (settledOutputVolumes.get(volume) === this) return true;
    const anchor = anchoredOutputVolumes.get(volume);
    if (anchor?.adapter !== this) return false;
    const anchorGone = await this.#cleanupContainer(anchor.id, anchor.name).catch(() => false);
    const volumeGone = await this.#cleanupVolume(volume.name).catch(() => false);
    if (anchorGone && volumeGone) {
      anchoredOutputVolumes.delete(volume);
      settledOutputVolumes.set(volume, this);
    }
    return anchorGone && volumeGone;
  }

  async #settle(id, name, volume) {
    const containerGone = await this.#cleanupContainer(id, name).catch(() => false);
    const volumeGone = await this.#cleanupAnchoredOutputVolume(volume);
    if (!containerGone || !volumeGone) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
  }

  async runTool({ runtimeImage, policy, inputHandle, jobHandle, jobId, toolHandle, signal }) {
    if (this.#poisoned) throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    const pinnedSources = await Promise.all([
      statePinnedFileSource(inputHandle),
      statePinnedFileSource(jobHandle),
      statePinnedFileSource(toolHandle, { executable: true }),
    ]);
    const [inputSource, jobSource, toolSource] = pinnedSources.map((value) => value.source);
    const allocatedVolume = await this.#createOutputVolume(policy, jobId);
    const volume = await this.#createVolumeAnchor(allocatedVolume, runtimeImage, policy, jobId);
    if (!volume) return Object.freeze({ kind: 'unavailable', volume: null });
    let id = null;
    let name = null;
    try {
      this.#testFault('before-parser-create');
      name = containerName();
      const fileMounts = [
        { source: inputSource, target: '/input/payload' },
        { source: jobSource, target: '/input/job' },
        { source: toolSource, target: '/tool/program' },
      ];
      const args = [
        ...hardeningArguments({ jobId, name, policy, role: 'parser', seccompPath: this.#seccompPath }),
        '--mount', mountFile(inputSource, '/input/payload'),
        '--mount', mountFile(jobSource, '/input/job'),
        '--mount', mountFile(toolSource, '/tool/program'),
        '--mount', `type=volume,src=${volume.name},dst=/output,volume-nocopy`,
        '--entrypoint=/tool/program',
        runtimeImage,
      ];
      id = await this.#createContainer(name, args, { entrypoint: '/tool/program', fileMounts, jobId, outputReadonly: false, policy, role: 'parser', runtimeContractSha256: LINUX_RUNTIME_CONTRACT_SHA256, runtimeImage, volume: volume.name, volumeMountpoint: volume.mountpoint });
      if (!id) {
        const [volumeGone, aliasesValid] = await Promise.all([
          this.#cleanupAnchoredOutputVolume(volume),
          revalidateStatePinnedFileSources(pinnedSources).then(() => true, () => false),
        ]);
        if (!volumeGone || !aliasesValid) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
        return Object.freeze({ kind: 'unavailable', volume: null });
      }
      try {
        await revalidateStatePinnedFileSources(pinnedSources);
      } catch {
        await this.#settle(id, name, volume).catch(() => null);
        this.#poisoned = true;
        throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
      }
      const deadline = Math.min(policy.elapsedMilliseconds, 60_000);
      const value = await this.#control(['start', '--attach', id], { maximumStdout: 64 * 1024, maximumStderr: 64 * 1024, timeoutMilliseconds: deadline, signal });
      let failureClass = workerFailureClass(value);
      let postNonzeroKind = null;
      if (failureClass === 'NONZERO') {
        const inspected = await this.#control(['container', 'inspect', id], { maximumStderr: 64 * 1024, maximumStdout: 64 * 1024, timeoutMilliseconds: 2_000 });
        const disposition = postNonzeroFailureDisposition(value, inspected, id, name);
        failureClass = disposition.failureClass;
        postNonzeroKind = disposition.kind;
        if (disposition.poison) this.#poisoned = true;
      }
      const containerGone = await this.#cleanupContainer(id, name);
      const aliasesValid = await revalidateStatePinnedFileSources(pinnedSources).then(() => true, () => false);
      if (!containerGone || !aliasesValid) { await this.#cleanupAnchoredOutputVolume(volume); this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      const anchorMismatch = await this.#volumeAnchorMismatch(volume);
      if (anchorMismatch !== null) {
        if (!await this.#cleanupAnchoredOutputVolume(volume)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
        throw new Error(`SANDBOX_INSPECT_MISMATCH:${anchorMismatch}`);
      }
      const kind = postNonzeroKind ?? (value.kind === 'timeout' ? 'timeout' : value.kind === 'aborted' ? 'cancelled' : value.kind === 'overflow' ? 'output-limit' : value.kind !== 'exit' || value.code !== 0 || value.stdoutBytes !== 0 || value.stderr.length !== 0 ? 'failed' : 'success');
      return Object.freeze(kind === 'failed' ? { failureClass, kind, volume } : { kind, volume });
    } catch (error) {
      const containerGone = name === null ? true : await this.#cleanupContainer(id ?? name, name).catch(() => false);
      const [volumeGone, aliasesValid] = await Promise.all([
        this.#cleanupAnchoredOutputVolume(volume).catch(() => false),
        revalidateStatePinnedFileSources(pinnedSources).then(() => true, () => false),
      ]);
      if (!containerGone || !volumeGone || !aliasesValid) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      throw error;
    }
  }

  async collectOutput({ runtimeImage, policy, volume, bindingHandle, framePath, jobId, maximumFrameBytes }) {
    if (this.#poisoned) throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    if (anchoredOutputVolumes.get(volume)?.adapter !== this) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
    let id = null;
    let name = null;
    let pinnedSource = null;
    try {
      const anchorMismatch = await this.#volumeAnchorMismatch(volume);
      if (anchorMismatch !== null) {
        if (!await this.#cleanupAnchoredOutputVolume(volume)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
        throw new Error(`SANDBOX_INSPECT_MISMATCH:${anchorMismatch}`);
      }
      pinnedSource = await statePinnedFileSource(bindingHandle);
      const bindingSource = pinnedSource.source;
      this.#testFault('before-collector-create');
      name = containerName();
      const fileMounts = [{ source: bindingSource, target: '/input/binding' }];
      const args = [
        ...hardeningArguments({ jobId, name, policy, role: 'output-shim', seccompPath: this.#seccompPath }),
        '--mount', mountFile(bindingSource, '/input/binding'),
        '--mount', `type=volume,src=${volume.name},dst=/output,readonly,volume-nocopy`,
        '--entrypoint=/ogvcs-output-shim',
        runtimeImage,
      ];
      id = await this.#createContainer(name, args, { entrypoint: '/ogvcs-output-shim', fileMounts, jobId, outputReadonly: true, policy, role: 'output-shim', runtimeContractSha256: LINUX_RUNTIME_CONTRACT_SHA256, runtimeImage, volume: volume.name, volumeMountpoint: volume.mountpoint });
      if (!id) {
        const [volumeGone, aliasValid] = await Promise.all([
          this.#cleanupAnchoredOutputVolume(volume),
          revalidateStatePinnedFileSources([pinnedSource]).then(() => true, () => false),
        ]);
        if (!volumeGone || !aliasValid) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
        return Object.freeze({ kind: 'failed', frameBytes: 0 });
      }
      try {
        await revalidateStatePinnedFileSources([pinnedSource]);
      } catch {
        await this.#settle(id, name, volume).catch(() => null);
        this.#poisoned = true;
        throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
      }
      const value = await this.#control(['start', '--attach', id], { stdoutPath: framePath, maximumStdout: maximumFrameBytes, maximumStderr: 64 * 1024, timeoutMilliseconds: Math.min(policy.elapsedMilliseconds, 60_000) });
      await this.#settle(id, name, volume);
      try { await revalidateStatePinnedFileSources([pinnedSource]); } catch { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      return Object.freeze({ kind: value.kind === 'overflow' ? 'output-limit' : value.kind !== 'exit' || value.code !== 0 || value.stderr.length !== 0 ? 'failed' : 'success', frameBytes: value.stdoutBytes });
    } catch (error) {
      const containerGone = name === null ? true : await this.#cleanupContainer(id ?? name, name).catch(() => false);
      const [volumeGone, aliasValid] = await Promise.all([
        this.#cleanupAnchoredOutputVolume(volume).catch(() => false),
        pinnedSource === null ? true : revalidateStatePinnedFileSources([pinnedSource]).then(() => true, () => false),
      ]);
      if (!containerGone || !volumeGone || !aliasValid) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      throw error;
    }
  }

  async discardVolume(volume) {
    if (!await this.#cleanupAnchoredOutputVolume(volume)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
  }
}

export const isDockerReferenceAdapter = (value) => adapters.has(value);

export const executeDockerForTesting = execute;
export const createDockerReferenceAdapterForTesting = (executeCommand, seccompCanonical = '{}', faults = new Set()) => {
  if (typeof executeCommand !== 'function' || types.isProxy(executeCommand) || typeof seccompCanonical !== 'string' || !(faults instanceof Set)) throw new TypeError('test Docker executor is invalid');
  const adapter = new DockerReferenceAdapter('/test/docker', '/test/seccomp.json', 'e'.repeat(64), seccompCanonical);
  adapterTestExecutors.set(adapter, executeCommand);
  adapterTestFaults.set(adapter, faults);
  return adapter;
};
export const detachedStartResultMatchesForTesting = detachedStartResultMatches;
export const isRegularPinnedFileHandleForTesting = async (handle, options = {}) => {
  try { await statePinnedFileSource(handle, options); return true; } catch { return false; }
};
export const postNonzeroFailureDispositionForTesting = postNonzeroFailureDisposition;
export const workerFailureClassForTesting = workerFailureClass;
