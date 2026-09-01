import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { isDigest, sha256 } from './reference-contract.mjs';

const SAFE_COMMAND_ENVIRONMENT = Object.freeze({ LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' });
const COMMAND_OUTPUT_MAXIMUM = 256 * 1024;
const CONTROL_TIMEOUT_MILLISECONDS = 10_000;
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

const hardeningArguments = ({ name, policy, seccompPath }) => [
  '--name', name,
  '--pull=never',
  '--network=none',
  '--read-only',
  '--cap-drop=ALL',
  '--security-opt=no-new-privileges=true',
  `--security-opt=seccomp=${seccompPath}`,
  '--cgroupns=private',
  '--ipc=none',
  '--pid=private',
  '--hostname=ogvcs-worker',
  '--log-driver=none',
  `--pids-limit=${policy.processes}`,
  `--memory=${policy.memoryBytes}b`,
  `--memory-swap=${policy.memoryBytes}b`,
  '--cpus=1.0',
  `--ulimit=cpu=${Math.ceil(policy.cpuMilliseconds / 1000)}:${Math.ceil(policy.cpuMilliseconds / 1000)}`,
  `--ulimit=fsize=${policy.outputBytes}:${policy.outputBytes}`,
  '--ulimit=nofile=64:64',
  '--stop-timeout=1',
  '--user=65532:65532',
  '--workdir=/scratch',
  `--tmpfs=/scratch:rw,nosuid,nodev,noexec,size=${policy.scratchBytes},uid=65532,gid=65532,mode=0700`,
];

const mountFile = (handle, target) => `type=bind,src=${procDescriptorPath(handle)},dst=${target},readonly`;

export const validateRuntimeImageInspect = (image, runtimeImage, runtimeContractSha256) => {
  const config = image?.Config;
  const empty = (candidate) => candidate === null || (Array.isArray(candidate) && candidate.length === 0);
  const emptyRecord = (candidate) => candidate === null || (candidate && typeof candidate === 'object' && !Array.isArray(candidate) && Object.keys(candidate).length === 0);
  const labels = config?.Labels;
  return image?.Id === runtimeImage
    && image?.Os === 'linux'
    && image?.Architecture === 'amd64'
    && image?.RootFS?.Type === 'layers'
    && Array.isArray(image?.RootFS?.Layers)
    && image.RootFS.Layers.length === 1
    && Number.isSafeInteger(image?.Size)
    && image.Size > 0
    && image.Size <= 32 * 1024 * 1024
    && config !== null
    && typeof config === 'object'
    && empty(config.Env)
    && empty(config.Cmd)
    && empty(config.Entrypoint)
    && emptyRecord(config.Volumes)
    && config.Healthcheck == null
    && emptyRecord(config.ExposedPorts)
    && config.User === ''
    && config.WorkingDir === ''
    && Object.keys(labels ?? {}).sort().join(',') === 'org.opengamevcs.sandbox.runtime,org.opengamevcs.sandbox.runtime-contract-sha256'
    && labels['org.opengamevcs.sandbox.runtime'] === 'linux-reference-v1'
    && labels['org.opengamevcs.sandbox.runtime-contract-sha256'] === runtimeContractSha256;
};

export class DockerReferenceAdapter {
  #binary;
  #seccompPath;
  #seccompDigest;
  #poisoned = false;

  static async open({ dockerBinary, seccompProfilePath, expectedSeccompSha256 }) {
    if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('Linux reference worker requires Linux x86_64');
    const [binary, seccompPath] = await Promise.all([safeExecutable(dockerBinary), realpath(seccompProfilePath)]);
    const seccompBytes = await readFile(seccompPath);
    if (!isDigest(expectedSeccompSha256) || sha256(seccompBytes) !== expectedSeccompSha256) throw new Error('owned seccomp profile digest differs');
    const details = await lstat(seccompPath);
    if (!details.isFile() || details.isSymbolicLink() || (details.mode & 0o022) !== 0) throw new Error('owned seccomp profile mode is unsafe');
    const adapter = new DockerReferenceAdapter(binary, seccompPath, expectedSeccompSha256);
    await adapter.#probeHost();
    adapters.add(adapter);
    return adapter;
  }

  constructor(binary, seccompPath, seccompDigest) {
    this.#binary = binary;
    this.#seccompPath = seccompPath;
    this.#seccompDigest = seccompDigest;
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
    if (server?.Os !== 'linux' || server?.Arch !== 'amd64' || details?.OSType !== 'linux' || String(details?.CgroupVersion) !== '2' || !['cpu', 'memory', 'pids'].every((controller) => availableControllers.has(controller)) || !security.includes('name=seccomp') || !security.includes('name=cgroupns') || security.includes('name=rootless')) throw new Error('Docker required Linux security controls are unavailable');
  }

  async verifyRuntimeImage(runtimeImage, runtimeContractSha256) {
    const value = await this.#control(['image', 'inspect', runtimeImage]);
    if (value.kind !== 'exit' || value.code !== 0) return false;
    let images;
    try { images = JSON.parse(value.stdout.toString('utf8')); } catch { return false; }
    if (!Array.isArray(images) || images.length !== 1) return false;
    return validateRuntimeImageInspect(images[0], runtimeImage, runtimeContractSha256);
  }

  async #createOutputVolume(policy) {
    const name = volumeName();
    const options = `size=${policy.outputBytes},uid=65532,gid=65532,mode=0700,nosuid,nodev,noexec`;
    const value = await this.#control(['volume', 'create', '--driver=local', '--opt=type=tmpfs', '--opt=device=tmpfs', `--opt=o=${options}`, '--label=org.opengamevcs.sandbox=reference-v1', name]);
    if (value.kind !== 'exit') {
      await this.#cleanupVolume(name).catch(() => false);
      this.#poisoned = true;
      throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    }
    if (value.code !== 0 || value.stdout.toString('utf8').trim() !== name) {
      if (!await this.#cleanupVolume(name)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      throw new Error('bounded output volume is unavailable');
    }
    return name;
  }

  async #createContainer(name, argumentsAfterCreate) {
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
    const inspected = await this.#control(['container', 'inspect', '--format', '{{.Id}} {{.Name}}', id]);
    if (inspected.kind !== 'exit' || inspected.code !== 0 || inspected.stdout.toString('utf8').trim() !== `${id} /${name}`) {
      await this.#cleanupContainer(id, name).catch(() => false);
      this.#poisoned = true;
      throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
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
    const volumeGone = containerGone && await this.#cleanupVolume(volume);
    if (!containerGone || !volumeGone) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
  }

  async runTool({ runtimeImage, policy, inputHandle, jobHandle, toolHandle, signal }) {
    if (this.#poisoned) throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    const volume = await this.#createOutputVolume(policy);
    const name = containerName();
    const args = [
      ...hardeningArguments({ name, policy, seccompPath: this.#seccompPath }),
      '--mount', mountFile(inputHandle, '/input/payload'),
      '--mount', mountFile(jobHandle, '/input/job'),
      '--mount', mountFile(toolHandle, '/tool/program'),
      '--mount', `type=volume,src=${volume},dst=/output,volume-nocopy`,
      '--entrypoint=/tool/program',
      runtimeImage,
    ];
    let id;
    try { id = await this.#createContainer(name, args); } catch (error) { await this.#cleanupVolume(volume).catch(() => {}); throw error; }
    if (!id) { await this.#cleanupVolume(volume); return Object.freeze({ kind: 'unavailable', volume: null }); }
    const deadline = Math.min(policy.elapsedMilliseconds, 60_000);
    const value = await execute({ binary: this.#binary, args: ['start', '--attach', id], maximumStdout: 64 * 1024, maximumStderr: 64 * 1024, timeoutMilliseconds: deadline, signal });
    const containerGone = await this.#cleanupContainer(id, name);
    if (!containerGone) { await this.#cleanupVolume(volume); this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
    const kind = value.kind === 'timeout' ? 'timeout' : value.kind === 'aborted' ? 'cancelled' : value.kind === 'overflow' ? 'output-limit' : value.kind !== 'exit' || value.code !== 0 || value.stdoutBytes !== 0 || value.stderr.length !== 0 ? 'failed' : 'success';
    return Object.freeze({ kind, volume });
  }

  async collectOutput({ runtimeImage, policy, volume, bindingHandle, framePath, maximumFrameBytes }) {
    if (this.#poisoned) throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    const name = containerName();
    const args = [
      ...hardeningArguments({ name, policy, seccompPath: this.#seccompPath }),
      '--mount', mountFile(bindingHandle, '/input/binding'),
      '--mount', `type=volume,src=${volume},dst=/output,readonly,volume-nocopy`,
      '--entrypoint=/ogvcs-output-shim',
      runtimeImage,
    ];
    let id;
    try { id = await this.#createContainer(name, args); } catch (error) { await this.#cleanupVolume(volume).catch(() => {}); throw error; }
    if (!id) { await this.#cleanupVolume(volume); return Object.freeze({ kind: 'failed', frameBytes: 0 }); }
    const value = await execute({ binary: this.#binary, args: ['start', '--attach', id], stdoutPath: framePath, maximumStdout: maximumFrameBytes, maximumStderr: 64 * 1024, timeoutMilliseconds: Math.min(policy.elapsedMilliseconds, 60_000) });
    await this.#settle(id, name, volume);
    return Object.freeze({ kind: value.kind === 'overflow' ? 'output-limit' : value.kind !== 'exit' || value.code !== 0 || value.stderr.length !== 0 ? 'failed' : 'success', frameBytes: value.stdoutBytes });
  }

  async discardVolume(volume) {
    if (!await this.#cleanupVolume(volume)) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
  }
}

export const isDockerReferenceAdapter = (value) => adapters.has(value);

export const executeDockerForTesting = execute;
