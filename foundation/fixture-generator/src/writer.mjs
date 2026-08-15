import { lstat, open, stat } from 'node:fs/promises';
import path from 'node:path';

import { resourceLimit, unsafeDestination } from './errors.mjs';
import { injectPersistenceFault, syncDirectory } from './io.mjs';

/**
 * One generation-wide resource ledger. Artifact sizes model bytes occupying
 * the staging filesystem; totalWrittenBytes separately drives the deterministic
 * test fault. Atomic replacements temporarily reserve both the old artifact
 * and its new temporary inode, matching the peak space needed by atomicWrite.
 */
export class ResourceBudget {
  constructor(options = {}) {
    const initialMemoryBytes = process.memoryUsage().rss;
    this.artifacts = new Map();
    this.deadline = options.deadline;
    this.failAfterBytes = options.failAfterBytes;
    this.maximumMemoryBytes = options.maximumMemoryBytes;
    this.maximumMemoryGrowthBytes = options.maximumMemoryGrowthBytes;
    this.maximumPhysicalBytes = options.maximumPhysicalBytes;
    this.testFailurePhase = options.testFailurePhase;
    this.memoryExceeded = null;
    this.memoryBaselineBytes = initialMemoryBytes;
    this.peakMemoryBytes = initialMemoryBytes;
    this.peakPhysicalBytes = 0;
    this.physicalBytes = 0;
    this.totalWrittenBytes = 0;
  }

  memoryViolation(memoryBytes, phase) {
    if (this.maximumMemoryBytes !== undefined && memoryBytes > this.maximumMemoryBytes) {
      return {
        limit: this.maximumMemoryBytes,
        message: 'Request maximumMemoryBytes limit reached',
        observed: memoryBytes,
        phase,
      };
    }
    const growthBytes = Math.max(0, memoryBytes - this.memoryBaselineBytes);
    if (
      this.maximumMemoryGrowthBytes !== undefined
      && growthBytes > this.maximumMemoryGrowthBytes
    ) {
      return {
        limit: this.maximumMemoryGrowthBytes,
        message: 'Planned verification memory-growth limit reached',
        observed: growthBytes,
        observedRss: memoryBytes,
        phase,
      };
    }
    return null;
  }

  checkRuntime(phase = 'generation') {
    if (this.testFailurePhase === phase) {
      throw resourceLimit('Injected runtime budget failure', { phase });
    }
    const now = Date.now();
    if (this.deadline !== undefined && now > this.deadline) {
      throw resourceLimit('Request maximumDurationSeconds limit reached', { phase });
    }
    const memoryBytes = process.memoryUsage().rss;
    this.peakMemoryBytes = Math.max(this.peakMemoryBytes, memoryBytes);
    const violation = this.memoryExceeded ?? this.memoryViolation(memoryBytes, phase);
    if (violation) {
      throw resourceLimit(violation.message, {
        limit: violation.limit,
        observed: violation.observed,
        ...(violation.observedRss === undefined ? {} : { observedRss: violation.observedRss }),
        phase: violation.phase,
      });
    }
  }

  assertMemoryHeadroom(additionalBytes, phase = 'memory-allocation') {
    if (!Number.isSafeInteger(additionalBytes) || additionalBytes < 0) {
      throw resourceLimit('Prospective memory allocation is outside the safe integer range', {
        additionalBytes,
        phase,
      });
    }
    const observed = process.memoryUsage().rss;
    const projected = observed + additionalBytes;
    if (!Number.isSafeInteger(projected)) {
      throw resourceLimit('Prospective memory allocation exceeds the safe integer range', {
        additionalBytes,
        observed,
        phase,
      });
    }
    const violation = this.memoryExceeded ?? this.memoryViolation(projected, phase);
    if (violation) {
      throw resourceLimit(violation.message, {
        additionalBytes,
        limit: violation.limit,
        observed,
        phase: violation.phase,
        projected,
      });
    }
  }

  assertPhysical(nextBytes, artifact) {
    if (this.maximumPhysicalBytes !== undefined && nextBytes > this.maximumPhysicalBytes) {
      throw resourceLimit('Request maximumPhysicalBytes limit reached', {
        artifact,
        limit: this.maximumPhysicalBytes,
        required: nextBytes,
      });
    }
  }

  accountWrite(bytes, artifact = 'artifact') {
    this.checkRuntime(`write:${artifact}`);
    if (!Number.isSafeInteger(bytes) || bytes < 0) throw new TypeError('accounted byte count must be a non-negative safe integer');
    this.totalWrittenBytes += bytes;
    if (this.failAfterBytes !== undefined && this.totalWrittenBytes > this.failAfterBytes) {
      throw resourceLimit('Injected physical-write limit reached', {
        artifact,
        limit: this.failAfterBytes,
        written: this.totalWrittenBytes,
      });
    }
  }

  setArtifactBytes(artifact, bytes, options = {}) {
    this.checkRuntime(`account:${artifact}`);
    if (!Number.isSafeInteger(bytes) || bytes < 0) throw new TypeError('artifact byte count must be a non-negative safe integer');
    const previous = this.artifacts.get(artifact) ?? 0;
    if (options.written && bytes > previous) this.accountWrite(bytes - previous, artifact);
    const nextPhysical = this.physicalBytes - previous + bytes;
    this.assertPhysical(nextPhysical, artifact);
    this.artifacts.set(artifact, bytes);
    this.physicalBytes = nextPhysical;
    this.peakPhysicalBytes = Math.max(this.peakPhysicalBytes, nextPhysical);
  }

  appendArtifactBytes(artifact, bytes) {
    const current = this.artifacts.get(artifact) ?? 0;
    this.setArtifactBytes(artifact, current + bytes, { written: true });
  }

  removeArtifact(artifact) {
    const previous = this.artifacts.get(artifact) ?? 0;
    this.artifacts.delete(artifact);
    this.physicalBytes -= previous;
  }

  retainArtifacts(artifacts = []) {
    const retained = new Set(artifacts);
    for (const artifact of [...this.artifacts.keys()]) {
      if (!retained.has(artifact)) this.removeArtifact(artifact);
    }
  }

  beginAtomicWrite(artifact, bytes) {
    this.checkRuntime(`atomic-write:${artifact}`);
    if (!Number.isSafeInteger(bytes) || bytes < 0) throw new TypeError('atomic byte count must be a non-negative safe integer');
    this.accountWrite(bytes, `${artifact}.tmp`);
    this.assertPhysical(this.physicalBytes + bytes, `${artifact}.tmp`);
    this.peakPhysicalBytes = Math.max(this.peakPhysicalBytes, this.physicalBytes + bytes);
    let finished = false;
    return {
      abort: () => { finished = true; },
      commit: () => {
        if (finished) return;
        finished = true;
        this.setArtifactBytes(artifact, bytes);
      },
    };
  }

  async runPhase(phase, action) {
    this.checkRuntime(phase);
    const sample = () => {
      const observed = process.memoryUsage().rss;
      this.peakMemoryBytes = Math.max(this.peakMemoryBytes, observed);
      if (
        !this.memoryExceeded
      ) this.memoryExceeded = this.memoryViolation(observed, phase);
    };
    const sampler = setInterval(sample, 25);
    sampler.unref?.();
    try {
      const result = await action();
      sample();
      this.checkRuntime(phase);
      return result;
    } finally {
      clearInterval(sampler);
    }
  }
}

export class BufferedFileWriter {
  static async create(filePath, options = {}) {
    if (options.append) {
      const metadata = await lstat(filePath).catch(() => null);
      if (!metadata?.isFile() || metadata.isSymbolicLink()) {
        throw unsafeDestination('Cannot append to an unsafe or missing artifact', { path: filePath });
      }
    }
    injectPersistenceFault('stream-open', filePath);
    const handle = await open(filePath, options.append ? 'a' : 'wx', options.mode ?? 0o600);
    try {
      const existingBytes = options.append ? (await stat(filePath)).size : 0;
      const artifact = options.artifact ?? filePath;
      options.budget?.setArtifactBytes(artifact, existingBytes);
      return new BufferedFileWriter(handle, filePath, existingBytes, options.flushBytes, options.budget, artifact);
    } catch (error) {
      await handle.close().catch(() => {});
      throw error;
    }
  }

  constructor(handle, filePath, existingBytes = 0, flushBytes = 1024 * 1024, budget, artifact = filePath) {
    this.handle = handle;
    this.filePath = filePath;
    this.bytes = existingBytes;
    this.flushBytes = flushBytes;
    this.buffers = [];
    this.bufferedBytes = 0;
    this.failed = false;
    this.budget = budget;
    this.artifact = artifact;
  }

  async write(value) {
    const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
    this.budget?.appendArtifactBytes(this.artifact, bytes.length);
    this.buffers.push(bytes);
    this.bufferedBytes += bytes.length;
    this.bytes += bytes.length;
    if (this.bufferedBytes >= this.flushBytes) await this.flush();
  }

  async flush(sync = false) {
    if (this.bufferedBytes > 0) {
      const bytes = this.buffers.length === 1 ? this.buffers[0] : Buffer.concat(this.buffers, this.bufferedBytes);
      try {
        injectPersistenceFault('stream-write', this.filePath);
        let offset = 0;
        while (offset < bytes.length) {
          const result = await this.handle.write(bytes, offset, bytes.length - offset);
          if (result.bytesWritten <= 0) throw new Error('Persistence write made no progress');
          offset += result.bytesWritten;
        }
      } catch (error) {
        this.failed = true;
        throw error;
      }
      this.buffers = [];
      this.bufferedBytes = 0;
    }
    if (sync) {
      try {
        injectPersistenceFault('stream-sync', this.filePath);
        await this.handle.sync();
      } catch (error) {
        this.failed = true;
        throw error;
      }
    }
  }

  async close() {
    let failure;
    try {
      if (!this.failed) await this.flush(true);
      injectPersistenceFault('stream-close', this.filePath);
    } catch (error) {
      failure = error;
    }
    try {
      await this.handle.close();
    } catch (error) {
      failure ??= error;
    }
    if (failure) throw failure;
    await syncDirectory(path.dirname(this.filePath), 'stream-parent-sync', this.filePath);
  }

  async abort() {
    this.failed = true;
    this.buffers = [];
    this.bufferedBytes = 0;
    await this.handle.close().catch(() => {});
  }
}
