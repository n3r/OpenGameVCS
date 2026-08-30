import { atomicWriteStream } from '@opengamevcs/path-filesystem';
import { fail, normalizeError } from './errors.mjs';
import { PROFILE } from './identity.mjs';
import {
  consumeVerificationReceipt,
  createVerificationReceipt,
  VERIFICATION_RECEIPT_VERIFIER,
} from './receipt.mjs';
import { parseManifestReceiptRequirements } from './verify.mjs';
import { reconstructManifest } from './verify.mjs';

const PROFILE_TEXT = `${PROFILE.namespace}/${PROFILE.id}@${PROFILE.major}`;

function createQueueSource() {
  let pending;
  let slot;
  let closed = false;
  let terminal;

  function fail(error) {
    if (terminal === undefined) terminal = error;
    closed = true;
    if (slot) {
      const current = slot;
      slot = undefined;
      current.reject(terminal);
    }
    if (pending) {
      const waiter = pending;
      pending = undefined;
      waiter.reject(terminal);
    }
  }

  return Object.freeze({
    async next() {
      if (slot) {
        const current = slot;
        slot = undefined;
        current.resolve();
        return { done: false, value: current.value };
      }
      if (terminal !== undefined) throw terminal;
      if (closed) return { done: true, value: undefined };
      return new Promise((resolve, reject) => { pending = { resolve, reject }; });
    },
    push(value) {
      if (terminal !== undefined) throw terminal;
      if (closed) throw new Error('publication queue closed');
      if (slot) throw new Error('publication queue already has a pending write');
      if (pending) {
        const waiter = pending;
        pending = undefined;
        waiter.resolve({ done: false, value });
        return Promise.resolve();
      }
      return new Promise((resolve, reject) => {
        slot = { value, resolve, reject };
      });
    },
    close() {
      if (terminal !== undefined) return;
      closed = true;
      if (!slot && pending) {
        const waiter = pending;
        pending = undefined;
        waiter.resolve({ done: true, value: undefined });
      }
    },
    fail(error) {
      fail(error ?? new Error('publication queue failed'));
    },
    [Symbol.asyncIterator]() { return this; },
    return() {
      if (terminal === undefined) this.close();
      return Promise.resolve({ done: true, value: undefined });
    },
  });
}

export function createAtomicWriteStreamPublicationAdapter(workspace, repositoryPath, options = {}) {
  const requirements = parseManifestReceiptRequirements(options.manifest, options);
  const cancellation = new AbortController();
  const source = createQueueSource();
  const signal = options.signal === undefined
    ? cancellation.signal
    : AbortSignal.any([cancellation.signal, options.signal]);
  let state = 'open';
  let committed = false;
  let terminalError;
  let writePromise;
  let commitPromise;

  function rememberTerminal(cause) {
    if (terminalError === undefined) terminalError = normalizeError(cause, 'CHUNK_PUBLICATION_FAILED');
    return terminalError;
  }

  function ensureWriter() {
    if (writePromise) return writePromise;
    writePromise = Promise.resolve(atomicWriteStream(workspace, repositoryPath, source, {
      ...options,
      expectedBytes: Number(requirements.logicalBytes),
      expectedSha256: requirements.wholeFileSha256,
      signal,
    })).catch((cause) => {
      const failure = rememberTerminal(cause);
      source.fail(failure);
      throw failure;
    });
    writePromise.catch(() => {});
    return writePromise;
  }

  async function teardown(cause) {
    const failure = rememberTerminal(cause);
    state = 'closed';
    cancellation.abort();
    source.fail(failure);
    if (writePromise) {
      try { await writePromise; } catch {}
    }
    throw failure;
  }

  return Object.freeze({
    async write(fragment) {
      if (state !== 'open' || committed) throw terminalError ?? new Error('publication queue is not writable');
      ensureWriter();
      return source.push(Buffer.from(fragment));
    },
    async commit(context = {}) {
      if (committed) throw new Error('publication queue is already closed');
      if (state === 'closed') throw terminalError ?? new Error('publication queue is already closed');
      if (state === 'committing') return commitPromise;
      state = 'committing';
      commitPromise = (async () => {
      try {
        consumeVerificationReceipt(context.verificationReceipt, {
          verifier: VERIFICATION_RECEIPT_VERIFIER,
          profile: PROFILE_TEXT,
          manifestObjectId: requirements.manifestObjectId,
          manifestSha256: requirements.manifestSha256,
          logicalBytes: requirements.logicalBytes,
          wholeFileSha256: requirements.wholeFileSha256,
        }, 'CHUNK_PUBLICATION_FAILED');
        source.close();
        const workspacePublication = await ensureWriter();
        const verificationReceipt = createVerificationReceipt({
          ...requirements,
          profile: PROFILE_TEXT,
          workspacePublication,
        });
        committed = true;
        return Object.freeze({ workspacePublication, verificationReceipt });
      } catch (cause) {
        return teardown(cause);
      }
      })();
      return commitPromise;
    },
    async abort(cause) {
      if (committed || state === 'closed') return;
      state = 'closed';
      cancellation.abort();
      source.fail(cause ?? new Error('publication aborted'));
      if (writePromise) {
        try { await writePromise; } catch {}
      }
    },
  });
}

export async function reconstructManifestToWorkspace(input = {}) {
  try {
    if (!input || typeof input !== 'object' || input.workspace === undefined
        || typeof input.repositoryPath !== 'string' || input.repositoryPath.length === 0
        || (input.publicationOptions !== undefined
          && (!input.publicationOptions || typeof input.publicationOptions !== 'object'
            || Array.isArray(input.publicationOptions)))) {
      fail('CHUNK_RESOURCE_INVALID');
    }
    const {
      workspace,
      repositoryPath,
      publicationOptions = {},
      ...verification
    } = input;
    const publication = createAtomicWriteStreamPublicationAdapter(workspace, repositoryPath, {
      ...publicationOptions,
      manifest: verification.manifest,
      signal: publicationOptions.signal ?? verification.signal,
    });
    return await reconstructManifest({ ...verification, publication });
  } catch (cause) {
    throw normalizeError(cause, 'CHUNK_PUBLICATION_FAILED');
  }
}
