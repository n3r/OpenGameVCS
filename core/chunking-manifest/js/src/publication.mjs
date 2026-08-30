import { atomicWriteStream } from '@opengamevcs/path-filesystem';
import { normalizeError } from './errors.mjs';
import { PROFILE } from './identity.mjs';
import { consumeVerificationReceipt, createVerificationReceipt } from './receipt.mjs';
import { parseManifestReceiptRequirements } from './verify.mjs';

const PROFILE_TEXT = `${PROFILE.namespace}/${PROFILE.id}@${PROFILE.major}`;

function createQueueSource() {
  const queue = [];
  let pending;
  let closed = false;
  return Object.freeze({
    async next() {
      if (queue.length > 0) return { done: false, value: queue.shift() };
      if (closed) return { done: true, value: undefined };
      return new Promise((resolve, reject) => { pending = { resolve, reject }; });
    },
    push(value) {
      if (closed) throw new Error('publication queue closed');
      if (pending) {
        const waiter = pending;
        pending = undefined;
        waiter.resolve({ done: false, value });
        return;
      }
      queue.push(value);
    },
    close(error) {
      closed = true;
      if (pending) {
        const waiter = pending;
        pending = undefined;
        if (error) waiter.reject(error);
        else waiter.resolve({ done: true, value: undefined });
      }
    },
    [Symbol.asyncIterator]() { return this; },
    return() {
      this.close();
      return Promise.resolve({ done: true, value: undefined });
    },
  });
}

export function createAtomicWriteStreamPublicationAdapter(workspace, repositoryPath, options = {}) {
  const requirements = parseManifestReceiptRequirements(options.manifest, options);
  const cancellation = new AbortController();
  const source = createQueueSource();
  const writePromise = atomicWriteStream(workspace, repositoryPath, source, {
    ...options,
    expectedBytes: Number(requirements.logicalBytes),
    expectedSha256: requirements.wholeFileSha256,
    signal: options.signal ?? cancellation.signal,
  });
  let closed = false;
  let committed = false;
  return Object.freeze({
    write(fragment) {
      if (closed || committed) throw new Error('publication queue is not writable');
      source.push(Buffer.from(fragment));
    },
    async commit(context = {}) {
      if (closed || committed) throw new Error('publication queue is already closed');
      try {
        consumeVerificationReceipt(context.verificationReceipt, {
          verifier: context.verificationReceipt?.verifier,
          profile: PROFILE_TEXT,
          manifestObjectId: requirements.manifestObjectId,
          manifestSha256: requirements.manifestSha256,
          logicalBytes: requirements.logicalBytes,
          wholeFileSha256: requirements.wholeFileSha256,
        }, 'CHUNK_PUBLICATION_FAILED');
        committed = true;
        source.close();
        const workspacePublication = await writePromise;
        const verificationReceipt = createVerificationReceipt({
          ...requirements,
          profile: PROFILE_TEXT,
          workspacePublication,
        });
        return Object.freeze({ workspacePublication, verificationReceipt });
      } catch (cause) {
        closed = true;
        cancellation.abort();
        source.close(cause);
        try { await writePromise; } catch {}
        throw normalizeError(cause, 'CHUNK_PUBLICATION_FAILED');
      }
    },
    async abort() {
      if (closed || committed) return;
      closed = true;
      cancellation.abort();
      source.close();
      try { await writePromise; } catch {}
    },
  });
}
