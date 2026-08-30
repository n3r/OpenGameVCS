import {
  Digest, ProfileRef, hashObject, loadBundledRegistry, validateRegistrySet, writeContentManifest,
} from '@opengamevcs/object-model';
import { wrap } from './errors.mjs';

export const PROFILE = Object.freeze({ namespace: 'chunking.opengamevcs', id: 'gear-fastcdc-1m', major: 1 });
const PROFILE_REF = new ProfileRef(PROFILE.namespace, PROFILE.id, PROFILE.major);

async function candidateRegistry() {
  const bundled = await loadBundledRegistry();
  const documents = structuredClone(Object.fromEntries(bundled.documents));
  documents['profiles.json'].entries.push({
    family: 'chunking', id: PROFILE.id, major: PROFILE.major, namespace: PROFILE.namespace,
    owner: 'OGVCS-007 candidate', productionWriteAllowed: false, state: 'conformance-only',
  });
  documents['profiles.json'].entries.sort((left, right) => {
    const a = `${left.namespace}\0${left.id}\0${String(left.major).padStart(10, '0')}`;
    const b = `${right.namespace}\0${right.id}\0${String(right.major).padStart(10, '0')}`;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  return validateRegistrySet(documents);
}
const REGISTRY = await candidateRegistry();

export function chunkIdentity(bytes) {
  const reference = hashObject(1, bytes);
  return Object.freeze({ digest: Buffer.from(reference.digest), objectId: reference.toString(), reference });
}

export async function contentManifest(logicalLength, wholeFileDigest, parts, options = {}) {
  const output = [];
  const partCount = options.partCount ?? (Array.isArray(parts) ? parts.length : undefined);
  const source = typeof parts === 'function'
    ? (pass, context) => {
      const values = parts(pass, context);
      return (function *mapped() {
        for (const { reference, length } of values) {
          yield new Map([[0, reference.toMap()], [1, length]]);
        }
      })();
    }
    : parts.map(({ reference, length }) => new Map([[0, reference.toMap()], [1, length]]));
  const sink = options.sink === undefined
    ? (bytes) => { output.push(Buffer.from(bytes)); }
    : async (bytes) => {
      try { return await options.sink(bytes); }
      catch (cause) { throw wrap('CHUNK_SINK_FAILED', cause); }
    };
  const result = await writeContentManifest({
    registry: REGISTRY,
    operation: 'conformance',
    logicalLength: BigInt(logicalLength),
    wholeFileDigest: new Digest(1, wholeFileDigest),
    chunkProfile: PROFILE_REF,
    partCount,
    parts: source,
    sink,
  });
  return Object.freeze({
    bytes: options.sink === undefined ? Buffer.concat(output) : undefined,
    objectId: result.objectRef.toString(),
    profile: PROFILE_REF.toString(),
    summary: result.summary,
  });
}
