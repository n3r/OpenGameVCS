import {
  Digest, ProfileRef, hashObject, loadBundledRegistry, validateRegistrySet, writeContentManifest,
} from '@opengamevcs/object-model';

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

export async function contentManifest(logicalLength, wholeFileDigest, parts) {
  const output = [];
  const objectParts = parts.map(({ reference, length }) => new Map([[0, reference.toMap()], [1, length]]));
  const result = await writeContentManifest({
    registry: REGISTRY,
    operation: 'conformance',
    logicalLength: BigInt(logicalLength),
    wholeFileDigest: new Digest(1, wholeFileDigest),
    chunkProfile: PROFILE_REF,
    partCount: objectParts.length,
    parts: objectParts,
    sink: (bytes) => { output.push(Buffer.from(bytes)); },
  });
  return Object.freeze({
    bytes: Buffer.concat(output),
    objectId: result.objectRef.toString(),
    profile: PROFILE_REF.toString(),
  });
}
