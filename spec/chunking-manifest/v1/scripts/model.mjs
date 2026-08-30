export const PROFILE_TEXT = 'chunking.opengamevcs/gear-fastcdc-1m@1';

export const GOLDEN_INPUTS = Object.freeze([
  { caseId: 'empty', recipe: { kind: 'literal', hex: '' } },
  { caseId: 'tiny-ascii', recipe: { kind: 'literal', hex: '4f70656e47616d655643530a' } },
  { caseId: 'small-maximum', recipe: { kind: 'repeat', byte: 165, length: 262144 } },
  { caseId: 'counter-a-six-mib', recipe: { kind: 'sha256-counter', seed: 'counter-a', length: 6291456 } },
  { caseId: 'counter-b-four-mib', recipe: { kind: 'sha256-counter', seed: 'counter-b', length: 4194304 } },
  { caseId: 'zero-five-mib', recipe: { kind: 'repeat', byte: 0, length: 5242880 } },
  { caseId: 'ff-five-mib', recipe: { kind: 'repeat', byte: 255, length: 5242880 } },
  { caseId: 'insertion-base', recipe: { kind: 'sha256-counter', seed: 'insertion-base', length: 5242880 } },
  { caseId: 'insertion-plus-17', recipe: { kind: 'insert', base: { kind: 'sha256-counter', seed: 'insertion-base', length: 5242880 }, offset: 1048593, hex: '00112233445566778899aabbccddeeff42' } },
]);

export const MALFORMED = Object.freeze([
  { caseId: 'declared-negative', operation: 'chunk', parameters: { declaredLength: -1 }, expectedError: 'CHUNK_DECLARED_LENGTH_INVALID' },
  { caseId: 'declared-over-limit', operation: 'chunk', parameters: { declaredLength: 1099511627777 }, expectedError: 'CHUNK_DECLARED_LENGTH_INVALID' },
  { caseId: 'source-short', operation: 'chunk', parameters: { declaredLength: 4, sourceHex: '000102' }, expectedError: 'CHUNK_SOURCE_TOO_SHORT' },
  { caseId: 'source-long', operation: 'chunk', parameters: { declaredLength: 2, sourceHex: '000102' }, expectedError: 'CHUNK_SOURCE_TOO_LONG' },
  { caseId: 'unknown-profile', operation: 'chunk', parameters: { declaredLength: 0, profile: 'chunking.opengamevcs/unknown@1' }, expectedError: 'CHUNK_PROFILE_UNSUPPORTED' },
  { caseId: 'wrong-profile-major', operation: 'chunk', parameters: { declaredLength: 0, profile: 'chunking.opengamevcs/gear-fastcdc-1m@2' }, expectedError: 'CHUNK_PROFILE_UNSUPPORTED' },
  { caseId: 'boundary-shift', operation: 'verify', parameters: { vector: 'counter-a-six-mib', boundaryDelta: 1 }, expectedError: 'CHUNK_BOUNDARY_MISMATCH' },
  { caseId: 'chunk-bit-flip', operation: 'verify', parameters: { vector: 'counter-a-six-mib', chunkIndex: 0, xor: 1 }, expectedError: 'CHUNK_DIGEST_MISMATCH' },
  { caseId: 'manifest-bit-flip', operation: 'verify', parameters: { vector: 'counter-a-six-mib', manifestByte: 0, xor: 1 }, expectedError: 'CHUNK_MANIFEST_MISMATCH' },
  { caseId: 'fragment-over-limit', operation: 'chunk', parameters: { declaredLength: 67108865, fragmentLength: 67108865 }, expectedError: 'CHUNK_FRAGMENT_INVALID' },
  { caseId: 'resource-below-scalar-minimum', operation: 'chunk', parameters: { declaredLength: 6291456, maxWorkingMemoryBytes: 4259839 }, expectedError: 'CHUNK_RESOURCE_EXHAUSTED' },
]);
