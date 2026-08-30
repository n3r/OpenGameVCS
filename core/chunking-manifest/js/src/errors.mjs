export const ERROR_CODES = Object.freeze([
  'CHUNK_BOUNDARY_MISMATCH',
  'CHUNK_COUNT_EXCEEDED',
  'CHUNK_DECLARED_LENGTH_INVALID',
  'CHUNK_DIGEST_MISMATCH',
  'CHUNK_FINGERPRINT_INPUT_INVALID',
  'CHUNK_FRAGMENT_INVALID',
  'CHUNK_MANIFEST_MISMATCH',
  'CHUNK_METADATA_CONFLICT',
  'CHUNK_PROFILE_UNSUPPORTED',
  'CHUNK_PUBLICATION_FAILED',
  'CHUNK_RESOURCE_EXHAUSTED',
  'CHUNK_RESOURCE_INVALID',
  'CHUNK_RESOURCE_UNSUPPORTED',
  'CHUNK_SCRATCH_EXHAUSTED',
  'CHUNK_SESSION_FAILED',
  'CHUNK_SESSION_FINISHED',
  'CHUNK_SINK_FAILED',
  'CHUNK_SINK_INVALID',
  'CHUNK_SOURCE_INVALID',
  'CHUNK_SOURCE_MISSING',
  'CHUNK_SOURCE_TOO_LONG',
  'CHUNK_SOURCE_TOO_SHORT',
]);

const CODES = new Set(ERROR_CODES);

export class ChunkingError extends Error {
  constructor(code, details = {}, options = {}) {
    if (!CODES.has(code)) throw new TypeError(`unknown chunking error code: ${code}`);
    super(code, options);
    this.name = 'ChunkingError';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function fail(code, details, options) {
  throw new ChunkingError(code, details, options);
}

export function wrap(code, cause, details = {}) {
  if (cause instanceof ChunkingError && cause.code === code) return cause;
  return new ChunkingError(code, details, { cause });
}
