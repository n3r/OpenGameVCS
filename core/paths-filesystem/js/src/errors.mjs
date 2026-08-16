import { pathContract } from './contract.mjs';

const codes = new Set(pathContract.errorEntries.map(({ name }) => name));
const exitByCode = Object.freeze({
  PATH_INPUT_INVALID: 2, PATH_NOT_NFC: 2, PATH_LIMIT_EXCEEDED: 2,
  PATH_PROFILE_UNKNOWN: 2, PATH_PLATFORM_FORBIDDEN: 2, PATH_COLLISION: 2,
  CASE_MODE_INVALID: 2, ENTRY_INVALID: 2, RENAME_CONFLICT: 2,
  CAPABILITY_UNAVAILABLE: 3, SYMLINK_FORBIDDEN: 3,
  UNSAFE_TARGET: 4, TARGET_CHANGED: 4, TARGET_BUSY: 4,
  ATOMIC_REPLACE_FAILED: 4, CRASH_REMNANT: 4,
  WATCH_STATE_INVALID: 5, WATCH_GAP: 5, WATCH_OVERFLOW: 5,
  WATCH_UNCLEAN_SHUTDOWN: 5, RECONCILIATION_REQUIRED: 5,
  LIMIT_EXCEEDED: 6, IO_ERROR: 6,
});

function safeDetails(details) {
  if (details === undefined) return undefined;
  if (details === null || typeof details !== 'object' || Array.isArray(details)) throw new TypeError('error details must be a record');
  const result = {};
  for (const [key, value] of Object.entries(details)) {
    if (!/^[a-z][A-Za-z0-9]*$/u.test(key)) throw new TypeError('error detail key is invalid');
    if (typeof value === 'string') {
      if (value.length > 256 || /[/\\\0]/u.test(value)) throw new TypeError('error detail string is not privacy-safe');
      result[key] = value;
    } else if (typeof value === 'boolean' || (Number.isSafeInteger(value) && value >= 0) || value === null) {
      result[key] = value;
    } else {
      throw new TypeError('error detail value is not privacy-safe');
    }
  }
  return Object.freeze(result);
}

export class PathFilesystemError extends Error {
  constructor(code, message, options = {}) {
    if (!codes.has(code)) throw new TypeError(`unknown path/filesystem error code: ${code}`);
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'PathFilesystemError';
    this.code = code;
    this.exitCode = options.exitCode ?? exitByCode[code] ?? 6;
    this.details = safeDetails(options.details);
  }

  toJSON() {
    return Object.freeze({ code: this.code, ...(this.details === undefined ? {} : { details: this.details }) });
  }
}

export function pathFail(code, message = code, details, cause) {
  throw new PathFilesystemError(code, message, { details, cause });
}

export function asPathError(error, fallback = 'IO_ERROR', message = 'path/filesystem operation failed') {
  if (error instanceof PathFilesystemError) return error;
  const osCode = typeof error?.code === 'string' ? error.code : null;
  if (osCode === 'ELOOP') return new PathFilesystemError('UNSAFE_TARGET', 'filesystem link traversal was refused', { details: { osCode }, cause: error });
  if (['EBUSY', 'EACCES', 'EPERM', 'ETXTBSY'].includes(osCode)) return new PathFilesystemError('TARGET_BUSY', 'filesystem target remained busy', { details: { osCode }, cause: error });
  return new PathFilesystemError(fallback, message, { details: osCode === null ? undefined : { osCode }, cause: error });
}

export function errorDecision(error) {
  const normalized = asPathError(error);
  return Object.freeze({ accepted: false, error: normalized.code, ...(normalized.details === undefined ? {} : { detail: normalized.details }) });
}
