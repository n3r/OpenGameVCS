export const IDENTITY_ERROR_CODES = Object.freeze([
  'INPUT_INVALID',
  'LIMIT_EXCEEDED',
  'AUTHENTICATION_DENIED',
  'CREDENTIAL_REVOKED',
  'EPOCH_STALE',
  'POLICY_UNAVAILABLE',
  'AUDIT_INTEGRITY',
  'STATE_CONFLICT',
]);

export class IdentityPolicyError extends Error {
  constructor(code, message = code, options = {}) {
    if (!IDENTITY_ERROR_CODES.includes(code)) throw new TypeError('unknown identity-policy error code');
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'IdentityPolicyError';
    this.code = code;
    this.retryable = code === 'POLICY_UNAVAILABLE';
    Object.freeze(this);
  }
}

export function identityFail(code, message = code, options) {
  throw new IdentityPolicyError(code, message, options);
}

export function asIdentityError(error, fallback = 'INPUT_INVALID') {
  return error instanceof IdentityPolicyError
    ? error
    : new IdentityPolicyError(fallback, fallback, { cause: error });
}
