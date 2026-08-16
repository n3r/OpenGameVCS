export const ERROR_CODES = Object.freeze({
  INPUT_INVALID: 'AUTHZ_INPUT_INVALID',
  CONTRACT_INVALID: 'AUTHZ_CONTRACT_INVALID',
  LIMIT_EXCEEDED: 'AUTHZ_LIMIT_EXCEEDED',
  TIMEOUT: 'AUTHZ_TIMEOUT',
  ADAPTER_PROTOCOL: 'AUTHZ_ADAPTER_PROTOCOL',
  ADAPTER_FAILED: 'AUTHZ_ADAPTER_FAILED',
  IO: 'AUTHZ_IO_ERROR',
});

const EXIT_CODES = Object.freeze({
  [ERROR_CODES.INPUT_INVALID]: 2,
  [ERROR_CODES.CONTRACT_INVALID]: 3,
  [ERROR_CODES.LIMIT_EXCEEDED]: 4,
  [ERROR_CODES.TIMEOUT]: 4,
  [ERROR_CODES.ADAPTER_PROTOCOL]: 4,
  [ERROR_CODES.ADAPTER_FAILED]: 4,
  [ERROR_CODES.IO]: 4,
});

export class AuthorizationContractError extends Error {
  constructor(code, message, options = {}) {
    if (!Object.values(ERROR_CODES).includes(code)) throw new TypeError('unknown authorization contract error code');
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'AuthorizationContractError';
    this.code = code;
    this.exitCode = options.exitCode ?? EXIT_CODES[code];
  }

  toJSON() {
    return { code: this.code, message: this.message };
  }
}

export function contractError(code, message, options) {
  throw new AuthorizationContractError(code, message, options);
}

export function asContractError(error, code = ERROR_CODES.CONTRACT_INVALID, message = 'authorization contract operation failed') {
  if (error instanceof AuthorizationContractError) return error;
  return new AuthorizationContractError(code, message, { cause: error });
}
