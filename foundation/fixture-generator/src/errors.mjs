export const EXIT_CODES = Object.freeze({
  OK: 0,
  USAGE: 2,
  INVALID_REQUEST: 3,
  UNSAFE_DESTINATION: 4,
  CONFLICT: 5,
  INTEGRITY: 6,
  RESOURCE_LIMIT: 7,
  INTERRUPTED: 8,
  INTERNAL: 70,
});

export class FixtureError extends Error {
  constructor(type, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'FixtureError';
    this.type = type;
    this.exitCode = options.exitCode ?? EXIT_CODES.INTERNAL;
    this.details = options.details ?? {};
  }
}

export function invalidRequest(message, details = {}) {
  return new FixtureError('invalid-request', message, {
    exitCode: EXIT_CODES.INVALID_REQUEST,
    details,
  });
}

export function unsafeDestination(message, details = {}) {
  return new FixtureError('unsafe-destination', message, {
    exitCode: EXIT_CODES.UNSAFE_DESTINATION,
    details,
  });
}

export function conflict(message, details = {}) {
  return new FixtureError('conflict', message, {
    exitCode: EXIT_CODES.CONFLICT,
    details,
  });
}

export function integrityFailure(message, details = {}) {
  return new FixtureError('integrity-failure', message, {
    exitCode: EXIT_CODES.INTEGRITY,
    details,
  });
}

export function resourceLimit(message, details = {}) {
  return new FixtureError('resource-limit', message, {
    exitCode: EXIT_CODES.RESOURCE_LIMIT,
    details,
  });
}

export function usageError(message, details = {}) {
  return new FixtureError('usage', message, {
    exitCode: EXIT_CODES.USAGE,
    details,
  });
}

export function asFixtureError(error) {
  if (error instanceof FixtureError) return error;
  if (error?.code === 'ENAMETOOLONG') {
    return unsafeDestination('Resolved path exceeds the host filesystem path limit', {
      code: error.code,
    });
  }
  return new FixtureError('internal', error?.message ?? String(error), {
    cause: error,
    exitCode: EXIT_CODES.INTERNAL,
  });
}

export function publicError(error) {
  const known = asFixtureError(error);
  return {
    error: {
      details: known.details,
      exitCode: known.exitCode,
      message: known.message,
      type: known.type,
    },
    ok: false,
    schemaVersion: 'ogvcs.fixture/cli-result/v1',
  };
}
