import { cloneJson } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError } from './errors.mjs';
import { HARD_LIMITS, boundedInteger } from './limits.mjs';
import { validateProtocolValue } from './schema.mjs';

export function validateCursor(contract, input, options = {}) {
  return validateProtocolValue(contract, 'Cursor.schema.json', input, { ...options, maxBytes: HARD_LIMITS.cursorBytes });
}

export function validatePageEnvelope(contract, input, options = {}) {
  const value = validateProtocolValue(contract, 'PageEnvelope.schema.json', input, { ...options, maxBytes: HARD_LIMITS.controlMessageBytes });
  if (value.state === 'more' && (value.nextCursor === undefined || value.problem !== undefined)) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'continuation page requires only a next cursor');
  }
  if (value.state === 'complete' && (value.nextCursor !== undefined || value.problem !== undefined)) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'complete page cannot carry continuation or gap state');
  }
  if (value.state === 'gap' && (value.nextCursor !== undefined || value.problem === undefined || value.problem.code !== 'CURSOR_GAP')) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'gap page requires only a CURSOR_GAP problem');
  }
  return value;
}

export function createPageEnvelope(contract, input, options = {}) {
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  if (maximumWorking < 2) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'page working-memory ceiling exceeded');
  const inputWorking = Math.floor(maximumWorking / 2);
  const value = cloneJson(input, {
    ...options,
    maxBytes: HARD_LIMITS.controlMessageBytes,
    maxArrayItems: HARD_LIMITS.arrayItems,
    maxWorkingMemoryBytes: inputWorking,
  });
  if (value === null || typeof value !== 'object' || Array.isArray(value)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'page input must be an object');
  return validatePageEnvelope(contract, {
    schemaVersion: 'ogvcs.protocol/page-envelope/v1',
    correlationId: value.correlationId,
    items: value.items,
    state: value.state,
    ...(value.nextCursor === undefined ? {} : { nextCursor: value.nextCursor }),
    ...(value.problem === undefined ? {} : { problem: value.problem }),
  }, { ...options, maxWorkingMemoryBytes: maximumWorking - inputWorking });
}
