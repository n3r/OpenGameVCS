import { cloneJson } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError } from './errors.mjs';
import { HARD_LIMITS } from './limits.mjs';
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
  if (input === null || typeof input !== 'object' || Array.isArray(input)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'page input must be an object');
  return validatePageEnvelope(contract, {
    schemaVersion: 'ogvcs.protocol/page-envelope/v1',
    correlationId: input.correlationId,
    items: cloneJson(input.items, { ...options, maxArrayItems: HARD_LIMITS.pageItems }),
    state: input.state,
    ...(input.nextCursor === undefined ? {} : { nextCursor: input.nextCursor }),
    ...(input.problem === undefined ? {} : { problem: input.problem }),
  }, options);
}
