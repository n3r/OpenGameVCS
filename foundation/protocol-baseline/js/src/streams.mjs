import { canonicalBytes, parseJson } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError } from './errors.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';
import { validateProtocolValue } from './schema.mjs';

const STREAM_FRAME_SCHEMA = 'StreamFrame.schema.json';
const TERMINAL_KINDS = new Set(['terminal', 'gap', 'cancelled', 'error']);

function frameOptions(options) {
  if (!options.contract?.validator || typeof options.contract.validator.validate !== 'function') {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'canonical protocol streams require an authenticated protocol contract');
  }
  if (Object.hasOwn(options, 'terminalKinds') || Object.hasOwn(options, 'schema')) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'canonical protocol stream semantics cannot be overridden');
  }
  return Object.freeze({
    maxLineBytes: boundedInteger(options.maxLineBytes, 256 * 1024, HARD_LIMITS.streamLineBytes, 'maxLineBytes'),
    maxBytes: boundedInteger(options.maxBytes, 8 * 1024 * 1024, HARD_LIMITS.streamBytes, 'maxBytes'),
    maxFrames: boundedInteger(options.maxFrames, 10_000, HARD_LIMITS.streamFrames, 'maxFrames'),
    maxRetainedBytes: boundedInteger(options.maxRetainedBytes, 16 * 1024 * 1024, HARD_LIMITS.stateBytes, 'maxRetainedBytes'),
    maxWorkingMemoryBytes: boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes'),
    terminalKinds: TERMINAL_KINDS,
    contract: options.contract,
    deadline: deadlineFrom(options),
  });
}

function primitiveFrameShape(frame) {
  if (frame === null || typeof frame !== 'object' || Array.isArray(frame)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream frame is not an object');
  if (typeof frame.streamId !== 'string' || Buffer.byteLength(frame.streamId, 'utf8') < 1 || Buffer.byteLength(frame.streamId, 'utf8') > 256) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream frame identifier is invalid');
  }
  if (!Number.isSafeInteger(frame.sequence) || frame.sequence < 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream frame sequence is invalid');
  if (typeof frame.kind !== 'string' || frame.kind.length === 0 || frame.kind.length > 32) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream frame kind is invalid');
}

function verifiedFrame(frame, settings) {
  const value = validateProtocolValue(settings.contract, STREAM_FRAME_SCHEMA, frame, {
    maxBytes: settings.maxLineBytes,
    deadline: settings.deadline,
  });
  primitiveFrameShape(value);
  if (value.kind === 'gap' && value.problem?.code !== 'CURSOR_GAP') {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'gap stream frame requires a CURSOR_GAP problem', { details: { reason: 'gapProblem' } });
  }
  return value;
}

class FrameSequence {
  constructor(settings) {
    this.settings = settings;
    this.count = 0;
    this.streamId = undefined;
    this.terminal = undefined;
  }

  accept(frame) {
    if (this.terminal !== undefined) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream contains a frame after its terminal frame');
    if (this.count >= this.settings.maxFrames) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream frame ceiling exceeded');
    if (frame.sequence !== this.count) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream frame sequence numbers are not contiguous');
    if (this.streamId === undefined) this.streamId = frame.streamId;
    else if (frame.streamId !== this.streamId) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream identifier changed within a stream');
    this.count += 1;
    if (this.settings.terminalKinds.has(frame.kind)) this.terminal = frame.kind;
  }

  finish() {
    if (this.terminal === undefined) protocolError(RUNTIME_ERROR_CODES.STREAM_INCOMPLETE, 'stream ended without an explicit terminal frame');
    return Object.freeze({ streamId: this.streamId, frames: this.count, terminalKind: this.terminal });
  }
}

export function encodeStreamFrame(frame, options = {}) {
  const settings = frameOptions(options);
  const value = verifiedFrame(frame, settings);
  const bytes = canonicalBytes(value, { maxBytes: settings.maxLineBytes, deadline: settings.deadline });
  if (bytes.length > settings.maxLineBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream line ceiling exceeded');
  return Buffer.concat([bytes, Buffer.from('\n')]);
}

export function parseCanonicalStream(input, options = {}) {
  const settings = frameOptions(options);
  if (!(typeof input === 'string' || Buffer.isBuffer(input) || input instanceof Uint8Array)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream input must be text or bytes');
  let bytes;
  if (typeof input === 'string') {
    if (input.length > settings.maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream byte ceiling exceeded');
    let byteLength;
    try { byteLength = Buffer.byteLength(input, 'utf8'); } catch (error) { protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream text is not well-formed Unicode', { cause: error }); }
    if (byteLength > settings.maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream byte ceiling exceeded');
    bytes = Buffer.from(input, 'utf8');
    if (new TextDecoder('utf-8', { fatal: true }).decode(bytes) !== input) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream text is not well-formed Unicode');
  } else {
    if (input.byteLength > settings.maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream byte ceiling exceeded');
    bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
  }
  if (bytes.length === 0) protocolError(RUNTIME_ERROR_CODES.STREAM_INCOMPLETE, 'stream is empty');
  if (bytes.length > settings.maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream byte ceiling exceeded');
  const inputReservation = bytes.length + 1024;
  if (!Number.isSafeInteger(inputReservation) || inputReservation > settings.maxWorkingMemoryBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream combined working-memory ceiling exceeded');
  const sequence = new FrameSequence(settings);
  const frames = [];
  let retainedBytes = 0;
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if ((index & 0xffff) === 0) settings.deadline.checkpoint();
    if (bytes[index] !== 0x0a) {
      if (index - start + 1 > settings.maxLineBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream line ceiling exceeded');
      continue;
    }
    if (index === start || bytes[index - 1] === 0x0d) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream line delimiter is invalid');
    const line = bytes.subarray(start, index);
    const parseReservation = 128 + (4 * line.length);
    if (!Number.isSafeInteger(parseReservation) || inputReservation + retainedBytes + parseReservation > settings.maxWorkingMemoryBytes) {
      protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream combined working-memory ceiling exceeded before frame parse');
    }
    const parsed = parseJson(line, { requireCanonical: true, maxBytes: settings.maxLineBytes, deadline: settings.deadline });
    const frame = verifiedFrame(parsed, settings);
    sequence.accept(frame);
    retainedBytes += 512 + (line.length * 4);
    if (!Number.isSafeInteger(retainedBytes) || retainedBytes > settings.maxRetainedBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'decoded stream memory ceiling exceeded');
    if (inputReservation + retainedBytes > settings.maxWorkingMemoryBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream combined working-memory ceiling exceeded');
    frames.push(frame);
    start = index + 1;
  }
  if (start !== bytes.length) protocolError(RUNTIME_ERROR_CODES.STREAM_INCOMPLETE, 'stream ended within a frame');
  const summary = sequence.finish();
  settings.deadline.checkpoint();
  return Object.freeze({ frames: Object.freeze(frames), summary });
}

async function writeChunk(writable, bytes, deadline) {
  const completion = new Promise((resolve, reject) => {
    let listening = false;
    const onError = (error) => reject(error);
    if (typeof writable.once === 'function') {
      writable.once('error', onError);
      listening = true;
    }
    try {
      writable.write(bytes, (error) => {
        if (error) {
          reject(error);
        } else {
          if (listening) writable.removeListener('error', onError);
          resolve();
        }
      });
    } catch (error) {
      if (listening) writable.removeListener('error', onError);
      reject(error);
    }
  });
  try { await deadline.race(completion, 'stream output'); } catch (error) {
    if (error?.code?.startsWith?.('PROTOCOL_')) throw error;
    protocolError(RUNTIME_ERROR_CODES.IO, 'stream output failed', { cause: error });
  }
  deadline.checkpoint();
}

export async function writeCanonicalStream(frames, writable, options = {}) {
  if (frames === null || frames === undefined || typeof frames[Symbol.iterator] !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream frames must be iterable');
  if (!writable || typeof writable.write !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'stream output must be writable');
  const settings = frameOptions(options);
  const sequence = new FrameSequence(settings);
  let totalBytes = 0;
  for (const supplied of frames) {
    settings.deadline.checkpoint();
    const frame = verifiedFrame(supplied, settings);
    sequence.accept(frame);
    const payload = canonicalBytes(frame, { maxBytes: settings.maxLineBytes, deadline: settings.deadline });
    if (payload.length > settings.maxLineBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream line ceiling exceeded');
    totalBytes += payload.length + 1;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > settings.maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'stream byte ceiling exceeded');
    await writeChunk(writable, Buffer.concat([payload, Buffer.from('\n')]), settings.deadline);
  }
  const summary = sequence.finish();
  return Object.freeze({ ...summary, bytes: totalBytes });
}
