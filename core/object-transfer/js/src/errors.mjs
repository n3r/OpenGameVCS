export class ObjectTransferError extends Error {
  constructor(code, message = code, options = {}) { super(message, options); this.name = 'ObjectTransferError'; this.code = code; }
}

export function transferError(code, message, options) { throw new ObjectTransferError(code, message, options); }

export function mapIo(error, message = 'object-transfer filesystem operation failed') {
  if (error instanceof ObjectTransferError) throw error;
  transferError('TRANSFER_BACKEND_IO', message, { cause: error });
}
