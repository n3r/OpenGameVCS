import { createHash } from 'node:crypto';

const TABLE_DOMAIN = Buffer.from('OpenGameVCS Gear table v1\0', 'ascii');
const OBJECT_DOMAIN = Buffer.from('OpenGameVCS object\0', 'ascii');
const MASK64 = 0xffff_ffff_ffff_ffffn;
const MIN = 262144; const TARGET = 1048576; const MAX = 2097152;
const EARLY = 0x1f_ffffn; const LATE = 0x07_ffffn;

const sha = (bytes) => createHash('sha256').update(bytes).digest();
function u16(value) { const out = Buffer.alloc(2); out.writeUInt16BE(value); return out; }
function u64(value) { const out = Buffer.alloc(8); out.writeBigUInt64BE(BigInt(value)); return out; }
export const table = Object.freeze(Array.from({ length: 256 }, (_, index) => sha(Buffer.concat([TABLE_DOMAIN, u16(index)])).readBigUInt64BE(0)));
export const tableSha256 = sha(Buffer.concat(table.map(u64))).toString('hex');

export function materialize(recipe) {
  if (recipe.kind === 'literal') return Buffer.from(recipe.hex, 'hex');
  if (recipe.kind === 'repeat') return Buffer.alloc(recipe.length, recipe.byte);
  if (recipe.kind === 'sha256-counter') {
    const output = Buffer.alloc(recipe.length); let offset = 0; let counter = 0;
    while (offset < output.length) {
      const counterBytes = Buffer.alloc(8); counterBytes.writeBigUInt64BE(BigInt(counter));
      const blockDigest = sha(Buffer.concat([Buffer.from('OpenGameVCS chunk vector block v1\0'), Buffer.from(recipe.seed, 'utf8'), Buffer.from([0]), counterBytes]));
      const take = Math.min(blockDigest.length, output.length - offset);
      blockDigest.copy(output, offset, 0, take);
      offset += take; counter += 1;
    }
    return output;
  }
  if (recipe.kind === 'insert') {
    const base = materialize(recipe.base); const inserted = Buffer.from(recipe.hex, 'hex');
    return Buffer.concat([base.subarray(0, recipe.offset), inserted, base.subarray(recipe.offset)]);
  }
  throw new Error(`unknown recipe ${recipe.kind}`);
}

function cborHead(major, input) {
  const value = BigInt(input);
  if (value < 24n) return Buffer.from([(major << 5) | Number(value)]);
  if (value <= 255n) return Buffer.from([(major << 5) | 24, Number(value)]);
  if (value <= 65535n) { const out = Buffer.alloc(3); out[0] = (major << 5) | 25; out.writeUInt16BE(Number(value), 1); return out; }
  if (value <= 0xffff_ffffn) { const out = Buffer.alloc(5); out[0] = (major << 5) | 26; out.writeUInt32BE(Number(value), 1); return out; }
  const out = Buffer.alloc(9); out[0] = (major << 5) | 27; out.writeBigUInt64BE(value, 1); return out;
}
function cbor(value) {
  if (Number.isSafeInteger(value) && value >= 0) return cborHead(0, value);
  if (typeof value === 'string') { const bytes = Buffer.from(value); return Buffer.concat([cborHead(3, bytes.length), bytes]); }
  if (value instanceof Uint8Array) { const bytes = Buffer.from(value); return Buffer.concat([cborHead(2, bytes.length), bytes]); }
  if (Array.isArray(value)) return Buffer.concat([cborHead(4, value.length), ...value.map(cbor)]);
  if (value instanceof Map) {
    const entries = [...value].map(([key, item]) => [cbor(key), cbor(item)]).sort(([a], [b]) => a.length - b.length || Buffer.compare(a, b));
    return Buffer.concat([cborHead(5, entries.length), ...entries.flat()]);
  }
  throw new Error('unsupported CBOR reference value');
}
function objectDigest(kind, bytes) { return sha(Buffer.concat([OBJECT_DOMAIN, u16(1), u16(kind), bytes])); }
const objectText = (kind, digest) => `ogvcs:v1:${kind === 1 ? 'chunk' : 'content-manifest'}:sha256:${digest.toString('hex')}`;

export function calculate(bytes) {
  const boundaries = []; let fp = 0n; let start = 0;
  if (bytes.length > 262144) {
    for (let offset = 0; offset < bytes.length; offset += 1) {
      const length = offset - start + 1;
      fp = ((fp << 1n) + table[bytes[offset]]) & MASK64;
      if (length >= MIN) {
        const mask = length < TARGET ? EARLY : LATE;
        if ((fp & mask) === 0n || length === MAX) { boundaries.push(offset + 1); start = offset + 1; fp = 0n; }
      }
    }
  }
  if (bytes.length > 0 && boundaries.at(-1) !== bytes.length) boundaries.push(bytes.length);
  const parts = []; let prior = 0;
  for (const boundary of boundaries) {
    const chunk = bytes.subarray(prior, boundary); const digest = objectDigest(1, chunk);
    parts.push({ digest, length: chunk.length, objectId: objectText(1, digest) }); prior = boundary;
  }
  const whole = sha(bytes);
  const ref = (part) => new Map([[0, 1], [1, 1], [2, 1], [3, part.digest]]);
  const payload = cbor(new Map([[0, 1], [1, 2], [2, []], [16, bytes.length], [17, new Map([[0, 1], [1, whole]])], [18, new Map([[0, 'chunking.opengamevcs'], [1, 'gear-fastcdc-1m'], [2, 1]])], [19, parts.map((part) => new Map([[0, ref(part)], [1, part.length]]))]]));
  const manifestDigest = objectDigest(2, payload);
  return {
    boundaries,
    chunks: parts.map(({ digest, ...part }) => part),
    class: bytes.length === 0 ? 'empty' : bytes.length <= 262144 ? 'whole' : 'cdc-1m',
    logicalLength: bytes.length,
    manifestHex: payload.toString('hex'),
    manifestObjectId: objectText(2, manifestDigest),
    wholeFileSha256: whole.toString('hex'),
  };
}
