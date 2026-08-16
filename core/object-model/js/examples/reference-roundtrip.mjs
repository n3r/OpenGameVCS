import {
  ObjectRef,
  createObjectHashWriter,
  equalBytes,
  hashObject,
  toHex
} from '@opengamevcs/object-model';

const payload = new TextEncoder().encode('OpenGameVCS public package example\n');
const direct = hashObject(1, payload);
const writer = createObjectHashWriter(1);
writer.update(payload.subarray(0, 7));
writer.update(payload.subarray(7));
const streamed = writer.finish();
const parsed = ObjectRef.parse(direct.toString());

if (!equalBytes(direct.digest, streamed.digest) || !equalBytes(direct.digest, parsed.digest)) {
  throw new Error('public reference round trip changed the identity');
}

process.stdout.write(`${JSON.stringify({
  bytes: payload.length,
  digestHex: toHex(direct.digest),
  objectRef: direct.toString(),
  status: 'valid'
})}\n`);
