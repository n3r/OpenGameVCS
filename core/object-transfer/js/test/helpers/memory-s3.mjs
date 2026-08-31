import { createHash } from 'node:crypto';

const EMPTY_SHA256 = createHash('sha256').update('').digest('hex');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const xmlEscape = (value) => value.replace(/&/gu, '&amp;').replace(/</gu, '&lt;').replace(/>/gu, '&gt;')
  .replace(/"/gu, '&quot;').replace(/'/gu, '&apos;');

function response(status, body = null, headers = {}) {
  return new Response(body, { status, headers });
}

export class MemoryS3Service {
  constructor({ bucket = 'ogvcs-test', pageSize = 1000 } = {}) {
    this.bucket = bucket;
    this.bucketExists = false;
    this.objects = new Map();
    this.requests = [];
    this.pageSize = pageSize;
    this.responseLossAfterPut = 0;
    this.corruptNextBody = false;
    this.corruptNextMetadata = false;
    this.corruptAfterPut = false;
    this.hang = false;
  }

  fetch = async (input, options = {}) => {
    const url = input instanceof URL ? input : new URL(input);
    const headers = new Headers(options.headers);
    const method = options.method ?? 'GET';
    const authorization = headers.get('authorization');
    if (!authorization?.startsWith('AWS4-HMAC-SHA256 Credential=')) throw new Error('request is not SigV4 authenticated');
    if (headers.get('x-amz-content-sha256') === null || headers.get('x-amz-date') === null) {
      throw new Error('request omits signed S3 headers');
    }
    this.requests.push(Object.freeze({
      method,
      pathname: url.pathname,
      query: url.search,
      authorization,
      signedHeaders: Object.freeze([...headers.keys()].sort()),
    }));
    if (this.hang) {
      return new Promise((resolve, reject) => {
        const abort = () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
        if (options.signal?.aborted) abort();
        else options.signal?.addEventListener('abort', abort, { once: true });
      });
    }
    const segments = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    if (segments[0] !== this.bucket) return response(404);
    const key = segments.slice(1).join('/');
    if (key === '' && url.searchParams.get('list-type') === '2' && method === 'GET') {
      if (!this.bucketExists) return response(404);
      const prefix = url.searchParams.get('prefix') ?? '';
      const maximum = Math.max(1, Math.min(Number(url.searchParams.get('max-keys') ?? 1000), this.pageSize));
      const start = url.searchParams.has('continuation-token')
        ? Number(Buffer.from(url.searchParams.get('continuation-token'), 'base64url').toString('ascii')) : 0;
      if (!Number.isSafeInteger(start) || start < 0) return response(400);
      const keys = [...this.objects.keys()].filter((value) => value.startsWith(prefix)).sort();
      const page = keys.slice(start, start + maximum);
      const next = start + page.length;
      const truncated = next < keys.length;
      const xml = `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>${page.map((value) => `<Contents><Key>${xmlEscape(value)}</Key></Contents>`).join('')}<IsTruncated>${truncated}</IsTruncated>${truncated ? `<NextContinuationToken>${Buffer.from(String(next)).toString('base64url')}</NextContinuationToken>` : ''}</ListBucketResult>`;
      return response(200, xml, { 'content-type': 'application/xml' });
    }
    if (key === '') {
      if (method === 'HEAD') return response(this.bucketExists ? 200 : 404);
      if (method === 'PUT') { this.bucketExists = true; return response(200); }
      return response(405);
    }
    if (!this.bucketExists) return response(404);
    if (method === 'PUT') {
      const body = options.body === undefined ? Buffer.alloc(0) : Buffer.from(options.body);
      if (headers.get('x-amz-content-sha256') !== sha256(body)) return response(400);
      const existing = this.objects.get(key) ?? null;
      if (headers.get('if-none-match') === '*' && existing !== null) return response(412);
      const ifMatch = headers.get('if-match');
      if (ifMatch !== null && existing?.etag !== ifMatch) return response(412);
      const storedHeaders = {};
      for (const [name, value] of headers) {
        if (name.startsWith('x-amz-meta-') || name === 'x-amz-checksum-sha256' || name === 'content-type') {
          storedHeaders[name] = value;
        }
      }
      const etag = body.length > 1024 ? `"${sha256(body).slice(0, 24)}-2"` : `"${sha256(body)}"`;
      const storedBody = Buffer.from(body);
      if (this.corruptAfterPut && storedBody.length > 0) {
        this.corruptAfterPut = false;
        storedBody[0] ^= 1;
      }
      this.objects.set(key, Object.freeze({ body: storedBody, headers: Object.freeze(storedHeaders), etag }));
      if (this.responseLossAfterPut > 0) {
        this.responseLossAfterPut -= 1;
        throw new TypeError('simulated response loss');
      }
      return response(200, null, { etag });
    }
    const stored = this.objects.get(key) ?? null;
    if (method === 'DELETE') {
      this.objects.delete(key);
      return response(stored ? 204 : 404);
    }
    if (!stored) return response(404);
    const outputHeaders = {
      ...stored.headers,
      etag: stored.etag,
      'content-length': String(stored.body.length),
    };
    if (this.corruptNextMetadata) {
      this.corruptNextMetadata = false;
      outputHeaders['x-amz-meta-ogvcs-length'] = String(stored.body.length + 1);
    }
    if (method === 'HEAD') return response(200, null, outputHeaders);
    if (method === 'GET') {
      let body = Buffer.from(stored.body);
      if (this.corruptNextBody && body.length > 0) {
        this.corruptNextBody = false;
        body[0] ^= 1;
      }
      outputHeaders['content-length'] = String(body.length);
      return response(200, body, outputHeaders);
    }
    return response(405);
  };

  assertNoCredentialLeak(secret) {
    const serialized = JSON.stringify(this.requests);
    if (serialized.includes(secret)) throw new Error('credential leaked into a captured request');
  }

  corruptObjectBody(key) {
    const existing = this.objects.get(key);
    if (!existing || existing.body.length < 1) throw new Error('object is absent');
    const body = Buffer.from(existing.body);
    body[0] ^= 1;
    this.objects.set(key, Object.freeze({ ...existing, body }));
  }

  static emptySha256 = EMPTY_SHA256;
}
