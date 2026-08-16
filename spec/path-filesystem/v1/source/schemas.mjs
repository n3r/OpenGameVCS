const string = (extra = {}) => ({ type: 'string', ...extra });
const integer = (minimum = 0, extra = {}) => ({ type: 'integer', minimum, ...extra });
const closed = (properties, required = Object.keys(properties)) => ({
  type: 'object', additionalProperties: false, required, properties,
});

const errorCode = string({ pattern: '^[A-Z][A-Z0-9_]*$' });
const profileRef = string({ pattern: '^path\\.opengamevcs/[a-z][a-z0-9-]*@1$' });
const relativePath = string({ minLength: 1, maxLength: 4096 });

export const registrySchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://opengamevcs.dev/schemas/path/v1/registry.schema.json',
  title: 'OpenGameVCS path contract registry',
  ...closed({
    schemaVersion: { const: 'ogvcs.path/registry/v1' },
    registry: string({ pattern: '^[a-z][a-z0-9-]*$' }),
    version: { const: 1 },
    entries: { type: 'array', minItems: 1, maxItems: 256, items: { type: 'object' } },
  }),
};

export const pathResultSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://opengamevcs.dev/schemas/path/v1/path-result.schema.json',
  title: 'OpenGameVCS joined-path result',
  oneOf: [
    closed({
      accepted: { const: true }, canonical: relativePath,
      segments: { type: 'array', minItems: 1, maxItems: 256, items: string({ minLength: 1, maxLength: 255 }) },
      measures: closed({ depth: integer(1, { maximum: 256 }), joinedUtf8Bytes: integer(1, { maximum: 4096 }), joinedUtf16Units: integer(1, { maximum: 4096 }) }),
      repositoryKey: string({ minLength: 1, maxLength: 32768 }),
      platformKey: string({ minLength: 1, maxLength: 32768 }),
    }),
    closed({ accepted: { const: false }, error: errorCode, detail: { type: 'object' } }, ['accepted', 'error']),
  ],
};

export const preflightRequestSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://opengamevcs.dev/schemas/path/v1/preflight-request.schema.json',
  title: 'OpenGameVCS materialization preflight request',
  ...closed({
    schemaVersion: { const: 'ogvcs.path/preflight-request/v1' },
    caseMode: { enum: ['case-sensitive', 'case-folded'] },
    profile: profileRef,
    platform: { enum: ['linux', 'macos', 'windows'] },
    capabilities: closed({ atomicReplace: { type: 'boolean' }, executableBit: { type: 'boolean' }, symlink: { type: 'boolean' } }),
    entries: {
      type: 'array', maxItems: 100000,
      items: closed({
        id: string({ minLength: 1, maxLength: 256, pattern: '^[A-Za-z0-9._:-]+$' }), path: relativePath,
        kind: { enum: ['directory', 'regular', 'executable', 'symlink'] },
        mode: { enum: ['directory', 'regular-file', 'executable-file', 'symlink'] },
        symlinkTarget: string({ minLength: 1, maxLength: 4096 }),
      }, ['id', 'path', 'kind', 'mode']),
    },
  }),
};

export const preflightResultSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://opengamevcs.dev/schemas/path/v1/preflight-result.schema.json',
  title: 'OpenGameVCS materialization preflight result',
  oneOf: [
    closed({
      accepted: { const: true },
      summary: closed({
        entries: integer(0, { maximum: 100000 }), executable: integer(0, { maximum: 100000 }),
        symlinks: integer(0, { maximum: 100000 }), nativeExecutableBits: integer(0, { maximum: 100000 }),
        planSha256: string({ pattern: '^[0-9a-f]{64}$' }),
      }),
    }),
    closed({ accepted: { const: false }, error: errorCode, detail: { type: 'object' } }, ['accepted', 'error']),
  ],
};

export const watcherStateSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://opengamevcs.dev/schemas/path/v1/watcher-state.schema.json',
  title: 'OpenGameVCS watcher reconciliation state',
  ...closed({
    schemaVersion: { const: 'ogvcs.path/watcher-state/v1' },
    adapter: string({ minLength: 1, maxLength: 128 }),
    cursor: { oneOf: [{ type: 'null' }, string({ minLength: 1, maxLength: 4096 })] },
    generation: integer(0),
    session: { oneOf: [{ type: 'null' }, string({ minLength: 1, maxLength: 256 })] },
    authoritativeClean: { type: 'boolean' },
    reconciliationRequired: { type: 'boolean' },
    reason: { oneOf: [{ type: 'null' }, { enum: ['initial-scan', 'overflow', 'cursor-gap', 'unclean-shutdown', 'adapter-error', 'state-corrupt'] }] },
  }),
};

export const renamePlanSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://opengamevcs.dev/schemas/path/v1/rename-plan.schema.json',
  title: 'OpenGameVCS two-phase rename plan',
  oneOf: [
    closed({
      accepted: { const: true }, caseMode: { enum: ['case-sensitive', 'case-folded'] }, profile: profileRef,
      transaction: string({ pattern: '^[0-9a-f]{24}$' }),
      steps: { type: 'array', maxItems: 200000, items: closed({ from: relativePath, to: relativePath, fileId: string({ pattern: '^[0-9a-f]{32}$' }), phase: { enum: ['stage', 'publish'] } }) },
    }, ['accepted', 'caseMode', 'profile', 'transaction', 'steps']),
    closed({ accepted: { const: false }, error: errorCode, detail: { type: 'object' } }, ['accepted', 'error']),
  ],
};

export const conformanceReportSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://opengamevcs.dev/schemas/path/v1/conformance-report.schema.json',
  title: 'OpenGameVCS path/filesystem conformance report',
  ...closed({
    schemaVersion: { const: 'ogvcs.path/conformance-report/v1' },
    contractVersion: { const: '1.0.0' },
    implementation: closed({ name: string({ minLength: 1, maxLength: 128 }), version: string({ minLength: 1, maxLength: 64 }), runtime: string({ minLength: 1, maxLength: 256 }) }),
    platform: { enum: ['linux', 'macos', 'windows'] },
    capabilities: closed({
      atomicReplace: { type: 'boolean' }, casePreserving: { type: 'boolean' },
      caseSensitive: { type: 'boolean' }, directorySync: { type: 'boolean' },
      executableBit: { type: 'boolean' }, hardlink: { type: 'boolean' },
      normalizationSensitive: { type: 'boolean' }, symlink: { type: 'boolean' },
    }),
    manifestSha256: string({ pattern: '^[0-9a-f]{64}$' }),
    registrySetSha256: string({ pattern: '^[0-9a-f]{64}$' }),
    unicodeCaseFoldingSha256: string({ pattern: '^[0-9a-f]{64}$' }),
    resultsSha256: string({ pattern: '^[0-9a-f]{64}$' }),
    total: integer(1), passed: integer(0), failed: integer(0),
    results: { type: 'array', minItems: 1, maxItems: 1000, items: closed({ id: string({ minLength: 1, maxLength: 256 }), category: string({ minLength: 1, maxLength: 64 }), passed: { type: 'boolean' }, expectedSha256: string({ pattern: '^[0-9a-f]{64}$' }), actualSha256: string({ pattern: '^[0-9a-f]{64}$' }) }) },
  }),
};

export const allSchemas = Object.freeze({
  'conformance-report.schema.json': conformanceReportSchema,
  'path-result.schema.json': pathResultSchema,
  'preflight-request.schema.json': preflightRequestSchema,
  'preflight-result.schema.json': preflightResultSchema,
  'registry.schema.json': registrySchema,
  'rename-plan.schema.json': renamePlanSchema,
  'watcher-state.schema.json': watcherStateSchema,
});
