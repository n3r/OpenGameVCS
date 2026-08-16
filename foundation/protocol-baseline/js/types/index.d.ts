import type {
  AdapterResult,
  AdapterTrace,
  RunnerCase,
  RunnerConfiguredLimits,
  RunnerExecutionControl,
  RunnerReport,
  RunnerResult,
} from '@opengamevcs/protocol-types-v1';

export type {
  AdapterResult,
  AdapterTrace,
  RunnerCase,
  RunnerConfiguredLimits,
  RunnerExecutionControl,
  RunnerReport,
  RunnerResult,
} from '@opengamevcs/protocol-types-v1';

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export interface RuntimeOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
  deadline?: Deadline;
  now?: () => number;
  atUnixMs?: number;
  [key: string]: unknown;
}

export interface ProtocolContract {
  readonly manifest: JsonObject;
  readonly manifestSha256: string;
  readonly root: string;
  readonly schemas: Readonly<Record<string, JsonObject>>;
  readonly registries: Readonly<Record<string, JsonObject>>;
  readonly vectors: Readonly<Record<string, JsonObject>>;
  readonly profiles: Readonly<Record<string, JsonObject>>;
  readonly validator: ProtocolSchemaValidator;
  readonly totalBytes: number;
  readonly workingMemoryBytes: number;
}

export const JSON_LIMITS: Readonly<Record<string, number>>;
export const HARD_LIMITS: Readonly<Record<string, number>>;
export const PROTOCOL_LIMITS_BY_NAME: Readonly<Record<string, number>>;
export const RUNTIME_ERROR_CODES: Readonly<Record<string, string>>;
export const RUNTIME_TO_WIRE: Readonly<Record<string, string>>;
export const PROTOCOL_OPERATIONS: readonly string[];
export const NEGOTIATION_AXES: readonly (readonly [string, string])[];

export class ProtocolBaselineError extends Error {
  readonly code: string; readonly exitCode: number; readonly preMutation: boolean; readonly details?: Readonly<Record<string, JsonPrimitive>>;
  toJSON(): Readonly<{ code: string; safeClass: 'input' | 'contract' | 'resource' | 'state' | 'stream' | 'adapter' | 'io'; preMutation: boolean }>;
}
export class ProtocolSemanticError extends Error { readonly code: string; readonly preMutation: true; toJSON(): JsonObject; }
export function protocolError(code: string, message: string, options?: RuntimeOptions): never;
export function protocolSemanticError(code: string, message: string, options?: RuntimeOptions): never;
export function asProtocolError(error: unknown, code?: string, message?: string): ProtocolBaselineError;

export class Deadline {
  constructor(options?: RuntimeOptions);
  checkpoint(): void;
  readonly signal: AbortSignal;
  remainingMs(): number;
  race<T>(promise: PromiseLike<T> | T, label?: string): Promise<T>;
}
export function deadlineFrom(options?: RuntimeOptions): Deadline;
export function boundedInteger(value: unknown, fallback: number, maximum: number, label: string, options?: { minimum?: number }): number;

export function inspectJson(value: JsonValue, options?: RuntimeOptions): Readonly<{ nodes: number; encodedBytes: number; collectionItems: number }>;
export function canonicalJson(value: JsonValue, options?: RuntimeOptions): string;
export function canonicalBytes(value: JsonValue, options?: RuntimeOptions): Uint8Array;
export function parseJson(input: string | Uint8Array, options?: RuntimeOptions): JsonValue;
export function parseCanonicalJson(input: string | Uint8Array, options?: RuntimeOptions): JsonValue;
export function cloneJson<T extends JsonValue>(value: T, options?: RuntimeOptions): T;
export function base64urlDecode(value: string, options?: RuntimeOptions): Uint8Array;

export class ProtocolSchemaValidator {
  constructor(schemas: Map<string, JsonObject> | Record<string, JsonObject>);
  schema(selector: string | JsonObject): JsonObject;
  validate<T extends JsonValue>(value: T, selector: string | JsonObject, options?: RuntimeOptions): T;
}
export function validateProtocolValue<T extends JsonValue>(contract: ProtocolContract, selector: string | JsonObject, value: T, options?: RuntimeOptions): T;
export function loadProtocolContract(options?: RuntimeOptions & { root?: string | URL; cache?: boolean }): Promise<ProtocolContract>;
export function clearProtocolContractCacheForTest(): void;

export function validateRequestEnvelope(contract: ProtocolContract, input: JsonObject, options?: RuntimeOptions): JsonObject;
export function validateResponseEnvelope(contract: ProtocolContract, input: JsonObject, options?: RuntimeOptions): JsonObject;
export function parseRequestEnvelope(contract: ProtocolContract, input: string | Uint8Array, options?: RuntimeOptions): JsonObject;
export function parseResponseEnvelope(contract: ProtocolContract, input: string | Uint8Array, options?: RuntimeOptions): JsonObject;
export function encodeRequestEnvelope(contract: ProtocolContract, input: JsonObject, options?: RuntimeOptions): Uint8Array;
export function encodeResponseEnvelope(contract: ProtocolContract, input: JsonObject, options?: RuntimeOptions): Uint8Array;

export function semanticIdempotencyFingerprint(projection: JsonValue, options?: RuntimeOptions): string;
export function requestIdempotencyProjection(request: JsonObject, options?: RuntimeOptions & { contract?: ProtocolContract }): JsonObject;
export function createIdempotencyDescriptor(contract: ProtocolContract, key: string, request: JsonObject, options?: RuntimeOptions): JsonObject;
export function validateIdempotencyDescriptor(contract: ProtocolContract, descriptor: JsonObject, request: JsonObject, options?: RuntimeOptions): JsonObject;
export class IdempotencyReplayStore {
  constructor(options?: RuntimeOptions);
  begin(input: JsonObject, options?: RuntimeOptions): Readonly<JsonObject>;
  commit(lease: object, outcome: JsonValue, options?: RuntimeOptions): Readonly<JsonObject>;
  abort(lease: object, error?: Error): boolean;
  execute(input: JsonObject, mutate: () => Promise<JsonValue> | JsonValue, options?: RuntimeOptions): Promise<Readonly<JsonObject>>;
  summary(): Readonly<{ entries: number; pending: number; memoryBytes: number }>;
}

export class CursorStore {
  constructor(options?: RuntimeOptions);
  issue(input: JsonObject, options?: RuntimeOptions): Readonly<{ token: string; issuedAt: number; expiresAt: number }>;
  issuePublic(contract: ProtocolContract, input: JsonObject, options?: RuntimeOptions): JsonObject;
  read(token: string, scope: JsonObject, options?: RuntimeOptions): JsonObject;
  readPublic(contract: ProtocolContract, cursor: JsonObject, scope: JsonObject, options?: RuntimeOptions): JsonObject;
  advance(token: string, scope: JsonObject, next: JsonObject, options?: RuntimeOptions): Readonly<{ token: string; issuedAt: number; expiresAt: number }>;
  markGap(token: string, gapCode: string, options?: RuntimeOptions): void;
  summary(): Readonly<{ entries: number; memoryBytes: number }>;
}
export function validateCursor(contract: ProtocolContract, input: JsonObject, options?: RuntimeOptions): JsonObject;
export function validatePageEnvelope(contract: ProtocolContract, input: JsonObject, options?: RuntimeOptions): JsonObject;
export function createPageEnvelope(contract: ProtocolContract, input: JsonObject, options?: RuntimeOptions): JsonObject;

export interface WritableLike { write(chunk: Uint8Array, callback: (error?: Error | null) => void): unknown; once?(event: string, listener: (...args: unknown[]) => void): unknown; removeListener?(event: string, listener: (...args: unknown[]) => void): unknown; }
export function encodeStreamFrame(frame: JsonObject, options?: RuntimeOptions & { contract?: ProtocolContract }): Uint8Array;
export function parseCanonicalStream(input: string | Uint8Array, options?: RuntimeOptions & { contract?: ProtocolContract }): Readonly<{ frames: JsonObject[]; summary: JsonObject }>;
export function writeCanonicalStream(frames: Iterable<JsonObject>, writable: WritableLike, options?: RuntimeOptions & { contract?: ProtocolContract }): Promise<Readonly<JsonObject>>;

export interface AuthorizationGrantContract { readonly manifest: JsonObject; readonly manifestSha256: string; readonly registrySetSha256: string; readonly root: string; readonly validator: ProtocolSchemaValidator; }
export function loadAuthorizationGrantContract(options?: RuntimeOptions & { root?: string | URL; cache?: boolean }): Promise<AuthorizationGrantContract>;
export function clearAuthorizationGrantCacheForTest(): void;
export function inspectRequestRootGrant(envelope: JsonObject, authorizationContract: AuthorizationGrantContract, options?: RuntimeOptions): Readonly<JsonObject>;
export function validateRequestRootGrant(envelope: JsonObject, authorizationContract: AuthorizationGrantContract, verifyGrant: (envelope: JsonObject, context: JsonObject) => unknown, context: JsonObject, options?: RuntimeOptions): Promise<Readonly<JsonObject>>;
export function createCompactTransferGrant(contract: ProtocolContract, authorizationContract: AuthorizationGrantContract, envelope: JsonObject, options?: RuntimeOptions): JsonObject;
export function decodeCompactTransferGrant(contract: ProtocolContract, authorizationContract: AuthorizationGrantContract, carrier: JsonObject, options?: RuntimeOptions): Readonly<JsonObject>;
export function validateCompactTransferGrant(contract: ProtocolContract, authorizationContract: AuthorizationGrantContract, carrier: JsonObject, verifyGrant: (envelope: JsonObject, context: JsonObject) => unknown, context: JsonObject, options?: RuntimeOptions): Promise<Readonly<JsonObject>>;

export function strongRepresentationValidator(bytes: Uint8Array, options?: RuntimeOptions): string;
export function rfc9530Sha256(bytes: Uint8Array, options?: RuntimeOptions): string;
export function validateTransferProbe(contract: ProtocolContract, input: JsonObject, options?: RuntimeOptions): JsonObject;
export function validateTransferProbeResult(contract: ProtocolContract, input: JsonObject, options?: RuntimeOptions): JsonObject;
export function validateTransferHttpRangeCarrier(contract: ProtocolContract, input: JsonObject, options?: RuntimeOptions): JsonObject;
export class SyntheticTransferProbe {
  constructor(representation: Uint8Array, options?: RuntimeOptions);
  descriptor(): Readonly<JsonObject>;
  read(request: JsonObject, options?: RuntimeOptions): Readonly<JsonObject>;
  verifyComplete(parts: string[], options?: RuntimeOptions): Readonly<JsonObject>;
  execute(contract: ProtocolContract, probe: JsonObject, options: RuntimeOptions & { authorizationContract: AuthorizationGrantContract; authorizationContext: JsonObject; verifyGrant: (envelope: JsonObject, context: JsonObject, options?: RuntimeOptions) => unknown }): Promise<JsonObject>;
}

export class MacReceiptCodec { constructor(options: RuntimeOptions); issue(claims: JsonObject, options?: RuntimeOptions): string; verify(token: string, bindings: JsonObject, options?: RuntimeOptions): JsonObject; }
export class NegotiationReceiptCodec { constructor(options: RuntimeOptions & { contract: ProtocolContract }); issue(claims: JsonObject, options?: RuntimeOptions): JsonObject; verify(receipt: JsonObject, bindings: JsonObject, options?: RuntimeOptions): JsonObject; }
export function buildBaselineOffer(contract: ProtocolContract, options?: RuntimeOptions): JsonObject;
export class ProtocolNegotiator { constructor(options: RuntimeOptions & { contract: ProtocolContract }); negotiate(offer: JsonObject, context?: JsonObject, options?: RuntimeOptions): Promise<Readonly<JsonObject>>; verifyMutationReceipt(receipt: JsonObject, principal: JsonObject, options?: RuntimeOptions): JsonObject; }

export class ProtocolProblemCatalog { constructor(contract: ProtocolContract); entry(code: string): JsonObject; create(code: string, options?: RuntimeOptions): JsonObject; fromRuntimeError(error: unknown, options?: RuntimeOptions): JsonObject; validate(problem: JsonObject, http?: JsonObject, options?: RuntimeOptions): JsonObject; responseHeaders(problem: JsonObject, options?: RuntimeOptions): ReadonlyArray<Readonly<{ name: string; value: string }>>; response(code: string, options?: RuntimeOptions): JsonObject; success(correlationId: string, body: JsonValue, options?: RuntimeOptions): JsonObject; }

export class BoundedLoopbackServer { constructor(options: RuntimeOptions); exchange(input: string | Uint8Array, options?: RuntimeOptions): Promise<Uint8Array>; }
export class BoundedLoopbackClient { constructor(options: RuntimeOptions); call(value: JsonObject, options?: RuntimeOptions): Promise<JsonObject>; }
export function createBoundedLoopback(options: RuntimeOptions): Readonly<{ client: BoundedLoopbackClient; server: BoundedLoopbackServer }>;

export function collectProtocolScenarios(contract: ProtocolContract, options?: RuntimeOptions): readonly JsonObject[];
export function scenarioForAdapter(scenario: JsonObject, contract?: ProtocolContract, options?: RuntimeOptions): RunnerCase;
export function createRunnerHello(contract: ProtocolContract, adapterId: string, options?: RuntimeOptions): JsonObject;
export function executeReferenceProtocolCase(input: RunnerCase, context: RuntimeOptions & { contract: ProtocolContract }): Promise<AdapterResult>;
export function runProtocolConformance(contract: ProtocolContract, evaluator: (input: RunnerCase, context: RuntimeOptions & { contract: ProtocolContract }) => Promise<AdapterResult> | AdapterResult, options: RuntimeOptions & { adapterId?: string; implementation?: string }): Promise<RunnerReport>;
export function runReferenceProtocolConformance(contract: ProtocolContract, options?: RuntimeOptions & { adapterId?: string }): Promise<RunnerReport>;
export function runExternalProtocolConformance(contract: ProtocolContract, adapter: string[] | { command: string; args?: string[]; env?: Record<string, string> }, options?: RuntimeOptions & { expectedAdapterId?: string; nodeAdapterReadRoots?: string[] }): Promise<RunnerReport>;
