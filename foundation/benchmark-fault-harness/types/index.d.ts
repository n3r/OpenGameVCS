export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type HarnessCode = 'HARNESS_OK' | 'HARNESS_INPUT_INVALID' | 'HARNESS_LIMIT_EXCEEDED' | 'HARNESS_NEGOTIATION_INCOMPATIBLE' | 'HARNESS_PROTOCOL_MALFORMED' | 'HARNESS_DRIVER_FAILED' | 'HARNESS_RETRYABLE' | 'HARNESS_TASK_INCOMPLETE' | 'HARNESS_ASSERTION_FAILED' | 'HARNESS_FAULT_INVARIANT_FAILED' | 'HARNESS_THRESHOLD_FAILED' | 'HARNESS_BUNDLE_INVALID' | 'HARNESS_CACHE_STATE_INVALID' | 'HARNESS_PRIVILEGE_REQUIRED' | 'HARNESS_DEADLINE_EXCEEDED' | 'HARNESS_CANCELLED' | 'HARNESS_IO';
export type TaskId = 'setup' | 'status' | 'sync' | 'submit' | 'lock' | 'merge' | 'ci' | 'verify' | 'backup' | 'restore' | 'export' | 'chunking-verify';
export type CacheState = 'cold' | 'warm-local-cache' | 'warm-regional-cache' | 'mixed-cache';
export type HarnessProfile = 'local-smoke' | 'presubmit' | 'nightly' | 'release' | 'chunking-selection-bounded';

export class BenchmarkHarnessError extends Error { readonly code: Exclude<HarnessCode, 'HARNESS_OK'>; readonly details?: Readonly<Record<string, unknown>>; }
export const HARNESS_ERROR_CODES: readonly HarnessCode[];
export const HARNESS_LIMITS: Readonly<Record<string, number>>;
export function asHarnessError(error: unknown, fallback?: Exclude<HarnessCode, 'HARNESS_OK'>): BenchmarkHarnessError;
export function harnessFail(code: Exclude<HarnessCode, 'HARNESS_OK'>, message: string, options?: { cause?: unknown; details?: Record<string, unknown> }): never;
export function boundedInteger(value: number | undefined, fallback: number, maximum: number, name: string, minimum?: number): number;
export function checkedAdd(left: number, right: number, label?: string): number;

export class HarnessDeadline { constructor(options?: { timeoutMs?: number; signal?: AbortSignal; now?: () => number }); readonly signal: AbortSignal; checkpoint(): void; remaining(): number; race<T>(promise: PromiseLike<T> | T, label?: string): Promise<T>; }
export function canonicalJson(value: JsonValue, options?: { maxBytes?: number; maxNodes?: number; maxDepth?: number; maxWorkingMemoryBytes?: number }): string;
export function canonicalBytes(value: JsonValue, options?: { maxBytes?: number; maxNodes?: number; maxDepth?: number; maxWorkingMemoryBytes?: number }): Uint8Array;
export function canonicalDigest(value: JsonValue, domain?: string): string;
export function cloneData<T extends JsonValue>(value: T): T;
export function deepFreeze<T>(value: T): Readonly<T>;
export function parseLargeCanonical(input: string | Uint8Array, options?: { maxBytes?: number; maxWorkingMemoryBytes?: number }): JsonValue;
export function sha256(bytes: string | Uint8Array): string;

export interface BenchmarkContract { readonly manifestSha256: string; readonly root: string; readonly manifest: JsonValue; readonly registries: Readonly<Record<string, { readonly entries: readonly any[] }>>; readonly profiles: Readonly<Record<string, any>>; readonly thresholds: Readonly<Record<string, any>>; readonly vectors: Readonly<Record<string, any>>; readonly validator: { validate(value: unknown, selector: string, options?: unknown): any }; }
export function loadBenchmarkContract(options?: { root?: string | URL; cache?: boolean; timeoutMs?: number; signal?: AbortSignal; maxAssetBytes?: number; maxArtifacts?: number; maxContractBytes?: number; maxWorkingMemoryBytes?: number }): Promise<BenchmarkContract>;
export function clearBenchmarkContractCacheForTest(): void;
export function validateBenchmarkValue<T>(contract: BenchmarkContract, selector: string, value: T, options?: unknown): T;

export class DeterministicRandom { constructor(seed: string); integer(maximumExclusive: number): number; bytes(length: number): Uint8Array; shuffle<T>(values: readonly T[]): T[]; }
export interface FaultSchedule { readonly schemaVersion: 'ogvcs.benchmark/fault-schedule/v1'; readonly seedDigest: string; readonly scheduleDigest: string; readonly events: readonly { ordinal: number; faultPoint: string; action: string; occurrence: number }[]; }
export class InjectedFault extends BenchmarkHarnessError { readonly event: FaultSchedule['events'][number]; }
export class FaultScheduler { constructor(schedule: FaultSchedule); readonly schedule: FaultSchedule; point(faultPoint: string, phase?: 'before' | 'after'): readonly FaultSchedule['events'][number][]; observed(): readonly (FaultSchedule['events'][number] & { phase: string })[]; }
export function createFaultSchedule(seed: string, faultPointIds: readonly string[], options?: { count?: number; actions?: readonly string[]; shuffle?: boolean; occurrence?: number }): FaultSchedule;
export function isInjectedFault(error: unknown): error is InjectedFault;

export interface CacheInspection { readonly state: CacheState; readonly localBytes: number; readonly regionalBytes: number; readonly reads: number; readonly localHits: number; readonly regionalHits: number; readonly originBytes: number; readonly stateDigest: string; }
export class DeterministicCacheController { constructor(options?: { maxBytes?: number }); prepare(state: CacheState): CacheInspection; read(bytes: number): CacheInspection; inspect(): CacheInspection; }
export function registeredCacheStates(): CacheState[];
export interface NetworkProfile { readonly id: string; readonly mode: 'simulated' | 'privileged'; readonly rttMs: number; readonly bandwidthBytesPerSecond: number; readonly lossPartsPerMillion: number; readonly interruptionEvery: number; readonly duplicateEvery: number; readonly reorderWindow: number; }
export class NetworkController { constructor(profile: NetworkProfile, options?: { allowPrivileged?: boolean; adapter?: { isolated: true; apply(profile: NetworkProfile): void; reset(): void }; signal?: AbortSignal; simulateDelay?: boolean }); planTransfer(bytes: number, direction?: 'send' | 'receive'): Readonly<{ delayMicroseconds: number; effects: readonly string[]; retries: number; wireBytes: number }>; transfer(bytes: number, direction?: 'send' | 'receive', signal?: AbortSignal): Promise<Readonly<{ delayMicroseconds: number; effects: readonly string[]; retries: number; wireBytes: number }>>; inspect(): Readonly<Record<string, unknown>>; reset(): void; }

export interface BenchmarkSample { readonly schemaVersion: 'ogvcs.benchmark/sample/v1'; readonly id: string; readonly taskId: TaskId; readonly corpusId: string; readonly repetition: number; readonly cacheState: CacheState; readonly networkProfile: string; readonly status: 'success' | 'failed' | 'incomplete'; readonly failureCode: HarnessCode | null; readonly wallMicroseconds: number; readonly cpuMicroseconds: number; readonly peakMemoryBytes: number; readonly diskReadBytes: number; readonly diskWriteBytes: number; readonly networkReadBytes: number; readonly networkWriteBytes: number; readonly logicalBytes: number; readonly uniqueBytes: number; readonly retries: number; readonly assertions: readonly { id: string; passed: boolean }[]; readonly faultScheduleDigest: string | null; }
export interface TaskSummary { readonly schemaVersion: 'ogvcs.benchmark/task-summary/v1'; readonly taskId: TaskId; readonly corpusId: string; readonly cacheState: CacheState; readonly networkProfile: string; readonly [key: string]: JsonValue; }
export interface BenchmarkCorpus { readonly id: string; readonly verified: true; readonly logicalBytes: number; readonly [key: string]: unknown; }
export interface BenchmarkTaskService {
  snapshot(): any;
  /** Must observe input.signal and settle after it aborts. Use ExternalDriverSession for non-cooperative or untrusted implementations. */
  executeTask(taskId: TaskId, input: Readonly<Record<string, unknown> & { signal: AbortSignal }>): Promise<any>;
}
export interface BenchmarkMatrixOptions {
  readonly contract: BenchmarkContract;
  readonly corpora: readonly BenchmarkCorpus[];
  readonly harnessProfile?: HarnessProfile;
  readonly iterations?: number;
  readonly concurrency?: number;
  readonly taskTimeoutMs?: number;
  readonly maxWorkingMemoryBytes?: number;
  readonly signal?: AbortSignal;
  readonly seed?: string;
  readonly serviceFactory?: (context: Readonly<Record<string, unknown>>) => BenchmarkTaskService | Promise<BenchmarkTaskService>;
  readonly [key: string]: unknown;
}
export function nearestRank(values: readonly number[], percentile: number): number;
export function medianAbsoluteDeviation(values: readonly number[]): number;
export function summarizeSamples(samples: readonly BenchmarkSample[]): readonly TaskSummary[];
export function measureTask<T>(operation: () => Promise<T> | T, options?: { clock?: () => bigint; cpu?: () => { user: number; system: number }; memory?: () => number; sampleIntervalMs?: number }): Promise<Readonly<{ value: T; wallMicroseconds: number; cpuMicroseconds: number; peakMemoryBytes: number }>>;
export function measureHarnessOverhead(options?: { iterations?: number; baselineMicroseconds?: number[]; wrappedMicroseconds?: number[] }): Promise<Readonly<{ measuredBasisPoints: number; correctionApplied: boolean; correctionMicroseconds: number; method: string }>>;
export function validateHarnessOverhead(value: { measuredBasisPoints: number; correctionApplied: boolean; correctionMicroseconds: number; method: string }): Readonly<{ measuredBasisPoints: number; correctionApplied: boolean; correctionMicroseconds: number; method: string }>;

export const REFERENCE_CORPORA: readonly string[];
export function materializeReferenceCorpora(root: string, options?: Record<string, unknown>): Promise<readonly any[]>;
export function loadReferenceCorpus(root: string, destination: string): Promise<any>;
export class FakeRepositoryService { constructor(options?: { brokenMode?: string }); setFaultScheduler(scheduler: FaultScheduler): void; mutationCount(): number; snapshot(): Readonly<JsonValue>; snapshotDigest(): string; executeTask(taskId: TaskId, input?: Record<string, unknown>): Promise<any>; }
export function checkRepositoryInvariants(stateOrService: unknown): Readonly<{ passed: boolean; checks: readonly { id: string; passed: boolean }[] }>;
export function proveFaultDeterminism(contract: BenchmarkContract, seed?: string): Readonly<{ deterministic: boolean; schedule: FaultSchedule }>;
export function runFaultMatrix(contract: BenchmarkContract, options?: { seed?: string }): Promise<any>;
export function runBrokenServiceSelfTest(contract: BenchmarkContract): Promise<any>;
export function runSecurityNegativeSuites(): Promise<any>;
export function redactPublicData(value: JsonValue): Readonly<{ value: JsonValue; credentialsRemoved: number; partnerIdentifiersHashed: number }>;

export interface ResultPublication { readonly result: any; readonly evidenceReport: any; readonly environmentRecords: readonly any[]; readonly samples: readonly BenchmarkSample[]; readonly summaries: readonly TaskSummary[]; readonly conformanceReport?: any; }
export function buildResultBundle(contract: BenchmarkContract, matrix: any, options: Record<string, unknown> & { evidenceReport: unknown }): ResultPublication;
export function writeResultBundle(directory: string, contract: BenchmarkContract, publication: ResultPublication): Promise<Readonly<{ directory: string; manifest: any; postCommitWarnings: readonly any[] }>>;
export function verifyResultBundle(directory: string, contract: BenchmarkContract): Promise<Readonly<{ verified: true; manifest: any; result: any; evidenceReport: any; environmentRecords: readonly any[]; samples: readonly BenchmarkSample[]; summaries: readonly TaskSummary[]; conformance: any }>>;
export function compareResultBundles(contract: BenchmarkContract, baseline: Pick<ResultPublication, 'result' | 'summaries' | 'environmentRecords'>, candidate: Pick<ResultPublication, 'result' | 'summaries' | 'environmentRecords'>, options?: { tolerancePartsPerMillion?: number }): any;

export class ExternalDriverSession { readonly contract: BenchmarkContract; readonly hello: any; readonly results: readonly any[]; command(operation: string, payload?: JsonValue, options?: { retry?: boolean }): Promise<any>; close(options?: { sendStop?: boolean }): Promise<void>; abort(): Promise<void>; }
export function startExternalDriver(adapter: readonly string[] | { command: string; args?: readonly string[]; env?: Record<string, string>; cwd?: string }, contract: BenchmarkContract, options?: { timeoutMs?: number; signal?: AbortSignal; maxMessageBytes?: number; maxStreamBytes?: number }): Promise<ExternalDriverSession>;
export function runExternalDriverConformance(adapter: readonly string[] | { command: string; args?: readonly string[]; env?: Record<string, string>; cwd?: string }, contract: BenchmarkContract, options?: Record<string, unknown>): Promise<any>;
export function serveFakeDriver(contract: BenchmarkContract, options?: Record<string, unknown>): Promise<void>;
export function runHarnessConformance(contract: BenchmarkContract, options: Record<string, unknown>): Promise<any>;
export function runBenchmarkMatrix(options: BenchmarkMatrixOptions): Promise<any>;
export function applyEvidenceToMatrix(matrix: any, evidence?: Record<string, number>): any;
export function planHarnessMatrix(contract: BenchmarkContract): readonly any[];
export function runReferenceHarness(options: Record<string, unknown> & { workspace: string }): Promise<any>;
export function runBenchmarkReport(options: Record<string, unknown> & { output: string }): Promise<any>;
export function captureEnvironment(options: Record<string, unknown>): any;
export function evaluateThresholds(thresholdFile: any, summaries: readonly TaskSummary[], context: Record<string, unknown>): any;
