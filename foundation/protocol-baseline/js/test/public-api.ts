import {
  ProtocolProblemCatalog,
  executeReferenceProtocolCase,
  runExternalProtocolConformance,
  runProtocolConformance,
  validateTransferHttpRangeCarrier,
  type AdapterResult,
  type ProtocolContract,
  type RunnerCase,
  type RunnerReport,
} from '@opengamevcs/protocol-baseline';

declare const contract: ProtocolContract;
declare const runnerCase: RunnerCase;

const adapterResult: Promise<AdapterResult> = executeReferenceProtocolCase(runnerCase, { contract });
const report: Promise<RunnerReport> = runProtocolConformance(
  contract,
  async (input, context) => executeReferenceProtocolCase(input, context),
  { adapterId: 'ogvcs.protocol/types-smoke@1' },
);
const external: Promise<RunnerReport> = runExternalProtocolConformance(
  contract,
  ['node', 'adapter.mjs'],
  { expectedAdapterId: 'ogvcs.protocol/types-smoke@1', nodeAdapterReadRoots: ['/tmp/adapter-closure'] },
);
const rangeResult = validateTransferHttpRangeCarrier(contract, {
  probe: {}, requestHeaders: [], responseHeaders: [], responseStatus: 200,
  responseBodyHex: '', transportResponse: {},
});
const responseHeaders = new ProtocolProblemCatalog(contract).responseHeaders({
  code: 'PROTOCOL_LIMIT_EXCEEDED',
});

void adapterResult;
void report;
void external;
void rangeResult;
void responseHeaders;
