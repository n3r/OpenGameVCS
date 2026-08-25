# `@opengamevcs/protocol-baseline`

MIT-licensed, bounded Node.js runtime for the generated OpenGameVCS public
protocol v1 contract. Version `1.0.0-rc.1` consumes
`@opengamevcs/protocol-contract-v1@1.0.0-rc.1` and independently authenticates
the complete manifest-inventoried schema, registry, profile, limit, and
conformance-vector authority before use. Counts are read from that authenticated
authority rather than duplicated in this package documentation.

The package provides safe duplicate-detecting I-JSON parsing and RFC 8785
emission, generated-schema validation, independent-axis negotiation and MACed
receipts, semantic idempotency and replay, opaque scoped cursors, explicit page
and stream completion, closed RFC 9457 problems, request-root transfer-grant
carriage, a synthetic identity-coded range/resume probe, bounded loopback
client/server stubs, and reference/external conformance runners.

## Runtime example

```js
import {
  loadProtocolContract,
  parseRequestEnvelope,
  runReferenceProtocolConformance,
} from '@opengamevcs/protocol-baseline';

const contract = await loadProtocolContract();
const request = parseRequestEnvelope(contract, requestBytes);
const report = await runReferenceProtocolConformance(contract);
```

Pass `{ root: '/unpacked/protocol-contract-v1' }` when consuming an explicitly
located offline artifact instead of the installed contract dependency.

## CLI

```text
ogvcs-protocol inspect [--contract <root>]
ogvcs-protocol run [--contract <root>] [--output <report.json>]
                   [--adapter <command> [--adapter-arg <argument>]...]
                   [--node-adapter-read-root <absolute-root>]...
                   [--expected-adapter-id <id>]
                   [--timeout-ms <milliseconds>] [--max-cases <count>]
```

The built-in evaluator identifies as `ogvcs.protocol/reference-js@1`. The
independent process adapter in this repository identifies as
`ogvcs.protocol/independent-js@1` and is invoked as:

```text
node foundation/protocol-baseline/adapters/js-independent/bin/ogvcs-protocol-independent-adapter.mjs --contract spec/protocols/v1
```

Adapters receive only canonical `RunnerCase` JSONL on stdin. They emit one
`RunnerHello` and one `AdapterResult` per case. The harness audits the complete
bounded `AdapterTrace`, discards it, and projects the safe `RunnerResult`.
Expected outcomes, requirements, trace digests, hidden markers, and
forbidden-response fields remain exclusively in the harness. The final output
is the exact generated `RunnerReport` shape:
`schemaVersion`, `adapterId`, `contractManifestSha256`, `results`, `passed`,
`failed`, and `reportDigest`.

For Node adapters, pass one or more absolute `--node-adapter-read-root` values.
The runner then launches Node permission mode with read access limited to those
isolated adapter-package roots and its private staged protocol-authority root.
The staged root contains only the manifest-authenticated adapter execution view
and its exact profile/registry/schema inventory; it contains no vectors or
expected outcomes. A successful adapter must write nothing to stderr. Packed
conformance should additionally construct a physical dependency closure that
omits both protocol and predecessor vector packages. Source-tree runs use the
same permission option, while static source review remains part of their
independence evidence.

## Trust and resource boundary

All public wire/data inputs and callback results are copied into bounded inert
snapshots before semantic use. Proxy traps, accessors, custom iterators, and
mutable caller-owned objects are not protocol authority. Operation options such
as functions, clocks, `AbortSignal` instances, and I/O destinations are trusted
host controls rather than wire data; their completed return values still cross
the inert-data boundary before they can become protocol results.

All public entry points apply finite hard ceilings, configured reductions, and
cooperative deadline/cancellation checkpoints. `maxWorkingMemoryBytes` is a
composite live-operation ceiling: retained contract/scenario/canary inventories,
adapter input and output, decoded results, canonical staging, stream/envelope
buffers, and other simultaneously live copies share that allowance. The HTTP
Range response body is transfer data with its own range and working-memory
ceilings, not a control-message string; its surrounding carrier metadata is
still inertly snapshotted. A JavaScript or operating-system I/O call already in
progress cannot be preempted; callers with strict wall-clock SLAs must supply
timeout-bounded/cancellable I/O or use process isolation. Bytes written to a
destination and handler output remain staging and untrusted until the operation
returns successfully. The in-memory idempotency and cursor stores are reference
components; multi-process deployments need an atomic bounded persistence
implementation preserving the same semantics.

`SyntheticTransferProbe` is deliberately application-neutral. It does not
define production routes, packs, upload sessions, multipart behavior,
compression, placement, or availability. Its typed `execute` boundary first
validates the compact request-root carrier against the pinned authorization
contract and requires the exact predecessor verifier result
`{result:"allow",code:"ALLOW_EXPLICIT"}`; a generic policy callback cannot
stand in for grant verification.
