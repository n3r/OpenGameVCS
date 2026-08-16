# `@opengamevcs/authorization-contract`

Dependency-free JavaScript bindings and a public conformance runner for
OpenGameVCS authorization contract v1. The package validates bounded contract
documents, executes the two synthetic reference policies, verifies deterministic
authorization views, signs/verifies conformance-only Ed25519 grants, and runs the
abuse catalog against either the reference fixture or a bounded NDJSON adapter.

This is not a production identity provider, policy database, grant issuer, or
audit store. Production enforcement belongs to OGVCS-009 and must consume the
language-neutral contract package rather than private implementation modules.

## Public API

```js
import {
  buildAuthorizedView,
  evaluateFixturePolicy,
  loadAuthorizationContract,
  requestRootForObjectIds,
  runThreatVectors,
  verifyTransferGrant
} from '@opengamevcs/authorization-contract';

const contract = await loadAuthorizationContract();
const report = await runThreatVectors();
if (report.failed !== 0) throw new Error('authorization conformance failed');
```

`loadAuthorizationContract()` reads the separately installed language-neutral
package through its public exports, verifies the exact manifest hash, all 31
artifact hashes, every frozen registry assignment, and the 13-registry set
digest, and returns a deeply frozen view. The reference policy
and signing helper are explicitly fixture/conformance-only. They must not be
used as a production enforcement or issuing service.

`authorizationRequestFromFixtureOperation()` maps a verified OGVCS-001
`OperationScenario` v2 record into the closed authorization request contract.
It does not treat the fixture's expected decision as production authority.

`requestRootForObjectIds()` computes the normative domain-separated SHA-256
commitment for a sorted unique bounded object-ID plan. In root-scoped grant
mode, `verifyTransferGrant()` requires `context.requestObjectIds` to come from
verifier-owned authenticated transfer-plan state, recomputes the root, and
checks that `context.objectId` is a member. Never populate that list directly
from the grant holder's request.

The `publicJwk` argument must be retrieved from trusted issuer configuration for
`context.keyId` and `context.keyGeneration`; never accept it from the grant
holder. The signed claims must match both context fields before an allow result.

## CLI and external adapters

```sh
ogvcs-authz inspect
ogvcs-authz verify-grants
ogvcs-authz run --output authorization-report.json
ogvcs-authz run \
  --adapter /absolute/path/to/server-adapter \
  --adapter-arg --endpoint \
  --adapter-arg https://service.example
```

Adapters use canonical NDJSON over standard input/output. They are spawned
without a shell, receive a minimal environment, and are bounded to 120 seconds,
64 MiB stdout, 8 MiB stderr, 4 MiB per line, and one child process by default.
The process tree is terminated on timeout, cancellation, overflow, or protocol
failure. A malformed, missing, extra, reordered, noncanonical, unknown-code, or
privacy-leaking result fails the run. See the packaged
`docs/runner-protocol.md` in
`@opengamevcs/authorization-contract-v1` for the exact exchange.

## Security and resource boundary

- Canonical JSON is capped at 4 MiB, depth 32, 200,000 nodes, 64 KiB per
  string, and 256 bytes per key unless a smaller public option applies.
- Request, policy, grant, context, and adapter result objects are closed and use
  frozen registry assignments.
- Invalid authorization input produces a privacy-safe fail-closed fixture
  decision; malformed contract/tool input produces a typed
  `AuthorizationContractError`.
- Authorized view filtering happens before pagination/cursor creation. Returned
  cursors bind only the authorized set and expose no hidden total or position.
- The Ed25519 conformance key and `signConformanceGrant` are test material. The
  signing helper requires the explicit `{ conformanceOnly: true }` option.
- JavaScript process controls do not replace an OS sandbox. Run untrusted server
  adapters under the normative sandbox boundary.

The package supports Node.js 22 or newer on Linux, macOS, and Windows, installs
offline with the exact `1.0.0` contract dependency, and ships its MIT license,
types, CLI, and protocol example.
