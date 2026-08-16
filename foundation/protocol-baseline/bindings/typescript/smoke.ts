// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.
import type { CapabilityAxes, RunnerCase } from "./index.js";
const axes: CapabilityAxes = {
  protocolVersions: ["ogvcs.control.https-json@1"], schemaVersions: ["ogvcs.protocol.schema@1"],
  repositoryFormats: ["ogvcs.repository-format@1"], authorizationContracts: ["ogvcs.authorization@1"],
  pathContracts: ["ogvcs.path-filesystem@1"], pathProfiles: ["path.opengamevcs/portable@1"],
  eventVersions: ["ogvcs.events.base@1"], transferProfiles: ["ogvcs.transfer.range-resume-probe@1"],
  extensions: [], requiredCapabilities: [],
};
const runnerCase: RunnerCase = { schemaVersion: "ogvcs.protocol/runner-case/v1", id: "typescript-smoke", operation: "negotiate", input: {}, inputKind: "semantic-value", control: { cancellation: "none", clockSamplesUnixMs: [0] } };
void [axes, runnerCase];
