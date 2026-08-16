// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.

import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { canonicalize, semanticFingerprint } from "../../../../foundation/protocol-baseline/codegen/canonical.mjs";
import { assertSupportedModelType } from "../../../../foundation/protocol-baseline/codegen/generate.mjs";
import { verifyTransferGrant } from "../../../../core/authz-contract/js/src/index.mjs";
import { validateProtocolContract } from "../validate-spec.mjs";

const SPEC_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPOSITORY_ROOT = path.resolve(SPEC_ROOT, "../../..");

async function readScenarioDocuments() {
  const manifest = JSON.parse(await fs.readFile(path.join(SPEC_ROOT, "vectors/manifest.json"), "utf8"));
  return Promise.all(manifest.artifacts
    .filter((artifact) => Number.isSafeInteger(artifact.cases))
    .map(async (artifact) => JSON.parse(await fs.readFile(path.join(SPEC_ROOT, artifact.path), "utf8"))));
}

async function readScenarios(category) {
  return (await readScenarioDocuments()).filter((document) => document.category === category).flatMap((document) => document.cases);
}

test("independent validator accepts the complete generated contract and bindings", async () => {
  const summary = await validateProtocolContract({ repositoryRoot: REPOSITORY_ROOT });
  assert.equal(summary.messages, 46);
  assert.equal(summary.fields, 352);
  assert.equal(summary.errors, 25);
  assert.equal(summary.limits, 35);
  assert.equal(summary.scenarios, 360);
  assert.match(summary.manifestSha256, /^[0-9a-f]{64}$/);
});

test("canonical emission and semantic fingerprint ignore member order, not semantic input", () => {
  const left = { operation: "example/mutate@1", body: { z: 2, a: 1 } };
  const reordered = { body: { a: 1, z: 2 }, operation: "example/mutate@1" };
  const changed = { body: { a: 1, z: 3 }, operation: "example/mutate@1" };
  assert.equal(canonicalize(left), canonicalize(reordered));
  assert.equal(semanticFingerprint("ogvcs.protocol/idempotency/v1", left), semanticFingerprint("ogvcs.protocol/idempotency/v1", reordered));
  assert.notEqual(semanticFingerprint("ogvcs.protocol/idempotency/v1", left), semanticFingerprint("ogvcs.protocol/idempotency/v1", changed));
  assert.throws(() => canonicalize({ unsafe: 1.5 }), /safe integer/);
  assert.throws(() => canonicalize({ unicode: "\ud800" }), /unpaired high surrogate/);
});

test("generator rejects every unsupported or unbounded model feature", () => {
  assert.throws(() => assertSupportedModelType({ kind: "number" }), /unsupported type kind number/);
  assert.throws(() => assertSupportedModelType({ kind: "string", minLength: 0 }), /string bounds are invalid/);
  assert.throws(() => assertSupportedModelType({ kind: "array", minItems: 0, maxItems: 1 }), /has no type object/);
  assert.throws(() => assertSupportedModelType({ kind: "reference", name: "Missing" }), /unknown message Missing/);
  assert.throws(() => assertSupportedModelType({ kind: "enum", values: ["one", 2] }), /mixes enum primitive types/);
  assert.throws(() => assertSupportedModelType({ kind: "map", minProperties: 0, maxProperties: 1, values: { kind: "boolean" } }), /map key pattern is invalid/);
  assert.equal(assertSupportedModelType({ kind: "array", minItems: 0, maxItems: 2, items: { kind: "integer", minimum: 0, maximum: 2 } }), true);
});

test("independent manifest validation rejects one-byte artifact drift", async (context) => {
  const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "ogvcs-protocol-contract-"));
  context.after(() => fs.rm(temporaryRoot, { recursive: true, force: true }));
  const copiedSpec = path.join(temporaryRoot, "spec/protocols/v1");
  await fs.mkdir(path.dirname(copiedSpec), { recursive: true });
  await fs.cp(SPEC_ROOT, copiedSpec, { recursive: true });
  const profilePath = path.join(copiedSpec, "profiles/control-https-json-v1.json");
  const original = await fs.readFile(profilePath, "utf8");
  await fs.writeFile(profilePath, original.replace('"tls":"1.3"', '"tls":"1.2"'));
  await assert.rejects(
    validateProtocolContract({ repositoryRoot: temporaryRoot, specRoot: copiedSpec, bindingsRoot: path.join(temporaryRoot, "missing-bindings") }),
    /control-https-json-v1\.json digest differs/,
  );
});

test("manifest-authenticated adapter execution view rejects independent tampering", async (context) => {
  const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "ogvcs-protocol-view-"));
  context.after(() => fs.rm(temporaryRoot, { recursive: true, force: true }));
  const copiedSpec = path.join(temporaryRoot, "spec/protocols/v1");
  await fs.mkdir(path.dirname(copiedSpec), { recursive: true });
  await fs.cp(SPEC_ROOT, copiedSpec, { recursive: true });
  const viewPath = path.join(copiedSpec, "adapter-execution-view.json");
  const view = JSON.parse(await fs.readFile(viewPath, "utf8"));
  view.authorityArtifacts[0].sha256 = `0${view.authorityArtifacts[0].sha256.slice(1)}`;
  await fs.writeFile(viewPath, canonicalize(view));
  await assert.rejects(
    validateProtocolContract({ repositoryRoot: temporaryRoot, specRoot: copiedSpec, bindingsRoot: path.join(temporaryRoot, "missing-bindings") }),
    /does not authenticate adapter execution view bytes/,
  );
});

test("frozen boundary schemas preserve security and ownership exclusions", async () => {
  const read = async (relativePath) => JSON.parse(await fs.readFile(path.join(SPEC_ROOT, relativePath), "utf8"));
  const problem = await read("schemas/ProblemDetails.schema.json");
  assert.equal(problem.additionalProperties, false);
  assert.equal(problem.properties.detail, undefined);
  assert.equal(problem.properties.instance, undefined);
  assert.equal(problem.allOf[0].oneOf.length, 25);
  const grant = await read("schemas/CompactTransferGrant.schema.json");
  assert.deepEqual([grant.properties.explicitObjectCount.minimum, grant.properties.explicitObjectCount.maximum], [0, 0]);
  assert.equal(grant.properties.objectIds, undefined);
  const cursor = await read("schemas/Cursor.schema.json");
  assert.deepEqual(Object.keys(cursor.properties), ["token"]);
  const cursorScope = await read("schemas/CursorScopeInput.schema.json");
  assert.equal(cursorScope.additionalProperties, false);
  assert.deepEqual([...cursorScope.required].sort(), ["operation", "queryDigest", "repository", "subject", "tenant"]);
  const cursorCase = await read("schemas/CursorCaseInput.schema.json");
  assert.ok(cursorCase["x-ogvcs-semantic-constraints"].some((entry) => entry.kind === "cursorScopes" && entry.projectionSchema === "CursorScopeInput"));
  assert.ok(cursorCase["x-ogvcs-semantic-constraints"].some((entry) => entry.kind === "cursorLifetime" && entry.maximumExpiry === Number.MAX_SAFE_INTEGER));
  assert.equal(cursorCase.properties.ttlMs.minimum, 1);
  const negotiationCase = await read("schemas/NegotiationCaseInput.schema.json");
  assert.equal(negotiationCase.properties.receiptLifetimeMs.minimum, 1);
  assert.equal(negotiationCase.properties.serverNonce.maxLength, 87);
  assert.ok(negotiationCase["x-ogvcs-semantic-constraints"].some((entry) => entry.kind === "canonicalBase64url" && entry.minimumDecodedBytes === 16 && entry.maximumDecodedBytes === 64));
  assert.ok(negotiationCase["x-ogvcs-semantic-constraints"].some((entry) => entry.kind === "negotiationTransport" && entry.requiredScheme === "https" && entry.requiredTls === "1.3" && entry.loopbackException === false));
  const envelopeCase = await read("schemas/EnvelopeCaseInput.schema.json");
  assert.ok(envelopeCase.properties.targetSchema.enum.includes("NegotiationCaseInput"));
  assert.ok(envelopeCase.properties.targetSchema.enum.includes("CursorCaseInput"));
  const page = await read("schemas/PageEnvelope.schema.json");
  assert.equal(page.properties.items.items.$ref, "#/$defs/JsonValue");
  assert.ok(page.$defs.JsonValue, "nested JSON array references must have a local bounded definition");
  const request = await read("schemas/RequestEnvelope.schema.json");
  assert.equal(request.properties.extensions.type, "object");
  assert.equal(request.properties.extensions.maxProperties, 32);
  assert.match(request.properties.extensions.propertyNames.pattern, /@\[0-9\]/);
  const response = await read("schemas/ResponseEnvelope.schema.json");
  assert.equal(response.allOf[0].if.properties.success.const, true);
  assert.deepEqual(response.allOf[0].then.required, ["body"]);
  assert.deepEqual(response.allOf[0].else.required, ["problem"]);
  assert.equal((await read("schemas/PageEnvelope.schema.json")).allOf[0].oneOf.length, 3);
  const stream = await read("schemas/StreamFrame.schema.json");
  assert.equal(stream.allOf[0].oneOf.length, 5);
  assert.equal(stream.properties.finalDigest, undefined);
  const assignments = await read("registries/field-assignments.json");
  assert.ok(assignments.messages.find((entry) => entry.name === "StreamFrame").reservedFields.some((entry) => entry.id === 7 && entry.name === "finalDigest"));
  const profile = await read("profiles/transfer-probe-v1.json");
  for (const excluded of ["production-routes", "upload-sessions", "pack-layout", "compression", "placement", "availability"]) assert.ok(profile.excluded.includes(excluded));
  assert.equal(profile.httpRangeCarrier.request.semanticEnd, "endOffsetExclusive=endInclusive+1");
  assert.equal(profile.httpRangeCarrier.response.unsatisfiedStatus, 416);
  assert.equal(profile.httpRangeCarrier.response.successfulValidators.contentDigest, "exactly-one-canonical-RFC9530-sha-256");
  assert.equal(profile.httpRangeCarrier.response.successfulValidators.etag, "exactly-one-canonical-RFC9110-quoted-strong");
  assert.equal(profile.httpRangeCarrier.response.digestAuthority, "SHA-256(decoded-responseBodyHex)");
  assert.equal(profile.httpRangeCarrier.response.unsatisfiedValidators, "content-digest-and-etag-absent");
  assert.deepEqual(profile.httpRangeCarrier.response.allowedStatuses, [200, 206, 416]);
  assert.equal(profile.httpRangeCarrier.response.unsupportedStatusOutcome, "PROTOCOL_MALFORMED-before-validator-or-range-semantics");
  const controlProfile = await read("profiles/control-https-json-v1.json");
  assert.equal(controlProfile.transport.cleartext, "forbidden-for-negotiation-and-mutations");
  assert.equal(controlProfile.transport.loopbackCleartext, "envelope-conformance-harness-only");
  const transferCase = await read("schemas/TransferCaseInput.schema.json");
  assert.ok(transferCase["x-ogvcs-semantic-constraints"].some((entry) => entry.kind === "transferHttpRange"));
  assert.equal(transferCase.properties.responseBodyBytes, undefined);
  assert.equal(transferCase.properties.responseBodyHex.pattern, "^(?:[0-9a-f]{2})*$");
  assert.ok(transferCase.required.includes("responseBodyHex"));
  assert.ok(assignments.messages.find((entry) => entry.name === "TransferCaseInput").reservedFields.some((entry) => entry.id === 22 && entry.name === "responseBodyBytes"));
  assert.equal(transferCase.properties.requestHeaders.items.$ref, "TransportHeaderInput.schema.json");
  assert.equal(transferCase.properties.authorizationContext.$ref, "#/$defs/JsonValue");
  assert.equal(transferCase.properties.authorizationContext["x-ogvcs-sensitive"], true);
  assert.equal(transferCase.properties.authorizationPublicJwk.$ref, "#/$defs/JsonValue");
  assert.equal(transferCase.properties.authorizationPublicJwk["x-ogvcs-sensitive"], false);
  for (const oracle of ["grantVerification", "authorizationVectorPath", "authorizationCaseId", "authorizationCaseSha256", "authorizationContextPatch"]) assert.equal(transferCase.properties[oracle], undefined);
  const configured = await read("schemas/RunnerConfiguredLimits.schema.json");
  assert.equal(configured.properties.maxErrorParameters.minimum, 0);
  assert.equal(configured.properties.maxControlMessageBytes.minimum, 1);
  const runnerControl = await read("schemas/RunnerExecutionControl.schema.json");
  assert.ok(runnerControl["x-ogvcs-semantic-constraints"].some((entry) => entry.kind === "runnerClockSamples" && entry.order === "nondecreasing" && entry.hardMaximumMs === 120_000 && entry.expirationOutcome === "DEADLINE_EXCEEDED"));
  const safeParameter = await read("schemas/SafeParameter.schema.json");
  const retry = safeParameter.allOf[0].oneOf.find((branch) => branch.properties.name.const === "retryAfterMs");
  const retryPattern = new RegExp(retry.properties.value.pattern, "u");
  assert.equal(retryPattern.test("86400000"), true);
  assert.equal(retryPattern.test("86400001"), false);
  assert.equal(retryPattern.test("99999999"), false);
  assert.equal(JSON.stringify(safeParameter).includes("currentGeneration"), false);
  const idempotency = await read("schemas/IdempotencyDescriptor.schema.json");
  assert.deepEqual(idempotency.required.slice(-2), ["issuedAtUnixMs", "expiresAtUnixMs"]);
  assert.match(idempotency.properties.key.pattern, /^\^ik1/);
  assert.deepEqual(idempotency["x-ogvcs-semantic-constraints"], [{
    kind: "selfDatingIdempotencyKey",
    keyField: "key",
    issuedAtField: "issuedAtUnixMs",
    expiresAtField: "expiresAtUnixMs",
    maxFutureIssueSkewMs: 0,
    maxLifetimeMs: 86_400_000,
  }]);
  const projection = await read("schemas/IdempotencyProjectionInput.schema.json");
  assert.deepEqual([...projection.required].sort(), ["body", "extensions", "operation", "schemaVersion"]);
  assert.equal(projection.additionalProperties, false);
  const fingerprintCase = await read("schemas/FingerprintCaseInput.schema.json");
  for (const kind of ["selfDatingIdempotencyKey", "idempotencyProjections", "indexIntoArray", "idempotencyExecution"]) assert.ok(fingerprintCase["x-ogvcs-semantic-constraints"].some((entry) => entry.kind === kind));
  const transferNonGrant = await read("schemas/TransferProbeNonGrantInput.schema.json");
  assert.equal(transferNonGrant.properties.grant, undefined);
  assert.equal(transferNonGrant.properties.schemaVersion.const, "ogvcs.protocol/transfer-probe-non-grant-input/v1");
  assert.notEqual(transferNonGrant.properties.schemaVersion.const, (await read("schemas/TransferProbe.schema.json")).properties.schemaVersion.const);
  assert.ok(transferNonGrant["x-ogvcs-semantic-constraints"].some((entry) => entry.kind === "transferProbeRange"));
  const selectors = (await Promise.all((await fs.readdir(path.join(SPEC_ROOT, "schemas"))).filter((name) => name.endsWith(".schema.json")).map(async (name) => (await read(`schemas/${name}`)).properties?.schemaVersion?.const))).filter((value) => typeof value === "string");
  assert.equal(new Set(selectors).size, selectors.length);
});

test("adapter execution view excludes every oracle while authenticating the full contract", async () => {
  const read = async (relativePath) => JSON.parse(await fs.readFile(path.join(SPEC_ROOT, relativePath), "utf8"));
  const view = await read("adapter-execution-view.json");
  const viewBytes = await fs.readFile(path.join(SPEC_ROOT, "adapter-execution-view.json"));
  const manifest = await read("manifest.json");
  const { createHash } = await import("node:crypto");
  assert.equal(view.contractManifestSha256, undefined);
  assert.equal(view.generatorInputs, undefined);
  assert.equal(manifest.adapterExecutionView.sha256, createHash("sha256").update(viewBytes).digest("hex"));
  assert.equal(manifest.adapterExecutionView.bytes, viewBytes.length);
  assert.equal(view.authorityArtifacts.every((artifact) => ["profiles/", "registries/", "schemas/"].some((prefix) => artifact.path.startsWith(prefix))), true);
  assert.deepEqual(view.excludedNamespaces, ["docs/", "vectors/"]);
  assert.deepEqual(manifest.generatorInputs.map(({ path: inputPath }) => inputPath), ["spec/authorization/v1/LICENSE", "spec/authorization/v1/manifest.json", "spec/authorization/v1/vectors/grants.json"]);
});

test("resource and release corpora are executable authority-derived inputs", async () => {
  const resources = await readScenarios("resources");
  assert.equal(resources.length, 81);
  assert.equal(resources.every((entry) => entry.configuredLimits && !entry.resourceRecipe && !Object.hasOwn(entry.input, "logicalSize")), true);
  const release = await readScenarios("release");
  assert.equal(release.every((entry) => entry.requirementIds.includes("OGVCS-041-AC-05")), true);
  assert.ok(release.some((entry) => entry.id === "release-preflight-field-code-reuse"));
  assert.ok(release.some((entry) => entry.id === "release-preflight-extension-reorder" && entry.expected.result === "accept"));
  assert.ok(release.some((entry) => entry.id === "release-preflight-unique-optional-addition" && entry.expected.result === "accept"));
  assert.ok(release.some((entry) => entry.id === "release-preflight-new-code-collision" && entry.expected.result === "reject"));
  assert.ok(release.some((entry) => entry.id === "release-preflight-new-name-collision" && entry.expected.result === "reject"));
  for (const id of ["release-preflight-field-type-change", "release-preflight-field-presence-change", "release-preflight-field-fingerprint-change", "release-preflight-field-sensitivity-change", "release-preflight-limit-policy-change", "release-preflight-error-parameter-domain-change"]) {
    assert.ok(release.some((entry) => entry.id === id && entry.expected.code === "PROTOCOL_UNSUPPORTED"));
  }
  const baselineRelease = release.find((entry) => entry.id === "release-preflight-current-candidate");
  assert.equal(baselineRelease.input.proposedAssignments.every((entry) => /^[0-9a-f]{64}$/u.test(entry.semanticSha256)), true);
  const idempotency = await readScenarios("idempotency");
  const retired = idempotency.find((entry) => entry.id === "idempotency-after-retention-same-key-requires-new-key");
  assert.deepEqual([retired.expected.code, retired.expected.preMutation, retired.expected.mutationCount], ["IDEMPOTENCY_KEY_REQUIRED", false, 1]);
  assert.ok(retired.input.atUnixMs > retired.input.idempotencyExpiresAtUnixMs + retired.input.tombstoneRetentionMs);
  const extensionMax = resources.find((entry) => entry.id === "resource-max-extension-entries-max");
  assert.deepEqual(Object.keys(extensionMax.input.document.extensions).sort(), [...extensionMax.input.selectedExtensions].sort());
  const fingerprintFields = ["body", "extensions", "operation", "schemaVersion"];
  const malformedProjectionIds = new Set(["idempotency-projection-missing-schema-version", "idempotency-projection-unknown-field"]);
  for (const scenario of idempotency.filter((entry) => !malformedProjectionIds.has(entry.id))) for (const projectionEntry of scenario.input.projections) assert.deepEqual(Object.keys(projectionEntry).sort(), fingerprintFields);
  const firstExecution = idempotency.find((entry) => entry.id === "idempotency-retry-only-unused-key-first-execution");
  assert.deepEqual([firstExecution.expected.result, firstExecution.expected.preMutation, firstExecution.expected.mutationCount], ["accept", false, 1]);
  assert.deepEqual([firstExecution.input.attemptProjectionIndexes, firstExecution.input.attemptSchedule, firstExecution.input.attemptAuthorizationDecisions], [[0], ["retry"], ["allow"]]);
  const zeroRetention = idempotency.find((entry) => entry.id === "idempotency-zero-tombstone-retention-first-execution");
  assert.deepEqual([zeroRetention.input.tombstoneRetentionMs, zeroRetention.expected.result, zeroRetention.expected.preMutation, zeroRetention.expected.mutationCount], [0, "accept", false, 1]);
  const deniedReplay = idempotency.find((entry) => entry.id === "idempotency-response-loss-replay-authorization-revoked");
  assert.deepEqual([deniedReplay.expected.code, deniedReplay.expected.preMutation, deniedReplay.expected.mutationCount], ["AUTHORIZATION_DENIED", false, 1]);
  assert.deepEqual(deniedReplay.input.attemptAuthorizationDecisions, ["allow", "deny"]);
  const cursors = await readScenarios("cursors");
  assert.ok(cursors.some((entry) => entry.id === "cursor-wrong-operation" && entry.expected.code === "CURSOR_SCOPE_MISMATCH"));
  for (const id of ["cursor-scope-unknown-field", "cursor-scope-missing-operation"]) assert.ok(cursors.some((entry) => entry.id === id && entry.expected.code === "PROTOCOL_MALFORMED"));
  const capabilityAxes = new Set(resources.filter((entry) => entry.resourceWitness.limit === "maxCapabilityItems" && entry.resourceWitness.relation === "max-plus-one").map((entry) => entry.resourceWitness.axis));
  assert.equal(capabilityAxes.size, 10);
  const rangeDimensions = new Set(resources.filter((entry) => entry.resourceWitness.limit === "maxTransferRangeBytes" && entry.resourceWitness.dimension).map((entry) => entry.resourceWitness.dimension));
  assert.deepEqual([...rangeDimensions].sort(), ["request", "response"]);
  const transfer = await readScenarios("transfer");
  for (const id of [
    "transfer-http-no-range-200", "transfer-http-no-range-open-end-200", "transfer-http-range-roundtrip-206", "transfer-http-range-open-end-206", "transfer-http-unsatisfied-range-416",
    "transfer-http-content-digest-missing", "transfer-http-content-digest-malformed-present", "transfer-http-content-digest-duplicate-case-folded", "transfer-http-content-digest-body-mismatch", "transfer-http-content-digest-expected-mismatch",
    "transfer-http-etag-missing", "transfer-http-etag-weak", "transfer-http-etag-malformed", "transfer-http-etag-duplicate-case-folded", "transfer-http-etag-resume-mismatch",
    "transfer-http-unsatisfied-content-digest-forbidden", "transfer-http-unsatisfied-etag-forbidden", "transfer-http-if-range-weak", "transfer-http-range-duplicate-case-folded", "transfer-http-unsupported-status-without-validators",
  ]) assert.ok(transfer.some((entry) => entry.id === id));
  const zeroProgressInterrupted = transfer.find((entry) => entry.id === "transfer-result-interrupted-zero-progress");
  assert.deepEqual([zeroProgressInterrupted.expected.result, zeroProgressInterrupted.input.probeResult.status, zeroProgressInterrupted.input.probeResult.acceptedStart, zeroProgressInterrupted.input.probeResult.acceptedEndExclusive], ["accept", "interrupted", 512, 512]);
  for (const scenario of transfer.filter((entry) => entry.input.route === "http-range" && entry.expected.result === "accept")) {
    assert.match(scenario.input.responseBodyHex, /^(?:[0-9a-f]{2})*$/u);
    assert.equal(scenario.input.responseHeaders.filter((header) => header.name.toLowerCase() === "content-digest").length, 1);
    assert.equal(scenario.input.responseHeaders.filter((header) => header.name.toLowerCase() === "etag").length, 1);
  }
  const openNoRange = transfer.find((entry) => entry.id === "transfer-http-no-range-open-end-200");
  assert.equal(Object.hasOwn(openNoRange.input.probe, "endOffsetExclusive"), false);
  assert.equal(openNoRange.input.requestHeaders.some((header) => header.name.toLowerCase() === "range"), false);
  const negotiationScenarios = await readScenarios("negotiation");
  const cleartextLoopback = negotiationScenarios.find((entry) => entry.id === "negotiation-cleartext-loopback-rejected");
  assert.deepEqual([cleartextLoopback.input.transportScheme, cleartextLoopback.input.tlsVersion, cleartextLoopback.input.loopbackConformance, cleartextLoopback.expected.code], ["http", "1.3", true, "NEGOTIATION_DOWNGRADE_REJECTED"]);
  const nonce64 = negotiationScenarios.find((entry) => entry.id === "negotiation-server-nonce-max-64-bytes");
  const nonce65 = negotiationScenarios.find((entry) => entry.id === "negotiation-server-nonce-max-plus-one-65-bytes");
  assert.deepEqual([Buffer.from(nonce64.input.serverNonce, "base64url").length, nonce64.expected.result], [64, "accept"]);
  assert.deepEqual([Buffer.from(nonce65.input.serverNonce, "base64url").length, nonce65.expected.code], [65, "PROTOCOL_MALFORMED"]);
  const safeRequired = negotiationScenarios.find((entry) => entry.id === "negotiation-required-safe-extension-selected");
  assert.deepEqual(safeRequired.input.serverSelection.extensions, ["ogvcs.extension.safe-optional@1"]);
  assert.ok(safeRequired.input.offer.capabilities.requiredCapabilities.includes("ogvcs.extension.safe-optional@1"));
  const deterministic = negotiationScenarios.find((entry) => entry.id === "negotiation-extension-selection-deterministic");
  assert.deepEqual(deterministic.input.offer.capabilities.extensions, ["ogvcs.extension.audit-optional@1", "ogvcs.extension.safe-optional@1"]);
  assert.deepEqual(deterministic.input.serverSelection.extensions, ["ogvcs.extension.safe-optional@1", "ogvcs.extension.audit-optional@1"]);
  const malformed = await readScenarios("malformed");
  const zeroReceiptLifetime = malformed.find((entry) => entry.id === "malformed-negotiation-zero-receipt-lifetime");
  const zeroCursorTtl = malformed.find((entry) => entry.id === "malformed-cursor-zero-ttl");
  assert.deepEqual([zeroReceiptLifetime.input.targetSchema, zeroReceiptLifetime.input.document.receiptLifetimeMs, zeroReceiptLifetime.expected.code], ["NegotiationCaseInput", 0, "PROTOCOL_MALFORMED"]);
  assert.deepEqual([zeroCursorTtl.input.targetSchema, zeroCursorTtl.input.document.ttlMs, zeroCursorTtl.expected.code], ["CursorCaseInput", 0, "PROTOCOL_MALFORMED"]);
  const decreasingClock = malformed.find((entry) => entry.id === "malformed-decreasing-clock-samples");
  assert.deepEqual([decreasingClock.control.clockSamplesUnixMs, decreasingClock.expected.code, decreasingClock.expected.preMutation], [[1_001, 1_000], "PROTOCOL_MALFORMED", true]);
  const envelopeScenarios = await readScenarios("envelopes");
  const hardDefaultDeadline = envelopeScenarios.find((entry) => entry.id === "envelope-hard-default-operation-time-expired");
  assert.deepEqual([hardDefaultDeadline.control.clockSamplesUnixMs, hardDefaultDeadline.configuredLimits, hardDefaultDeadline.expected.code], [[0, 120_000], undefined, "DEADLINE_EXCEEDED"]);
  const cursorIssuedAtOverflow = cursors.find((entry) => entry.id === "cursor-issued-at-max-expiry-overflow");
  assert.deepEqual([cursorIssuedAtOverflow.input.issuedAtUnixMs, cursorIssuedAtOverflow.input.readAtUnixMs, cursorIssuedAtOverflow.input.ttlMs, cursorIssuedAtOverflow.expected.code], [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1, "PROTOCOL_MALFORMED"]);
  for (const [id, count] of [["transfer-grant-explicit-object-count-negative", -1], ["transfer-explicit-object-list", 1], ["transfer-grant-explicit-object-count-max-safe", Number.MAX_SAFE_INTEGER]]) {
    const scenario = transfer.find((entry) => entry.id === id);
    assert.deepEqual([scenario.input.probe.grant.explicitObjectCount, scenario.expected.code], [count, "TRANSFER_GRANT_INVALID"]);
  }
  const configuredGrantShape = transfer.find((entry) => entry.id === "transfer-configured-grant-bytes-then-malformed-shape");
  const configuredGrantEnvelopeBytes = Buffer.from(configuredGrantShape.input.probe.grant.envelope, "base64url").length;
  assert.deepEqual([
    configuredGrantShape.configuredLimits.maxGrantBytes,
    configuredGrantEnvelopeBytes,
    configuredGrantShape.input.probe.grant.explicitObjectCount,
    configuredGrantShape.expected.code,
  ], [741, 741, 1, "TRANSFER_GRANT_INVALID"]);
  assert.ok(Buffer.byteLength(canonicalize(configuredGrantShape.input.probe.grant), "utf8") > configuredGrantEnvelopeBytes);
  const negativeTotal = transfer.find((entry) => entry.id === "transfer-http-negative-total-bytes");
  assert.deepEqual([negativeTotal.input.transportResponse.totalBytes, negativeTotal.expected.code], [-1, "PROTOCOL_MALFORMED"]);
  const carried = transfer.filter((entry) => entry.predecessorCase !== undefined);
  assert.equal(new Set(carried.map((entry) => entry.predecessorCase.caseId)).size, 16);
  assert.equal(carried.every((entry) => entry.input.authorizationContext && entry.input.authorizationPublicJwk && !Object.hasOwn(entry.input, "authorizationCaseId") && !Object.hasOwn(entry.input, "grantVerification")), true);
});

test("every scenario has an independently reproducible harness-only trace oracle and golden stream bytes execute", async () => {
  const expected = new Map();
  let goldenScenario;
  for (const vector of await readScenarioDocuments()) {
    for (const scenario of vector.cases) {
      assert.match(scenario.expected.traceDigest, /^[0-9a-f]{64}$/u);
      expected.set(scenario.id, scenario.expected.traceDigest);
      if (scenario.id === "stream-golden-jsonl-byte-exact") goldenScenario = scenario;
    }
  }
  const { createHash } = await import("node:crypto");
  const lines = (await fs.readFile(path.join(SPEC_ROOT, "vectors/golden-traces.jsonl"), "utf8")).trimEnd().split("\n");
  assert.equal(lines.length, expected.size);
  for (const line of lines) {
    const record = JSON.parse(line);
    assert.equal(canonicalize(record), line);
    const digest = createHash("sha256").update(Buffer.from(canonicalize(record.trace), "utf8")).digest("hex");
    assert.equal(record.traceDigest, digest);
    assert.equal(expected.get(record.id), digest);
  }
  const goldenBytes = await fs.readFile(path.join(SPEC_ROOT, "vectors/golden-stream.jsonl"));
  assert.equal(Buffer.from(goldenScenario.input.jsonl, "utf8").equals(goldenBytes), true);
  assert.equal(goldenScenario.operation, "validate-stream");
  assert.equal(goldenScenario.inputKind, "jsonl");
});

test("every verifier-targeted authorization witness is a real request-root grant", async () => {
  const transfer = await readScenarios("transfer");
  const witnesses = transfer.filter((entry) => entry.predecessorCase !== undefined);
  let verifierCalls = 0;
  for (const scenario of witnesses) {
    const envelope = JSON.parse(Buffer.from(scenario.input.probe.grant.envelope, "base64url").toString("utf8"));
    if (scenario.predecessorCase.applicability === "excluded-explicit-object-carrier") {
      assert.equal(envelope.claims.requestRoot, null);
      assert.equal(envelope.claims.objectIds.length, 1);
      continue;
    }
    assert.equal(typeof envelope.claims.requestRoot, "string");
    assert.deepEqual(envelope.claims.objectIds, []);
    assert.equal(scenario.input.probe.grant.representation, "request-root");
    assert.equal(scenario.input.probe.grant.explicitObjectCount, 0);
    const decision = await verifyTransferGrant(envelope, scenario.input.authorizationContext, scenario.input.authorizationPublicJwk);
    assert.equal(decision.result, scenario.expected.result === "accept" ? "allow" : "deny", scenario.id);
    if (scenario.predecessorCase.caseId === "replayed") assert.deepEqual(decision, { result: "deny", code: "DENY_GRANT_REPLAY" });
    verifierCalls += 1;
  }
  assert.equal(verifierCalls, witnesses.length - 2);
});

test("R0 lifecycle prose forbids deprecated-read compatibility and new-session selection", async () => {
  const extensions = await fs.readFile(path.join(SPEC_ROOT, "docs/extensions-and-versioning.md"), "utf8");
  const negotiation = await fs.readFile(path.join(SPEC_ROOT, "docs/negotiation.md"), "utf8");
  assert.match(extensions, /Deprecated and reserved\s+entries are neither selected, emitted, nor interpreted in R0\./u);
  assert.match(extensions, /declares no deprecated-read compatibility window/u);
  assert.match(extensions, /deprecated registry entry remains\nsolely as a rejection witness/u);
  assert.doesNotMatch(extensions, /remain readable/u);
  assert.match(extensions, /R0 admits only\nadditions explicitly pre-reserved in that predecessor's authenticated\n`allowedAdditions`/u);
  assert.match(extensions, /Arbitrary new extension registration requires a future release-preflight\nversion/u);
  assert.match(negotiation, /Only candidate or ratified compatibility tuples are selectable\nfor new sessions\./u);
});
