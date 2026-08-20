#!/usr/bin/env node

// Dependency-free, language-neutral OGVCS repository-format-v1 vector generator.
// The implementation intentionally contains its own small deterministic-CBOR
// encoder so the checked-in bytes do not depend on either production codec.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const VERSION = "2.0.0";
const COMMAND = "node tools/reference-vector-generator/generate.mjs";
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const DEFAULT_OUTPUT = path.join(REPO_ROOT, "spec/repository-format/v1/vectors");
const SOURCE = fileURLToPath(import.meta.url);
const OBJECT_DOMAIN = Buffer.from("OpenGameVCS object\0", "ascii");
const LOGICAL_DOMAIN = Buffer.from("OpenGameVCS logical record\0", "ascii");
const CONFLICT_DOMAIN = Buffer.from("OpenGameVCS conflict\0", "ascii");
const BUNDLE_DOMAIN = Buffer.from("OpenGameVCS logical bundle\0", "ascii");
const IMPORT_MAPPING_DOMAIN = Buffer.from("OpenGameVCS import mapping\0", "ascii");
const REGISTRY_SET_DOMAIN = Buffer.from("OpenGameVCS registry set\0", "ascii");
const RESOURCE_SUMMARY_DOMAIN = Buffer.from("OpenGameVCS resource summary\0", "ascii");
const UNICODE_VERSION = "15.0.0";
const UNICODE_SOURCE_SHA256 = "7570877e0fa197c45338f7c41a02636da4e14c8dba6a3611a01cd30bf329d5ca";
const UNICODE_SOURCE_PATH = path.join(REPO_ROOT, "spec/repository-format/v1/unicode/DerivedAge-15.0.0.txt");
const UNICODE_LICENSE_PATH = path.join(REPO_ROOT, "spec/repository-format/v1/unicode/UNICODE-LICENSE.txt");
const UNICODE_NOTICE_PATH = path.join(REPO_ROOT, "spec/repository-format/v1/unicode/NOTICE.md");

function frozenUnicodeIntervals(sourceBytes) {
  assert.equal(hex(sha256(sourceBytes)), UNICODE_SOURCE_SHA256, "Unicode 15.0 DerivedAge source digest changed");
  const source = sourceBytes.toString("utf8");
  assert(source.startsWith("# DerivedAge-15.0.0.txt\n"), "Unicode age source version changed");
  const ranges = [];
  for (const line of source.split("\n")) {
    const match = /^([0-9A-F]{4,6})(?:\.\.([0-9A-F]{4,6}))?\s*;\s*([0-9]+)\.([0-9]+)\b/.exec(line);
    if (!match) continue;
    const major = Number(match[3]);
    const minor = Number(match[4]);
    assert(major < 15 || (major === 15 && minor === 0), `post-15.0 age assignment in frozen source: ${line}`);
    const from = Number.parseInt(match[1], 16);
    const to = Number.parseInt(match[2] ?? match[1], 16);
    assert(from <= to && to <= 0x10ffff, `invalid Unicode age range: ${line}`);
    if (to < 0xd800 || from > 0xdfff) ranges.push([from, to]);
    else {
      if (from < 0xd800) ranges.push([from, 0xd7ff]);
      if (to > 0xdfff) ranges.push([0xe000, to]);
    }
  }
  ranges.sort((left, right) => left[0] - right[0] || left[1] - right[1]);
  const merged = [];
  for (const range of ranges) {
    const previous = merged.at(-1);
    assert(!previous || range[0] > previous[1], "Unicode age ranges overlap");
    if (previous && range[0] === previous[1] + 1) previous[1] = range[1];
    else merged.push([...range]);
  }
  assert(merged.length > 0 && merged[0][0] === 0 && merged.at(-1)[1] <= 0x10ffff);
  return merged;
}

const UNICODE_SOURCE_BYTES = fs.readFileSync(UNICODE_SOURCE_PATH);
const FROZEN_UNICODE_INTERVALS = frozenUnicodeIntervals(UNICODE_SOURCE_BYTES);

function isFrozenUnicodeScalar(codePoint) {
  let low = 0;
  let high = FROZEN_UNICODE_INTERVALS.length - 1;
  while (low <= high) {
    const middle = (low + high) >>> 1;
    const [from, to] = FROZEN_UNICODE_INTERVALS[middle];
    if (codePoint < from) high = middle - 1;
    else if (codePoint > to) low = middle + 1;
    else return true;
  }
  return false;
}

function assertFrozenUnicodeText(value) {
  for (const scalar of value) {
    assert(isFrozenUnicodeScalar(scalar.codePointAt(0)),
      `generator text contains a scalar outside the Unicode ${UNICODE_VERSION} repertoire`);
  }
}

function map(entries) {
  return new Map(entries);
}

function uint16be(value) {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16BE(value);
  return bytes;
}

function uint32be(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function uint64be(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

function compareBytes(left, right) {
  return Buffer.compare(left, right);
}

function encodeHead(major, input) {
  const value = typeof input === "bigint" ? input : BigInt(input);
  assert(value >= 0n && value <= 0xffffffffffffffffn);
  if (value < 24n) return Buffer.from([(major << 5) | Number(value)]);
  if (value <= 0xffn) return Buffer.from([(major << 5) | 24, Number(value)]);
  if (value <= 0xffffn) {
    const bytes = Buffer.alloc(3);
    bytes[0] = (major << 5) | 25;
    bytes.writeUInt16BE(Number(value), 1);
    return bytes;
  }
  if (value <= 0xffffffffn) {
    const bytes = Buffer.alloc(5);
    bytes[0] = (major << 5) | 26;
    bytes.writeUInt32BE(Number(value), 1);
    return bytes;
  }
  const bytes = Buffer.alloc(9);
  bytes[0] = (major << 5) | 27;
  bytes.writeBigUInt64BE(value, 1);
  return bytes;
}

function cbor(value) {
  if (Buffer.isBuffer(value)) return Buffer.concat([encodeHead(2, value.length), value]);
  if (typeof value === "string") {
    assertFrozenUnicodeText(value);
    assert(value.normalize("NFC") === value, "generator text must already be NFC");
    const bytes = Buffer.from(value, "utf8");
    return Buffer.concat([encodeHead(3, bytes.length), bytes]);
  }
  if (typeof value === "boolean") return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === "number" || typeof value === "bigint") {
    if (typeof value === "number") assert(Number.isSafeInteger(value));
    const integer = BigInt(value);
    if (integer >= 0n) return encodeHead(0, integer);
    assert(integer >= -0x8000000000000000n);
    return encodeHead(1, -1n - integer);
  }
  if (Array.isArray(value)) return Buffer.concat([encodeHead(4, value.length), ...value.map(cbor)]);
  if (value instanceof Map) {
    const entries = [...value.entries()].map(([key, item]) => {
      return { key: cbor(key), value: cbor(item) };
    });
    entries.sort((a, b) => a.key.length - b.key.length || compareBytes(a.key, b.key));
    for (let index = 1; index < entries.length; index += 1) {
      assert(compareBytes(entries[index - 1].key, entries[index].key) !== 0, "duplicate CBOR map key");
    }
    return Buffer.concat([encodeHead(5, entries.length), ...entries.flatMap((entry) => [entry.key, entry.value])]);
  }
  throw new TypeError(`unsupported CBOR value: ${typeof value}`);
}

function uncheckedCborText(value) {
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([encodeHead(3, bytes.length), bytes]);
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest();
}

function hex(bytes) {
  return bytes.toString("hex");
}

function objectPreimage(kind, payload) {
  return Buffer.concat([OBJECT_DOMAIN, uint16be(1), uint16be(kind), payload]);
}

function objectDigest(kind, payload) {
  return sha256(objectPreimage(kind, payload));
}

function logicalPreimage(type, payload) {
  return Buffer.concat([LOGICAL_DOMAIN, uint16be(1), uint16be(type), payload]);
}

function logicalDigest(type, payload) {
  return sha256(logicalPreimage(type, payload));
}

function profile(namespace, id, major = 1) {
  return map([[0, namespace], [1, id], [2, major]]);
}

function digest(fill) {
  return Buffer.alloc(32, fill);
}

function id128(fill) {
  assert(fill !== 0);
  return Buffer.alloc(16, fill);
}

function typedDigest(bytes) {
  return map([[0, 1], [1, bytes]]);
}

function objectRef(kind, bytes) {
  return map([[0, 1], [1, kind], [2, 1], [3, bytes]]);
}

function identity(fill = 0x31) {
  return map([[0, profile("identity.test", "opaque")], [1, Buffer.from([fill])], [2, "Vector Actor"]]);
}

function policyResult(fill = 0x32) {
  return map([[0, profile("policy.test", "allow")], [1, 1], [2, 1], [3, typedDigest(digest(fill))]]);
}

function metadata(kind, fields, requiredFeatures = [], extensions = undefined) {
  const entries = [[0, 1], [1, kind], [2, requiredFeatures]];
  if (extensions !== undefined) entries.push([3, extensions]);
  entries.push(...fields);
  return map(entries);
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object" && !Buffer.isBuffer(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
}

function stableJson(value) {
  return Buffer.from(`${JSON.stringify(stableValue(value), null, 2)}\n`);
}

// JSON has no byte string or integer-keyed map type.  This tagged diagnostic
// form is deliberately boring and language neutral: it preserves every CBOR
// value without assigning application-level field names or depending on a
// production decoder.
function diagnosticValue(value) {
  if (Buffer.isBuffer(value)) return { byteStringHex: hex(value) };
  if (value instanceof Map) {
    return {
      map: [...value.entries()].map(([key, item]) => ({
        key: diagnosticValue(key),
        value: diagnosticValue(item)
      }))
    };
  }
  if (Array.isArray(value)) return { array: value.map(diagnosticValue) };
  if (typeof value === "bigint") return { unsignedDecimal: value.toString(10) };
  if (["string", "number", "boolean"].includes(typeof value)) return value;
  throw new TypeError(`unsupported diagnostic value: ${typeof value}`);
}

function objectText(kindName, objectId) {
  return `ogvcs:v1:${kindName}:sha256:${hex(objectId)}`;
}

function fileIdText(bytes) {
  assert(Buffer.isBuffer(bytes) && bytes.length === 16 && !bytes.equals(Buffer.alloc(16)));
  return `fid:${hex(bytes)}`;
}

function decimal(value) {
  return BigInt(value).toString(10);
}

function descriptorDigest(value) {
  return hex(sha256(stableJson(value)));
}

function cborHeadBytes(value) {
  const integer = BigInt(value);
  if (integer < 24n) return 1;
  if (integer <= 0xffn) return 2;
  if (integer <= 0xffffn) return 3;
  if (integer <= 0xffffffffn) return 5;
  return 9;
}

function mediaType(relative) {
  if (relative.startsWith("scenarios/graphs/") && relative.endsWith(".json")) {
    return "application/vnd.opengamevcs.abstract-reference-graph+json";
  }
  if (relative.endsWith(".cbor")) return "application/cbor";
  if (relative.endsWith(".cborseq")) return "application/cbor-seq";
  if (relative.endsWith(".bin")) return "application/octet-stream";
  if (relative.endsWith(".md")) return "text/markdown";
  if (relative.endsWith(".txt")) return "text/plain; charset=utf-8";
  return "application/json";
}

function writeTree(output, files, expectations) {
  files.set("expectations.json", stableJson({
    artifacts: [...files.keys()].sort((a, b) => a.localeCompare(b, "en")).map((relative) => ({
      expected: expectations.get(relative) ?? { result: "data" },
      path: relative
    })),
    schema: "ogvcs.repository-format.v1.artifact-expectations.v1"
  }));
  fs.mkdirSync(output, { recursive: true });
  const retained = new Set([...files.keys(), "manifest.json"]);
  for (const relative of directoryFiles(output).keys()) {
    if (!retained.has(relative)) fs.unlinkSync(path.join(output, relative));
  }
  for (const [relative, bytes] of files) {
    const destination = path.join(output, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, bytes);
  }
  const artifacts = [...files.entries()].sort(([a], [b]) => a.localeCompare(b, "en")).map(([relative, bytes]) => ({
    bytes: bytes.length,
    mediaType: mediaType(relative),
    path: relative,
    sha256: hex(sha256(bytes))
  }));
  const manifest = {
    artifacts,
    generator: {
      implementation: COMMAND,
      sourceSha256: hex(sha256(fs.readFileSync(SOURCE))),
      version: VERSION
    },
    manifestVersion: "ogvcs.repository-format/vector-manifest/v1",
    scenarios: [...files.entries()]
      .filter(([relative]) => relative.startsWith("scenarios/cases/") && relative.endsWith(".json"))
      .map(([relative, bytes]) => {
        const value = JSON.parse(bytes.toString("utf8"));
        return { path: relative, scenarioId: value.scenarioId, sha256: hex(sha256(bytes)) };
      })
      .sort((a, b) => a.scenarioId.localeCompare(b.scenarioId, "en"))
  };
  fs.writeFileSync(path.join(output, "manifest.json"), stableJson(manifest));
}

function directoryFiles(root) {
  const result = new Map();
  if (!fs.existsSync(root)) return result;
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, "en"))) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(absolute);
      else result.set(path.relative(root, absolute).split(path.sep).join("/"), fs.readFileSync(absolute));
    }
  };
  walk(root);
  return result;
}

function compareTrees(expectedRoot, actualRoot) {
  const expected = directoryFiles(expectedRoot);
  const actual = directoryFiles(actualRoot);
  const names = [...new Set([...expected.keys(), ...actual.keys()])].sort();
  const differences = [];
  for (const name of names) {
    if (!expected.has(name)) differences.push(`unexpected ${name}`);
    else if (!actual.has(name)) differences.push(`missing ${name}`);
    else if (!expected.get(name).equals(actual.get(name))) differences.push(`changed ${name}`);
  }
  return differences;
}

function addCbor(files, expectations, relative, value, expected) {
  const bytes = cbor(value);
  files.set(relative, bytes);
  expectations.set(relative, expected);
  return bytes;
}

function generate(output) {
  const files = new Map();
  const expectations = new Map();
  const acceptFraming = { highestLayer: 1, result: "accept" };
  const acceptSchema = { highestLayer: 2, result: "accept" };
  const rejectEncoding = (code) => ({ code, layer: 1, stage: "canonical-framing", result: "reject" });

  const unicodeLicenseBytes = fs.readFileSync(UNICODE_LICENSE_PATH);
  const unicodeNoticeBytes = fs.readFileSync(UNICODE_NOTICE_PATH);
  const unicodeIntervalsBytes = stableJson({
    intervalCount: FROZEN_UNICODE_INTERVALS.length,
    intervals: FROZEN_UNICODE_INTERVALS,
    repertoire: "Unicode scalar values whose Age is assigned in Unicode 15.0.0; surrogates excluded",
    scalarCount: FROZEN_UNICODE_INTERVALS.reduce((sum, [from, to]) => sum + to - from + 1, 0),
    schema: "ogvcs.repository-format.v1.unicode-age-intervals.v1",
    sourceSha256: UNICODE_SOURCE_SHA256,
    unicodeVersion: UNICODE_VERSION
  });
  files.set("unicode/DerivedAge-15.0.0.txt", UNICODE_SOURCE_BYTES);
  files.set("unicode/UNICODE-LICENSE.txt", unicodeLicenseBytes);
  files.set("unicode/NOTICE.md", unicodeNoticeBytes);
  files.set("unicode/age-15.0.0-intervals.json", unicodeIntervalsBytes);
  const unicodeAuthority = {
    compactIntervals: {
      bytes: unicodeIntervalsBytes.length,
      path: "unicode/age-15.0.0-intervals.json",
      sha256: hex(sha256(unicodeIntervalsBytes))
    },
    evaluationOrder: ["shortest-form UTF-8 and Unicode scalar decoding", "Unicode 15.0 Age repertoire", "NFC under the host normalizer"],
    license: {
      bytes: unicodeLicenseBytes.length,
      path: "unicode/UNICODE-LICENSE.txt",
      sha256: hex(sha256(unicodeLicenseBytes))
    },
    notice: {
      bytes: unicodeNoticeBytes.length,
      path: "unicode/NOTICE.md",
      sha256: hex(sha256(unicodeNoticeBytes))
    },
    schema: "ogvcs.repository-format.v1.unicode-authority.v1",
    source: {
      bytes: UNICODE_SOURCE_BYTES.length,
      path: "unicode/DerivedAge-15.0.0.txt",
      sha256: UNICODE_SOURCE_SHA256,
      url: "https://www.unicode.org/Public/15.0.0/ucd/DerivedAge.txt"
    },
    unicodeVersion: UNICODE_VERSION
  };

  const chunk = Buffer.from("OpenGameVCS\n", "ascii");
  const chunkId = objectDigest(1, chunk);
  files.set("objects/01-chunk.bin", chunk);
  expectations.set("objects/01-chunk.bin", acceptFraming);

  const pathProfile = profile("path.test", "opaque");
  const rejectingPathProfile = profile("path.test", "reject-reserved");
  const ratifiedPathProfile = profile("path.opengamevcs", "portable");
  const chunkProfile = profile("chunking.test", "external-boundaries");
  const alternateContentProfile = profile("content-policy.test", "alternate");
  const contentProfile = profile("content-policy.test", "opaque");
  const groupProfile = profile("group.test", "opaque");
  const roleProfile = profile("group-role.test", "member");
  const externalProfile = profile("external-key.test", "opaque");
  const fixtureAssetGroupProfile = profile("fixture-group.opengamevcs.test", "asset", 2);
  const fixtureAssetMetaGroupProfile = profile("fixture-group.opengamevcs.test", "asset-meta", 2);
  const fixtureMemberRoleProfile = profile("fixture-role.opengamevcs.test", "member", 2);
  const fixturePrimaryRoleProfile = profile("fixture-role.opengamevcs.test", "primary", 2);
  const fixtureSyntheticGuidProfile = profile("fixture-key.opengamevcs.test", "synthetic-guid", 2);

  const descriptorValue = metadata(6, [
    [16, id128(0x60)], [17, pathProfile], [18, [contentProfile, alternateContentProfile]], [19, [groupProfile, fixtureAssetGroupProfile, fixtureAssetMetaGroupProfile]], [20, [chunkProfile]]
  ]);
  const descriptorPayload = addCbor(files, expectations, "objects/06-repository-descriptor.cbor", descriptorValue, acceptSchema);
  const descriptorId = objectDigest(6, descriptorPayload);
  const descriptorRef = objectRef(6, descriptorId);

  const repeatedBytes = Buffer.concat([chunk, chunk]);
  const manifestValue = metadata(2, [
    [16, repeatedBytes.length],
    [17, typedDigest(sha256(repeatedBytes))],
    [18, chunkProfile],
    [19, [map([[0, objectRef(1, chunkId)], [1, chunk.length]]), map([[0, objectRef(1, chunkId)], [1, chunk.length]])]]
  ]);
  const manifestPayload = addCbor(files, expectations, "objects/02-content-manifest.cbor", manifestValue, acceptSchema);
  const manifestId = objectDigest(2, manifestPayload);
  const manifestRef = objectRef(2, manifestId);

  const entry = (name, kind, fid, mode, target, size) => map([
    [0, name], [1, kind], [2, fid], [3, mode], [4, target], [5, size], [6, contentProfile]
  ]);
  const childTreeValue = metadata(3, [[16, descriptorRef], [17, []]]);
  const childTreePayload = addCbor(files, expectations, "objects/03-tree-child.cbor", childTreeValue, acceptSchema);
  const childTreeId = objectDigest(3, childTreePayload);
  const childTreeRef = objectRef(3, childTreeId);
  const treeValue = metadata(3, [[16, descriptorRef], [17, [
    entry("dir", 1, id128(0x11), 1, childTreeRef, 0),
    entry("file", 2, id128(0x12), 2, manifestRef, repeatedBytes.length),
    entry("link", 4, id128(0x13), 4, manifestRef, repeatedBytes.length),
    entry("run", 3, id128(0x14), 3, manifestRef, repeatedBytes.length)
  ]]]);
  const treePayload = addCbor(files, expectations, "objects/03-tree.cbor", treeValue, acceptSchema);
  const treeId = objectDigest(3, treePayload);
  const treeRef = objectRef(3, treeId);

  const assetGroup = map([
    [0, id128(0x51)], [1, groupProfile], [2, id128(0x12)],
    [3, [map([[0, id128(0x12)], [1, roleProfile]])]],
    [4, [map([[0, externalProfile], [1, Buffer.from("external-key", "ascii")]])]]
  ]);
  const groupValue = metadata(5, [[16, descriptorRef], [17, [assetGroup]]]);
  const groupPayload = addCbor(files, expectations, "objects/05-asset-group-set.cbor", groupValue, acceptSchema);
  const groupId = objectDigest(5, groupPayload);

  const entryState = map([
    [0, ["file"]], [1, 2], [2, id128(0x12)], [3, 2], [4, manifestRef], [5, repeatedBytes.length], [6, contentProfile]
  ]);
  const conflictSide = map([[0, 1], [1, entryState]]);
  const conflictSubject = [1, [id128(0x12)], [["file"]]];
  const conflictRows = [];
  for (let mask = 0; mask < 8; mask += 1) {
    const preimageMapEntries = [[0, 1], [1, conflictSubject]];
    const recordEntries = [];
    if (mask & 4) { preimageMapEntries.push([2, conflictSide]); recordEntries.push([3, conflictSide]); }
    if (mask & 2) { preimageMapEntries.push([3, conflictSide]); recordEntries.push([4, conflictSide]); }
    if (mask & 1) { preimageMapEntries.push([4, conflictSide]); recordEntries.push([5, conflictSide]); }
    const keyedPayload = cbor(map(preimageMapEntries));
    const preimage = Buffer.concat([CONFLICT_DOMAIN, uint16be(1), keyedPayload]);
    const conflictId = sha256(preimage);
    const bits = mask.toString(2).padStart(3, "0");
    files.set(`conflicts/${bits}-keyed-preimage.cbor`, keyedPayload);
    expectations.set(`conflicts/${bits}-keyed-preimage.cbor`, acceptFraming);
    conflictRows.push({
      basePresent: Boolean(mask & 4),
      conflictId: hex(conflictId),
      domainHex: hex(CONFLICT_DOMAIN),
      formatVersionUint16beHex: "0001",
      keyedPayloadPath: `conflicts/${bits}-keyed-preimage.cbor`,
      leftPresent: Boolean(mask & 2),
      rightPresent: Boolean(mask & 1)
    });
    recordEntries.unshift([0, conflictId], [1, 1], [2, conflictSubject]);
    recordEntries.push([6, map([[0, 0]])]);
    conflictRows[conflictRows.length - 1].record = map(recordEntries);
  }
  const conflictRecords = conflictRows.map((row) => row.record).sort((a, b) => compareBytes(cbor(a.get(0)), cbor(b.get(0))));
  const conflictValue = metadata(11, [[16, descriptorRef], [17, conflictRecords]]);
  const conflictPayload = addCbor(files, expectations, "objects/11-conflict-set.cbor", conflictValue, acceptSchema);
  const conflictId = objectDigest(11, conflictPayload);

  const provenanceStatement = Buffer.from("neutral vector provenance", "ascii");
  const provenanceValue = metadata(9, [
    [16, profile("provenance.test", "opaque")], [17, [manifestRef]],
    [18, typedDigest(sha256(provenanceStatement))], [19, provenanceStatement]
  ]);
  const provenancePayload = addCbor(files, expectations, "objects/09-provenance.cbor", provenanceValue, acceptSchema);
  const provenanceId = objectDigest(9, provenancePayload);

  // The shared snapshot is a real zero-parent repository root. Its change set
  // therefore reconstructs every declared tree entry and group from empty
  // state; downstream historical replay must never trust declared roots.
  const rootAllocation = map([[0, descriptorRef], [1, 1]]);
  const rootStates = [
    map([[0, ["dir"]], [1, 1], [2, id128(0x11)], [3, 1], [5, 0], [6, contentProfile]]),
    map([[0, ["file"]], [1, 2], [2, id128(0x12)], [3, 2], [4, manifestRef], [5, repeatedBytes.length], [6, contentProfile]]),
    map([[0, ["link"]], [1, 4], [2, id128(0x13)], [3, 4], [4, manifestRef], [5, repeatedBytes.length], [6, contentProfile]]),
    map([[0, ["run"]], [1, 3], [2, id128(0x14)], [3, 3], [4, manifestRef], [5, repeatedBytes.length], [6, contentProfile]])
  ];
  const rootOperations = rootStates.map((state, sequence) => map([
    [0, sequence], [1, 1], [3, state], [5, rootAllocation]
  ]));
  rootOperations.push(map([[0, rootOperations.length], [1, 8], [8, assetGroup]]));
  const changeValue = metadata(4, [[16, descriptorRef], [18, rootOperations]]);
  const changePayload = addCbor(files, expectations, "objects/04-change-set.cbor", changeValue, acceptSchema);
  const changeId = objectDigest(4, changePayload);
  const changeRef = objectRef(4, changeId);
  const lifetimeProfileChangeSource = "lifecycle/change-set-lifetime-profile-conformance.cbor";
  const lifetimeProfileChangePayload = addCbor(files, expectations, lifetimeProfileChangeSource,
    // The ordinary root operations already carry the registered
    // content-policy.test/opaque@1 conformance-only profile.  Keep the
    // ChangeSet required-feature list empty so this fixture reaches profile
    // lifecycle instead of failing first as an unsupported feature.
    metadata(4, [[16, descriptorRef], [18, rootOperations]]), acceptSchema);
  const lifetimeProfileChangeId = objectDigest(4, lifetimeProfileChangePayload);
  const lifetimeProfileChangeText = objectText("change-set", lifetimeProfileChangeId);
  const lifetimeBadSchemaSource = "lifecycle/change-set-lifetime-bad-schema.cbor";
  const lifetimeBadSchemaPayload = addCbor(files, expectations, lifetimeBadSchemaSource,
    metadata(4, [[16, descriptorRef]]),
    { code: "SCHEMA_FIELD_INVALID", layer: 2, stage: "known-schema", result: "reject" });
  const lifetimeBadSchemaId = objectDigest(4, lifetimeBadSchemaPayload);
  const lifetimeBadSchemaText = objectText("change-set", lifetimeBadSchemaId);

  // A no-op change set gives the replay resource scenario a semantically
  // valid operation over a nonempty caller-owned base.  The reduced-memory
  // outcome must therefore come from reserving/cloning that base rather than
  // from an unrelated transition or lifetime-evidence failure.
  const replayBaseChangeValue = metadata(4, [[16, descriptorRef], [18, []]]);
  const replayBaseChangePath = "resources/replay-base-noop-change-set.cbor";
  const replayBaseChangePayload = addCbor(
    files, expectations, replayBaseChangePath, replayBaseChangeValue, acceptSchema
  );
  const replayBaseChangeId = objectDigest(4, replayBaseChangePayload);
  const replayBaseChangeText = objectText("change-set", replayBaseChangeId);

  const snapshotValue = metadata(7, [
    [16, descriptorRef], [17, []], [18, treeRef], [19, changeRef],
    [20, objectRef(5, groupId)], [21, identity()], [22, identity(0x32)],
    [23, -1], [24, 0], [25, "Seed é snapshot"], [26, policyResult()],
    [27, [objectRef(9, provenanceId)]]
  ]);
  const snapshotPayload = addCbor(files, expectations, "objects/07-snapshot.cbor", snapshotValue, acceptSchema);
  const snapshotId = objectDigest(7, snapshotPayload);
  const snapshotRef = objectRef(7, snapshotId);

  const shelfValue = metadata(8, [
    [16, descriptorRef], [17, id128(0x81)], [18, 1], [20, snapshotRef], [21, changeRef],
    [22, treeRef], [23, objectRef(5, groupId)], [24, objectRef(11, conflictId)],
    [25, identity()], [26, 1], [27, "Unresolved shelf"], [28, policyResult()],
    [29, [objectRef(9, provenanceId)]]
  ]);
  const shelfPayload = addCbor(files, expectations, "objects/08-shelf-revision.cbor", shelfValue, acceptSchema);
  const shelfId = objectDigest(8, shelfPayload);

  const attestationValue = metadata(10, [
    [16, snapshotRef], [17, profile("attestation.test", "opaque")], [18, identity()], [19, 2],
    [20, Buffer.from("attestation payload", "ascii")], [21, profile("signature.test", "opaque")],
    [22, Buffer.from([0x01, 0x02, 0x03])]
  ]);
  const attestationPayload = addCbor(files, expectations, "objects/10-attestation.cbor", attestationValue, acceptSchema);

  const objectRows = [
    [1, "chunk", "objects/01-chunk.bin", chunk],
    [2, "content-manifest", "objects/02-content-manifest.cbor", manifestPayload],
    [3, "tree", "objects/03-tree.cbor", treePayload],
    [4, "change-set", "objects/04-change-set.cbor", changePayload],
    [5, "asset-group-set", "objects/05-asset-group-set.cbor", groupPayload],
    [6, "repository-descriptor", "objects/06-repository-descriptor.cbor", descriptorPayload],
    [7, "snapshot", "objects/07-snapshot.cbor", snapshotPayload],
    [8, "shelf-revision", "objects/08-shelf-revision.cbor", shelfPayload],
    [9, "provenance", "objects/09-provenance.cbor", provenancePayload],
    [10, "attestation", "objects/10-attestation.cbor", attestationPayload],
    [11, "conflict-set", "objects/11-conflict-set.cbor", conflictPayload]
  ].map(([kind, name, payloadPath, payload]) => ({
    formatVersionUint16beHex: "0001",
    kind,
    kindUint16beHex: uint16be(kind).toString("hex"),
    name,
    objectDomainHex: hex(OBJECT_DOMAIN),
    objectId: hex(objectDigest(kind, payload)),
    payloadPath,
    preimageHex: payload.length <= 256 ? hex(objectPreimage(kind, payload)) : null,
    preimageRecipe: "objectDomainHex || formatVersionUint16beHex || kindUint16beHex || exact payloadPath bytes"
  }));

  const logicalValues = [
    [1, "repository-root", map([[0, 1], [1, 1], [16, descriptorRef], [17, snapshotRef]])],
    [2, "mutable-ref", map([[0, 1], [1, 2], [16, descriptorRef], [17, 1], [18, "main"], [19, snapshotRef], [20, 1]])],
    [3, "shelf-pointer", map([[0, 1], [1, 3], [16, descriptorRef], [17, id128(0x81)], [18, objectRef(8, shelfId)], [19, 1]])],
    [4, "file-id-lifetime", map([[0, 1], [1, 4], [16, descriptorRef], [17, id128(0x12)], [18, 1], [19, changeRef], [20, 0]])],
    [5, "import-mapping", map([[0, 1], [1, 5], [16, descriptorRef], [17, profile("importer.test", "fixture-adapter")], [18, digest(0x51)], [19, digest(0x52)], [20, id128(0x53)], [21, 2]])],
    [6, "pending-change-reference", map([[0, 1], [1, 6], [16, descriptorRef], [17, id128(0x61)], [18, snapshotRef], [19, changeRef], [20, objectRef(11, conflictId)]])],
    [7, "lock-reference", map([[0, 1], [1, 7], [16, descriptorRef], [17, 1], [18, id128(0x12)], [19, snapshotRef], [20, 7]])],
    [8, "annotation", map([[0, 1], [1, 8], [16, manifestRef], [17, profile("annotation.test", "opaque")], [18, Buffer.from("hint-a", "ascii")]])],
    [9, "fixture-event", map([[0, 1], [1, 9], [16, typedDigest(digest(0x91))], [17, 0], [18, profile("fixture-event.opengamevcs.test", "operation", 2)], [19, typedDigest(digest(0x92))], [20, "create"]])]
  ];
  const logicalRows = [];
  for (const [type, name, value] of logicalValues) {
    const relative = `logical-records/${String(type).padStart(2, "0")}-${name}.cbor`;
    const payload = addCbor(files, expectations, relative, value, acceptSchema);
    logicalRows.push({
      formatVersionUint16beHex: "0001",
      identity: hex(logicalDigest(type, payload)),
      logicalDomainHex: hex(LOGICAL_DOMAIN),
      payloadPath: relative,
      preimageHex: hex(logicalPreimage(type, payload)),
      type,
      typeUint16beHex: uint16be(type).toString("hex")
    });
  }
  const logicalWriterInvalidSource = "writer-inputs/logical-record-annotation-unknown-field.cbor";
  addCbor(files, expectations, logicalWriterInvalidSource,
    new Map(logicalValues.find(([type]) => type === 8)[2]).set(4095, 0),
    { code: "SCHEMA_FIELD_UNKNOWN", layer: 2, stage: "known-schema", result: "reject" });
  const logicalRecordRawMapSources = new Map();
  for (const [type, name, value] of logicalValues.filter(([candidate]) => candidate === 4 || candidate === 5)) {
    const mutations = [
      ["version-selector-invalid", (record) => record.set(0, 2), "SCHEMA_FIELD_INVALID"],
      ["type-selector-invalid", (record) => record.set(1, type === 4 ? 5 : 4), "SCHEMA_FIELD_INVALID"],
      ["extra-field-22", (record) => record.set(22, 0), "SCHEMA_FIELD_UNKNOWN"],
      ["extra-field-999", (record) => record.set(999, 0), "SCHEMA_FIELD_UNKNOWN"]
    ];
    for (const [suffix, mutate, code] of mutations) {
      const mutated = new Map(value);
      mutate(mutated);
      const source = `schema/logical-record-${name}-${suffix}.cbor`;
      addCbor(files, expectations, source, mutated,
        { code, layer: 2, stage: "known-schema", result: "reject" });
      logicalRecordRawMapSources.set(`logical-record-${name}-${suffix}`, source);
    }
  }

  function buildBundle(objectInputs, logicalInputs, objectRootRefs, options = {}) {
    const rootProfile = options.rootProfile ?? profile("bundle-role.test", "root");
    const objects = objectInputs.map(({ kind, payload }) => {
      const ref = objectRef(kind, objectDigest(kind, payload));
      return { kind, payload, ref, sortKey: cbor(ref) };
    }).sort((a, b) => compareBytes(a.sortKey, b.sortKey));
    const logicals = logicalInputs.map(({ type, value }) => {
      const payload = cbor(value);
      const identityBytes = logicalDigest(type, payload);
      return { identityBytes, payload, sortKey: Buffer.concat([uint16be(type), identityBytes]), type, value };
    }).sort((a, b) => compareBytes(a.sortKey, b.sortKey));
    const objectItemValues = objects.map((item, ordinal) => map([
      [0, 1], [1, 2], [2, ordinal], [3, item.ref], [4, item.payload]
    ]));
    const objectItems = objectItemValues.map(cbor);
    const logicalItemValues = logicals.map((item, ordinal) => map([
      [0, 1], [1, 3], [2, ordinal], [3, typedDigest(item.identityBytes)], [4, item.value]
    ]));
    const logicalItems = logicalItemValues.map(cbor);
    const roots = [
      ...objectRootRefs.map((ref) => ({ identity: ref, kind: 1, sortKey: Buffer.concat([Buffer.from([1]), cbor(ref), cbor(rootProfile)]) })),
      ...logicals.map((item) => ({ identity: typedDigest(item.identityBytes), kind: 2, sortKey: Buffer.concat([Buffer.from([2]), item.identityBytes, cbor(rootProfile)]) }))
    ].sort((a, b) => compareBytes(a.sortKey, b.sortKey));
    const rootItemValues = roots.map((root, ordinal) => map([
      [0, 1], [1, 4], [2, ordinal], [3, root.kind], [4, root.identity], [5, rootProfile]
    ]));
    const rootItems = rootItemValues.map(cbor);
    let declaredTotal = 0;
    let declaredLargest = 0;
    let result;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const headerValue = map([
        [0, 1], [1, 1], [2, 1], [3, objectItems.length], [4, logicalItems.length], [5, rootItems.length],
        [6, map([[0, declaredTotal], [1, declaredLargest], [2, options.declaredTraversalEdges ?? 16], [3, objects.length + logicals.length]])]
      ]);
      const header = cbor(headerValue);
      const beforeTrailer = Buffer.concat([header, ...objectItems, ...logicalItems, ...rootItems]);
      const transcriptDigest = sha256(Buffer.concat([BUNDLE_DOMAIN, uint16be(1), beforeTrailer]));
      const trailerValue = map([
        [0, 1], [1, 5], [2, objectItems.length], [3, logicalItems.length], [4, rootItems.length],
        [5, 2 + objectItems.length + logicalItems.length + rootItems.length], [6, typedDigest(transcriptDigest)]
      ]);
      const trailer = cbor(trailerValue);
      const parts = [header, ...objectItems, ...logicalItems, ...rootItems, trailer];
      const nextLargest = Math.max(...parts.map((part) => part.length));
      const nextTotal = parts.reduce((sum, part) => sum + part.length, 0);
      result = {
        beforeTrailer,
        itemKinds: ["header", ...objectItems.map(() => "object"), ...logicalItems.map(() => "logical-record"), ...rootItems.map(() => "root"), "trailer"],
        itemValues: [headerValue, ...objectItemValues, ...logicalItemValues, ...rootItemValues, trailerValue],
        logicals,
        objects,
        parts,
        sequence: Buffer.concat(parts),
        transcriptDigest
      };
      if (nextLargest === declaredLargest && nextTotal === declaredTotal) break;
      declaredLargest = nextLargest;
      declaredTotal = nextTotal;
    }
    assert.equal(result.sequence.length, declaredTotal);
    assert.equal(Math.max(...result.parts.map((part) => part.length)), declaredLargest);
    return result;
  }

  const annotationValue = logicalValues.find(([type]) => type === 8)[2];
  const validBundle = buildBundle(
    [{ kind: 1, payload: chunk }, { kind: 2, payload: manifestPayload }],
    [{ type: 8, value: annotationValue }],
    [manifestRef]
  );
  files.set("logical-bundles/valid-supplied-closure.cborseq", validBundle.sequence);
  expectations.set("logical-bundles/valid-supplied-closure.cborseq", { highestLayer: 3, mode: "conformance", result: "accept" });

  const nestedCaptureDepth = 8;
  const nestedCaptureInitialBytes = 64;
  let nestedCaptureValue = 0;
  for (let depth = 0; depth < nestedCaptureDepth; depth += 1) {
    nestedCaptureValue = map([[nestedCaptureValue, 0]]);
  }
  const nestedCaptureKeyBytes = cbor([...nestedCaptureValue.keys()][0]);
  assert(nestedCaptureKeyBytes.length < nestedCaptureInitialBytes,
    "each nested canonical key must fit one initial capture allocation");
  const nestedCaptureBundle = buildBundle([], [{ type: 8, value: nestedCaptureValue }], []);
  const nestedCaptureBundlePath = "logical-bundles/nested-map-key-capture-memory.cborseq";
  files.set(nestedCaptureBundlePath, nestedCaptureBundle.sequence);

  const objectEdgeOccurrences = new Map([[1, 0], [2, 2], [3, 5], [4, 8], [5, 1], [6, 0], [7, 5], [8, 7], [9, 1], [10, 1], [11, 13]]);
  const logicalEdgeOccurrences = new Map([[1, 2], [2, 2], [3, 2], [4, 2], [5, 1], [6, 4], [7, 2], [8, 1], [9, 0]]);
  const allFamilyTraversalEdges = objectRows.reduce((sum, row) => sum + objectEdgeOccurrences.get(row.kind), 0)
    + 1 // the separately supplied empty child tree has its descriptor edge
    + logicalRows.reduce((sum, row) => sum + logicalEdgeOccurrences.get(row.type), 0);
  assert.equal(allFamilyTraversalEdges, 60, "all-family bundle edge-occurrence accounting drift");
  const allFamilyBundle = buildBundle(
    [...objectRows.map((row) => ({ kind: row.kind, payload: files.get(row.payloadPath) })), { kind: 3, payload: childTreePayload }],
    logicalValues.map(([type, _name, value]) => ({ type, value })),
    objectRows.map((row) => objectRef(row.kind, Buffer.from(row.objectId, "hex"))),
    { declaredTraversalEdges: allFamilyTraversalEdges }
  );
  files.set("logical-bundles/valid-all-families.cborseq", allFamilyBundle.sequence);
  expectations.set("logical-bundles/valid-all-families.cborseq", { highestLayer: 3, mode: "conformance", result: "accept" });

  const objectItemStart = 1;
  const swappedParts = [...validBundle.parts];
  [swappedParts[objectItemStart], swappedParts[objectItemStart + 1]] = [swappedParts[objectItemStart + 1], swappedParts[objectItemStart]];
  files.set("logical-bundles/invalid-section-order.cborseq", Buffer.concat(swappedParts));
  expectations.set("logical-bundles/invalid-section-order.cborseq", { code: "BUNDLE_SEQUENCE_INVALID", layer: 1, stage: "sequence-shape-and-order", result: "reject" });

  const duplicateParts = [...validBundle.parts];
  const firstObject = validBundle.objects[0];
  duplicateParts[objectItemStart + 1] = cbor(map([[0, 1], [1, 2], [2, 1], [3, firstObject.ref], [4, firstObject.payload]]));
  files.set("logical-bundles/invalid-duplicate-identity.cborseq", Buffer.concat(duplicateParts));
  expectations.set("logical-bundles/invalid-duplicate-identity.cborseq", { code: "BUNDLE_DUPLICATE_IDENTITY", layer: 1, stage: "sequence-shape-and-order", result: "reject" });

  const missingBundle = buildBundle(
    [{ kind: 2, payload: manifestPayload }],
    [{ type: 8, value: annotationValue }],
    [manifestRef]
  );
  files.set("logical-bundles/invalid-closure-missing.cborseq", missingBundle.sequence);
  expectations.set("logical-bundles/invalid-closure-missing.cborseq", { code: "BUNDLE_CLOSURE_MISSING", layer: 2, stage: "closure-and-reference-resolution", result: "reject" });

  const emptyChunk = Buffer.alloc(0);
  const extraBundle = buildBundle(
    [{ kind: 1, payload: emptyChunk }, { kind: 1, payload: chunk }, { kind: 2, payload: manifestPayload }],
    [{ type: 8, value: annotationValue }],
    [manifestRef]
  );
  files.set("logical-bundles/invalid-closure-extra.cborseq", extraBundle.sequence);
  expectations.set("logical-bundles/invalid-closure-extra.cborseq", { code: "BUNDLE_CLOSURE_EXTRA", layer: 2, stage: "closure-and-reference-resolution", result: "reject" });

  const wrongKindProvenance = cbor(metadata(9, [
    [16, profile("provenance.test", "opaque")], [17, []], [18, typedDigest(sha256(Buffer.alloc(0)))]
  ]));
  const wrongKindDigest = objectDigest(9, wrongKindProvenance);
  const wrongKindManifestValue = metadata(2, [
    [16, 1], [17, typedDigest(digest(0xaa))], [18, chunkProfile],
    [19, [map([[0, objectRef(1, wrongKindDigest)], [1, 1]])]]
  ]);
  const wrongKindManifestPayload = cbor(wrongKindManifestValue);
  const wrongKindManifestRef = objectRef(2, objectDigest(2, wrongKindManifestPayload));
  const wrongKindAnnotation = map([[0, 1], [1, 8], [16, wrongKindManifestRef], [17, profile("annotation.test", "opaque")], [18, Buffer.alloc(0)]]);
  const wrongKindBundle = buildBundle(
    [{ kind: 2, payload: wrongKindManifestPayload }, { kind: 9, payload: wrongKindProvenance }],
    [{ type: 8, value: wrongKindAnnotation }],
    [wrongKindManifestRef]
  );
  files.set("logical-bundles/invalid-reference-wrong-kind.cborseq", wrongKindBundle.sequence);
  expectations.set("logical-bundles/invalid-reference-wrong-kind.cborseq", { code: "OBJECT_REFERENCE_KIND_MISMATCH", layer: 2, stage: "closure-and-reference-resolution", result: "reject" });

  const trailerMismatch = Buffer.from(validBundle.sequence);
  trailerMismatch[trailerMismatch.length - 1] ^= 0x01;
  files.set("logical-bundles/invalid-trailer-mismatch.cborseq", trailerMismatch);
  expectations.set("logical-bundles/invalid-trailer-mismatch.cborseq", { code: "BUNDLE_TRAILER_MISMATCH", layer: 1, stage: "transcript-authentication", result: "reject" });

  const unknownLogicalBundle = buildBundle(
    [], [{ type: 65_535, value: map([[0, 1], [1, 65_535]]) }], []
  );
  files.set("logical-bundles/invalid-logical-record-type.cborseq", unknownLogicalBundle.sequence);
  expectations.set("logical-bundles/invalid-logical-record-type.cborseq", {
    code: "LOGICAL_RECORD_TYPE_UNSUPPORTED", layer: 2, stage: "known-schema", result: "reject"
  });

  const schemaUnknownValue = new Map(manifestValue);
  schemaUnknownValue.set(4095, 0);
  addCbor(files, expectations, "schema/invalid-unknown-field.cbor", schemaUnknownValue,
    { code: "SCHEMA_FIELD_UNKNOWN", layer: 2, stage: "known-schema", result: "reject" });
  addCbor(files, expectations, "schema/invalid-extension-key.cbor", metadata(2, [
    [16, repeatedBytes.length], [17, typedDigest(sha256(repeatedBytes))], [18, chunkProfile],
    [19, [map([[0, objectRef(1, chunkId)], [1, chunk.length]]), map([[0, objectRef(1, chunkId)], [1, chunk.length]])]]
  ], [], map([["not-a-profile-ref", 1]])), { code: "EXTENSION_KEY_INVALID", layer: 2, stage: "known-schema", result: "reject" });
  addCbor(files, expectations, "schema/invalid-object-kind.cbor", metadata(65_535, []),
    { code: "OBJECT_KIND_UNSUPPORTED", layer: 2, stage: "known-schema", result: "reject" });
  const unsupportedChunkRef = new Map(objectRef(1, chunkId));
  unsupportedChunkRef.set(2, 2);
  addCbor(files, expectations, "schema/invalid-object-reference-format.cbor", metadata(2, [
    [16, chunk.length], [17, typedDigest(sha256(chunk))], [18, chunkProfile],
    [19, [map([[0, unsupportedChunkRef], [1, chunk.length]])]]
  ]), { code: "OBJECT_REFERENCE_FORMAT_UNSUPPORTED", layer: 2, stage: "known-schema", result: "reject" });

  files.set("logical-bundles/index.json", stableJson({
    negativeCases: [
      { artifact: "logical-bundles/invalid-section-order.cborseq", expected: { code: "BUNDLE_SEQUENCE_INVALID", layer: 1, stage: "sequence-shape-and-order", result: "reject" } },
      { artifact: "logical-bundles/invalid-duplicate-identity.cborseq", expected: { code: "BUNDLE_DUPLICATE_IDENTITY", layer: 1, stage: "sequence-shape-and-order", result: "reject" } },
      { artifact: "logical-bundles/invalid-closure-missing.cborseq", expected: { code: "BUNDLE_CLOSURE_MISSING", layer: 2, stage: "closure-and-reference-resolution", result: "reject" } },
      { artifact: "logical-bundles/invalid-closure-extra.cborseq", expected: { code: "BUNDLE_CLOSURE_EXTRA", layer: 2, stage: "closure-and-reference-resolution", result: "reject" } },
      { artifact: "logical-bundles/invalid-reference-wrong-kind.cborseq", expected: { code: "OBJECT_REFERENCE_KIND_MISMATCH", layer: 2, stage: "closure-and-reference-resolution", result: "reject" } },
      { artifact: "logical-bundles/invalid-trailer-mismatch.cborseq", expected: { code: "BUNDLE_TRAILER_MISMATCH", layer: 1, stage: "transcript-authentication", result: "reject" } },
      { artifact: "logical-bundles/invalid-logical-record-type.cborseq", expected: { code: "LOGICAL_RECORD_TYPE_UNSUPPORTED", layer: 2, stage: "known-schema", result: "reject" } },
      { artifact: "logical-bundles/valid-supplied-closure.cborseq", claim: "fidelity-export", expected: { code: "BUNDLE_EXPORT_CLAIM_FORBIDDEN", layer: 3, stage: "repository-semantics", result: "reject" } }
    ],
    schema: "ogvcs.repository-format.v1.logical-bundle-vectors.v1",
    valid: {
      artifact: "logical-bundles/valid-supplied-closure.cborseq",
      expected: { highestLayer: 3, mode: "conformance", result: "accept" },
      itemBytes: validBundle.parts.map((part) => part.length),
      itemCount: validBundle.parts.length,
      logicalRecordIdentity: hex(validBundle.logicals[0].identityBytes),
      objectIdsInCanonicalOrder: validBundle.objects.map((item) => ({ kind: item.kind, objectId: hex(item.ref.get(3)) })),
      sequenceBytes: validBundle.sequence.length,
      transcriptDigest: hex(validBundle.transcriptDigest)
    }
  }));

  const annotationB = map([[0, 1], [1, 8], [16, manifestRef], [17, profile("annotation.test", "opaque")], [18, Buffer.from("hint-b", "ascii")]]);
  const annotationBPayload = addCbor(files, expectations, "invariants/annotation-b.cbor", annotationB, acceptSchema);
  const annotationA = logicalValues.find(([type]) => type === 8)[2];
  const annotationAPayload = cbor(annotationA);
  files.set("objects/index.json", stableJson({ objects: objectRows, schema: "ogvcs.repository-format.v1.object-vectors.v1" }));
  files.set("logical-records/index.json", stableJson({ records: logicalRows, schema: "ogvcs.repository-format.v1.logical-record-vectors.v1" }));
  files.set("conflicts/index.json", stableJson({
    combinations: conflictRows.map(({ record, ...row }) => row),
    conflictIdRecipe: "SHA-256(domainHex || 0001 || exact keyedPayloadPath bytes)",
    schema: "ogvcs.repository-format.v1.conflict-preimages.v1"
  }));
  files.set("invariants/index.json", stableJson({
    annotationInvariance: {
      annotationAIdentity: hex(logicalDigest(8, annotationAPayload)),
      annotationBIdentity: hex(logicalDigest(8, annotationBPayload)),
      manifestObjectIdAfter: hex(manifestId),
      manifestObjectIdBefore: hex(manifestId),
      subjectObjectId: hex(manifestId)
    },
    repeatedChunkReferences: {
      chunkObjectId: hex(chunkId),
      logicalLength: repeatedBytes.length,
      occurrenceCount: 2,
      objectPath: "objects/02-content-manifest.cbor",
      wholeFileSha256: hex(sha256(repeatedBytes))
    },
    schema: "ogvcs.repository-format.v1.invariants.v1"
  }));

  const objectValues = new Map([
    [1, chunk], [2, manifestValue], [3, treeValue], [4, changeValue], [5, groupValue],
    [6, descriptorValue], [7, snapshotValue], [8, shelfValue], [9, provenanceValue],
    [10, attestationValue], [11, conflictValue]
  ]);
  const decodedObjects = objectRows.map((row) => ({
    diagnostic: diagnosticValue(objectValues.get(row.kind)),
    kind: row.kind,
    kindName: row.name,
    objectId: row.objectId,
    payloadPath: row.payloadPath
  }));
  const decodedLogicalRecords = logicalValues.map(([type, name, value]) => ({
    diagnostic: diagnosticValue(value),
    identity: hex(logicalDigest(type, cbor(value))),
    name,
    payloadPath: `logical-records/${String(type).padStart(2, "0")}-${name}.cbor`,
    type
  }));
  const decodedBundleItems = [];
  const seenBundleKinds = new Set();
  let bundleOffset = 0;
  for (let index = 0; index < validBundle.parts.length; index += 1) {
    const kind = validBundle.itemKinds[index];
    const bytes = validBundle.parts[index];
    if (!seenBundleKinds.has(kind)) {
      decodedBundleItems.push({
        byteLength: bytes.length,
        byteOffset: bundleOffset,
        diagnostic: diagnosticValue(validBundle.itemValues[index]),
        itemKind: kind,
        source: "logical-bundles/valid-supplied-closure.cborseq"
      });
      seenBundleKinds.add(kind);
    }
    bundleOffset += bytes.length;
  }
  files.set("diagnostics/decoded-values.json", stableJson({
    bundleItemShapes: decodedBundleItems,
    diagnosticRepresentation: {
      array: "{array:[diagnostic-value,...]}",
      byteString: "{byteStringHex:lowercase-even-length-hex}",
      map: "{map:[{key:diagnostic-value,value:diagnostic-value},...]} in deterministic-CBOR key order",
      scalar: "JSON string, safe integer, or boolean; unsignedDecimal tag is used beyond JSON's exact integer range"
    },
    logicalRecords: decodedLogicalRecords,
    objects: decodedObjects,
    schema: "ogvcs.repository-format.v1.decoded-diagnostics.v1"
  }));
  files.set("diagnostics/text-values.json", stableJson({
    fileIds: [0x11, 0x12, 0x13, 0x14, 0x51, 0x53, 0x60, 0x81].map((fill) => ({
      bytesHex: hex(id128(fill)),
      text: fileIdText(id128(fill))
    })),
    objectRefs: objectRows.map((row) => ({
      kind: row.kind,
      kindName: row.name,
      objectId: row.objectId,
      text: objectText(row.name, Buffer.from(row.objectId, "hex"))
    })),
    parsePolicy: {
      fileId: "accept exactly fid: followed by 32 lowercase hexadecimal digits and reject the all-zero value",
      objectRef: "accept exactly ogvcs:v1:<registered-kind-textToken>:sha256:<64 lowercase hexadecimal digits> with no whitespace or aliases"
    },
    schema: "ogvcs.repository-format.v1.text-constructor-values.v1"
  }));

  const mutationSources = [
    ...objectRows.map((row) => ({
      byteLength: files.get(row.payloadPath).length,
      category: row.kind === 1 ? "raw-object" : "metadata-object",
      declaredIdentity: row.objectId,
      identityFailure: "OBJECT_ID_MISMATCH",
      source: row.payloadPath
    })),
    ...logicalRows.map((row) => ({
      byteLength: files.get(row.payloadPath).length,
      category: "logical-record",
      declaredIdentity: row.identity,
      identityFailure: "BUNDLE_RECORD_ID_MISMATCH",
      source: row.payloadPath
    }))
  ];
  const shapeMutationSources = decodedBundleItems.map((item) => ({
    byteLength: item.byteLength,
    byteOffset: item.byteOffset,
    category: `bundle-${item.itemKind}`,
    source: item.source
  }));
  const totalSingleBitMutations = [...mutationSources, ...shapeMutationSources]
    .reduce((sum, item) => sum + item.byteLength * 8, validBundle.sequence.length * 8);
  files.set("mutations/single-bit.json", stableJson({
    algorithm: {
      bitNumbering: "bitIndex 0 is mask 0x01 and bitIndex 7 is mask 0x80",
      id: "ogvcs.systematic-single-bit-xor",
      operation: "for byteOffset in [0,byteLength), then bitIndex in [0,8), clone the selected byte range and XOR byte[byteOffset] with (1 << bitIndex)",
      order: ["source catalogue order", "ascending byteOffset", "ascending bitIndex"],
      version: 1
    },
    bundleItemShapes: shapeMutationSources,
    invariants: {
      bundleItem: "apply canonical framing first; if framing succeeds, item/record/object identity and then transcript verification use the original declarations",
      bundleSequence: "apply canonical item framing, section/order/count/ordinal/mode/budget and embedded identity checks in normative layer order; if those pass, require BUNDLE_TRAILER_MISMATCH because the original trailer transcript digest cannot authenticate changed pre-trailer bytes",
      objectOrLogicalRecord: "apply canonical framing before identity; a canonical changed payload must recompute a digest different from declaredIdentity and fail identityFailure"
    },
    schema: "ogvcs.repository-format.v1.single-bit-mutation-recipes.v1",
    sources: mutationSources,
    totalCases: totalSingleBitMutations,
    wholeSequence: {
      byteLength: validBundle.sequence.length,
      category: "bundle-sequence",
      source: "logical-bundles/valid-supplied-closure.cborseq"
    }
  }));

  const prefixSources = [
    ...objectRows.filter((row) => row.kind > 1).map((row) => ({
      byteLength: files.get(row.payloadPath).length,
      category: "metadata-object",
      expected: { code: "CBOR_TRUNCATED", layer: 1, stage: "canonical-framing", result: "reject" },
      prefixes: { fromInclusive: 0, toInclusive: files.get(row.payloadPath).length - 1 },
      source: row.payloadPath
    })),
    ...logicalRows.map((row) => ({
      byteLength: files.get(row.payloadPath).length,
      category: "logical-record",
      expected: { code: "CBOR_TRUNCATED", layer: 1, stage: "canonical-framing", result: "reject" },
      prefixes: { fromInclusive: 0, toInclusive: files.get(row.payloadPath).length - 1 },
      source: row.payloadPath
    })),
    ...decodedBundleItems.map((item) => ({
      byteLength: item.byteLength,
      byteOffset: item.byteOffset,
      category: `bundle-${item.itemKind}`,
      expected: { code: "CBOR_TRUNCATED", layer: 1, stage: "canonical-framing", result: "reject" },
      prefixes: { fromInclusive: 0, toInclusive: item.byteLength - 1 },
      source: item.source
    }))
  ];
  const wholeSequenceRanges = [];
  let sequenceOffset = 0;
  for (const part of validBundle.parts) {
    wholeSequenceRanges.push({
      expected: { code: "BUNDLE_SEQUENCE_INVALID", layer: 1, stage: "sequence-shape-and-order", result: "reject" },
      fromInclusive: sequenceOffset,
      reason: "prefix ends at an item boundary before a complete trailer and EOF",
      toInclusive: sequenceOffset
    });
    if (part.length > 1) {
      wholeSequenceRanges.push({
        expected: { code: "CBOR_TRUNCATED", layer: 1, stage: "canonical-framing", result: "reject" },
        fromInclusive: sequenceOffset + 1,
        reason: "prefix ends inside the current deterministic-CBOR item",
        toInclusive: sequenceOffset + part.length - 1
      });
    }
    sequenceOffset += part.length;
  }
  assert.equal(sequenceOffset, validBundle.sequence.length);
  const totalTruncationCases = prefixSources.reduce((sum, item) => sum + item.byteLength, 0)
    + validBundle.sequence.length;
  files.set("mutations/truncation.json", stableJson({
    algorithm: {
      id: "ogvcs.every-proper-prefix",
      operation: "for prefixBytes in the declared inclusive range, validate source[0:prefixBytes] (or the selected item subrange[0:prefixBytes])",
      order: "ascending prefixBytes",
      precedence: ["CBOR_TRUNCATED when EOF is inside an item", "BUNDLE_SEQUENCE_INVALID when a whole-sequence EOF is between items before the complete trailer", "all later layer results are suppressed"],
      version: 1
    },
    schema: "ogvcs.repository-format.v1.truncation-recipes.v1",
    sources: prefixSources,
    totalCases: totalTruncationCases,
    wholeSequence: {
      byteLength: validBundle.sequence.length,
      ranges: wholeSequenceRanges,
      source: "logical-bundles/valid-supplied-closure.cborseq"
    }
  }));

  files.set("seed.json", stableJson({
    independentlyReproducible: {
      formula: "SHA-256(objectDomainHex || formatVersionUint16beHex || kindUint16beHex || payloadHex)",
      formatVersionUint16beHex: "0001",
      kindUint16beHex: "0001",
      objectDomainAscii: "OpenGameVCS object\\0",
      objectDomainHex: hex(OBJECT_DOMAIN),
      objectId: hex(chunkId),
      payloadAsciiEscaped: "OpenGameVCS\\n",
      payloadHex: hex(chunk),
      preimageHex: hex(objectPreimage(1, chunk))
    },
    schema: "ogvcs.repository-format.v1.hand-auditable-seed.v1"
  }));

  const fixtureDescriptor = metadata(6, [
    [16, id128(0x70)], [17, pathProfile],
    [18, [profile("fixture-content.opengamevcs.test", "meta", 2), profile("fixture-content.opengamevcs.test", "asset", 2)]],
    [19, [profile("fixture-group.opengamevcs.test", "asset-meta", 2)]],
    [20, [chunkProfile]]
  ]);
  const fixtureDescriptorPayload = addCbor(files, expectations, "profiles/fixture-descriptor.cbor", fixtureDescriptor, acceptSchema);
  const fixtureDescriptorRef = objectRef(6, objectDigest(6, fixtureDescriptorPayload));
  const fixtureTree = metadata(3, [[16, fixtureDescriptorRef], [17, [
    map([
      [0, "asset"], [1, 2], [2, id128(0x71)], [3, 2], [4, manifestRef], [5, repeatedBytes.length],
      [6, profile("fixture-content.opengamevcs.test", "asset", 2)]
    ]),
    map([
      [0, "asset.meta"], [1, 2], [2, id128(0x74)], [3, 2], [4, manifestRef], [5, repeatedBytes.length],
      [6, profile("fixture-content.opengamevcs.test", "meta", 2)]
    ])
  ]]]);
  addCbor(files, expectations, "profiles/fixture-tree.cbor", fixtureTree, acceptSchema);
  const fixtureGroupValue = map([
    [0, id128(0x72)], [1, profile("fixture-group.opengamevcs.test", "asset-meta", 2)], [2, id128(0x71)],
    [3, [
      map([[0, id128(0x74)], [1, profile("fixture-role.opengamevcs.test", "meta", 2)]]),
      map([[0, id128(0x71)], [1, profile("fixture-role.opengamevcs.test", "primary", 2)]])
    ]],
    [4, [map([[0, profile("fixture-key.opengamevcs.test", "synthetic-guid", 2)], [1, id128(0x73)]])]]
  ]);
  addCbor(files, expectations, "profiles/fixture-group-set.cbor", metadata(5, [[16, fixtureDescriptorRef], [17, [fixtureGroupValue]]]), acceptSchema);

  const bundleRoot = map([[0, 1], [1, 4], [2, 0], [3, 1], [4, manifestRef], [5, profile("bundle-role.test", "root")]]);
  addCbor(files, expectations, "profiles/bundle-root.cbor", bundleRoot, acceptSchema);

  const profileUses = [
    ["annotation-payload", "annotation.test/opaque@1", "logical-records/08-annotation.cbor", "annotation.profile"],
    ["attestation-predicate", "attestation.test/opaque@1", "objects/10-attestation.cbor", "attestation.predicate"],
    ["bundle-root-role", "bundle-role.test/root@1", "profiles/bundle-root.cbor", "bundle-root.role"],
    ["chunking", "chunking.test/external-boundaries@1", "objects/02-content-manifest.cbor", "manifest.chunk-profile"],
    ["content-policy", "content-policy.test/opaque@1", "objects/03-tree.cbor", "tree-entry.content-policy"],
    ["external-key", "external-key.test/opaque@1", "objects/05-asset-group-set.cbor", "group.external-key.scheme"],
    ["fixture-content-policy", "fixture-content.opengamevcs.test/asset@2", "profiles/fixture-tree.cbor", "fixture-tree-entry.content-policy"],
    ["fixture-event", "fixture-event.opengamevcs.test/operation@2", "logical-records/09-fixture-event.cbor", "fixture-event.profile"],
    ["fixture-external-key", "fixture-key.opengamevcs.test/synthetic-guid@2", "profiles/fixture-group-set.cbor", "fixture-group.external-key.scheme"],
    ["fixture-group", "fixture-group.opengamevcs.test/asset-meta@2", "profiles/fixture-group-set.cbor", "fixture-group.profile"],
    ["fixture-group-role", "fixture-role.opengamevcs.test/primary@2", "profiles/fixture-group-set.cbor", "fixture-group.member.role"],
    ["group", "group.test/opaque@1", "objects/05-asset-group-set.cbor", "group.profile"],
    ["group-role", "group-role.test/member@1", "objects/05-asset-group-set.cbor", "group.member.role"],
    ["identity", "identity.test/opaque@1", "objects/07-snapshot.cbor", "snapshot.author.scheme"],
    ["importer", "importer.test/fixture-adapter@1", "logical-records/05-import-mapping.cbor", "import-mapping.importer"],
    ["path", "path.test/opaque@1", "objects/06-repository-descriptor.cbor", "descriptor.path-profile"],
    ["policy", "policy.test/allow@1", "objects/07-snapshot.cbor", "snapshot.policy-result.profile"],
    ["provenance", "provenance.test/opaque@1", "objects/09-provenance.cbor", "provenance.producer"],
    ["signature", "signature.test/opaque@1", "objects/10-attestation.cbor", "attestation.signature-profile"]
  ].map(([family, profileText, artifact, field]) => ({
    artifact,
    expected: { highestLayer: 3, mode: "conformance", result: "accept" },
    family,
    field,
    profile: profileText,
    validationScope: "isolated profile family, registry state, and profile-specific behavior after layer-2 acceptance"
  }));

  const wrongFamilyDefinitions = [
    ["descriptor-path", metadata(6, [[16, id128(0x60)], [17, contentProfile], [18, [contentProfile]], [19, []]])],
    ["manifest-chunking", metadata(2, [[16, 0], [17, typedDigest(sha256(Buffer.alloc(0)))], [18, pathProfile], [19, []]])],
    ["tree-content-policy", metadata(3, [[16, descriptorRef], [17, [entry("x", 2, id128(0x20), 2, manifestRef, repeatedBytes.length).set(6, groupProfile)]]])],
    ["group-profile", metadata(5, [[16, descriptorRef], [17, [map([[0, id128(0x21)], [1, contentProfile], [2, id128(0x12)], [3, [map([[0, id128(0x12)], [1, roleProfile]])]]])]]])],
    ["group-member-role", metadata(5, [[16, descriptorRef], [17, [map([[0, id128(0x22)], [1, groupProfile], [2, id128(0x12)], [3, [map([[0, id128(0x12)], [1, profile("identity.test", "opaque")]])]]])]]])],
    ["group-external-key", metadata(5, [[16, descriptorRef], [17, [map([[0, id128(0x23)], [1, groupProfile], [2, id128(0x12)], [3, [map([[0, id128(0x12)], [1, roleProfile]])]], [4, [map([[0, roleProfile], [1, Buffer.from([1])]])]]])]]])],
    ["snapshot-identity", metadata(7, [[16, descriptorRef], [17, []], [18, treeRef], [19, changeRef], [21, map([[0, pathProfile], [1, Buffer.from([1])]])], [22, identity()], [23, 0], [24, 0], [25, ""], [26, policyResult()]])],
    ["snapshot-policy", metadata(7, [[16, descriptorRef], [17, []], [18, treeRef], [19, changeRef], [21, identity()], [22, identity()], [23, 0], [24, 0], [25, ""], [26, map([[0, pathProfile], [1, 0], [2, 1], [3, typedDigest(digest(1))]])]])],
    ["provenance-producer", metadata(9, [[16, contentProfile], [17, []], [18, typedDigest(sha256(Buffer.alloc(0)))], [19, Buffer.alloc(0)]])],
    ["attestation-predicate", metadata(10, [[16, manifestRef], [17, profile("signature.test", "opaque")], [18, identity()], [19, 0], [20, Buffer.alloc(0)]])],
    ["attestation-signature", metadata(10, [[16, manifestRef], [17, profile("attestation.test", "opaque")], [18, identity()], [19, 0], [20, Buffer.alloc(0)], [21, profile("attestation.test", "opaque")], [22, Buffer.from([1])]])],
    ["annotation-profile", map([[0, 1], [1, 8], [16, manifestRef], [17, profile("signature.test", "opaque")], [18, Buffer.alloc(0)]])],
    ["importer-profile", map([[0, 1], [1, 5], [16, descriptorRef], [17, pathProfile], [18, digest(1)], [19, digest(2)], [20, id128(1)], [21, 1]])],
    ["fixture-event-profile", map([[0, 1], [1, 9], [16, typedDigest(digest(1))], [17, 0], [18, pathProfile], [19, typedDigest(digest(2))], [20, "create"]])],
    ["bundle-root-role", map([[0, 1], [1, 4], [2, 0], [3, 1], [4, manifestRef], [5, profile("annotation.test", "opaque")]])]
  ];
  const wrongFamilyRows = [];
  for (const [name, value] of wrongFamilyDefinitions) {
    const relative = `profiles/wrong-family/${name}.cbor`;
    addCbor(files, expectations, relative, value, { code: "SCHEMA_FIELD_INVALID", layer: 2, stage: "known-schema", result: "reject" });
    wrongFamilyRows.push({ artifact: relative, expected: { code: "SCHEMA_FIELD_INVALID", layer: 2, stage: "known-schema", result: "reject" }, name });
  }
  files.set("profiles/index.json", stableJson({
    productionMode: profileUses.map((item) => ({
      artifact: item.artifact,
      expected: { code: "PROFILE_CONFORMANCE_ONLY", layer: 3, stage: "registry-semantics", mode: "production", result: "reject" },
      family: item.family,
      profile: item.profile,
      validationScope: item.validationScope
    })),
    schema: "ogvcs.repository-format.v1.profile-cases.v1",
    validFamilyUses: profileUses,
    wrongFamilyUses: wrongFamilyRows
  }));

  const unicodeAssignedSource = "unicode/cases/age-15-assigned.cbor";
  const unicodeAssignedBytes = cbor(String.fromCodePoint(0x1fae8));
  files.set(unicodeAssignedSource, unicodeAssignedBytes);
  expectations.set(unicodeAssignedSource, acceptFraming);
  const unicodeMalformed = new Map([
    ["unicode-age-newer-composition-pair.cbor", [0x16d63, 0x16d68]],
    ["unicode-age-newer-decomposed.cbor", [0x16d63, 0x16d67, 0x16d67]],
    ["unicode-age-newer-canonical.cbor", [0x16d6a]],
    ["unicode-age-frozen-unassigned.cbor", [0x0378]]
  ]);
  const malformed = new Map([
    ["truncated.cbor", Buffer.from("a100", "hex")],
    ["nonminimal-unsigned.cbor", Buffer.from("1800", "hex")],
    ["nonminimal-negative.cbor", Buffer.from("3800", "hex")],
    ["nonminimal-length.cbor", Buffer.from("5800", "hex")],
    ["map-key-order.cbor", Buffer.from("a201000001", "hex")],
    ["duplicate-map-key.cbor", Buffer.from("a200010002", "hex")],
    ["indefinite-bytes.cbor", Buffer.from("5f40ff", "hex")],
    ["indefinite-text.cbor", Buffer.from("7f60ff", "hex")],
    ["indefinite-array.cbor", Buffer.from("9fff", "hex")],
    ["indefinite-map.cbor", Buffer.from("bfff", "hex")],
    ["float.cbor", Buffer.from("f90000", "hex")],
    ["tag.cbor", Buffer.from("c000", "hex")],
    ["positive-bignum-tag-2.cbor", Buffer.from("c240", "hex")],
    ["negative-bignum-tag-3.cbor", Buffer.from("c340", "hex")],
    ["null.cbor", Buffer.from("f6", "hex")],
    ["undefined.cbor", Buffer.from("f7", "hex")],
    ["unassigned-simple.cbor", Buffer.from("f0", "hex")],
    ["invalid-utf8.cbor", Buffer.from("61ff", "hex")],
    ["nonshortest-utf8.cbor", Buffer.from("62c080", "hex")],
    ["non-nfc.cbor", Buffer.concat([Buffer.from([0x63]), Buffer.from("e\u0301", "utf8")])],
    ...[...unicodeMalformed].map(([name, codePoints]) => [name,
      uncheckedCborText(String.fromCodePoint(...codePoints))]),
    ["trailing-bytes.cbor", Buffer.concat([cbor(map([[0, 1], [1, 2], [2, []]])), Buffer.from([0])])],
    ["nesting-33.cbor", Buffer.concat([Buffer.alloc(33, 0x81), Buffer.from([0])])]
  ]);
  const malformedRows = [];
  for (const [name, bytes] of malformed) {
    const relative = `malformed/${name}`;
    const code = name === "truncated.cbor" ? "CBOR_TRUNCATED" : name === "trailing-bytes.cbor" ? "CBOR_TRAILING_BYTES" : name === "nesting-33.cbor" ? "LIMIT_NESTING" : "CBOR_NON_CANONICAL";
    files.set(relative, bytes);
    expectations.set(relative, rejectEncoding(code));
    const unicodeCodePoints = unicodeMalformed.get(name);
    malformedRows.push({
      artifact: relative,
      expected: rejectEncoding(code),
      hex: hex(bytes),
      name: name.replace(/\.cbor$/, ""),
      ...(unicodeCodePoints ? {
        codePoints: unicodeCodePoints.map((value) => `U+${value.toString(16).toUpperCase().padStart(4, "0")}`),
        failureOrder: "reject a scalar outside the frozen Unicode 15.0 Age repertoire before NFC comparison"
      } : {})
    });
  }
  const seedTruncations = [];
  for (let length = 0; length < manifestPayload.length; length += 1) {
    seedTruncations.push({ expected: { code: "CBOR_TRUNCATED", layer: 1, stage: "canonical-framing", result: "reject" }, prefixBytes: length });
  }
  files.set("malformed/index.json", stableJson({
    explicitCases: malformedRows,
    schema: "ogvcs.repository-format.v1.malformed-cbor.v1",
    truncationRecipe: {
      cases: seedTruncations,
      operation: "take the first prefixBytes bytes",
      source: "objects/02-content-manifest.cbor"
    }
  }));
  const unicodeCases = [
    {
      artifact: unicodeAssignedSource,
      codePoints: ["U+1FAE8"],
      expected: acceptFraming,
      purpose: "Unicode 15.0 Age boundary assignment is in the frozen repertoire and is NFC"
    },
    ...[...unicodeMalformed].map(([name, codePoints]) => ({
      artifact: `malformed/${name}`,
      codePoints: codePoints.map((value) => `U+${value.toString(16).toUpperCase().padStart(4, "0")}`),
      expected: rejectEncoding("CBOR_NON_CANONICAL"),
      purpose: "reject outside the frozen repertoire before applying host NFC"
    }))
  ];
  files.set("unicode/index.json", stableJson({ ...unicodeAuthority, cases: unicodeCases }));

  const limits = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "spec/repository-format/v1/registries/limits.json"), "utf8")).entries;
  const layerTwoLimits = new Set([
    "asset-group-members", "asset-groups", "change-set-operations",
    "logical-file-bytes", "manifest-chunks", "path-bytes",
    "path-segment-bytes", "path-segments", "snapshot-message-bytes",
    "snapshot-parents", "tree-entries"
  ]);
  const dimensionByName = {
    "asset-group-members": "members",
    "asset-groups": "groups",
    "bundle-index-entries": "indexEntries",
    "bundle-largest-item-bytes": "largestItemBytes",
    "bundle-logical-records": "logicalRecords",
    "bundle-objects": "objects",
    "bundle-roots": "roots",
    "bundle-sequence-bytes": "sequenceBytes",
    "bundle-total-items": "totalItems",
    "bundle-traversal-edges": "traversalEdges",
    "cbor-nesting-depth": "nestingLevels",
    "change-set-operations": "operations",
    "chunk-payload-bytes": "payloadBytes",
    "extension-aggregate-bytes-per-object": "encodedExtensionBytes",
    "extensions-per-object": "extensions",
    "generic-text-or-byte-value-bytes": "valueBytes",
    "logical-file-bytes": "logicalBytes",
    "manifest-chunks": "chunks",
    "metadata-payload-bytes": "metadataPayloadBytes",
    "path-bytes": "joinedPathUtf8Bytes",
    "path-segment-bytes": "segmentUtf8Bytes",
    "path-segments": "segments",
    "snapshot-message-bytes": "messageUtf8Bytes",
    "snapshot-parents": "parents",
    "tree-entries": "entries"
  };
  const emitterByName = {
    "asset-group-members": "emit one asset group; member[i].file-id = nonzero128(SHA-256(seed || uint64be(i))[0:16]), role is group-role.test/member@1, sort by encoded role then FileID",
    "asset-groups": "emit group[i] with group-id = nonzero128(SHA-256(seed || uint64be(i))[0:16]) and one distinct member; sort by GroupID",
    "bundle-index-entries": "set the isolated bundle index-entry work counter to n; do not reserve memory from n",
    "bundle-largest-item-bytes": "set header declared-largest-item-bytes to n and supply an actual canonical header no larger than the declaration",
    "bundle-logical-records": "emit n annotation logical-record items with ordinal i and subject digest SHA-256(seed || 0x4c || uint64be(i)); emit one required root per record and a matching trailer",
    "bundle-objects": "emit n eight-byte chunk object items whose payload is uint64be(i) and whose identity digest is SHA-256(object-domain || uint16be(1) || uint16be(1) || uint64be(i)); closure roots are supplied by the isolation harness",
    "bundle-roots": "emit n root items with ordinal i and identity SHA-256(seed || 0x52 || uint64be(i)); sort by root-kind, identity bytes, then role bytes",
    "bundle-sequence-bytes": "set header declared-total-sequence-bytes to n; stream actual item bytes independently and reject a declaration above the hard maximum before reserving or reading item bodies",
    "bundle-total-items": "set the isolated observed/trailer total-item counter to n using an unsigned arbitrary-precision counter; trailer count comparison follows the budget check",
    "bundle-traversal-edges": "set the isolated closure traversal-edge counter to n; each virtual edge i is (SHA-256(seed||0x46||uint64be(i)), SHA-256(seed||0x54||uint64be(i)))",
    "cbor-nesting-depth": "emit byte 0x81 exactly n times followed by byte 0x00",
    "change-set-operations": "emit operation[i] = {0:i,1:1,3:entry-state(i)} using fixed-width sortable path e<zero-padded-decimal(i)> and deterministic nonzero FileID recurrence",
    "chunk-payload-bytes": "emit n bytes; byte[i] = SHA-256(seed || uint64be(floor(i/32)))[i mod 32]",
    "extension-aggregate-bytes-per-object": "choose one extension byte-string payload length p by monotone search so canonical_size({0:1,1:9,2:[],3:{x.test/opaque@1:{0:bstr(p)}},16:producer,17:[],18:digest}) is exactly n; emit p recurrence bytes",
    "extensions-per-object": "emit extension entry i with key x.test/e-<zero-padded-decimal(i)>@1 and value {0:uint(i)}; sort keys by deterministic-CBOR encoded key bytes",
    "generic-text-or-byte-value-bytes": "emit one byte string of n recurrence bytes in provenance statement field 19",
    "logical-file-bytes": "emit a manifest logical-length n using exact unsigned arithmetic; chunk inventory is supplied separately and its sum must equal n; n=max+1 is a logical-ceiling failure, not an integer-overflow claim",
    "manifest-chunks": "emit n chunk parts, each {0:chunk-ref(i),1:1}; digest(i)=SHA-256(object-domain||uint16be(1)||uint16be(1)||one-byte(i mod 251)); ordered length sum is n",
    "metadata-payload-bytes": "choose padding length p by monotone search so canonical_size(metadata envelope plus extension x.test/opaque@1:{0:bstr(p)}) is exactly n; emit p recurrence bytes",
    "path-bytes": "emit 17 NFC ASCII segments; segments 0..15 have 240 bytes and segment 16 has n-(16*240)-16 bytes; joined measure is sum(utf8 lengths)+(segment-count-1)",
    "path-segment-bytes": "emit one NFC ASCII segment consisting of n bytes 0x61",
    "path-segments": "emit n one-byte NFC ASCII segments; segment[i] cycles a..z only in the isolated segment-count validator",
    "snapshot-message-bytes": "emit one NFC ASCII message consisting of n bytes 0x61",
    "snapshot-parents": "emit n unique kind-7 ObjectRefs; digest[i]=SHA-256(seed || 0x50 || uint64be(i)); preserve array order",
    "tree-entries": "emit n entries in ascending basename order e<zero-padded-decimal(i)>; FileID is deterministic nonzero128(SHA-256(seed||uint64be(i))[0:16]) and target/policy are fixed supplied references"
  };
  const isolationByName = {
    "bundle-index-entries": "invoke the bundle configured/hard-budget counter check with all earlier header fields canonical and within bounds",
    "bundle-largest-item-bytes": "invoke header budget validation after canonical unsigned decoding and before allocation or section reads",
    "bundle-logical-records": "provide valid header/budgets, deterministic identities, roots and trailer; isolate logical-record count before semantic closure",
    "bundle-objects": "provide valid header/budgets, unique ordered identities, roots and trailer; isolate object count before semantic closure",
    "bundle-roots": "provide valid header/budgets, canonical empty object/logical sections and trailer; isolate root count before root semantic resolution",
    "bundle-sequence-bytes": "invoke header budget validation after canonical unsigned decoding and before allocation or section reads",
    "bundle-total-items": "all item framing, ordinals and section counts are otherwise valid; isolate the total-item hard counter before trailer equality",
    "bundle-traversal-edges": "all supplied refs are well typed; isolate the traversal work counter before dereferencing the edge that exceeds the limit"
  };
  const virtualCases = [];
  const materializedRows = [];
  function materializedLimitValue(name, n) {
    if (name === "cbor-nesting-depth") return Buffer.concat([Buffer.alloc(n, 0x81), Buffer.from([0])]);
    if (name === "path-segment-bytes") return cbor("a".repeat(n));
    if (name === "path-bytes") {
      const segments = Array.from({ length: 17 }, () => "a".repeat(240));
      segments[16] = "a".repeat(n - (16 * 240) - 16);
      assert.equal(segments.reduce((sum, segment) => sum + Buffer.byteLength(segment), segments.length - 1), n);
      return cbor(segments);
    }
    if (name === "path-segments") return cbor(Array.from({ length: n }, () => "a"));
    if (name === "extensions-per-object") return cbor(map(Array.from({ length: n }, (_, i) => [`x.test/e-${String(i).padStart(3, "0")}@1`, map([[0, i]])])));
    if (name === "snapshot-parents") return cbor(Array.from({ length: n }, (_, i) => objectRef(7, sha256(Buffer.concat([Buffer.from("limit-parent", "ascii"), uint16be(i)])))));
    if (name === "asset-group-members") return cbor(Array.from({ length: n }, (_, i) => map([[0, id128(i + 1)], [1, roleProfile]])));
    return undefined;
  }
  function limitFailureStage(name, layer) {
    if (layer === 2) return "known-schema";
    if (name.startsWith("bundle-") || name === "metadata-payload-bytes" || name === "chunk-payload-bytes") {
      return "configured-resource-preflight";
    }
    return "canonical-framing";
  }
  const limitRows = limits.map((limit) => {
    assert.equal(typeof limit.errorCode, "string", `${limit.name} must assign errorCode`);
    assert(dimensionByName[limit.name], `missing dimension for ${limit.name}`);
    assert(emitterByName[limit.name], `missing emitter for ${limit.name}`);
    const row = {
      maximum: { expected: { highestLayer: limit.name.startsWith("bundle-") ? 1 : 2, result: "accept" }, value: limit.value },
      maximumPlusOne: {
        expected: {
          code: limit.errorCode,
          layer: layerTwoLimits.has(limit.name) ? 2 : 1,
          stage: limitFailureStage(limit.name, layerTwoLimits.has(limit.name) ? 2 : 1),
          result: "reject"
        },
        value: limit.value + 1
      },
      name: limit.name,
      unit: limit.unit
    };
    for (const [variant, n] of [["maximum", limit.value], ["maximum-plus-one", limit.value + 1]]) {
      const seed = sha256(Buffer.from(`OGVCS-002 limit constructor v1\0${limit.name}\0${variant}`, "utf8"));
      const metrics = {
        [dimensionByName[limit.name]]: decimal(n),
        counts: {
          chunks: decimal(limit.name === "manifest-chunks" ? n : 0),
          entries: decimal(limit.name === "tree-entries" ? n : 0),
          groups: decimal(limit.name === "asset-groups" ? n : 0),
          logicalRecords: decimal(limit.name === "bundle-logical-records" ? n : 0),
          members: decimal(limit.name === "asset-group-members" ? n : 0),
          objects: decimal(limit.name === "bundle-objects" ? n : 0),
          operations: decimal(limit.name === "change-set-operations" ? n : 0),
          roots: decimal(limit.name === "bundle-roots" ? n : 0),
          totalItems: decimal(limit.name === "bundle-total-items" ? n : 0)
        },
        cborUnsignedArgumentHeadBytes: cborHeadBytes(n),
        indexEntries: decimal(limit.name.includes("index") ? n : 0),
        logicalBytes: decimal(limit.name === "logical-file-bytes" ? n : 0),
        payloadBytes: decimal(limit.name.includes("payload-bytes") ? n : 0),
        sequenceBytes: decimal(limit.name === "bundle-sequence-bytes" ? n : 0),
        traversalEdges: decimal(limit.name.includes("traversal-edges") ? n : 0)
      };
      const summaryInput = {
        algorithm: "ogvcs.virtual-boundary-constructor",
        case: limit.name,
        metrics,
        seedHex: hex(seed),
        valueDecimal: decimal(n),
        variant,
        version: 1
      };
      const expected = variant === "maximum"
        ? row.maximum.expected
        : row.maximumPlusOne.expected;
      const constructor = {
        algorithm: { id: "ogvcs.virtual-boundary-constructor", version: 1 },
        arithmetic: "all counters, products, sums and comparisons use mathematical nonnegative integers; decode rejects values above uint64 before conversion to a host integer",
        case: limit.name,
        cborSizing: {
          byteOrTextString: "head(length)+length",
          canonicalMap: "head(pair-count)+sum(canonical-key-bytes+canonical-value-bytes), keys sorted by encoded length then lexical bytes",
          definiteArray: "head(element-count)+sum(canonical-element-bytes)",
          head: "1 byte for argument 0..23; 2 for 24..255; 3 for 256..65535; 5 for 65536..4294967295; 9 for 4294967296..18446744073709551615",
          textLength: "UTF-8 byte length after verifying input is already NFC"
        },
        emitter: emitterByName[limit.name],
        expected,
        expectedMetrics: metrics,
        isolationPrerequisites: isolationByName[limit.name] ?? "all enclosing fields and referenced fixed values are canonical, within their own limits, and valid; invoke only the named field/count validator before later graph semantics",
        seedHex: hex(seed),
        summary: {
          digestAlgorithm: "SHA-256",
          digestHex: descriptorDigest(summaryInput),
          input: summaryInput,
          serialization: "UTF-8 of lexicographically key-sorted, two-space-indented JSON with LF and one final LF"
        },
        valueDecimal: decimal(n),
        variant
      };
      virtualCases.push(constructor);
      const materialized = n <= 8192 ? materializedLimitValue(limit.name, Number(n)) : undefined;
      if (materialized !== undefined) {
        const relative = `limits/materialized/${limit.name}-${variant}.cbor`;
        files.set(relative, materialized);
        expectations.set(relative, { highestLayer: 1, result: "accept-constructor-input" });
        materializedRows.push({
          artifact: relative,
          byteLength: materialized.length,
          case: limit.name,
          sha256: hex(sha256(materialized)),
          variant
        });
      }
    }
    return row;
  });
  files.set("limits.json", stableJson({
    cases: limitRows,
    constructorIndex: "limits/virtual-constructors.json",
    materialization: "Each descriptor is an exact virtual constructor. Consumers stream/synthesize recurrence values and MUST NOT preallocate from a declaration. Materialized files are constructor inputs, not standalone whole-object semantic claims.",
    materializedIndex: "limits/materialized/index.json",
    schema: "ogvcs.repository-format.v1.limit-recipes.v2"
  }));
  assert.equal(virtualCases.length, limits.length * 2);
  files.set("limits/virtual-constructors.json", stableJson({
    cases: virtualCases,
    constructorCount: virtualCases.length,
    errorPrecedence: "canonical unsigned decoding and enclosing framing; configured receiver budget; format hard maximum; named field/count rule; remaining schema; graph and semantic validation. Stop at the first failure and expose no trusted partial output.",
    independentlyReproducible: true,
    schema: "ogvcs.repository-format.v1.virtual-limit-constructors.v1"
  }));
  files.set("limits/materialized/index.json", stableJson({
    artifacts: materializedRows,
    note: "These bounded CBOR artifacts materialize the exact recurrence input for small limits. Apply the associated isolation prerequisites and expected result from ../virtual-constructors.json.",
    schema: "ogvcs.repository-format.v1.materialized-limit-inputs.v1"
  }));

  const oldSnapshot = {
    extensions: { entries: [], registryVersion: 1 },
    formatVersion: 1,
    profiles: { entries: [
      { family: "bundle-root-role", id: "bundle-root-ratified", major: 1, namespace: "profile-state.test", productionWriteAllowed: true, state: "ratified" },
      { family: "chunking", id: "chunking-conformance", major: 1, namespace: "profile-state.test", productionWriteAllowed: false, state: "conformance-only" },
      { family: "path", id: "conformance", major: 1, namespace: "profile-state.test", productionWriteAllowed: false, state: "conformance-only" },
      { family: "content-policy", id: "content-conformance", major: 1, namespace: "profile-state.test", productionWriteAllowed: false, state: "conformance-only" },
      { family: "content-policy", id: "content-ratified", major: 1, namespace: "profile-state.test", productionWriteAllowed: true, state: "ratified" },
      { family: "path", id: "deprecated", major: 1, namespace: "profile-state.test", productionWriteAllowed: false, state: "deprecated" },
      { family: "path", id: "ratified", major: 1, namespace: "profile-state.test", productionWriteAllowed: true, state: "ratified" },
      { family: "path", id: "reserved", major: 1, namespace: "profile-state.test", productionWriteAllowed: false, state: "reserved" }
    ], registryVersion: 1 },
    requiredFeatures: { entries: [
      { behavior: "no-op: exercise lifecycle through the containing surface", code: 1, name: "lifecycle-conformance", state: "conformance-only" },
      { behavior: "no-op: exercise lifecycle through the containing surface", code: 2, name: "lifecycle-deprecated", state: "deprecated" }
    ], registryVersion: 1 },
    schema: "ogvcs.repository-format.v1.registry-snapshot.v1"
  };
  const newSnapshot = structuredClone(oldSnapshot);
  newSnapshot.extensions = { entries: [{ id: "opaque", major: 1, namespace: "extension-state.test", state: "ratified" }], registryVersion: 2 };
  newSnapshot.profiles.registryVersion = 2;
  newSnapshot.requiredFeatures = {
    entries: [...oldSnapshot.requiredFeatures.entries, {
      behavior: "no-op: validate the unchanged registered base kind semantics and preserve exact payload bytes",
      code: 3,
      name: "vector-required-feature",
      state: "ratified"
    }],
    registryVersion: 2
  };
  const lifecycleContentConformance = profile("profile-state.test", "content-conformance");
  const lifecycleContentRatified = profile("profile-state.test", "content-ratified");
  const lifecycleBundleRootRatified = profile("profile-state.test", "bundle-root-ratified");
  const lifecycleChunkingConformance = profile("profile-state.test", "chunking-conformance");
  const lifecycleProfiles = new Map([
    ["profile-state.test/deprecated@1", profile("profile-state.test", "deprecated")],
    ["profile-state.test/conformance@1", profile("profile-state.test", "conformance")],
    ["unknown.example/path@1", profile("unknown.example", "path")],
    ["content-policy.test/opaque@1", contentProfile]
  ]);
  const lifecycleDescriptors = new Map();
  for (const [profileText, selectedPathProfile] of lifecycleProfiles) {
    const label = profileText.replaceAll(/[^a-z0-9]+/g, "-").replace(/-+$/g, "");
    const expected = profileText === "content-policy.test/opaque@1"
      ? { code: "SCHEMA_FIELD_INVALID", layer: 2, stage: "known-schema", result: "reject" }
      : acceptSchema;
    const value = metadata(6, [
      [16, id128(0x6a)], [17, selectedPathProfile], [18, [lifecycleContentRatified]], [19, []]
    ]);
    const descriptorSource = `lifecycle/descriptor-${label}.cbor`;
    const payload = addCbor(files, expectations, descriptorSource, value, expected);
    const id = objectDigest(6, payload);
    const ref = objectRef(6, id);
    const refText = objectText("repository-descriptor", id);
    const bundle = buildBundle([{ kind: 6, payload }], [], [ref], {
      declaredTraversalEdges: 0,
      rootProfile: lifecycleBundleRootRatified
    });
    const bundleSource = `lifecycle/bundle-${label}.cborseq`;
    files.set(bundleSource, bundle.sequence);
    expectations.set(bundleSource, expected);
    lifecycleDescriptors.set(profileText, { bundleSource, descriptorSource, objectRef: refText, ref });
  }
  const lifecycleTrees = new Map();
  for (const [feature, label] of [[1, "conformance"], [2, "deprecated"], [3, "unknown"]]) {
    const value = metadata(3, [[16, descriptorRef], [17, []]], [feature]);
    const source = `lifecycle/tree-feature-${label}.cbor`;
    addCbor(files, expectations, source, value, acceptSchema);
    lifecycleTrees.set(feature, { requiredFeatures: [feature], source });
  }
  const lookupValidateAllProfileSource = lifecycleTrees.get(1).source;
  const lookupValidateAllProfilePayload = files.get(lookupValidateAllProfileSource);
  const lookupValidateAllProfileRef = objectText("tree", objectDigest(3, lookupValidateAllProfilePayload));
  const lookupValidateAllSchemaSource = "lifecycle/tree-known-schema-before-profile-lifecycle.cbor";
  const lookupValidateAllSchemaPayload = addCbor(files, expectations,
    lookupValidateAllSchemaSource,
    metadata(3, [[16, descriptorRef], [17, []], [4095, 0]]),
    { code: "SCHEMA_FIELD_UNKNOWN", layer: 2, stage: "known-schema", result: "reject" });
  const lookupValidateAllSchemaRef = objectText("tree", objectDigest(3, lookupValidateAllSchemaPayload));
  const lifecycleTreeOrderBeforeFeatureSource = "lifecycle/tree-order-before-feature-lifecycle.cbor";
  const lifecycleTreeOrderBeforeFeature = metadata(3, [[16, descriptorRef], [17, [
    map([
      [0, "b"], [1, 2], [2, id128(0x22)], [3, 2], [4, manifestRef],
      [5, repeatedBytes.length], [6, lifecycleContentRatified]
    ]),
    map([
      [0, "a"], [1, 2], [2, id128(0x21)], [3, 2], [4, manifestRef],
      [5, repeatedBytes.length], [6, lifecycleContentRatified]
    ])
  ]]], [1]);
  addCbor(files, expectations, lifecycleTreeOrderBeforeFeatureSource,
    lifecycleTreeOrderBeforeFeature,
    { code: "TREE_ENTRY_ORDER_INVALID", layer: 2, stage: "known-schema", result: "reject" });
  const lifecycleTreeOrderBeforeDescriptorSource = "lifecycle/tree-order-before-descriptor-mismatch.cbor";
  const lifecycleTreeOrderBeforeDescriptor = metadata(3, [[16, descriptorRef], [17, [
    map([
      [0, "b"], [1, 2], [2, id128(0x22)], [3, 2], [4, manifestRef],
      [5, repeatedBytes.length], [6, lifecycleContentRatified]
    ]),
    map([
      [0, "a"], [1, 2], [2, id128(0x21)], [3, 2], [4, manifestRef],
      [5, repeatedBytes.length], [6, lifecycleContentRatified]
    ])
  ]]]);
  addCbor(files, expectations, lifecycleTreeOrderBeforeDescriptorSource,
    lifecycleTreeOrderBeforeDescriptor,
    { code: "TREE_ENTRY_ORDER_INVALID", layer: 2, stage: "known-schema", result: "reject" });
  const lifecycleTreeTargetBeforeDuplicateFileIdSource = "lifecycle/tree-target-before-duplicate-fileid.cbor";
  const lifecycleTreeTargetBeforeDuplicateFileId = metadata(3, [[16, descriptorRef], [17, [
    map([
      [0, "a"], [1, 2], [2, id128(0x21)], [3, 2], [4, manifestRef],
      [5, repeatedBytes.length], [6, lifecycleContentRatified]
    ]),
    map([
      [0, "b"], [1, 2], [2, id128(0x21)], [3, 3], [4, manifestRef],
      [5, repeatedBytes.length], [6, lifecycleContentRatified]
    ])
  ]]]);
  addCbor(files, expectations, lifecycleTreeTargetBeforeDuplicateFileIdSource,
    lifecycleTreeTargetBeforeDuplicateFileId,
    { code: "TREE_ENTRY_TARGET_INVALID", layer: 2, stage: "known-schema", result: "reject" });
  const lifecycleTreeFeatureBeforeDuplicateFileIdSource = "lifecycle/tree-feature-before-duplicate-fileid.cbor";
  const lifecycleTreeFeatureBeforeDuplicateFileId = metadata(3, [[16, descriptorRef], [17, [
    map([
      [0, "a"], [1, 2], [2, id128(0x21)], [3, 2], [4, manifestRef],
      [5, repeatedBytes.length], [6, lifecycleContentRatified]
    ]),
    map([
      [0, "b"], [1, 2], [2, id128(0x21)], [3, 2], [4, manifestRef],
      [5, repeatedBytes.length], [6, lifecycleContentRatified]
    ])
  ]]], [1]);
  addCbor(files, expectations, lifecycleTreeFeatureBeforeDuplicateFileIdSource,
    lifecycleTreeFeatureBeforeDuplicateFileId,
    { code: "PROFILE_CONFORMANCE_ONLY", layer: 3, stage: "registry-semantics", result: "reject" });
  const precedenceTreeEntry = (name, fill, target = manifestRef, unknown = false) => map([
    [0, name], [1, 2], [2, id128(fill)], [3, 2], [4, target],
    [5, repeatedBytes.length], [6, lifecycleContentRatified], ...(unknown ? [[7, 0]] : [])
  ]);
  const lifecycleTreeKnownSchemaBeforeOrderSources = new Map();
  for (const [order, entries] of [
    ["forward", [
      precedenceTreeEntry("b", 0x31),
      precedenceTreeEntry("a", 0x32),
      precedenceTreeEntry("c", 0x33, manifestRef, true)
    ]],
    ["reverse", [
      precedenceTreeEntry("a", 0x31, manifestRef, true),
      precedenceTreeEntry("c", 0x32),
      precedenceTreeEntry("b", 0x33)
    ]]
  ]) {
    const source = `lifecycle/tree-known-schema-before-order-${order}.cbor`;
    addCbor(files, expectations, source,
      metadata(3, [[16, descriptorRef], [17, entries]]),
      { code: "SCHEMA_FIELD_UNKNOWN", layer: 2, stage: "known-schema", result: "reject" });
    lifecycleTreeKnownSchemaBeforeOrderSources.set(order, source);
  }
  const lifecycleChunkIdentityMismatch = Buffer.from(chunk);
  lifecycleChunkIdentityMismatch[0] ^= 0x01;
  const lifecycleChunkIdentityMismatchSource = "lifecycle/chunk-object-id-mismatch.bin";
  files.set(lifecycleChunkIdentityMismatchSource, lifecycleChunkIdentityMismatch);
  expectations.set(lifecycleChunkIdentityMismatchSource, { highestLayer: 1, result: "accept-constructor-input" });
  const manifestProviderCorrectOne = Buffer.from("provider-one", "ascii");
  const manifestProviderCorrectTwo = Buffer.from("provider-two", "ascii");
  const manifestProviderShort = manifestProviderCorrectOne.subarray(0, 11);
  const manifestProviderWrong = Buffer.from("provider-bad", "ascii");
  const manifestProviderShortSource = "writer-inputs/manifest-provider-short.bin";
  const manifestProviderWrongSource = "writer-inputs/manifest-provider-wrong.bin";
  assert.equal(manifestProviderCorrectOne.length, 12);
  assert.equal(manifestProviderCorrectTwo.length, 12);
  assert.equal(manifestProviderShort.length, 11);
  assert.equal(manifestProviderWrong.length, 12);
  files.set(manifestProviderShortSource, manifestProviderShort);
  files.set(manifestProviderWrongSource, manifestProviderWrong);
  expectations.set(manifestProviderShortSource, { highestLayer: 1, result: "accept-constructor-input" });
  expectations.set(manifestProviderWrongSource, { highestLayer: 1, result: "accept-constructor-input" });
  const lifecycleWrongFamilyTree = metadata(3, [[16, descriptorRef], [17, [map([
    [0, "wrong-family"], [1, 2], [2, id128(0x6b)], [3, 2], [4, manifestRef],
    [5, repeatedBytes.length], [6, pathProfile]
  ])]]]);
  const lifecycleWrongFamilyTreeSource = "lifecycle/tree-wrong-content-profile-family.cbor";
  addCbor(files, expectations, lifecycleWrongFamilyTreeSource, lifecycleWrongFamilyTree,
    { code: "SCHEMA_FIELD_INVALID", layer: 2, stage: "known-schema", result: "reject" });
  const lifecycleManifestValue = metadata(2, [
    [16, 0], [17, typedDigest(sha256(Buffer.alloc(0)))], [18, lifecycleChunkingConformance], [19, []]
  ]);
  const lifecycleManifestSource = "lifecycle/manifest-chunking-conformance.cbor";
  addCbor(files, expectations, lifecycleManifestSource, lifecycleManifestValue, acceptSchema);
  const lifecycleMissingChunkRef = objectRef(1, digest(0xe1));
  const lifecycleManifestMissingChunkValue = metadata(2, [
    [16, repeatedBytes.length], [17, typedDigest(sha256(repeatedBytes))],
    [18, lifecycleChunkingConformance],
    [19, [map([[0, lifecycleMissingChunkRef], [1, repeatedBytes.length]])]]
  ]);
  const lifecycleManifestMissingChunkSource = "lifecycle/manifest-missing-reference-before-profile-lifecycle.cbor";
  const lifecycleManifestMissingChunkPayload = addCbor(files, expectations,
    lifecycleManifestMissingChunkSource, lifecycleManifestMissingChunkValue,
    { code: "OBJECT_REFERENCE_MISSING", layer: 2, stage: "closure-and-reference-resolution", result: "reject" });
  const lifecycleManifestMissingChunkId = objectDigest(2, lifecycleManifestMissingChunkPayload);
  const lifecycleManifestMissingChunkRefText = objectText("content-manifest", lifecycleManifestMissingChunkId);
  const lifecycleManifestMissingChunkArtifact = {
    bytes: lifecycleManifestMissingChunkPayload.length,
    mediaType: "application/cbor",
    path: lifecycleManifestMissingChunkSource,
    sha256: hex(sha256(lifecycleManifestMissingChunkPayload))
  };
  files.set("registries/old-snapshot.json", stableJson(oldSnapshot));
  files.set("registries/new-snapshot.json", stableJson(newSnapshot));

  const unknownExtensionPayload = cbor(metadata(9, [
    [16, profile("provenance.test", "opaque")], [17, []], [18, typedDigest(sha256(Buffer.alloc(0)))]
  ], [], map([["extension-state.test/opaque@1", map([[0, Buffer.from("preserve", "ascii")]])]])));
  files.set("registries/unknown-optional-extension.cbor", unknownExtensionPayload);
  expectations.set("registries/unknown-optional-extension.cbor", { highestLayer: 3, result: "accept" });
  const unknownRequiredPayload = cbor(metadata(9, [
    [16, profile("provenance.test", "opaque")], [17, []], [18, typedDigest(sha256(Buffer.alloc(0)))]
  ], [3]));
  files.set("registries/unknown-required-feature.cbor", unknownRequiredPayload);
  expectations.set("registries/unknown-required-feature.cbor", { code: "REQUIRED_FEATURE_UNSUPPORTED", layer: 3, stage: "registry-semantics", result: "reject" });
  files.set("registries/index.json", stableJson({
    cases: [
      { artifact: "registries/unknown-required-feature.cbor", expected: { highestLayer: 1, result: "accept-forwardable" }, scenarioId: "registry-unknown-feature-forward", snapshot: "old" },
      { artifact: "registries/unknown-required-feature.cbor", expected: { code: "REQUIRED_FEATURE_UNSUPPORTED", layer: 3, stage: "registry-semantics", result: "reject" }, scenarioId: "registry-unknown-feature", snapshot: "old" },
      { artifact: "registries/unknown-required-feature.cbor", expected: { highestLayer: 3, mode: "conformance", result: "accept" }, featureBehavior: "no-op", snapshot: "new" },
      { artifact: "registries/unknown-optional-extension.cbor", expected: { highestLayer: 3, mode: "conformance", preservationSha256: hex(sha256(unknownExtensionPayload)), result: "accept-byte-preserved" }, scenarioId: "registry-unknown-extension-preserve", snapshot: "old" },
      { expected: { code: "REGISTRY_INVALID", layer: 3, stage: "registry-semantics", result: "reject" }, mutation: { action: "append-copy", file: "object-kinds.json", selector: { code: 1 } }, operation: "validate-registry-set", scenarioId: "registry-duplicate", sourceRegistryDirectory: "../registries" },
      { expected: { code: "REGISTRY_INVALID", layer: 3, stage: "registry-semantics", result: "reject" }, mutation: { action: "replace-entry-field", field: "payload", file: "object-kinds.json", selector: { code: 1 }, value: "deterministic-cbor" }, operation: "validate-registry-set", scenarioId: "registry-reassigned", sourceRegistryDirectory: "../registries" },
      { expected: { code: "REGISTRY_INVALID", layer: 3, stage: "registry-semantics", result: "reject" }, mutation: { action: "append-entry", entry: { name: "scenario-missing-error-code", unit: "bytes", value: 1 }, file: "limits.json" }, operation: "validate-registry-set", scenarioId: "registry-invalid-entry", sourceRegistryDirectory: "../registries" },
      { expected: { code: "PROFILE_STATE_FORBIDDEN", layer: 3, stage: "registry-semantics", result: "reject" }, operation: "read", profile: "profile-state.test/reserved@1", scenarioId: "registry-reserved", snapshot: "old" },
      { expected: { highestLayer: 3, result: "accept" }, operation: "read-or-production-write", profile: "profile-state.test/ratified@1", scenarioId: "registry-ratified-read-write", snapshot: "old" },
      { expected: { highestLayer: 3, result: "accept" }, operation: "read", profile: "profile-state.test/deprecated@1", scenarioId: "registry-deprecated-read", snapshot: "old" },
      { expected: { code: "PROFILE_STATE_FORBIDDEN", layer: 3, stage: "registry-semantics", result: "reject" }, operation: "production-write", profile: "profile-state.test/deprecated@1", scenarioId: "registry-deprecated-write", snapshot: "old" },
      { expected: { highestLayer: 3, result: "accept" }, operation: "conformance", profile: "profile-state.test/conformance@1", scenarioId: "registry-conformance-mode", snapshot: "old" },
      { expected: { code: "PROFILE_CONFORMANCE_ONLY", layer: 3, stage: "registry-semantics", result: "reject" }, operation: "production-write", profile: "profile-state.test/conformance@1", scenarioId: "registry-conformance-production", snapshot: "old" },
      { expected: { code: "PROFILE_UNKNOWN", layer: 3, stage: "registry-semantics", result: "reject" }, operation: "read", profile: "profile-state.test/unknown@1", scenarioId: "registry-unknown-profile", snapshot: "old" }
    ],
    newSnapshot: "registries/new-snapshot.json",
    notice: "These self-contained vector snapshots use fixture-only demo assignments and do not amend the live format-v1 registries.",
    oldSnapshot: "registries/old-snapshot.json",
    schema: "ogvcs.repository-format.v1.registry-evolution-cases.v1"
  }));

  function rebuildBundleValues(sourceValues, options = {}) {
    const values = sourceValues.map((value) => new Map(value));
    const header = values[0];
    let declaredTotal = 0;
    let declaredLargest = 0;
    let parts;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const budget = new Map(header.get(6));
      if (!options.preserveBudget) {
        budget.set(0, declaredTotal);
        budget.set(1, declaredLargest);
      }
      header.set(6, budget);
      const beforeTrailerParts = values.slice(0, -1).map(cbor);
      const transcript = sha256(Buffer.concat([BUNDLE_DOMAIN, uint16be(1), ...beforeTrailerParts]));
      const objects = values.slice(1, -1).filter((value) => value.get(1) === 2).length;
      const logicals = values.slice(1, -1).filter((value) => value.get(1) === 3).length;
      const roots = values.slice(1, -1).filter((value) => value.get(1) === 4).length;
      values[values.length - 1] = map([[0, 1], [1, 5], [2, objects], [3, logicals], [4, roots], [5, values.length], [6, typedDigest(transcript)]]);
      parts = values.map(cbor);
      const nextTotal = parts.reduce((sum, part) => sum + part.length, 0);
      const nextLargest = Math.max(...parts.map((part) => part.length));
      if (options.preserveBudget || (nextTotal === declaredTotal && nextLargest === declaredLargest)) break;
      declaredTotal = nextTotal;
      declaredLargest = nextLargest;
    }
    return Buffer.concat(parts);
  }
  const generatedBundleInputs = new Map();
  for (const id of [
    "bundle-item-header", "bundle-item-object", "bundle-item-logical-record", "bundle-item-root", "bundle-item-trailer",
    "bundle-logical-reference-preservation"
  ]) generatedBundleInputs.set(id, "logical-bundles/valid-supplied-closure.cborseq");
  for (const id of [
    "bundle-edge-families", "bundle-root-kind-object", "bundle-root-kind-logical-record",
    ...objectRows.map((row) => `bundle-object-kind-${row.kind}`),
    ...logicalRows.map((row) => `bundle-logical-type-${row.type}`)
  ]) generatedBundleInputs.set(id, "logical-bundles/valid-all-families.cborseq");
  function addBundleInput(id, values, options) {
    const relative = `logical-bundles/scenario-${id}.cborseq`;
    const bytes = rebuildBundleValues(values, options);
    files.set(relative, bytes);
    generatedBundleInputs.set(id, relative);
  }
  const validValues = validBundle.itemValues;
  const countValues = validValues.map((value) => new Map(value));
  countValues[0].set(3, countValues[0].get(3) + 1);
  addBundleInput("bundle-count", countValues);
  const ordinalValues = validValues.map((value) => new Map(value));
  ordinalValues[1].set(2, 1);
  addBundleInput("bundle-ordinal", ordinalValues);
  const modeValues = validValues.map((value) => new Map(value));
  modeValues[0].set(2, 2);
  addBundleInput("bundle-mode", modeValues);
  const budgetValues = validValues.map((value) => new Map(value));
  const excessiveBudget = new Map(budgetValues[0].get(6));
  excessiveBudget.set(0, 2199023255553);
  budgetValues[0].set(6, excessiveBudget);
  addBundleInput("bundle-budget", budgetValues, { preserveBudget: true });
  const declaredAccountingValues = validValues.map((value) => new Map(value));
  const understatedBudget = new Map(declaredAccountingValues[0].get(6));
  assert.equal(understatedBudget.get(3), 3, "valid closure index accounting drift");
  understatedBudget.set(3, 2);
  declaredAccountingValues[0].set(6, understatedBudget);
  addBundleInput("bundle-declared-accounting", declaredAccountingValues, { preserveBudget: true });
  const objectIdValues = validValues.map((value) => new Map(value));
  const changedPayload = Buffer.from(objectIdValues[1].get(4));
  changedPayload[0] ^= 1;
  objectIdValues[1].set(4, changedPayload);
  addBundleInput("bundle-object-id", objectIdValues);
  const recordIdValues = validValues.map((value) => new Map(value));
  recordIdValues.find((value) => value.get(1) === 3).set(3, typedDigest(digest(0xfa)));
  addBundleInput("bundle-record-id", recordIdValues);
  const rootInvalidValues = validValues.filter((value) => !(value.get(1) === 4 && value.get(3) === 2));
  rootInvalidValues[0] = new Map(rootInvalidValues[0]);
  rootInvalidValues[0].set(5, 1);
  addBundleInput("bundle-root-invalid", rootInvalidValues);
  const zeroBundle = buildBundle([], [], []);
  files.set("logical-bundles/scenario-bundle-zero-sections.cborseq", zeroBundle.sequence);
  generatedBundleInputs.set("bundle-zero-sections", "logical-bundles/scenario-bundle-zero-sections.cborseq");
  const multiRootBundle = buildBundle([{ kind: 1, payload: chunk }, { kind: 2, payload: manifestPayload }], [], [objectRef(1, chunkId), manifestRef]);
  files.set("logical-bundles/scenario-bundle-multi-root-disambiguation.cborseq", multiRootBundle.sequence);
  generatedBundleInputs.set("bundle-multi-root-disambiguation", "logical-bundles/scenario-bundle-multi-root-disambiguation.cborseq");
  const eofValues = validValues.map((value) => new Map(value));
  const eofBudget = new Map(eofValues[0].get(6));
  eofBudget.set(0, validBundle.sequence.length + 1);
  eofValues[0].set(6, eofBudget);
  const eofBytes = Buffer.concat([rebuildBundleValues(eofValues, { preserveBudget: true }), cbor(0)]);
  files.set("logical-bundles/scenario-bundle-eof.cborseq", eofBytes);
  generatedBundleInputs.set("bundle-eof", "logical-bundles/scenario-bundle-eof.cborseq");

  const readmeBytes = fs.readFileSync(path.join(REPO_ROOT, "spec/repository-format/v1/README.md"));
  const registryNames = [...readmeBytes.toString("utf8").matchAll(/\[`registries\/([^`]+\.json)`\]/g)]
    .map((match) => match[1])
    .filter((name, index, values) => values.indexOf(name) === index);
  const diskRegistryNames = fs.readdirSync(path.join(REPO_ROOT, "spec/repository-format/v1/registries"))
    .filter((name) => name.endsWith(".json"));
  assert.deepEqual([...registryNames].sort(), [...diskRegistryNames].sort(), "README registry order must name every registry JSON exactly once");
  const registryRecords = registryNames.map((name) => {
    const relative = `registries/${name}`;
    const relativeBytes = Buffer.from(relative, "utf8");
    const bytes = fs.readFileSync(path.join(REPO_ROOT, "spec/repository-format/v1", relative));
    return Buffer.concat([uint32be(relativeBytes.length), relativeBytes, uint64be(bytes.length), bytes]);
  });
  const registrySetSha256 = hex(sha256(Buffer.concat([REGISTRY_SET_DOMAIN, uint16be(1), ...registryRecords])));
  const liveRegistrySnapshot = {
    formatVersion: 1,
    registries: registryNames.map((name) => {
      const bytes = fs.readFileSync(path.join(REPO_ROOT, "spec/repository-format/v1/registries", name));
      return { bytes: bytes.length, path: `registries/${name}`, sha256: hex(sha256(bytes)) };
    }),
    registryVersion: 1,
    schema: "ogvcs.repository-format.v1.registry-set-snapshot.v1"
  };
  liveRegistrySnapshot.registrySetSha256 = registrySetSha256;
  files.set("registries/live-snapshot.json", stableJson(liveRegistrySnapshot));

  const errorCatalogue = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "spec/repository-format/v1/errors.json"), "utf8"));
  const errors = errorCatalogue.errors;
  const errorByCode = new Map(errors.map((error) => [error.code, error]));
  const scenarioStageOverrides = new Map([
    ["bundle-declared-accounting", "declared-accounting"],
    ["bundle-root-invalid", "closure-and-reference-resolution"],
    ["bundle-wrong-kind", "closure-and-reference-resolution"],
    ["limit-extensions-per-object-max-plus-one", "canonical-framing"],
    ["manifest-writer-limit-before-count-and-profile-lifecycle", "configured-resource-preflight"],
    ["manifest-writer-limit-before-kind", "configured-resource-preflight"],
    ["manifest-writer-count-before-kind-forward", "known-schema"],
    ["manifest-writer-count-before-kind-reverse", "known-schema"],
    ["manifest-writer-known-schema-before-chunk-length-forward", "known-schema"],
    ["manifest-writer-known-schema-before-chunk-length-reverse", "known-schema"],
    ["tree-writer-ordered-limit-before-count-and-feature-lifecycle", "configured-resource-preflight"],
    ["tree-writer-ordered-limit-before-kind", "configured-resource-preflight"],
    ["tree-writer-ordered-kind-before-order-forward", "known-schema"],
    ["tree-writer-ordered-kind-before-order-reverse", "known-schema"],
    ["tree-writer-sorted-limit-before-count-and-feature-lifecycle", "configured-resource-preflight"],
    ["tree-writer-sorted-family-before-kind-forward", "known-schema"],
    ["tree-writer-sorted-family-before-kind-reverse", "known-schema"],
    ["resource-lookup-edge-counter-rollback", "configured-resource-preflight"]
  ]);
  function failureStage(id, code, layer) {
    const error = errorByCode.get(code);
    assert(error, `unknown scenario error code ${code}`);
    const stages = error.sites.filter((site) => site.layers.includes(layer)).map((site) => site.stage);
    const override = scenarioStageOverrides.get(id) ??
      (id.startsWith("mode-") && code === "SCHEMA_FIELD_INVALID" && layer === 1 ? "configured-resource-preflight" : undefined) ??
      (code === "BUNDLE_BUDGET_EXCEEDED" ? "configured-resource-preflight" : undefined);
    if (override !== undefined) {
      assert(stages.includes(override), `${id}: ${code} does not permit ${override}/layer-${layer}`);
      return override;
    }
    assert.equal(stages.length, 1, `${id}: ${code}/layer-${layer} requires an explicit validation stage`);
    return stages[0];
  }
  const scenarioCases = [];
  const req = {
    ac02: ["OGVCS-002-AC-02"], ac03: ["OGVCS-002-AC-03"], ac04: ["OGVCS-002-AC-04"], ac06: ["OGVCS-002-AC-06"], ac07: ["OGVCS-002-AC-07"],
    ac08: ["OGVCS-002-AC-08"], ac09: ["OGVCS-002-AC-09"], ac10: ["OGVCS-002-AC-10"],
    ac11: ["OGVCS-002-AC-11"], fr04: ["OGVCS-002-FR-04"], fr06: ["OGVCS-002-FR-06"],
    fr09: ["OGVCS-002-FR-09"], fr11: ["OGVCS-002-FR-11"], fr13: ["OGVCS-002-FR-13"],
    nfr01: ["OGVCS-002-NFR-01"], nfr02: ["OGVCS-002-NFR-02"], nfr04: ["OGVCS-002-NFR-04"]
  };
  const unionReq = (...groups) => [...new Set(groups.flat())].sort();
  function addScenario(id, options = {}) {
    assert(/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id), `invalid scenario id ${id}`);
    assert(!scenarioCases.some((item) => item.id === id), `duplicate scenario ${id}`);
    const operation = options.operation ?? "validate-repository";
    const defaultLayer = operation === "canonical-scan" ? 1 : operation === "validate-bundle" ? 2 : 3;
    const layer = options.layer ?? defaultLayer;
    scenarioCases.push({
      code: options.code,
      detail: options.detail ?? id.replaceAll("-", " "),
      id,
      implementationScope: options.implementationScope,
      mode: options.mode ?? "conformance",
      obligationTags: [...new Set(options.obligationTags ?? [])].sort(),
      operation,
      parameters: options.parameters ?? {},
      requirements: unionReq(options.requirements ?? req.fr09),
      resultFamily: options.resultFamily ?? "repository",
      layer,
      stage: options.code ? options.stage ?? failureStage(id, options.code, layer) : undefined
    });
  }
  const accept = (id, tags, detail, requirements = req.fr09, operation = "validate-repository", resultFamily = "repository") =>
    addScenario(id, { detail, obligationTags: tags, operation, requirements, resultFamily });
  const reject = (id, code, tags, detail, requirements = unionReq(req.fr09, req.fr11), operation = "validate-repository", layer = 3) =>
    addScenario(id, { code, detail, layer, obligationTags: tags, operation, requirements });

  for (const [name, detail] of [
    ["create", "create /asset with fresh FileID 2121.. and exact regular entry state"],
    ["modify", "modify /asset content target while preserving path and FileID"],
    ["copy", "copy /asset to /asset-copy with fresh FileID 2222.."],
    ["move", "move /dir/asset to /other/asset while preserving FileID"],
    ["rename", "rename /asset to /asset-renamed in the same parent while preserving FileID"],
    ["delete", "delete exact /asset state and retain its consumed lifetime"],
    ["restore", "restore the exact ancestral /asset state after its strict-descendant delete"],
    ["group-create", "create group 5151.. from absent group state"],
    ["group-update", "update group 5151.. while preserving GroupID"],
    ["group-delete", "delete exact group 5151.. state"],
    ["merge-resolution", "apply a resolved content-conflict result and reproduce final tree"]
  ]) accept(`transition-${name}`, [`transition:${name}`], detail, unionReq(req.fr09, name === "restore" ? req.fr11 : []), "replay-change-set", name.startsWith("group-") ? "group" : "tree");
  reject("transition-exact-result-mismatch", "CHANGESET_RESULT_MISMATCH", ["transition:exact-replay", "transition:result-mismatch"], "replay canonical operations whose actual tree root differs from the candidate snapshot tree", unionReq(req.fr09, req.fr11), "replay-change-set");
  reject("transition-sequence-gap", "CHANGESET_SEQUENCE_INVALID", ["transition:sequence"], "operations 0 and 2 omit required sequence 1", req.fr09, "replay-change-set", 2);

  for (const [count, id, detail] of [[0, "history-zero-parent-root", "designated zero-parent repository root"], [1, "history-one-parent", "one-parent commit whose parent zero is replay base"], [2, "history-two-parent", "ordered two-parent merge"], [8, "history-eight-parent", "maximum ordered eight-parent merge"]]) {
    accept(id, [`history:parents-${count}`], detail, unionReq(req.fr09, req.ac06));
  }
  reject("history-second-root", "SNAPSHOT_ROOT_INVALID", ["history:second-root"], "second zero-parent snapshot in one repository", unionReq(req.fr09, req.ac06));
  reject("history-missing-parent", "OBJECT_REFERENCE_MISSING", ["history:missing-parent"], "parent ObjectRef absent from supplied lookup", unionReq(req.fr09, req.ac06), "validate-repository", 2);
  reject("history-duplicate-parent", "SNAPSHOT_PARENT_DUPLICATE", ["history:duplicate-parent"], "ordered parent array repeats one ObjectRef", unionReq(req.fr09, req.ac06), "validate-repository", 2);
  reject("history-parent-cycle", "SNAPSHOT_PARENT_CYCLE", ["history:cycle"], "prevalidated abstract snapshot-parent graph contains a two-node cycle", unionReq(req.fr09, req.ac06), "validate-abstract-reference-graph");
  reject("history-cross-repository-parent", "SNAPSHOT_PARENT_CROSS_REPOSITORY", ["history:cross-repository"], "parent binds a different repository descriptor", unionReq(req.fr09, req.ac06));
  reject("history-ninth-parent", "SNAPSHOT_PARENT_COUNT_INVALID", ["history:parents-9"], "candidate declares nine unique parents", unionReq(req.fr09, req.ac06), "validate-repository", 2);
  reject("history-base-mismatch", "CHANGESET_BASE_MISMATCH", ["history:base-mismatch"], "change-set base differs from parent zero", req.fr09);

  reject("fileid-zero", "FILEID_ZERO", ["fileid:zero"], "entry carries 16 all-zero bytes", unionReq(req.fr09, req.fr11, req.ac07), "validate-object", 2);
  reject("fileid-duplicate-expanded-tree", "FILEID_DUPLICATE_IN_TREE", ["fileid:duplicate"], "two expanded-tree paths carry identical nonzero FileID", unionReq(req.fr11, req.ac07), "validate-object", 3);
  reject("fileid-create-reuse", "FILEID_ALREADY_CONSUMED", ["fileid:create-reuse"], "create claims a pre-candidate consumed FileID", unionReq(req.fr11, req.ac07), "replay-change-set");
  reject("fileid-copy-reuse", "FILEID_ALREADY_CONSUMED", ["fileid:copy-reuse"], "copy result claims a pre-candidate consumed FileID", unionReq(req.fr11, req.ac07), "replay-change-set");
  reject("fileid-move-source-forgery", "FILEID_SOURCE_MISMATCH", ["fileid:source-forgery", "fileid:move-rename"], "move before-state substitutes another FileID", unionReq(req.fr11, req.ac07), "replay-change-set");
  accept("fileid-move-rename-preserves", ["fileid:move-rename"], "move then rename preserves exact FileID", unionReq(req.fr09, req.ac07), "replay-change-set", "tree");
  accept("fileid-copy-fresh", ["fileid:copy"], "copy allocates a distinct fresh FileID", unionReq(req.fr09, req.ac07), "replay-change-set", "tree");
  reject("fileid-delete-recreate-reuse", "FILEID_ALREADY_CONSUMED", ["fileid:delete-recreate"], "delete then create reuses consumed FileID", unionReq(req.fr11, req.ac07), "replay-change-set");
  accept("fileid-ancestral-restore", ["fileid:restore-ancestry"], "restore source and delete proof satisfy same-repository ancestry", unionReq(req.fr09, req.fr11, req.ac07), "replay-change-set", "tree");
  reject("fileid-restore-invalid-ancestry", "FILEID_RESTORE_PROOF_INVALID", ["fileid:restore-invalid-ancestry"], "delete snapshot is not an ancestor of candidate base", unionReq(req.fr11, req.ac07), "replay-change-set");
  reject("fileid-restore-source-forgery", "FILEID_RESTORE_PROOF_INVALID", ["fileid:restore-forgery"], "restore after-state differs from ancestral source state", unionReq(req.fr11, req.ac07), "replay-change-set");
  reject("fileid-cross-repository-proof", "FILEID_CROSS_REPOSITORY_PROOF", ["fileid:cross-repository"], "equal raw FileID bytes are legal independently but cross-repository proof is rejected", unionReq(req.fr11, req.ac07), "replay-change-set");
  accept("fileid-import-lost-ack-retry", ["fileid:import-retry"], "retry same importer and source tuple returns identical mapping 5353..", unionReq(req.fr09, req.fr11, req.ac07), "import-file-id", "fileid");
  reject("fileid-import-conflict", "FILEID_IMPORT_MAPPING_CONFLICT", ["fileid:import-conflict"], "same source tuple changes target FileID", unionReq(req.fr11, req.ac07), "import-file-id");
  reject("fileid-import-native-collision", "FILEID_IMPORT_MAPPING_CONFLICT", ["fileid:import-native-collision"], "import target is already consumed by a native allocation", unionReq(req.fr11, req.ac07), "import-file-id");
  reject("fileid-concurrent-loser", "FILEID_ALLOCATION_COLLISION", ["fileid:concurrent-loser-state"], "concurrent reservation loser leaves candidate ref and working additions unchanged", unionReq(req.fr11, req.ac07), "allocate-file-id");
  for (const [id, code, layer, stage, detail, mode] of [
    ["fileid-lifetime-first-change-missing", "FILEID_LIFETIME_EVIDENCE_INVALID", 3, "repository-semantics", "an absent syntactically kind-4 firstChangeSet is invalid lifetime evidence rather than a graph-closure claim", "conformance"],
    ["fileid-lifetime-first-change-wrong-kind", "OBJECT_REFERENCE_KIND_MISMATCH", 2, "known-schema", "a firstChangeSet with a non-ChangeSet typed reference is rejected before lifetime semantics", "conformance"],
    ["fileid-lifetime-first-change-object-id-mismatch", "OBJECT_ID_MISMATCH", 1, "declared-identity", "a present firstChangeSet whose declared identity does not match its bytes preserves identity precedence", "conformance"],
    ["fileid-lifetime-first-change-bad-schema", "SCHEMA_FIELD_INVALID", 2, "known-schema", "a present identity-valid firstChangeSet with an invalid ChangeSet shape preserves known-schema precedence", "conformance"],
    ["fileid-lifetime-first-change-profile-lifecycle", "PROFILE_CONFORMANCE_ONLY", 3, "registry-semantics", "a present valid firstChangeSet carrying a conformance-only content profile is rejected under production", "production"]
  ]) {
    addScenario(id, {
      code,
      detail,
      layer,
      mode,
      obligationTags: [`fileid:lifetime-first-change-${id.slice("fileid-lifetime-first-change-".length)}`],
      operation: "validate-repository-route",
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac07, req.ac08),
      stage
    });
  }
  for (const surface of ["lifetime", "request", "candidate"]) {
    const surfaceLabel = surface === "lifetime" ? "validateLifetimeAndImports"
      : surface === "request" ? "validateImportRequest"
        : "validateRepositoryCandidate";
    addScenario(`fileid-prior-import-mapping-${surface}-conformance`, {
      detail: `${surfaceLabel} accepts a repository-bound prior import mapping with its required descriptor, derived mapping key, matching immutable lifetime evidence, and conformance importer profile`,
      layer: 3,
      obligationTags: [`fileid:prior-import-mapping-${surface}-conformance`],
      operation: "validate-repository-route",
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac07, req.ac08),
      resultFamily: "fileid"
    });
    addScenario(`fileid-prior-import-mapping-${surface}-wrong-family`, {
      code: "SCHEMA_FIELD_INVALID",
      detail: `${surfaceLabel} rejects a prior import mapping whose importer ProfileRef belongs to the content-policy family before lifecycle interpretation`,
      layer: 2,
      obligationTags: [`fileid:prior-import-mapping-${surface}-wrong-family`],
      operation: "validate-repository-route",
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac07, req.ac08),
      stage: "known-schema"
    });
    addScenario(`fileid-prior-import-mapping-${surface}-production-conformance-only`, {
      code: "PROFILE_CONFORMANCE_ONLY",
      detail: `${surfaceLabel} rejects the registered conformance-only importer profile under production after whole-input family validation`,
      layer: 3,
      mode: "production",
      obligationTags: [`fileid:prior-import-mapping-${surface}-production-conformance-only`],
      operation: "validate-repository-route",
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac07, req.ac08),
      stage: "registry-semantics"
    });
    addScenario(`fileid-prior-import-mapping-${surface}-foreign-repository`, {
      code: "FILEID_CROSS_REPOSITORY_PROOF",
      detail: `${surfaceLabel} rejects a self-consistent prior import mapping, mapping key, and lifetime proof bound to another repository`,
      layer: 3,
      obligationTags: [`fileid:prior-import-mapping-${surface}-foreign-repository`],
      operation: "validate-repository-route",
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac07, req.ac08),
      stage: "repository-semantics"
    });
  }

  accept("tree-empty", ["tree:empty"], "empty one-directory tree", req.fr09, "validate-object", "tree");
  accept("tree-unicode", ["tree:unicode"], "NFC basenames é, 日本語 and 🎮 sorted by UTF-8 bytes", req.fr09, "validate-object", "tree");
  accept("unicode-age-15-assigned", ["unicode:age-15-assigned"],
    "a Unicode 15.0 assigned scalar in NFC is admitted by the frozen format-v1 repertoire",
    unionReq(req.fr04, req.fr09, req.nfr01, req.ac03, req.ac08), "canonical-scan", "unicode");
  for (const [id, tag, detail] of [
    ["unicode-age-newer-composition-pair", "unicode:newer-composition-pair",
      "two post-15.0 scalars that a newer host composes are rejected by frozen Age before NFC"],
    ["unicode-age-newer-decomposed", "unicode:newer-decomposed",
      "a post-15.0 decomposed sequence is rejected by frozen Age before NFC"],
    ["unicode-age-newer-canonical", "unicode:newer-canonical",
      "the newer host's canonical composed scalar remains outside the Unicode 15.0 repertoire"],
    ["unicode-age-frozen-unassigned", "unicode:frozen-unassigned",
      "a scalar unassigned in Unicode 15.0 is rejected even when a host treats it as NFC"]
  ]) {
    reject(id, "CBOR_NON_CANONICAL", [tag], detail,
      unionReq(req.fr04, req.fr09, req.nfr01, req.ac03, req.ac08), "canonical-scan", 1);
  }
  accept("tree-all-entry-kinds-modes", ["tree:all-entry-kinds", "tree:all-modes"], "directory 040000, regular 100644, executable 100755 and symlink 120000", req.fr09, "validate-object", "tree");
  accept("tree-million-entries", ["tree:million-entries"], "stream one million strictly ordered immediate entries", unionReq(req.fr09, req.nfr02, req.ac02), "validate-object", "tree");
  reject("tree-entry-order", "TREE_ENTRY_ORDER_INVALID", ["tree:order-error"], "swap two adjacent UTF-8 basename keys", req.fr09, "validate-object", 2);
  reject("tree-entry-target", "TREE_ENTRY_TARGET_INVALID", ["tree:target-error"], "regular entry declares executable mode while retaining regular-file kind", req.fr09, "validate-object", 2);
  reject("tree-manifest-length-mismatch", "TREE_ENTRY_TARGET_INVALID", ["tree:manifest-length-mismatch"], "file entry logical size differs from its resolved content-manifest length", unionReq(req.fr09, req.ac08), "validate-object", 3);
  reject("tree-path-core", "PATH_CORE_INVALID", ["tree:path-core-error"], "path exceeds the exact core byte ceiling", req.fr09, "validate-object");
  reject("tree-path-core-deep-chain", "PATH_CORE_INVALID", ["tree:path-core-deep-chain"], "a bounded chain deeper than the 256-segment path ceiling rejects with the typed core-path error without host recursion failure", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08), "validate-object");
  reject("tree-path-profile", "PATH_PROFILE_INVALID", ["tree:path-profile-error"], "registered test path profile rejects joined path", req.fr09, "validate-object");
  addScenario("tree-ratified-path-profile-accept", {
    detail: "caller-supplied validator accepts a complete joined path for the exact ratified profile",
    mode: "conformance",
    obligationTags: ["tree:ratified-path-profile-accept"],
    operation: "validate-object",
    requirements: unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.ac11),
    resultFamily: "tree"
  });
  addScenario("tree-ratified-path-profile-empty-accept", {
    detail: "caller-supplied validator is present and version-pinned for an empty tree using the exact ratified profile",
    mode: "conformance",
    obligationTags: ["tree:ratified-path-profile-empty-accept"],
    operation: "validate-object",
    requirements: unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.ac11),
    resultFamily: "tree"
  });
  addScenario("tree-ratified-path-profile-opaque-keys", {
    detail: "caller-supplied validator collision keys are opaque and retain decomposed and non-ASCII Unicode without normalization",
    mode: "conformance",
    obligationTags: ["tree:ratified-path-profile-opaque-keys"],
    operation: "validate-object",
    requirements: unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.ac11),
    resultFamily: "tree"
  });
  addScenario("tree-ratified-path-profile-case-sensitive-distinct", {
    detail: "case-sensitive repository context keeps A and a collision keys distinct",
    mode: "conformance",
    obligationTags: ["tree:ratified-path-profile-case-sensitive-distinct"],
    operation: "validate-object",
    requirements: unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.ac11),
    resultFamily: "tree"
  });
  addScenario("tree-ratified-path-profile-case-folded-collision", {
    code: "PATH_PROFILE_INVALID",
    detail: "case-folded repository context rejects A and a when the exact adapter returns one repository collision key",
    layer: 3,
    mode: "conformance",
    obligationTags: ["tree:ratified-path-profile-case-folded-collision"],
    operation: "validate-object",
    requirements: unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.ac11)
  });
  addScenario("tree-ratified-path-profile-reject", {
    code: "PATH_PROFILE_INVALID",
    detail: "caller-supplied validator rejects a complete joined path for the exact ratified profile",
    layer: 3,
    mode: "conformance",
    obligationTags: ["tree:ratified-path-profile-reject"],
    operation: "validate-object",
    requirements: unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.ac11)
  });
  addScenario("tree-ratified-path-profile-empty-missing-validator", {
    code: "PATH_PROFILE_INVALID",
    detail: "an empty tree using a ratified path profile still requires the exact caller-supplied validator",
    layer: 3,
    mode: "conformance",
    obligationTags: ["tree:ratified-path-profile-empty-missing-validator"],
    operation: "validate-object",
    requirements: unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.ac11)
  });
  for (const [id, tag, detail] of [
    ["tree-ratified-path-profile-missing-child-before-missing-validator", "tree:missing-child-before-missing-path-adapter", "expandTree rejects an absent child tree before a missing ratified path-profile adapter"],
    ["tree-ratified-path-profile-missing-manifest-before-wrong-validator", "tree:missing-manifest-before-wrong-path-adapter", "expandTree rejects an absent content manifest before a validator pinned to the wrong ratified path profile"],
    ["tree-ratified-path-profile-missing-chunk-before-missing-validator", "tree:missing-chunk-before-missing-path-adapter", "content-complete expandTree rejects an absent manifest chunk before a missing ratified path-profile adapter"],
    ["tree-missing-target-before-path-profile-lifecycle", "tree:missing-target-before-path-profile-lifecycle", "expandTree rejects an absent entry target before a conformance-only path-profile lifecycle fault under production"],
    ["tree-missing-manifest-before-descriptor-mismatch", "tree:missing-manifest-before-descriptor-mismatch", "expandTree rejects an absent manifest before the tree's repository-descriptor mismatch"],
    ["tree-missing-child-before-duplicate-fileid", "tree:missing-child-before-duplicate-fileid", "expandTree rejects an absent child tree before the same tree's duplicate FileID repository fault"]
  ]) {
    addScenario(id, {
      code: "OBJECT_REFERENCE_MISSING",
      detail,
      layer: 2,
      mode: id === "tree-missing-target-before-path-profile-lifecycle" ? "production" : "conformance",
      obligationTags: [tag],
      operation: "validate-repository-route",
      requirements: unionReq(req.fr04, req.fr06, req.fr09, req.fr11, req.fr13, req.nfr01, req.nfr04, req.ac08, req.ac11),
      stage: "closure-and-reference-resolution"
    });
  }
  reject("tree-ratified-path-profile-missing-repository-key", "PATH_PROFILE_INVALID", ["tree:ratified-path-profile-missing-repository-key"], "accepted external path-profile decision omits its required repository collision key", unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.ac11), "validate-path-profile-decision");
  reject("tree-ratified-path-profile-missing-platform-key", "PATH_PROFILE_INVALID", ["tree:ratified-path-profile-missing-platform-key"], "accepted external path-profile decision omits its required platform collision key", unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.ac11), "validate-path-profile-decision");
  reject("tree-ratified-path-profile-missing-case-mode", "PATH_PROFILE_INVALID", ["tree:ratified-path-profile-missing-case-mode"], "external path-profile adapter omits its required case-mode pin", unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.ac11), "validate-path-profile-decision");
  reject("tree-ratified-path-profile-wrong-case-mode", "PATH_PROFILE_INVALID", ["tree:ratified-path-profile-wrong-case-mode"], "external path-profile adapter case-mode pin differs from authenticated repository context", unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.ac11), "validate-path-profile-decision");

  for (const [id, detail] of [["group-create", "valid group create"], ["group-update", "valid group update preserving GroupID"], ["group-delete", "valid exact group delete"]]) accept(id, [`group:${id.slice(6)}`], detail, req.fr09, "replay-change-set", "group");
  reject("group-member-invalid", "GROUP_MEMBER_INVALID", ["group:member-invalid"], "primary is not one of the distinct expanded-tree members", unionReq(req.fr09, req.fr11));
  reject("group-membership-overlap", "GROUP_MEMBERSHIP_OVERLAP", ["group:overlap"], "one FileID appears in two groups", unionReq(req.fr09, req.fr11));
  reject("group-required-role-missing", "GROUP_REQUIRED_ROLE_MISSING", ["group:cardinality"], "fixture asset-meta group omits required meta role", unionReq(req.fr09, req.fr11));
  reject("group-external-key-duplicate", "GROUP_EXTERNAL_KEY_DUPLICATE", ["group:external-key"], "two groups repeat a profile-unique external key", unionReq(req.fr09, req.fr11));
  for (const order of ["forward", "reverse"]) {
    reject(`group-standalone-known-schema-before-profile-lifecycle-${order}`,
      "SCHEMA_FIELD_INVALID",
      [`group:standalone-known-schema-before-profile-lifecycle-${order}`],
      `standalone asset-group validation selects a later wrong-family profile before an earlier conformance-only lifecycle fault under production, with ${order} group order`,
      unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
      "validate-operation-mode", 2);
  }
  for (const [suffix, detail] of [
    ["later-group-non-map", "a later raw group is not a Map"],
    ["later-member-non-map", "a later raw member is not a Map"],
    ["later-external-key-non-map", "a later raw external-key entry is not a Map"],
    ["later-proxy", "a later Map Proxy is rejected without invoking its throwing caller trap"],
    ["groups-container-proxy", "the outer groups Map Proxy is rejected without invoking its throwing caller trap"],
    ["members-array-proxy", "a nested members Array Proxy is rejected without invoking its throwing caller trap"],
    ["external-keys-array-proxy", "a nested external-keys Array Proxy is rejected without invoking its throwing caller trap"]
  ]) {
    addScenario(`group-standalone-raw-${suffix}-before-profile-lifecycle`, {
      code: "SCHEMA_FIELD_INVALID",
      detail: `JavaScript standalone asset-group validation selects known-schema rejection because ${detail}, before an earlier conformance-only group lifecycle fault under production`,
      implementationScope: ["javascript"],
      layer: 2,
      obligationTags: [`group:standalone-raw-${suffix}-before-profile-lifecycle`],
      operation: "validate-operation-mode",
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
      stage: "known-schema"
    });
  }
  addScenario("asset-groups-config-proxy-no-caller-code", {
    code: "SCHEMA_FIELD_INVALID",
    detail: "JavaScript standalone asset-group validation rejects a hostile top-level configured-options Proxy at configured-resource preflight without invoking caller code",
    implementationScope: ["javascript"],
    layer: 1,
    obligationTags: ["group:asset-groups-config-proxy-no-caller-code"],
    operation: "validate-operation-mode",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
    stage: "configured-resource-preflight"
  });
  for (const [suffix, collection, detail] of [
    ["lifetime-record", "lifetimeRecords", "a malformed prior lifetime record"],
    ["import-mapping", "importMappings", "a malformed prior import mapping"]
  ]) {
    addScenario(`import-request-raw-context-${suffix}-schema-before-profile-lifecycle`, {
      code: "SCHEMA_FIELD_INVALID",
      detail: `JavaScript import-request validation selects ${detail} across the whole prior context before the request's conformance-only importer lifecycle fault under production, independent of row order`,
      implementationScope: ["javascript"],
      layer: 2,
      obligationTags: [`import-request:raw-context-${suffix}-schema-before-profile-lifecycle`],
      operation: "validate-operation-mode",
      parameters: { collection },
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
      stage: "known-schema"
    });
  }
  for (const [label, sourceName] of [["lifetime", "file-id-lifetime"], ["import-mapping", "import-mapping"]]) {
    for (const suffix of [
      "version-selector-invalid", "type-selector-invalid", "extra-field-22", "extra-field-999"
    ]) {
      const code = suffix.startsWith("extra-field-") ? "SCHEMA_FIELD_UNKNOWN" : "SCHEMA_FIELD_INVALID";
      addScenario(`logical-record-${label}-${suffix}`, {
        code,
        detail: `Canonical logical-record byte validation rejects ${sourceName} ${suffix.replaceAll("-", " ")} at the exact layer-2 record shape boundary in both language implementations`,
        layer: 2,
        obligationTags: [`fileid:serialized-${label}-${suffix}`],
        operation: "validate-operation-mode",
        requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac08),
        stage: "known-schema"
      });
    }
  }

  const conflictKinds = ["content", "divergent-move", "delete-modify", "type", "mode", "policy", "group", "path-collision"];
  for (const kind of conflictKinds) {
    if (kind === "mode") {
      reject("conflict-mode-resolved", "SCHEMA_FIELD_INVALID", ["conflict:tombstoned-kind-mode-rejected"], "reserved conflict-kind code 5 is rejected before resolution semantics", req.fr09, "validate-object", 2);
      reject("conflict-mode-unresolved-shelf", "SCHEMA_FIELD_INVALID", ["conflict:tombstoned-kind-mode-rejected"], "reserved conflict-kind code 5 is rejected before shelf placement semantics", req.fr09, "validate-object", 2);
    } else {
      accept(`conflict-${kind}-resolved`, [`conflict:kind-${kind}`, "conflict:resolved"], `resolved ${kind} conflict agrees with merge-resolution result`, req.fr09, "validate-repository", "conflict");
      accept(`conflict-${kind}-unresolved-shelf`, [`conflict:kind-${kind}`, "conflict:unresolved"], `unresolved ${kind} conflict remains valid on a shelf`, req.fr09, "validate-object", "shelf");
    }
  }
  accept("conflict-custom-driver", ["conflict:custom-driver", "conflict:resolved"], "custom resolution carries deterministic driver profile and exact result", req.fr09, "validate-repository", "conflict");
  for (const choice of ["base", "left", "right", "delete", "custom"]) accept(`conflict-choice-${choice}`, [`conflict:choice-${choice}`, "conflict:resolved"], `${choice} conflict resolution has the exact registered result-side coupling`, req.fr09, "validate-repository", "conflict");
  reject("conflict-id-mismatch", "CONFLICT_ID_MISMATCH", ["conflict:id-mismatch"], "declared conflict ID differs from keyed preimage", req.fr09, "validate-object", 2);
  reject("conflict-unresolved-published", "CONFLICT_UNRESOLVED_PUBLISHED", ["conflict:unresolved-published"], "published snapshot references unresolved conflict set", req.fr09);
  reject("conflict-resolution-mismatch", "CONFLICT_RESOLUTION_MISMATCH", ["conflict:resolution-mismatch"], "resolution record, merge operation and result state disagree", req.fr09);
  accept("shelf-revision-chain", ["shelf:revision-chain"], "two revisions share shelf and repository with exact predecessor number", req.fr09, "validate-object", "shelf");
  reject("shelf-chain-invalid", "SHELF_CHAIN_INVALID", ["shelf:chain-invalid"], "revision predecessor number is not exactly one less", req.fr09, "validate-object");
  accept("provenance-acyclic", ["provenance:acyclic"], "snapshot-reachable provenance DAG does not reach snapshot", req.fr09, "validate-repository", "provenance");
  reject("provenance-cycle", "PROVENANCE_CYCLE", ["provenance:cycle"], "prevalidated abstract provenance-input graph contains a two-node cycle", req.fr09, "validate-abstract-reference-graph");
  reject("provenance-reaches-snapshot", "OBJECT_ID_MISMATCH", ["provenance:snapshot-cycle"], "byte-materialized attempted snapshot/provenance back-edge changes a content-addressed payload and fails identity before cycle analysis", req.fr09, "canonical-scan", 1);
  accept("attestation-unsigned", ["attestation:unsigned"], "predicate with both signature fields absent", req.fr09, "validate-object", "attestation");
  accept("attestation-signed", ["attestation:signed"], "predicate with both signature profile and bytes present", req.fr09, "validate-object", "attestation");
  reject("attestation-signature-shape", "ATTESTATION_SIGNATURE_SHAPE_INVALID", ["attestation:signature-shape"], "signature profile present while signature bytes absent", req.fr09, "validate-object", 2);

  for (const [id, code, detail] of [
    ["manifest-empty", undefined, "zero logical length, empty chunks and SHA-256 of empty bytes"],
    ["manifest-repeated-chunk", undefined, "two occurrences of one chunk reference"],
    ["manifest-multi-chunk", undefined, "three distinct ordered chunks reconstruct exact digest"],
    ["manifest-corrupt-chunk", "MANIFEST_FILE_DIGEST_MISMATCH", "chunk bytes do not reproduce whole-file digest"],
    ["manifest-chunk-length", "MANIFEST_CHUNK_LENGTH_INVALID", "declared part length differs from raw chunk length"],
    ["manifest-length-sum-mismatch", "MANIFEST_LENGTH_MISMATCH", "exact arbitrary-precision part sum differs from declared logical length"],
    ["manifest-logical-ceiling", "LIMIT_LOGICAL_BYTES", "declared length is 1 TiB plus one byte; no integer-overflow claim"],
    ["manifest-unknown-profile", "PROFILE_UNKNOWN", "chunking profile is absent from registry snapshot"],
    ["manifest-one-tib", undefined, "virtual 1 TiB manifest streamed as 1,048,576 chunks of 1 MiB"],
    ["manifest-annotation-invariance", undefined, "changing separate annotation bytes preserves manifest ObjectID"]
  ]) {
    const tags = [`manifest:${id.slice(9)}`];
    const requirements = unionReq(req.fr09, req.ac09, id === "manifest-one-tib" ? req.nfr02 : []);
    if (code) reject(id, code, tags, detail, requirements, "validate-object",
      new Set(["MANIFEST_LENGTH_MISMATCH", "LIMIT_LOGICAL_BYTES"]).has(code) ? 2 : 3);
    else accept(id, tags, detail, requirements, "validate-object", "manifest");
  }

  for (const kind of ["header", "object", "logical-record", "root", "trailer"]) accept(`bundle-item-${kind}`, [`bundle:item-${kind}`], `canonical ${kind} item shape`, unionReq(req.fr09, req.ac10), "validate-bundle", "bundle");
  accept("bundle-zero-sections", ["bundle:zero-sections"], "header and trailer with zero objects, logical records and roots", unionReq(req.fr09, req.ac10), "validate-bundle", "bundle");
  accept("bundle-logical-reference-preservation", ["bundle:logical-preservation"], "annotation logical-record bytes and typed identity preserved", unionReq(req.fr09, req.ac10), "validate-bundle", "bundle");
  accept("bundle-multi-root-disambiguation", ["bundle:multi-root-sort"], "same identity with distinct roles sorted by root-kind, identity and role bytes", unionReq(req.fr09, req.ac10), "validate-bundle", "bundle");
  reject("bundle-sort-order", "BUNDLE_SEQUENCE_INVALID", ["bundle:sort"], "swap adjacent canonically ordered items", unionReq(req.fr09, req.ac10), "validate-bundle", 1);
  reject("bundle-count", "BUNDLE_SEQUENCE_INVALID", ["bundle:count"], "header section count differs from observed items", unionReq(req.fr09, req.ac10), "validate-bundle", 1);
  reject("bundle-ordinal", "BUNDLE_SEQUENCE_INVALID", ["bundle:ordinal"], "section ordinal skips zero", unionReq(req.fr09, req.ac10), "validate-bundle", 1);
  reject("bundle-mode", "BUNDLE_MODE_UNSUPPORTED", ["bundle:mode"], "closure mode 2 is unsupported", unionReq(req.fr09, req.ac10), "validate-bundle", 1);
  reject("bundle-budget", "BUNDLE_BUDGET_EXCEEDED", ["bundle:budget"], "declared total exceeds hard maximum before allocation", unionReq(req.fr09, req.ac10), "validate-bundle", 1);
  reject("bundle-declared-accounting", "BUNDLE_BUDGET_EXCEEDED", ["bundle:declared-accounting"], "authenticated header understates the supplied object and logical-record index count", unionReq(req.fr09, req.ac08, req.ac10), "validate-bundle", 1);
  reject("bundle-object-id", "OBJECT_ID_MISMATCH", ["bundle:object-id"], "object item payload differs from declared ObjectRef", unionReq(req.fr09, req.ac10), "validate-bundle", 1);
  reject("bundle-record-id", "BUNDLE_RECORD_ID_MISMATCH", ["bundle:record-id"], "logical record differs from declared typed digest", unionReq(req.fr09, req.ac10), "validate-bundle", 1);
  reject("bundle-root-invalid", "BUNDLE_ROOT_INVALID", ["bundle:root-invalid"], "required logical record root is absent", unionReq(req.fr09, req.ac10), "validate-bundle", 2);
  reject("bundle-trailer", "BUNDLE_TRAILER_MISMATCH", ["bundle:trailer"], "trailer transcript digest differs", unionReq(req.fr09, req.ac10), "validate-bundle", 1);
  reject("bundle-eof", "BUNDLE_SEQUENCE_INVALID", ["bundle:eof"], "complete CBOR item follows trailer", unionReq(req.fr09, req.ac10), "validate-bundle", 1);
  reject("bundle-duplicate", "BUNDLE_DUPLICATE_IDENTITY", ["bundle:duplicate"], "object identity appears twice", unionReq(req.fr09, req.ac10), "validate-bundle", 1);
  reject("bundle-closure-missing", "BUNDLE_CLOSURE_MISSING", ["bundle:closure-missing"], "reachable chunk object is omitted", unionReq(req.fr09, req.ac10), "validate-bundle", 2);
  reject("bundle-closure-extra", "BUNDLE_CLOSURE_EXTRA", ["bundle:closure-extra"], "unreachable immutable object is supplied", unionReq(req.fr09, req.ac10), "validate-bundle", 2);
  reject("bundle-wrong-kind", "OBJECT_REFERENCE_KIND_MISMATCH", ["bundle:wrong-kind"], "manifest chunk ref resolves to provenance object bytes", unionReq(req.fr09, req.ac10), "validate-bundle", 2);
  reject("bundle-export-claim", "BUNDLE_EXPORT_CLAIM_FORBIDDEN", ["bundle:forbidden-claim"], "caller relabels supplied closure as fidelity export", unionReq(req.fr09, req.ac10), "validate-bundle-claim");
  accept("bundle-edge-families", ["bundle:every-edge-family", "bundle:every-root-family"], "closure traverses every registered immutable and logical outbound edge family", unionReq(req.fr09, req.ac10), "validate-bundle", "bundle");
  for (const row of objectRows) accept(`bundle-object-kind-${row.kind}`, [`bundle:edge-object-kind-${row.kind}`], `supplied closure traverses all outbound edges of object kind ${row.kind} (${row.name})`, unionReq(req.fr09, req.ac10), "validate-bundle", "bundle");
  for (const row of logicalRows) accept(`bundle-logical-type-${row.type}`, [`bundle:logical-type-${row.type}`], `logical record type ${row.type} is byte-preserved, rooted and traversed`, unionReq(req.fr09, req.ac10), "validate-bundle", "bundle");
  accept("bundle-root-kind-object", ["bundle:root-kind-object"], "object root identity and role profile use canonical root ordering", unionReq(req.fr09, req.ac10), "validate-bundle", "bundle");
  accept("bundle-root-kind-logical-record", ["bundle:root-kind-logical-record"], "logical-record root identity and role profile use canonical root ordering", unionReq(req.fr09, req.ac10), "validate-bundle", "bundle");
  reject("bundle-visitor-max-item-budget", "BUNDLE_BUDGET_EXCEEDED", ["bundle:visitor-item-budget"], "public bundle visitor enforces its configured largest-item ceiling", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08, req.ac10), "validate-bundle", 1);
  reject("bundle-visitor-max-items-budget", "BUNDLE_BUDGET_EXCEEDED", ["bundle:visitor-count-budget"], "public bundle visitor enforces its configured item-count ceiling", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08, req.ac10), "validate-bundle", 1);
  reject("bundle-visitor-nested-map-key-capture-memory", "LIMIT_MEMORY", ["bundle:visitor-nested-key-capture-memory"], "public streaming canonical scan charges all simultaneously active and retained map-key capture capacities before allocating the eighth nested capture", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08, req.ac10), "validate-bundle", 1);
  reject("bundle-transcript-max-bytes-budget", "BUNDLE_BUDGET_EXCEEDED", ["bundle:transcript-budget"], "public bundle transcript writer enforces its configured byte ceiling", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08, req.ac10), "validate-bundle", 1);
  reject("bundle-writer-sequence-before-object-id", "BUNDLE_SEQUENCE_INVALID", ["bundle:writer-sequence-before-object-id"], "logical-bundle memory and ordered writers reject descending object order before a later declared object digest mismatch", unionReq(req.fr09, req.fr11, req.nfr01, req.ac08, req.ac10), "write-logical-bundle", 1);
  addScenario("bundle-writer-object-id-before-unknown-kind", {
    code: "OBJECT_ID_MISMATCH",
    detail: "JavaScript logical-bundle memory and ordered writers reject a declared object digest mismatch before later additive-kind lifecycle interpretation",
    implementationScope: ["javascript"],
    layer: 1,
    obligationTags: ["bundle:writer-object-id-before-unknown-kind"],
    operation: "write-logical-bundle",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac08, req.ac10)
  });
  reject("bundle-writer-object-id-before-feature-lifecycle", "OBJECT_ID_MISMATCH",
    ["bundle:writer-object-id-before-feature-lifecycle"],
    "logical-bundle memory and ordered writers reject a known tree's declared object digest mismatch before its conformance-only required-feature lifecycle fault under production-write",
    unionReq(req.fr09, req.fr11, req.nfr01, req.ac08, req.ac10), "write-logical-bundle", 1);
  for (const order of ["forward", "reverse"]) {
    reject(`bundle-writer-section-object-id-before-feature-lifecycle-${order}`,
      "OBJECT_ID_MISMATCH",
      [`bundle:writer-section-object-id-before-feature-lifecycle-${order}`],
      `logical-bundle memory and ordered writers select a sibling object's declared identity mismatch before a conformance-only tree feature under production-write with the lifecycle fault ${order === "forward" ? "first" : "last"}`,
      unionReq(req.fr09, req.fr11, req.nfr01, req.ac08, req.ac10),
      "write-logical-bundle", 1);
    reject(`bundle-writer-section-root-order-before-role-lifecycle-${order}`,
      "BUNDLE_SEQUENCE_INVALID",
      [`bundle:writer-section-root-order-before-role-lifecycle-${order}`],
      `logical-bundle memory and ordered writers select descending root order before a conformance-only root-role profile under production-write with the lifecycle fault ${order === "forward" ? "first" : "last"}`,
      unionReq(req.fr09, req.fr11, req.nfr01, req.ac08, req.ac10),
      "write-logical-bundle", 1);
    reject(`bundle-writer-section-sequence-before-logical-schema-${order}`,
      "BUNDLE_SEQUENCE_INVALID",
      [`bundle:writer-section-sequence-before-logical-schema-${order}`],
      `logical-bundle memory and ordered writers select a descending logical-record sequence at layer 1 before an unknown-field logical-record at layer 2 with the schema fault ${order === "forward" ? "first" : "last"}`,
      unionReq(req.fr09, req.fr11, req.nfr01, req.ac08, req.ac10),
      "write-logical-bundle", 1);
  }

  reject("manifest-writer-too-few-parts", "SCHEMA_FIELD_INVALID", ["manifest:writer-too-few-parts"], "manifest writer iterator yields fewer parts than its declaration", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08, req.ac09), "write-content-manifest", 2);
  reject("manifest-writer-too-many-parts", "SCHEMA_FIELD_INVALID", ["manifest:writer-too-many-parts"], "manifest writer iterator yields more parts than its declaration", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08, req.ac09), "write-content-manifest", 2);
  reject("manifest-writer-count-before-profile-lifecycle", "SCHEMA_FIELD_INVALID", ["manifest:writer-count-before-profile-lifecycle"], "manifest writer rejects an actual-versus-declared iterator count mismatch before a later conformance-only profile lifecycle fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08, req.ac09), "write-content-manifest", 2);
  reject("manifest-writer-limit-before-count-and-profile-lifecycle", "LIMIT_COUNT", ["manifest:writer-limit-before-count-and-profile-lifecycle"], "manifest writer rejects its configured item ceiling before the same input's declared-count mismatch and conformance-only profile lifecycle fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08, req.ac09), "write-content-manifest", 1);
  reject("manifest-writer-object-id-before-profile-lifecycle", "OBJECT_ID_MISMATCH", ["manifest:writer-object-id-before-profile-lifecycle"], "manifest writer rejects supplied chunk bytes that differ from the declared chunk identity before a conformance-only chunking-profile lifecycle fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08, req.ac09), "write-content-manifest", 1);
  for (const order of ["forward", "reverse"]) reject(
    `manifest-writer-known-schema-before-chunk-length-${order}`,
    "OBJECT_REFERENCE_KIND_MISMATCH",
    [`manifest:writer-known-schema-before-chunk-length-${order}`],
    `manifest writer selects the layer-2 wrong-kind part over a layer-3 chunk-length fault in ${order} occurrence order`,
    unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08, req.ac09),
    "write-content-manifest", 2);
  for (const order of ["forward", "reverse"]) reject(
    `manifest-writer-content-object-id-before-chunk-length-${order}`,
    "OBJECT_ID_MISMATCH",
    [`manifest:writer-content-object-id-before-chunk-length-${order}`],
    `manifest writer completes the bounded content-provider pass and selects a same-length corrupt chunk identity at layer 1 over a short sibling chunk at layer 3 in ${order} part order`,
    unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08, req.ac09),
    "write-content-manifest", 1);
  reject("manifest-writer-limit-before-kind", "LIMIT_COUNT",
    ["manifest:writer-limit-before-kind"],
    "manifest writer rejects an actual part count above the configured ceiling before inspecting a wrong-kind part",
    unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08, req.ac09),
    "write-content-manifest", 1);
  for (const order of ["forward", "reverse"]) reject(
    `manifest-writer-count-before-kind-${order}`,
    "SCHEMA_FIELD_INVALID",
    [`manifest:writer-count-before-kind-${order}`],
    `manifest writer selects the global actual-versus-declared part-count mismatch before a wrong-kind part in ${order} occurrence order`,
    unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08, req.ac09),
    "write-content-manifest", 2);
  reject("tree-writer-ordered-too-many-entries", "SCHEMA_FIELD_INVALID", ["tree:writer-ordered-too-many-entries"], "ordered tree writer iterator yields two entries while its declaration is one and its configured ceiling is two", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08), "write-tree", 2);
  reject("tree-writer-sorted-too-many-entries", "SCHEMA_FIELD_INVALID", ["tree:writer-sorted-too-many-entries"], "sorted tree writer iterator yields two entries while its declaration is one and its configured ceiling is two", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08), "write-tree", 2);
  reject("tree-writer-ordered-count-before-feature-lifecycle", "SCHEMA_FIELD_INVALID", ["tree:writer-ordered-count-before-feature-lifecycle"], "ordered tree writer rejects an actual-versus-declared iterator count mismatch before a later conformance-only required-feature lifecycle fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08), "write-tree", 2);
  reject("tree-writer-sorted-count-before-feature-lifecycle", "SCHEMA_FIELD_INVALID", ["tree:writer-sorted-count-before-feature-lifecycle"], "sorted tree writer rejects an actual-versus-declared iterator count mismatch before a later conformance-only required-feature lifecycle fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08), "write-tree", 2);
  reject("tree-writer-ordered-count-before-entry-profile-lifecycle", "SCHEMA_FIELD_INVALID", ["tree:writer-ordered-count-before-entry-profile-lifecycle"], "ordered tree writer rejects an actual-versus-declared iterator count mismatch before an earlier entry's conformance-only content-policy lifecycle fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08), "write-tree", 2);
  reject("tree-writer-sorted-count-before-entry-profile-lifecycle", "SCHEMA_FIELD_INVALID", ["tree:writer-sorted-count-before-entry-profile-lifecycle"], "sorted tree writer rejects an actual-versus-declared iterator count mismatch before an earlier input entry's conformance-only content-policy lifecycle fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08), "write-tree", 2);
  reject("tree-writer-ordered-count-before-duplicate-fileid", "SCHEMA_FIELD_INVALID", ["tree:writer-ordered-count-before-duplicate-fileid"], "ordered tree writer rejects an actual-versus-declared iterator count mismatch before the same iterator's duplicate FileID repository fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac07, req.ac08), "write-tree", 2);
  reject("tree-writer-sorted-count-before-duplicate-fileid", "SCHEMA_FIELD_INVALID", ["tree:writer-sorted-count-before-duplicate-fileid"], "sorted tree writer rejects an actual-versus-declared iterator count mismatch before the same iterator's duplicate FileID repository fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac07, req.ac08), "write-tree", 2);
  reject("tree-writer-ordered-limit-before-count-and-feature-lifecycle", "LIMIT_COUNT", ["tree:writer-ordered-limit-before-count-and-feature-lifecycle"], "ordered tree writer rejects its configured item ceiling before the same input's declared-count mismatch and conformance-only required-feature lifecycle fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08), "write-tree", 1);
  reject("tree-writer-sorted-limit-before-count-and-feature-lifecycle", "LIMIT_COUNT", ["tree:writer-sorted-limit-before-count-and-feature-lifecycle"], "sorted tree writer rejects its configured item ceiling before the same input's declared-count mismatch and conformance-only required-feature lifecycle fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08), "write-tree", 1);
  reject("tree-writer-ordered-limit-before-kind", "LIMIT_COUNT",
    ["tree:writer-ordered-limit-before-kind"],
    "ordered tree writer rejects an actual item count above the configured ceiling before inspecting a wrong-kind entry",
    unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08), "write-tree", 1);
  for (const order of ["forward", "reverse"]) reject(
    `tree-writer-ordered-kind-before-order-${order}`,
    "OBJECT_REFERENCE_KIND_MISMATCH",
    [`tree:writer-ordered-kind-before-order-${order}`],
    `ordered tree writer selects the higher-ranked wrong-kind entry over noncanonical entry order in ${order} occurrence order`,
    unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
    "write-tree", 2);
  for (const order of ["forward", "reverse"]) reject(
    `tree-writer-sorted-family-before-kind-${order}`,
    "SCHEMA_FIELD_INVALID",
    [`tree:writer-sorted-family-before-kind-${order}`],
    `sorted tree writer selects a wrong-family content profile before a wrong-kind entry target in ${order} source/name order`,
    unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
    "write-tree", 2);
  reject("mode-tree-file-order-before-feature-lifecycle", "TREE_ENTRY_ORDER_INVALID", ["mode:tree-file-order-before-feature-lifecycle"], "file-backed tree verification rejects noncanonical entry order before the same tree's conformance-only required-feature lifecycle fault under production-write", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08), "validate-operation-mode", 2);
  reject("mode-tree-file-order-before-descriptor-mismatch", "TREE_ENTRY_ORDER_INVALID", ["mode:tree-file-order-before-descriptor-mismatch"], "file-backed tree verification rejects a later noncanonical entry order before the caller's wrong repository descriptor", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08), "validate-operation-mode", 2);
  reject("mode-tree-file-target-before-duplicate-fileid", "TREE_ENTRY_TARGET_INVALID", ["mode:tree-file-target-before-duplicate-fileid"], "file-backed tree verification rejects a later entry target/mode defect before the tree's duplicate FileID repository-semantic fault", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac07, req.ac08), "validate-operation-mode", 2);
  reject("mode-tree-file-feature-before-duplicate-fileid", "PROFILE_CONFORMANCE_ONLY", ["mode:tree-file-feature-before-duplicate-fileid"], "file-backed tree verification selects the conformance-only required-feature registry failure before the tree's duplicate FileID repository failure", unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac07, req.ac08), "validate-operation-mode", 3);
  for (const order of ["forward", "reverse"]) reject(
    `mode-tree-file-known-schema-before-order-${order}`,
    "SCHEMA_FIELD_UNKNOWN",
    [`mode:tree-file-known-schema-before-order-${order}`],
    `file-backed tree verification selects the higher-ranked unknown entry field over noncanonical entry order in ${order} occurrence order`,
    unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
    "validate-operation-mode", 2);
  addScenario("mode-manifest-verify-missing-reference-before-profile-lifecycle", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "manifest verification rejects an absent referenced chunk before the manifest's conformance-only chunking-profile lifecycle fault under production mode",
    layer: 2,
    mode: "production",
    obligationTags: ["mode:manifest-verify-missing-reference-before-profile-lifecycle"],
    operation: "validate-operation-mode",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08, req.ac09),
    stage: "closure-and-reference-resolution"
  });
  for (const order of ["forward", "reverse"]) {
    reject(`lookup-validate-all-known-schema-before-profile-lifecycle-${order}`,
      "SCHEMA_FIELD_UNKNOWN",
      [`lookup:validate-all-known-schema-before-profile-lifecycle-${order}`],
      `whole-set lookup validation selects a known-schema defect before a conformance-only registry fault with ${order} authenticated lookup order`,
      unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
      "validate-operation-mode", 2);
  }
  for (const [id, tag, detail, operation] of [
    ["tree-missing-reference-before-profile-lifecycle", "tree:missing-reference-before-profile-lifecycle", "tree validation rejects an absent entry target before the entry's conformance-only content-policy lifecycle fault", "validate-repository-route"],
    ["replay-missing-reference-before-profile-lifecycle", "transition:missing-reference-before-profile-lifecycle", "change-set replay rejects an absent entry target before later profile lifecycle interpretation", "validate-repository-route"],
    ["conflict-missing-reference-before-profile-lifecycle", "conflict:missing-reference-before-profile-lifecycle", "conflict validation rejects an absent referenced object before later profile lifecycle interpretation", "validate-repository"],
    ["provenance-missing-reference-before-profile-lifecycle", "provenance:missing-reference-before-profile-lifecycle", "provenance validation rejects an absent input object before later profile lifecycle interpretation", "validate-repository-route"]
  ]) {
    addScenario(id, {
      code: "OBJECT_REFERENCE_MISSING",
      detail,
      layer: 2,
      mode: "production",
      obligationTags: [tag],
      operation,
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
      stage: "closure-and-reference-resolution"
    });
  }
  for (const route of ["manifest", "tree", "replay", "conflict", "snapshot", "provenance", "shelf"]) {
    for (const order of ["forward", "reverse"]) {
      addScenario(`closure-${route}-identity-before-missing-${order}`, {
        code: "OBJECT_ID_MISMATCH",
        detail: `${route} closure selects a reached sibling's corrupt supplied identity at layer 1 before another reached missing reference at layer 2, with ${order} edge order`,
        layer: 1,
        obligationTags: [`closure:${route}-identity-before-missing-${order}`],
        operation: "validate-repository-route",
        requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
        stage: "declared-identity"
      });
    }
  }
  addScenario("snapshot-graph-missing-change-before-profile-lifecycle", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "standalone snapshot-graph validation rejects an absent referenced ChangeSet before the snapshot's conformance-only required-feature lifecycle fault",
    layer: 2,
    mode: "production",
    obligationTags: ["snapshot-graph:missing-change-before-profile-lifecycle"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
    stage: "closure-and-reference-resolution"
  });
  addScenario("snapshot-graph-missing-descriptor-before-descriptor-mismatch", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "standalone snapshot-graph validation resolves an absent snapshot descriptor before evaluating that descriptor's cross-repository mismatch",
    layer: 2,
    obligationTags: ["snapshot-graph:missing-descriptor-before-descriptor-mismatch"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac06, req.ac08),
    stage: "closure-and-reference-resolution"
  });
  for (const order of ["forward", "reverse"]) {
    addScenario(`snapshot-graph-second-root-before-missing-parent-${order}`, {
      code: "OBJECT_REFERENCE_MISSING",
      detail: `snapshot-graph validation resolves every parent and rejects an absent parent before a reachable second zero-parent root, with ${order} parent order`,
      layer: 2,
      obligationTags: [`snapshot-graph:second-root-before-missing-parent-${order}`],
      operation: "validate-repository-route",
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac06, req.ac08),
      stage: "closure-and-reference-resolution"
    });
  }
  addScenario("replay-restore-missing-source-tree-before-profile-lifecycle", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "restore replay resolves the ancestral source snapshot tree before applying that source snapshot's conformance-only lifecycle semantics under production",
    layer: 2,
    mode: "production",
    obligationTags: ["transition:restore-missing-source-tree-before-profile-lifecycle"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac07, req.ac08),
    stage: "closure-and-reference-resolution"
  });
  addScenario("replay-restore-missing-proof-descriptor-before-cross-repository", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "restore replay resolves an absent proof repository descriptor before cross-repository proof and conformance-only lifecycle semantics under production",
    layer: 2,
    mode: "production",
    obligationTags: ["transition:restore-missing-proof-descriptor-before-cross-repository"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac07, req.ac08),
    stage: "closure-and-reference-resolution"
  });
  for (const order of ["forward", "reverse"]) {
    addScenario(`provenance-cycle-branch-before-missing-input-${order}`, {
      code: "OBJECT_REFERENCE_MISSING",
      detail: `fully transitive provenance validation selects an absent input in a later branch before a forbidden cycle branch, with ${order} authenticated root order`,
      layer: 2,
      obligationTags: [`provenance:cycle-branch-before-missing-input-${order}`],
      operation: "validate-repository-route",
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
      stage: "closure-and-reference-resolution"
    });
  }
  reject("conflict-entry-target-missing", "OBJECT_REFERENCE_MISSING",
    ["conflict:entry-target-missing"],
    "standalone conflict validation rejects an absent direct entry-side content-manifest target",
    unionReq(req.fr09, req.fr11, req.nfr01, req.ac08), "validate-repository-route", 2);
  addScenario("conflict-entry-target-wrong-kind", {
    code: "OBJECT_REFERENCE_KIND_MISMATCH",
    detail: "standalone conflict validation rejects a direct entry-side target whose typed ObjectRef is not a content manifest",
    layer: 2,
    obligationTags: ["conflict:entry-target-wrong-kind"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac08),
    stage: "known-schema"
  });
  addScenario("conflict-entry-target-missing-before-profile-lifecycle", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "standalone conflict validation rejects an absent direct entry-side target before the same side's conformance-only content-policy lifecycle fault under production mode",
    layer: 2,
    mode: "production",
    obligationTags: ["conflict:entry-target-missing-before-profile-lifecycle"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
    stage: "closure-and-reference-resolution"
  });
  addScenario("replay-entry-target-wrong-kind", {
    code: "OBJECT_REFERENCE_KIND_MISMATCH",
    detail: "change-set replay rejects an ordinary EntryState target whose typed ObjectRef is not a content manifest",
    layer: 2,
    obligationTags: ["transition:entry-target-wrong-kind"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac08),
    stage: "known-schema"
  });
  addScenario("repository-candidate-verify-content-false", {
    code: "SCHEMA_FIELD_INVALID",
    detail: "full repository candidate validation rejects a caller attempt to disable content completeness before inspecting the candidate graph",
    layer: 1,
    obligationTags: ["repository:candidate-verify-content-false-rejected"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac08),
    stage: "configured-resource-preflight"
  });
  addScenario("repository-candidate-content-missing", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "full repository candidate validation with content completeness enabled rejects an absent manifest chunk",
    layer: 2,
    obligationTags: ["repository:candidate-content-complete-missing-chunk"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac08),
    stage: "closure-and-reference-resolution"
  });
  addScenario("repository-candidate-missing-tree-before-second-root", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "full repository candidate validation rejects an absent candidate tree before the same candidate's second-zero-parent repository fault",
    layer: 2,
    obligationTags: ["repository:candidate-missing-tree-before-second-root"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac06, req.ac08),
    stage: "closure-and-reference-resolution"
  });
  addScenario("repository-candidate-missing-change-before-profile-lifecycle", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "full repository candidate validation rejects an absent candidate ChangeSet before the snapshot's conformance-only required-feature lifecycle fault under production",
    layer: 2,
    mode: "production",
    obligationTags: ["repository:candidate-missing-change-before-profile-lifecycle"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.nfr04, req.ac08),
    stage: "closure-and-reference-resolution"
  });
  addScenario("repository-candidate-missing-change-base", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "full repository candidate validation rejects an absent syntactically valid ChangeSet base even when candidate parent zero is present",
    layer: 2,
    obligationTags: ["repository:candidate-missing-change-base"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac06, req.ac08),
    stage: "closure-and-reference-resolution"
  });
  addScenario("shelf-verify-content-false", {
    code: "SCHEMA_FIELD_INVALID",
    detail: "shelf validation rejects a caller attempt to disable content completeness before inspecting the shelf graph",
    layer: 1,
    obligationTags: ["shelf:verify-content-false-rejected"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac08),
    stage: "configured-resource-preflight"
  });
  addScenario("shelf-content-missing", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "shelf validation with content completeness enabled rejects an absent manifest chunk",
    layer: 2,
    obligationTags: ["shelf:content-complete-missing-chunk"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac08),
    stage: "closure-and-reference-resolution"
  });
  addScenario("shelf-missing-previous-before-chain-invalid", {
    code: "OBJECT_REFERENCE_MISSING",
    detail: "shelf validation rejects an absent previous revision before evaluating the candidate revision-number chain fault",
    layer: 2,
    obligationTags: ["shelf:missing-previous-before-chain-invalid"],
    operation: "validate-repository-route",
    requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac08),
    stage: "closure-and-reference-resolution"
  });
  for (const [id, tag, detail] of [
    ["shelf-unrelated-known-schema-object-ignored", "shelf:unrelated-known-schema-object-ignored",
      "shelf validation accepts a complete reached shelf closure while ignoring an unrelated supplied object with a known-schema defect"],
    ["shelf-unrelated-profile-object-ignored", "shelf:unrelated-profile-object-ignored",
      "shelf validation accepts a complete reached shelf closure while ignoring an unrelated supplied object with an unknown profile"]
  ]) {
    addScenario(id, {
      detail,
      obligationTags: [tag],
      operation: "validate-repository-route",
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac08),
      resultFamily: "shelf"
    });
  }

  reject("resource-lookup-edge-counter-rollback", "LIMIT_COUNT", ["limits:lookup-edge-counter-rollback"], "tree expansion rolls its configured edge counter back after failure and the same lookup validates a fitting manifest", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08), "validate-resource-reservation", 1);
  reject("resource-lookup-scratch-counter-rollback", "LIMIT_SCRATCH", ["limits:lookup-scratch-counter-rollback"], "tree expansion rolls its configured scratch counter back after failure and the same lookup expands a fitting tree", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08), "validate-resource-reservation", 1);
  reject("resource-tree-stream-transaction-composite-memory", "LIMIT_MEMORY", ["limits:tree-stream-transaction-composite-memory"], "file-backed tree validation composes reader, current-entry, and FileID-index memory; a late bounded failure aborts without changing the target and the same FileID index accepts a fitting retry", unionReq(req.fr09, req.nfr01, req.nfr04, req.ac07, req.ac08), "validate-resource-reservation", 1);

  addScenario("typed-reference-arbitrary-kind-map-relabel", {
    code: "SCHEMA_FIELD_INVALID",
    detail: "an arbitrary caller kind-name map cannot relabel frozen object kind 3 from tree to evil",
    implementationScope: ["javascript"],
    layer: 1,
    obligationTags: ["typed-reference:arbitrary-kind-map-relabel"],
    operation: "validate-typed-reference-authority",
    requirements: unionReq(req.fr04, req.fr09, req.nfr01, req.ac03, req.ac11),
    stage: "configured-resource-preflight"
  });
  for (const [field, detail] of [
    ["sourceNamespaceDigest", "source namespace digest"],
    ["sourceIdentityDigest", "source identity digest"],
    ["requestedFileId", "requested FileID"]
  ]) {
    addScenario(`import-request-raw-${field.replaceAll(/[A-Z]/g, match => `-${match.toLowerCase()}`)}-schema-before-profile-lifecycle`, {
      code: "SCHEMA_FIELD_INVALID",
      detail: `JavaScript raw import-request validation selects a malformed ${detail} before a conformance-only importer lifecycle fault under production, independent of property insertion order`,
      implementationScope: ["javascript"],
      layer: 2,
      obligationTags: [`import-request:raw-${field}-schema-before-profile-lifecycle`],
      operation: "validate-operation-mode",
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac08),
      stage: "known-schema"
    });
  }
  for (const [suffix, detail] of [
    ["lifetime-record-schema-before-duplicate", "a malformed later lifetime record before duplicate lifetime semantics"],
    ["import-mapping-schema-before-conflict", "a malformed later import mapping before duplicate-tuple conflict semantics"],
    ["working-addition-schema-before-duplicate", "a malformed later working addition before duplicate working-lifetime semantics"]
  ]) {
    addScenario(`lifetime-raw-${suffix}`, {
      code: "SCHEMA_FIELD_INVALID",
      detail: `JavaScript raw lifetime/import validation selects ${detail}, independent of row order`,
      implementationScope: ["javascript"],
      layer: 2,
      obligationTags: [`fileid:raw-${suffix}`],
      operation: "validate-operation-mode",
      requirements: unionReq(req.fr09, req.fr11, req.nfr01, req.ac07, req.ac08),
      stage: "known-schema"
    });
  }
  reject("typed-reference-durable-overlength-colon-dense", "SCHEMA_FIELD_INVALID", ["typed-reference:durable-overlength-colon-dense"], "a colon-dense durable ObjectRef above the 144-byte bound is rejected before token splitting", unionReq(req.fr04, req.fr09, req.nfr01, req.ac03, req.ac11), "validate-typed-reference-authority", 2);
  reject("typed-reference-duplicate-kind-token", "REGISTRY_INVALID",
    ["typed-reference:duplicate-kind-token"],
    "a candidate complete registry cannot assign the content-manifest text token to both kind codes 2 and 3",
    unionReq(req.fr04, req.fr09, req.nfr01, req.ac03, req.ac11),
    "validate-typed-reference-authority", 3);

  const modeRequirements = unionReq(req.fr04, req.fr06, req.fr09, req.fr13, req.nfr01, req.nfr04, req.ac11);
  const modeReject = (id, code, tag, detail, layer = 1) =>
    reject(id, code, [tag], detail, modeRequirements, "validate-operation-mode", layer);
  const repositorySemanticSurfaces = ["repository-candidate", "import-request", "tree-expand", "manifest-verify", "asset-groups"];
  for (const surface of repositorySemanticSurfaces) {
    addScenario(`mode-${surface}-conformance-accept`, {
      detail: `${surface}: a complete registry, explicit conformance mode, and concrete public-route carrier execute through layer three`,
      layer: 3,
      obligationTags: [`mode:${surface}-conformance-accept`],
      operation: "validate-operation-mode",
      requirements: modeRequirements,
      resultFamily: ["tree-expand", "manifest-verify"].includes(surface) ? (surface === "tree-expand" ? "tree" : "manifest") : "repository"
    });
    for (const [suffix, description] of [
      ["read", "registry read operation is not a repository validation mode"],
      ["invalid", "unknown validation mode is rejected"],
      ["omitted", "layer-three validation mode must be explicit"]
    ]) {
      modeReject(`mode-${surface}-${suffix}`, "SCHEMA_FIELD_INVALID", `mode:${surface}-${suffix}-rejected`,
        `${surface}: ${description} before payload work`);
    }
    modeReject(`mode-${surface}-production-conformance-profile`, "PROFILE_CONFORMANCE_ONLY",
      `mode:${surface}-production-conformance-rejected`,
      `production ${surface} semantics reject a selected conformance-only profile`, 3);
    for (const variant of ["partial", "forged"]) {
      modeReject(`mode-${surface}-${variant}-registry`, "SCHEMA_FIELD_INVALID",
        `mode:${surface}-${variant}-registry-rejected`,
        `${surface} rejects a ${variant} registry authority before payload work`);
    }
  }
  for (const surface of repositorySemanticSurfaces) {
    modeReject(`mode-${surface}-missing-registry`, "SCHEMA_FIELD_INVALID",
      `mode:${surface}-registry-required`,
      `${surface} layer-three semantics require a complete registry snapshot before payload work`);
    modeReject(`mode-${surface}-semantic-disabled`, "SCHEMA_FIELD_INVALID",
      `mode:${surface}-semantic-disabled-rejected`,
      `${surface} cannot claim layer-three success while registry semantics are disabled`);
  }
  for (const suffix of ["case-mode-missing", "case-mode-invalid"]) {
    modeReject(`mode-tree-expand-${suffix}`, "SCHEMA_FIELD_INVALID", `mode:tree-expand-${suffix}-rejected`,
      `tree expansion requires an explicit closed repository case mode before object work`);
  }
  addScenario("mode-repository-lookup-layer2-registry-free", {
    detail: "pure object lookup may stop after framing, identity, and known-schema validation without semantic authority",
    layer: 2,
    obligationTags: ["mode:repository-lookup-layer2-registry-free"],
    operation: "validate-operation-mode",
    requirements: modeRequirements,
    resultFamily: "repository"
  });
  modeReject("mode-repository-lookup-layer2-authority-omitted", "SCHEMA_FIELD_INVALID",
    "mode:repository-lookup-layer2-authority-omitted-rejected",
    "repository lookup must explicitly select the registry-free layer-two boundary; omitting all authority is not a default");
  for (const [suffix, description] of [["read", "registry read is not a visitor mode"], ["invalid", "unknown visitor mode is rejected"]]) {
    modeReject(`mode-bundle-visitor-${suffix}`, "SCHEMA_FIELD_INVALID", `mode:bundle-visitor-${suffix}-rejected`,
      `bundle visitor ${description} before consuming input`);
  }
  addScenario("mode-bundle-visitor-omitted", {
    detail: "registry-free bundle visitor may omit semantic mode and remains a framing-only layer-two surface",
    layer: 2,
    obligationTags: ["mode:bundle-visitor-omitted"],
    operation: "validate-operation-mode",
    requirements: modeRequirements,
    resultFamily: "bundle"
  });
  addScenario("bundle-semantic-callback-does-not-promote", {
    code: "SCHEMA_FIELD_INVALID",
    detail: "a no-op semantic callback cannot promote supplied-closure verification beyond its authenticated layer-two boundary",
    layer: 1,
    obligationTags: ["bundle:semantic-callback-does-not-promote"],
    operation: "validate-operation-mode",
    requirements: unionReq(req.fr04, req.fr06, req.fr09, req.nfr01, req.ac10, req.ac11),
    resultFamily: "bundle",
    stage: "configured-resource-preflight"
  });

  const operationEmitterSurfaces = ["metadata-encoder", "tree-ordered", "tree-sorted", "content-manifest", "bundle-ordered", "bundle-memory-encoder"];
  const emitterProductionConformanceId = (surface) => `mode-${surface}-production-conformance-${surface.startsWith("tree-") ? "feature" : "profile"}`;
  for (const surface of operationEmitterSurfaces) {
    for (const [suffix, description] of [
      ["selector-missing", "emitter operation is required"],
      ["selector-read", "read operation cannot emit new metadata"],
      ["selector-invalid", "unknown emitter operation is rejected"]
    ]) {
      modeReject(`mode-${surface}-${suffix}`, "SCHEMA_FIELD_INVALID", `mode:${surface}-${suffix}-rejected`,
        `${surface}: ${description} before input or output work`);
    }
    modeReject(`mode-${surface}-missing-registry`, "SCHEMA_FIELD_INVALID", `mode:${surface}-registry-required`,
      `${surface} requires a complete registry snapshot before input or output work`);
    modeReject(emitterProductionConformanceId(surface), "PROFILE_CONFORMANCE_ONLY",
      `mode:${surface}-production-conformance-rejected`,
      `production-write ${surface} rejects the conformance-only ${surface.startsWith("tree-") ? "required feature" : "profile"} embedded in its actual input`, 3);
    for (const variant of ["partial", "forged"]) {
      modeReject(`mode-${surface}-${variant}-registry`, "SCHEMA_FIELD_INVALID",
        `mode:${surface}-${variant}-registry-rejected`,
        `${surface} rejects a ${variant} registry authority before input or output work`);
    }
  }
  const semanticCodecSurfaces = ["tree-file", "metadata-decoder", "bundle-memory-verifier", "bundle-stream-verifier"];
  const codecLayerTwoSurfaces = ["tree-schema-decoder", "metadata-decoder", "bundle-memory-verifier", "bundle-stream-verifier"];
  const codecLifecycleId = (surface, suffix) => `mode-${surface}-${surface === "tree-file" ? "feature-" : ""}${suffix}`;
  for (const surface of semanticCodecSurfaces) {
    for (const [suffix, code, detail] of [
      ["deprecated-read-accept", undefined, "readable deprecated authority is accepted only by the explicit read operation"],
      ["conformance-read-rejected", "PROFILE_CONFORMANCE_ONLY", "conformance-only authority is not readable outside conformance execution"],
      ["conformance-accept", undefined, "conformance-only authority is accepted by explicit conformance execution"],
      ["deprecated-production-write-rejected", "PROFILE_STATE_FORBIDDEN", "deprecated authority cannot authorize new production bytes"],
      ["conformance-production-write-rejected", "PROFILE_CONFORMANCE_ONLY", "conformance-only authority cannot authorize new production bytes"]
    ]) {
      const id = codecLifecycleId(surface, suffix);
      const tag = `mode:${surface}-${surface === "tree-file" ? "feature-" : ""}${suffix}`;
      const carrier = surface === "tree-file" ? "required feature" : "profile";
      if (code) modeReject(id, code, tag, `${surface}: ${detail} through the ${carrier} embedded in the actual surface input`, 3);
      else addScenario(id, {
        detail: `${surface}: ${detail} through the ${carrier} embedded in the actual surface input`,
        layer: 3,
        obligationTags: [tag],
        operation: "validate-operation-mode",
        requirements: modeRequirements,
        resultFamily: surface.startsWith("bundle-") ? "bundle" : surface === "tree-file" ? "tree" : "repository"
      });
    }
    modeReject(`mode-${surface}-registry-operation-omitted`, "SCHEMA_FIELD_INVALID",
      `mode:${surface}-registry-operation-required`,
      `${surface} with a registry requires an explicit read, conformance, or production-write operation`);
    modeReject(`mode-${surface}-registry-operation-invalid`, "SCHEMA_FIELD_INVALID",
      `mode:${surface}-registry-operation-invalid-rejected`,
      `${surface} rejects an unknown registry operation before consuming input`);
    modeReject(`mode-${surface}-missing-registry`, "SCHEMA_FIELD_INVALID",
      `mode:${surface}-registry-required`,
      `${surface} semantic validation requires a complete registry snapshot before consuming input`);
    modeReject(`mode-${surface}-semantic-disabled`, "SCHEMA_FIELD_INVALID",
      `mode:${surface}-semantic-disabled-rejected`,
      `${surface} cannot claim layer-three success while registry semantics are disabled`);
    if (surface !== "tree-file") {
      addScenario(`mode-${surface}-registry-free-layer2`, {
        detail: `${surface} without a registry and with semantic validation disabled stops at layer two`,
        layer: 2,
        obligationTags: [`mode:${surface}-registry-free-layer2`],
        operation: "validate-operation-mode",
        requirements: modeRequirements,
        resultFamily: surface.startsWith("bundle-") ? "bundle" : "repository"
      });
      reject(`mode-${surface}-registry-free-wrong-family`, "SCHEMA_FIELD_INVALID",
        [`mode:${surface}-registry-free-wrong-family-rejected`],
        `${surface} preserves frozen profile-family checks at layer two even when registry semantics are disabled`,
        modeRequirements, "validate-operation-mode", 2);
    }
    const unknownAuthority = surface === "tree-file" ? "feature" : "profile";
    modeReject(`mode-${surface}-unknown-${unknownAuthority}`,
      surface === "tree-file" ? "REQUIRED_FEATURE_UNSUPPORTED" : "PROFILE_UNKNOWN",
      `mode:${surface}-unknown-${unknownAuthority}-rejected`,
      `${surface} rejects the unknown additive ${unknownAuthority} embedded in its actual input only after registry semantic lookup`, 3);
    for (const variant of ["partial", "forged"]) {
      modeReject(`mode-${surface}-${variant}-registry`, "SCHEMA_FIELD_INVALID",
        `mode:${surface}-${variant}-registry-rejected`,
        `${surface} rejects a ${variant} registry authority before consuming input`);
    }
  }
  addScenario("mode-tree-schema-decoder-registry-free-layer2", {
    detail: "the distinct decoded-tree schema reader may validate through known-schema layer two without registry semantics",
    layer: 2,
    obligationTags: ["mode:tree-schema-decoder-registry-free-layer2"],
    operation: "validate-operation-mode",
    requirements: modeRequirements,
    resultFamily: "tree"
  });
  reject("mode-tree-schema-decoder-registry-free-wrong-family", "SCHEMA_FIELD_INVALID",
    ["mode:tree-schema-decoder-registry-free-wrong-family-rejected"],
    "the registry-free decoded-tree schema reader preserves frozen profile-family checks at layer two",
    modeRequirements, "validate-operation-mode", 2);
  for (const surface of codecLayerTwoSurfaces) {
    modeReject(`mode-${surface}-authority-omitted`, "SCHEMA_FIELD_INVALID",
      `mode:${surface}-authority-omitted-rejected`,
      `${surface} must explicitly select semantic:false for registry-free layer two; omitting all authority is not a default`);
    modeReject(`mode-${surface}-semantic-false-with-registry`, "SCHEMA_FIELD_INVALID",
      `mode:${surface}-semantic-false-with-registry-rejected`,
      `${surface} rejects semantic:false when a registry authority is supplied`);
    modeReject(`mode-${surface}-semantic-false-with-operation`, "SCHEMA_FIELD_INVALID",
      `mode:${surface}-semantic-false-with-operation-rejected`,
      `${surface} rejects semantic:false when a lifecycle operation is supplied`);
  }

  for (const [suffix, profileField] of [
    ["unknown-group-profile", "groupProfile"],
    ["unknown-role-profile", "roleProfile"],
    ["unknown-external-key-profile", "externalKeyProfile"]
  ]) {
    addScenario(`group-standalone-${suffix}`, {
      code: "PROFILE_UNKNOWN",
      detail: `standalone asset-group validation rejects an unregistered ${profileField} before group rules`,
      layer: 3,
      obligationTags: [`group:standalone-${suffix}`],
      operation: "validate-operation-mode",
      requirements: modeRequirements
    });
  }
  for (const [suffix, profileField, profileValue] of [
    ["wrong-family-group-profile", "groupProfile", "content-policy.test/opaque@1"],
    ["wrong-family-role-profile", "roleProfile", "group.test/opaque@1"],
    ["wrong-family-external-key-profile", "externalKeyProfile", "group-role.test/member@1"]
  ]) {
    addScenario(`group-standalone-${suffix}`, {
      code: "SCHEMA_FIELD_INVALID",
      detail: `standalone asset-group validation rejects a ${profileField} from the wrong registered family before group rules`,
      layer: 2,
      obligationTags: [`group:standalone-${suffix}`],
      operation: "validate-operation-mode",
      requirements: modeRequirements
    });
  }
  addScenario("repository-lookup-zero-time", {
    code: "LIMIT_TIME",
    detail: "an empty repository object lookup with configured maxTimeMs zero fails at its entry checkpoint",
    layer: 1,
    obligationTags: ["limits:repository-lookup-zero-time"],
    operation: "validate-operation-mode",
    requirements: unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08)
  });
  addScenario("tree-groups-combined-memory", {
    code: "LIMIT_MEMORY",
    detail: "internal repository validation reserves the simultaneous expanded tree, group set, and membership/collision indexes before replay",
    layer: 1,
    obligationTags: ["limits:tree-groups-combined-memory"],
    operation: "validate-tree-groups-memory",
    requirements: unionReq(req.fr09, req.nfr01, req.nfr04, req.ac08)
  });
  for (const [suffix, cluster, detail] of [
    ["replay-base", "replay-base", "replay reserves the caller-owned base state before clone or mutation"],
    ["fileid-lifetime-import-indexes", "fileid-lifetime-import-indexes", "lifetime records, working additions, import mappings, and retained lookup indexes share one bounded reservation"],
    ["graph-workspace-indexes", "graph-workspace-indexes", "snapshot, provenance, ancestry, shelf, and abstract-graph traversal indexes share one bounded workspace"],
    ["conflict-group-indexes", "conflict-group-indexes", "conflict and asset-group cardinality and membership indexes are reserved before construction"],
    ["many-invalid-error-selection", "many-invalid-error-selection", "whole-lookup error selection retains only a bounded ranked candidate and remains reusable after failure"]
  ]) {
    addScenario(`resource-${suffix}-memory`, {
      code: "LIMIT_MEMORY",
      detail,
      layer: 1,
      obligationTags: [`limits:${suffix}-memory`],
      operation: "validate-resource-reservation",
      requirements: unionReq(req.fr04, req.fr06, req.fr09, req.nfr01, req.nfr04, req.ac08)
    });
  }
  addScenario("resource-import-request-many-mappings-deadline", {
    code: "LIMIT_TIME",
    detail: "bounded many-mapping import validation checkpoints its retained index and expires before the final lookup without scanning, mutation, or reuse failure",
    layer: 1,
    obligationTags: ["limits:import-request-many-mappings-deadline"],
    operation: "validate-resource-reservation",
    requirements: unionReq(req.fr04, req.fr06, req.fr09, req.nfr01, req.nfr04, req.ac08)
  });

  accept("mutation-systematic-single-bit", ["mutation:single-bit", "hash:tamper"], "execute every single-bit recipe over all small objects, records, item shapes and sequence", unionReq(req.fr09, req.ac03), "canonical-scan", "mutation");
  accept("truncation-every-prefix", ["truncation:every-prefix"], "execute every proper-prefix recipe with item-boundary precedence", unionReq(req.fr09, req.ac08), "canonical-scan", "mutation");
  reject("hash-tampered-object", "OBJECT_ID_MISMATCH", ["hash:tamper"], "canonical payload byte mutation under original ObjectRef", unionReq(req.fr09, req.ac03), "canonical-scan", 1);
  accept("malformed-complete-corpus", ["malformed:complete"], "execute all deterministic-CBOR malformed artifacts", unionReq(req.fr09, req.ac08), "canonical-scan", "mutation");

  for (const [id, code, detail] of [
    ["registry-duplicate", "REGISTRY_INVALID", "duplicate numeric assignment"],
    ["registry-reassigned", "REGISTRY_INVALID", "same numeric assignment with changed meaning"],
    ["registry-invalid-entry", "REGISTRY_INVALID", "invalid grammar/state/cross-reference"],
    ["registry-reserved", "PROFILE_STATE_FORBIDDEN", "reserved profile read or write"],
    ["registry-deprecated-write", "PROFILE_STATE_FORBIDDEN", "deprecated profile selected for new production write"],
    ["registry-conformance-production", "PROFILE_CONFORMANCE_ONLY", "conformance-only profile in production"],
    ["registry-unknown-profile", "PROFILE_UNKNOWN", "unknown required profile"],
    ["registry-unknown-feature", "REQUIRED_FEATURE_UNSUPPORTED", "old registry semantically rejects unsupported required feature"]
  ]) reject(id, code, [`registry:${id.slice(9)}`], detail, unionReq(req.fr09, req.ac11), "validate-object");
  accept("registry-ratified-read-write", ["registry:ratified"], "ratified profile supports read and new write", unionReq(req.fr09, req.ac11), "validate-object", "registry");
  accept("registry-deprecated-read", ["registry:deprecated-read"], "deprecated profile remains readable", unionReq(req.fr09, req.ac11), "validate-object", "registry");
  accept("registry-conformance-mode", ["registry:conformance"], "conformance-only profile accepted in conformance mode", unionReq(req.fr09, req.ac11), "validate-object", "registry");
  accept("registry-unknown-feature-forward", ["registry:unknown-feature-forward"], "old codec canonical-scans rehashes and byte-preserves unsupported-required-feature object", unionReq(req.fr09, req.ac11), "canonical-scan", "registry");
  accept("registry-unknown-extension-preserve", ["registry:unknown-extension-preserve"], "unknown optional extension survives lossless round trip byte-for-byte", unionReq(req.fr09, req.ac11), "validate-object", "registry");

  const fixtureAdapterCases = new Map([
    ["error-fixture-schema-unsupported", {
      adapter: { postGenerationMutation: { type: "request-profile-version", value: "1.0.0" } },
      expectedCode: "FIXTURE_SCHEMA_UNSUPPORTED"
    }],
    ["error-fixture-semantic-invalid", {
      adapter: { verifierResult: "semantic-invalid" },
      expectedCode: "FIXTURE_SEMANTIC_INVALID"
    }],
    ["error-fixture-mapping-missing", {
      adapter: { persistLedger: "omit" },
      expectedCode: "FIXTURE_MAPPING_MISSING"
    }],
    ["error-fixture-content-unavailable", {
      adapter: { persistLedger: "memory" },
      expectedCode: "FIXTURE_CONTENT_UNAVAILABLE",
      materialization: "index-only"
    }],
    ["error-fixture-native-binding-missing", {
      adapter: { persistLedger: "memory", requireNativeHistoryBindings: true },
      expectedCode: "FIXTURE_NATIVE_BINDING_MISSING"
    }]
  ].map(([id, recipe]) => [id, {
    adapter: {
      allocation: "incrementing-nonzero-128-bit",
      persistLedger: "memory",
      targetConsumption: "always-available",
      ...recipe.adapter
    },
    expectedCode: recipe.expectedCode,
    generatorRequest: {
      destination: `fixture-adapter/${id}`,
      extensions: {
        "generation.large-file-mode": "virtual",
        "generation.materialization": recipe.materialization ?? "full"
      },
      profile: { id: "code-heavy", version: "2.0.0" },
      scale: { historyOperationCount: 8, largeFileBytes: 0, maxDepth: 5, pathCount: 6 },
      seed: `ogvcs-002-${id}`
    },
    schema: "ogvcs.repository-format.v1.fixture-adapter-invocation.v1"
  }]));
  for (const [id, recipe] of fixtureAdapterCases) {
    addScenario(id, {
      code: recipe.expectedCode,
      detail: `execute the public fixture adapter and reject with ${recipe.expectedCode}`,
      implementationScope: ["javascript"],
      layer: 3,
      obligationTags: [`error:${recipe.expectedCode}`, `fixture-adapter:${id.slice("error-fixture-".length)}`],
      operation: "adapt-fixture",
      requirements: unionReq(req.fr09, req.ac04)
    });
  }

  for (const limit of limits) {
    addScenario(`limit-${limit.name}-max`, {
      detail: `execute ${limit.name} maximum virtual constructor`,
      layer: limit.name.startsWith("bundle-") ? 1 : 2,
      obligationTags: [`limit:${limit.name}:max`, "limits:all"],
      operation: limit.name.startsWith("bundle-") ? "validate-bundle" : "validate-object",
      requirements: unionReq(req.fr09, req.ac08),
      resultFamily: "limit"
    });
    reject(`limit-${limit.name}-max-plus-one`, limit.errorCode, [`limit:${limit.name}:max-plus-one`, "limits:all"], `execute ${limit.name} maximum-plus-one virtual constructor`, unionReq(req.fr09, req.ac08), limit.name.startsWith("bundle-") ? "validate-bundle" : "validate-object", layerTwoLimits.has(limit.name) ? 2 : 1);
  }

  // Representative resource-interaction rows supplement rather than replace
  // the one-code-at-a-time stable-error authority below.
  const supplementalErrorCases = new Set([
    "repository-lookup-zero-time", "tree-groups-combined-memory",
    "resource-replay-base-memory", "resource-fileid-lifetime-import-indexes-memory",
    "resource-graph-workspace-indexes-memory", "resource-conflict-group-indexes-memory",
    "resource-many-invalid-error-selection-memory", "resource-import-request-many-mappings-deadline",
    "resource-lookup-edge-counter-rollback", "resource-lookup-scratch-counter-rollback",
    "resource-tree-stream-transaction-composite-memory",
    "lookup-validate-all-known-schema-before-profile-lifecycle-forward",
    "lookup-validate-all-known-schema-before-profile-lifecycle-reverse",
    "fileid-lifetime-first-change-missing",
    "fileid-lifetime-first-change-wrong-kind",
    "fileid-lifetime-first-change-object-id-mismatch",
    "fileid-lifetime-first-change-bad-schema",
    "fileid-lifetime-first-change-profile-lifecycle",
    "mode-tree-file-known-schema-before-order-forward",
    "mode-tree-file-known-schema-before-order-reverse",
    "bundle-visitor-nested-map-key-capture-memory",
    "logical-record-lifetime-extra-field-22",
    "logical-record-lifetime-extra-field-999",
    "logical-record-import-mapping-extra-field-22",
    "logical-record-import-mapping-extra-field-999",
    "unicode-age-frozen-unassigned", "unicode-age-newer-canonical",
    "unicode-age-newer-composition-pair", "unicode-age-newer-decomposed"
  ]);
  const coveredCodes = new Set(scenarioCases
    .filter((item) => item.code && !supplementalErrorCases.has(item.id))
    .map((item) => item.code));
  const isolatedErrorAuthority = new Map([
    ["CBOR_TRUNCATED", ["canonical-scan", 1]],
    ["CBOR_NON_CANONICAL", ["canonical-scan", 1]],
    ["CBOR_TRAILING_BYTES", ["canonical-scan", 1]],
    ["SCHEMA_FIELD_UNKNOWN", ["validate-object", 2]],
    ["LIMIT_MEMORY", ["validate-bundle", 1]],
    ["LIMIT_SCRATCH", ["validate-bundle", 1]],
    ["LIMIT_TIME", ["validate-bundle", 1]],
    ["OBJECT_REFERENCE_FORMAT_UNSUPPORTED", ["validate-object", 2]],
    ["REPOSITORY_DESCRIPTOR_MISMATCH", ["validate-object", 3]],
    ["OBJECT_KIND_UNSUPPORTED", ["validate-object", 2]],
    ["EXTENSION_KEY_INVALID", ["validate-object", 2]],
    ["LOGICAL_RECORD_TYPE_UNSUPPORTED", ["validate-bundle", 2]],
    ["CHANGESET_TRANSITION_INVALID", ["replay-change-set", 3]],
    ["FILEID_ENTROPY_UNAVAILABLE", ["allocate-file-id", 3]],
    ["FILEID_ALLOCATION_EXHAUSTED", ["allocate-file-id", 3]],
    ["FILEID_LIFETIME_EVIDENCE_INVALID", ["validate-repository", 3]],
    ["CONFLICT_SUBJECT_INVALID", ["validate-repository", 3]],
  ]);
  for (const error of errors) {
    if (coveredCodes.has(error.code)) continue;
    const authority = isolatedErrorAuthority.get(error.code);
    assert(authority, `missing explicit isolated error authority for ${error.code}`);
    const [operation, layer] = authority;
    reject(`error-${error.code.toLowerCase().replaceAll("_", "-")}`, error.code, [`error:${error.code}`], `isolated stable error constructor for ${error.code}`, req.fr09, operation, layer);
  }
  assert.deepEqual(
    [...isolatedErrorAuthority.keys()].sort(),
    errors.filter((error) => !coveredCodes.has(error.code)).map((error) => error.code).sort(),
    "isolated error authority must exactly cover otherwise-unrepresented stable codes"
  );

  const configuredResourceCases = new Map([
    ["bundle-transcript-max-bytes-budget", {
      api: "create-bundle-transcript-hash-writer",
      limits: { maxBytes: 1 },
      source: "logical-bundles/valid-supplied-closure.cborseq"
    }],
    ["bundle-visitor-max-item-budget", {
      api: "visit-logical-bundle",
      limits: { maxItemBytes: 1 },
      source: "logical-bundles/valid-supplied-closure.cborseq"
    }],
    ["bundle-visitor-max-items-budget", {
      api: "visit-logical-bundle",
      limits: { maxItems: 1 },
      source: "logical-bundles/valid-supplied-closure.cborseq"
    }],
    ["bundle-visitor-nested-map-key-capture-memory", {
      api: "visit-logical-bundle",
      captureWorkspace: {
        depth: nestedCaptureDepth,
        derivation: "one-byte-below-active-and-retained-canonical-key-capacity-v1",
        eachKeyAloneFits: true,
        growth: "initial-64-double-to-required-v1"
      },
      limits: {
        maxCaptureBytes: nestedCaptureDepth * nestedCaptureInitialBytes - 1,
        maxNesting: nestedCaptureDepth + 2,
        maxValueBytes: nestedCaptureInitialBytes
      },
      source: nestedCaptureBundlePath
    }],
    ["error-limit-memory", {
      api: "verify-logical-bundle-stream",
      limits: { maxMemoryBytes: 1 },
      source: "logical-bundles/valid-supplied-closure.cborseq"
    }],
    ["error-limit-scratch", {
      api: "verify-logical-bundle-stream",
      limits: { maxMemoryBytes: 67_108_864, maxScratchBytes: 0 },
      source: "logical-bundles/valid-supplied-closure.cborseq"
    }],
    ["error-limit-time", {
      api: "verify-logical-bundle-stream",
      limits: { maxTimeMs: 0 },
      source: "logical-bundles/valid-supplied-closure.cborseq"
    }]
  ]);
  const manifestWriterPart = {
    chunk: objectText("chunk", chunkId),
    length: String(chunk.length)
  };
  const manifestWriterCases = new Map([
    ["manifest-writer-too-few-parts", {
      api: "write-content-manifest",
      chunkArtifact: "objects/01-chunk.bin",
      chunkProfile: "chunking.test/external-boundaries@1",
      declaredParts: "2",
      logicalLength: String(chunk.length),
      maxItems: 2,
      operation: "conformance",
      parts: [manifestWriterPart],
      registry: "bundled",
      schema: "ogvcs.repository-format.v1.manifest-writer-input.v1",
      wholeFileSha256: hex(sha256(chunk))
    }],
    ["manifest-writer-too-many-parts", {
      api: "write-content-manifest",
      chunkArtifact: "objects/01-chunk.bin",
      chunkProfile: "chunking.test/external-boundaries@1",
      declaredParts: "1",
      logicalLength: String(repeatedBytes.length),
      maxItems: 2,
      operation: "conformance",
      parts: [manifestWriterPart, manifestWriterPart],
      registry: "bundled",
      schema: "ogvcs.repository-format.v1.manifest-writer-input.v1",
      wholeFileSha256: hex(sha256(repeatedBytes))
    }]
  ]);
  manifestWriterCases.set("manifest-writer-count-before-profile-lifecycle", {
    ...manifestWriterCases.get("manifest-writer-too-many-parts"),
    chunkProfile: "profile-state.test/chunking-conformance@1",
    operation: "production-write",
    outputDisposition: {
      orderedStagingSink: "aborted-discard",
      successCommit: false
    },
    registryFixture: {
      path: "registries/index.json",
      scenarioId: "registry-conformance-production"
    }
  });
  manifestWriterCases.set("manifest-writer-limit-before-count-and-profile-lifecycle", {
    ...manifestWriterCases.get("manifest-writer-count-before-profile-lifecycle"),
    maxItems: 1
  });
  manifestWriterCases.set("manifest-writer-object-id-before-profile-lifecycle", {
    ...manifestWriterCases.get("manifest-writer-too-few-parts"),
    chunkArtifact: lifecycleChunkIdentityMismatchSource,
    chunkProfile: "profile-state.test/chunking-conformance@1",
    declaredParts: "1",
    maxItems: 1,
    operation: "production-write",
    outputDisposition: {
      orderedStagingSink: "aborted-discard",
      successCommit: false
    },
    registryFixture: {
      path: "registries/index.json",
      scenarioId: "registry-conformance-production"
    },
    wholeFileSha256: hex(sha256(lifecycleChunkIdentityMismatch))
  });
  const manifestWriterLengthFaultPart = { ...manifestWriterPart, length: "11" };
  const manifestWriterWrongKindPart = {
    chunk: objectText("content-manifest", manifestId),
    length: String(chunk.length)
  };
  for (const order of ["forward", "reverse"]) {
    manifestWriterCases.set(`manifest-writer-known-schema-before-chunk-length-${order}`, {
      ...manifestWriterCases.get("manifest-writer-too-many-parts"),
      declaredParts: "2",
      logicalLength: "23",
      outputDisposition: {
        orderedStagingSink: "aborted-discard",
        successCommit: false
      },
      parts: order === "forward"
        ? [manifestWriterLengthFaultPart, manifestWriterWrongKindPart]
        : [manifestWriterWrongKindPart, manifestWriterLengthFaultPart]
    });
  }
  const manifestProviderShortPart = {
    chunk: objectText("chunk", objectDigest(1, manifestProviderCorrectOne)),
    length: String(manifestProviderCorrectOne.length)
  };
  const manifestProviderWrongPart = {
    chunk: objectText("chunk", objectDigest(1, manifestProviderCorrectTwo)),
    length: String(manifestProviderCorrectTwo.length)
  };
  for (const order of ["forward", "reverse"]) {
    const parts = order === "forward"
      ? [manifestProviderShortPart, manifestProviderWrongPart]
      : [manifestProviderWrongPart, manifestProviderShortPart];
    const declaredBytes = order === "forward"
      ? Buffer.concat([manifestProviderCorrectOne, manifestProviderCorrectTwo])
      : Buffer.concat([manifestProviderCorrectTwo, manifestProviderCorrectOne]);
    manifestWriterCases.set(`manifest-writer-content-object-id-before-chunk-length-${order}`, {
      ...manifestWriterCases.get("manifest-writer-too-many-parts"),
      chunkArtifact: undefined,
      declaredParts: "2",
      logicalLength: String(declaredBytes.length),
      outputDisposition: {
        orderedStagingSink: "aborted-discard",
        successCommit: false
      },
      parts,
      chunkArtifacts: order === "forward"
        ? [manifestProviderShortSource, manifestProviderWrongSource]
        : [manifestProviderWrongSource, manifestProviderShortSource],
      wholeFileSha256: hex(sha256(declaredBytes))
    });
    delete manifestWriterCases.get(`manifest-writer-content-object-id-before-chunk-length-${order}`).chunkArtifact;
  }
  manifestWriterCases.set("manifest-writer-limit-before-kind", {
    ...manifestWriterCases.get("manifest-writer-too-many-parts"),
    declaredParts: "2",
    maxItems: 1,
    outputDisposition: {
      orderedStagingSink: "aborted-discard",
      successCommit: false
    },
    parts: [manifestWriterWrongKindPart, manifestWriterPart]
  });
  for (const order of ["forward", "reverse"]) {
    manifestWriterCases.set(`manifest-writer-count-before-kind-${order}`, {
      ...manifestWriterCases.get("manifest-writer-too-many-parts"),
      outputDisposition: {
        orderedStagingSink: "aborted-discard",
        successCommit: false
      },
      parts: order === "forward"
        ? [manifestWriterPart, manifestWriterWrongKindPart]
        : [manifestWriterWrongKindPart, manifestWriterPart]
    });
  }
  const treeWriterEntries = [0x21, 0x22].map((fill, index) => ({
    contentPolicy: "content-policy.test/opaque@1",
    fileId: hex(id128(fill)),
    kind: 2,
    logicalSize: String(repeatedBytes.length),
    mode: 2,
    name: index === 0 ? "a" : "b",
    target: objectText("content-manifest", manifestId)
  }));
  const treeWriterCases = new Map([
    ["tree-writer-ordered-too-many-entries", {
      api: "write-tree",
      descriptor: objectText("repository-descriptor", descriptorId),
      entries: treeWriterEntries,
      entryCount: "1",
      maxItems: 2,
      operation: "conformance",
      ordering: "ordered",
      registry: "bundled",
      schema: "ogvcs.repository-format.v1.tree-writer-input.v1"
    }],
    ["tree-writer-sorted-too-many-entries", {
      api: "write-tree",
      descriptor: objectText("repository-descriptor", descriptorId),
      entries: [...treeWriterEntries].reverse(),
      entryCount: "1",
      maxItems: 2,
      operation: "conformance",
      ordering: "sorted",
      registry: "bundled",
      schema: "ogvcs.repository-format.v1.tree-writer-input.v1"
    }]
  ]);
  treeWriterCases.set("tree-writer-ordered-count-before-feature-lifecycle", {
    ...treeWriterCases.get("tree-writer-ordered-too-many-entries"),
    operation: "production-write",
    outputDisposition: {
      orderedStagingSink: "aborted-discard",
      successCommit: false
    },
    registryFixture: {
      path: "registries/index.json",
      scenarioId: "registry-conformance-production"
    },
    requiredFeatures: [1]
  });
  treeWriterCases.set("tree-writer-sorted-count-before-feature-lifecycle", {
    ...treeWriterCases.get("tree-writer-sorted-too-many-entries"),
    operation: "production-write",
    outputDisposition: {
      orderedStagingSink: "aborted-discard",
      successCommit: false
    },
    registryFixture: {
      path: "registries/index.json",
      scenarioId: "registry-conformance-production"
    },
    requiredFeatures: [1]
  });
  const firstEntryContentConformance = (entries) => entries.map((entry, index) =>
    index === 0 ? { ...entry, contentPolicy: "profile-state.test/content-conformance@1" } : entry);
  treeWriterCases.set("tree-writer-ordered-count-before-entry-profile-lifecycle", {
    ...treeWriterCases.get("tree-writer-ordered-too-many-entries"),
    entries: firstEntryContentConformance(treeWriterCases.get("tree-writer-ordered-too-many-entries").entries),
    operation: "production-write",
    outputDisposition: {
      orderedStagingSink: "aborted-discard",
      successCommit: false
    },
    registryFixture: {
      path: "registries/index.json",
      scenarioId: "registry-conformance-production"
    }
  });
  treeWriterCases.set("tree-writer-sorted-count-before-entry-profile-lifecycle", {
    ...treeWriterCases.get("tree-writer-sorted-too-many-entries"),
    entries: firstEntryContentConformance(treeWriterCases.get("tree-writer-sorted-too-many-entries").entries),
    operation: "production-write",
    outputDisposition: {
      orderedStagingSink: "aborted-discard",
      successCommit: false
    },
    registryFixture: {
      path: "registries/index.json",
      scenarioId: "registry-conformance-production"
    }
  });
  const duplicateTreeWriterFileId = (entries) => entries.map((entry) =>
    ({ ...entry, fileId: hex(id128(0x21)) }));
  treeWriterCases.set("tree-writer-ordered-count-before-duplicate-fileid", {
    ...treeWriterCases.get("tree-writer-ordered-too-many-entries"),
    entries: duplicateTreeWriterFileId(treeWriterCases.get("tree-writer-ordered-too-many-entries").entries),
    outputDisposition: {
      orderedStagingSink: "aborted-discard",
      successCommit: false
    }
  });
  treeWriterCases.set("tree-writer-sorted-count-before-duplicate-fileid", {
    ...treeWriterCases.get("tree-writer-sorted-too-many-entries"),
    entries: duplicateTreeWriterFileId(treeWriterCases.get("tree-writer-sorted-too-many-entries").entries),
    outputDisposition: {
      orderedStagingSink: "aborted-discard",
      successCommit: false
    }
  });
  treeWriterCases.set("tree-writer-ordered-limit-before-count-and-feature-lifecycle", {
    ...treeWriterCases.get("tree-writer-ordered-count-before-feature-lifecycle"),
    maxItems: 1
  });
  treeWriterCases.set("tree-writer-sorted-limit-before-count-and-feature-lifecycle", {
    ...treeWriterCases.get("tree-writer-sorted-count-before-feature-lifecycle"),
    maxItems: 1
  });
  treeWriterCases.set("tree-writer-ordered-limit-before-kind", {
    ...treeWriterCases.get("tree-writer-ordered-too-many-entries"),
    entries: [
      { ...treeWriterEntries[0], target: objectText("tree", treeId) },
      treeWriterEntries[1]
    ],
    entryCount: "2",
    maxItems: 1,
    outputDisposition: {
      orderedStagingSink: "aborted-discard",
      successCommit: false
    }
  });
  const treeWriterPrecedenceEntry = (name, fill, target = objectText("content-manifest", manifestId)) => ({
    contentPolicy: "content-policy.test/opaque@1",
    fileId: hex(id128(fill)),
    kind: 2,
    logicalSize: String(repeatedBytes.length),
    mode: 2,
    name,
    target
  });
  for (const order of ["forward", "reverse"]) {
    treeWriterCases.set(`tree-writer-ordered-kind-before-order-${order}`, {
      ...treeWriterCases.get("tree-writer-ordered-too-many-entries"),
      entries: order === "forward" ? [
        treeWriterPrecedenceEntry("b", 0x31),
        treeWriterPrecedenceEntry("a", 0x32),
        treeWriterPrecedenceEntry("c", 0x33, objectText("tree", treeId))
      ] : [
        treeWriterPrecedenceEntry("a", 0x31, objectText("tree", treeId)),
        treeWriterPrecedenceEntry("c", 0x32),
        treeWriterPrecedenceEntry("b", 0x33)
      ],
      entryCount: "3",
      maxItems: 3,
      outputDisposition: {
        orderedStagingSink: "aborted-discard",
        successCommit: false
      }
    });
  }
  for (const order of ["forward", "reverse"]) {
    const familyFault = {
      ...treeWriterEntries[0],
      contentPolicy: "path.test/opaque@1",
      name: order === "forward" ? "a" : "b"
    };
    const kindFault = {
      ...treeWriterEntries[1],
      name: order === "forward" ? "b" : "a",
      target: objectText("tree", treeId)
    };
    treeWriterCases.set(`tree-writer-sorted-family-before-kind-${order}`, {
      ...treeWriterCases.get("tree-writer-sorted-too-many-entries"),
      entries: order === "forward" ? [familyFault, kindFault] : [kindFault, familyFault],
      entryCount: "2",
      maxItems: 2,
      outputDisposition: {
        orderedStagingSink: "aborted-discard",
        successCommit: false
      }
    });
  }
  const bundleWriterCommon = {
    api: "write-logical-bundle",
    maxMemoryBytes: 67_108_864,
    operation: "conformance",
    outputDisposition: {
      inMemoryResult: "absent",
      orderedStagingSink: "aborted-discard",
      successCommit: false
    },
    plan: {
      budget: {
        indexEntries: 2,
        largestItemBytes: 10_000,
        sequenceBytes: 100_000,
        traversalEdges: 100
      },
      logicalRecordCount: 0,
      objectCount: 2,
      rootCount: 0
    },
    registry: "bundled",
    schema: "ogvcs.repository-format.v1.logical-bundle-writer-input.v1",
    source: "logical-bundles/valid-all-families.cborseq",
    writerSurfaces: ["bundle-memory-encoder", "bundle-ordered"]
  };
  const bundleWriterCases = new Map([
    ["bundle-writer-sequence-before-object-id", {
      ...bundleWriterCommon,
      objectMutations: [
        { outputOrdinal: 0, sourceOrdinal: 2 },
        { outputOrdinal: 1, replaceDeclaredDigest: "00".repeat(32), sourceOrdinal: 1 }
      ]
    }],
    ["bundle-writer-object-id-before-unknown-kind", {
      ...bundleWriterCommon,
      objectMutations: [{
        allowUnknownKind: true,
        outputOrdinal: 0,
        replaceDeclaredDigest: "00".repeat(32),
        replaceKind: 65_535,
        sourceOrdinal: 1
      }],
      plan: {
        ...bundleWriterCommon.plan,
        budget: { ...bundleWriterCommon.plan.budget, indexEntries: 1 },
        objectCount: 1
      }
    }],
    ["bundle-writer-object-id-before-feature-lifecycle", {
      ...bundleWriterCommon,
      objectMutations: [{
        kind: 3,
        outputOrdinal: 0,
        replaceDeclaredDigest: "00".repeat(32),
        sourceArtifact: "lifecycle/tree-feature-conformance.cbor"
      }],
      operation: "production-write",
      plan: {
        ...bundleWriterCommon.plan,
        budget: { ...bundleWriterCommon.plan.budget, indexEntries: 1 },
        objectCount: 1
      },
      registryFixture: {
        path: "registries/index.json",
        scenarioId: "registry-conformance-production"
      }
    }]
  ]);
  const bundleWriterProduction = {
    operation: "production-write",
    registryFixture: {
      path: "registries/index.json",
      scenarioId: "registry-conformance-production"
    }
  };
  for (const order of ["forward", "reverse"]) {
    const featureObject = {
      kind: 3,
      outputOrdinal: order === "forward" ? 0 : 1,
      sourceArtifact: "lifecycle/tree-feature-conformance.cbor"
    };
    const identityFault = order === "forward" ? {
      kind: 4,
      outputOrdinal: 1,
      replaceDeclaredDigest: "00".repeat(32),
      sourceArtifact: "objects/04-change-set.cbor"
    } : {
      kind: 2,
      outputOrdinal: 0,
      replaceDeclaredDigest: "00".repeat(32),
      sourceArtifact: "objects/02-content-manifest.cbor"
    };
    bundleWriterCases.set(`bundle-writer-section-object-id-before-feature-lifecycle-${order}`, {
      ...bundleWriterCommon,
      ...bundleWriterProduction,
      objectMutations: order === "forward"
        ? [featureObject, identityFault]
        : [identityFault, featureObject]
    });
    const conformanceRoot = order === "forward" ? {
      identity: objectText("tree", treeId),
      kind: 1,
      roleProfile: "bundle-role.test/root@1"
    } : {
      identity: objectText("content-manifest", manifestId),
      kind: 1,
      roleProfile: "bundle-role.test/root@1"
    };
    const ratifiedRoot = order === "forward" ? {
      identity: objectText("content-manifest", manifestId),
      kind: 1,
      roleProfile: "profile-state.test/bundle-root-ratified@1"
    } : {
      identity: objectText("tree", treeId),
      kind: 1,
      roleProfile: "profile-state.test/bundle-root-ratified@1"
    };
    bundleWriterCases.set(`bundle-writer-section-root-order-before-role-lifecycle-${order}`, {
      ...bundleWriterCommon,
      ...bundleWriterProduction,
      objectMutations: [
        { outputOrdinal: 0, sourceOrdinal: 1 },
        { outputOrdinal: 1, sourceOrdinal: 2 }
      ],
      plan: { ...bundleWriterCommon.plan, rootCount: 2 },
      rootInputs: order === "forward"
        ? [conformanceRoot, ratifiedRoot]
        : [ratifiedRoot, conformanceRoot]
    });
    const logicalRecordInputs = (order === "forward" ? [
      logicalWriterInvalidSource,
      "logical-records/09-fixture-event.cbor",
      "logical-records/07-lock-reference.cbor"
    ] : [
      "logical-records/09-fixture-event.cbor",
      "logical-records/07-lock-reference.cbor",
      logicalWriterInvalidSource
    ]).map((sourceArtifact, outputOrdinal) => ({ outputOrdinal, sourceArtifact }));
    bundleWriterCases.set(`bundle-writer-section-sequence-before-logical-schema-${order}`, {
      ...bundleWriterCommon,
      logicalRecordInputs,
      objectMutations: [],
      plan: {
        ...bundleWriterCommon.plan,
        budget: { ...bundleWriterCommon.plan.budget, indexEntries: 3 },
        logicalRecordCount: 3,
        objectCount: 0
      }
    });
  }
  const operationModeCases = new Map();
  const operationModeSchema = "ogvcs.repository-format.v1.operation-mode-input.v1";
  const bundleSource = "logical-bundles/valid-supplied-closure.cborseq";
  const operationModeDescriptor = objectText("repository-descriptor", descriptorId);
  const operationModeSnapshot = objectText("snapshot", snapshotId);
  const operationModeTree = objectText("tree", treeId);
  const operationModeManifest = objectText("content-manifest", manifestId);
  const baseRootWorkingLifetimeAdditions = rootStates.map((value, firstOperation) => ({
    fileId: hex(value.get(2)),
    firstChangeSet: objectText("change-set", changeId),
    firstOperation,
    origin: "native-create"
  }));
  const sourceForSurface = (surface) => {
    if (surface.startsWith("bundle-")) return bundleSource;
    if (["manifest-verify", "content-manifest"].includes(surface)) return "objects/02-content-manifest.cbor";
    if (["tree-expand", "tree-ordered", "tree-sorted", "tree-file", "tree-schema-decoder", "metadata-encoder", "metadata-decoder"].includes(surface)) return "objects/03-tree.cbor";
    if (["repository-candidate", "import-request", "repository-lookup-layer2"].includes(surface)) return "objects/07-snapshot.cbor";
    return undefined;
  };
  const repositoryRouteCarrier = (surface) => {
    const shared = {
      objectLookup: "scenario.context.objectLookup",
      repositoryDescriptor: operationModeDescriptor
    };
    if (surface === "repository-candidate") return {
      ...shared,
      candidateSnapshot: operationModeSnapshot,
      designatedRoot: operationModeSnapshot,
      lifetimeContext: {
        importMappings: [],
        lifetimeRecords: [],
        workingLifetimeAdditions: baseRootWorkingLifetimeAdditions
      }
    };
    if (surface === "import-request") return {
      ...shared,
      importContext: {
        importMappings: [],
        lifetimeRecords: [],
        workingLifetimeAdditions: []
      },
      importRequest: {
        importerProfile: "importer.test/fixture-adapter@1",
        requestedFileId: hex(id128(0x77)),
        sourceIdentityDigest: hex(digest(0x72)),
        sourceNamespaceDigest: hex(digest(0x71))
      }
    };
    if (surface === "tree-expand") return { ...shared, tree: operationModeTree };
    if (surface === "manifest-verify") return { ...shared, manifest: operationModeManifest };
    if (surface === "tree-file") return shared;
    if (surface === "asset-groups") return shared;
    return {};
  };
  const baseModeRequest = (surface, extra = {}) => ({
    api: "validate-operation-mode",
    registry: "bundled",
    schema: operationModeSchema,
    ...(sourceForSurface(surface) ? { source: sourceForSurface(surface) } : {}),
    surface,
    ...repositoryRouteCarrier(surface),
    ...(surface === "tree-expand" ? { caseMode: "case-sensitive" } : {}),
    ...extra
  });
  const authorityOmittedRequest = (surface) => {
    const request = baseModeRequest(surface, { source: "malformed/nonminimal-unsigned.cbor" });
    delete request.registry;
    return request;
  };
  const lifecycleProfileCarrier = (surface, profileText) => {
    const artifact = lifecycleDescriptors.get(profileText);
    assert(artifact, `${surface}: missing lifecycle descriptor for ${profileText}`);
    return {
      expectedProfileFamily: "path",
      objectRef: artifact.objectRef,
      profile: profileText,
      source: surface.startsWith("bundle-") ? artifact.bundleSource : artifact.descriptorSource
    };
  };
  const lifecycleFeatureCarrier = (feature) => {
    const artifact = lifecycleTrees.get(feature);
    assert(artifact, `missing lifecycle tree for required feature ${feature}`);
    return { requiredFeatures: artifact.requiredFeatures, source: artifact.source };
  };
  const emitterLifecycleCarrier = (surface) => {
    if (surface === "metadata-encoder") {
      return lifecycleProfileCarrier(surface, "profile-state.test/conformance@1");
    }
    if (surface === "tree-ordered" || surface === "tree-sorted") {
      return lifecycleFeatureCarrier(1);
    }
    if (surface === "content-manifest") {
      return {
        expectedProfileFamily: "chunking",
        profile: "profile-state.test/chunking-conformance@1",
        source: lifecycleManifestSource
      };
    }
    if (surface === "bundle-ordered" || surface === "bundle-memory-encoder") {
      return lifecycleProfileCarrier(surface, "profile-state.test/conformance@1");
    }
    assert.fail(`missing emitter lifecycle carrier for ${surface}`);
  };
  const invalidRegistryVariant = (variant) => variant === "partial" ? {
    registry: "partial",
    registryMutation: { action: "drop-document", path: "registries/profiles.json" }
  } : {
    registry: "forged",
    registryMutation: { action: "replace-registry-set-sha256", value: "0".repeat(64) }
  };
  const semanticSurfaces = ["repository-candidate", "import-request", "tree-expand", "manifest-verify", "asset-groups"];
  for (const surface of semanticSurfaces) {
    operationModeCases.set(`mode-${surface}-conformance-accept`, baseModeRequest(surface, {
      mode: "conformance", requestedLayer: 3, semanticProfiles: true
    }));
    operationModeCases.set(`mode-${surface}-read`, baseModeRequest(surface, {
      mode: "read", requestedLayer: 3, semanticProfiles: true
    }));
    operationModeCases.set(`mode-${surface}-invalid`, baseModeRequest(surface, {
      mode: "invalid", requestedLayer: 3, semanticProfiles: true
    }));
    operationModeCases.set(`mode-${surface}-omitted`, baseModeRequest(surface, {
      requestedLayer: 3, semanticProfiles: true
    }));
    operationModeCases.set(`mode-${surface}-production-conformance-profile`, baseModeRequest(surface, {
      mode: "production", requestedLayer: 3, semanticProfiles: true
    }));
    for (const variant of ["partial", "forged"]) {
      operationModeCases.set(`mode-${surface}-${variant}-registry`, baseModeRequest(surface, {
        ...invalidRegistryVariant(variant), mode: "conformance", requestedLayer: 3,
        semanticProfiles: true, ...(sourceForSurface(surface) ? { source: "malformed/nonminimal-unsigned.cbor" } : {})
      }));
    }
  }
  for (const surface of ["repository-candidate", "import-request", "tree-expand", "manifest-verify", "asset-groups"]) {
    operationModeCases.set(`mode-${surface}-missing-registry`, baseModeRequest(surface, {
      mode: "conformance", registry: "absent", requestedLayer: 3, semanticProfiles: true
    }));
    operationModeCases.set(`mode-${surface}-semantic-disabled`, baseModeRequest(surface, {
      mode: "conformance", requestedLayer: 3, semanticProfiles: false
    }));
  }
  const treeExpandMissingCaseMode = baseModeRequest("tree-expand", {
    mode: "conformance", requestedLayer: 3, semanticProfiles: true
  });
  delete treeExpandMissingCaseMode.caseMode;
  operationModeCases.set("mode-tree-expand-case-mode-missing", treeExpandMissingCaseMode);
  operationModeCases.set("mode-tree-expand-case-mode-invalid", baseModeRequest("tree-expand", {
    caseMode: "invalid", mode: "conformance", requestedLayer: 3, semanticProfiles: true
  }));
  operationModeCases.set("mode-repository-lookup-layer2-registry-free", baseModeRequest("repository-lookup-layer2", {
    registry: "absent", requestedLayer: 2, semanticProfiles: false
  }));
  operationModeCases.set("mode-repository-lookup-layer2-authority-omitted",
    authorityOmittedRequest("repository-lookup-layer2"));
  for (const [suffix, mode] of [["read", "read"], ["invalid", "invalid"]]) {
    operationModeCases.set(`mode-bundle-visitor-${suffix}`, baseModeRequest("bundle-visitor", {
      mode, registry: "absent", requestedLayer: 2, semanticProfiles: false
    }));
  }
  operationModeCases.set("mode-bundle-visitor-omitted", baseModeRequest("bundle-visitor", {
    registry: "absent", requestedLayer: 2, semanticProfiles: false
  }));
  operationModeCases.set("bundle-semantic-callback-does-not-promote", baseModeRequest("bundle-memory-verifier", {
    registry: "absent", requestedLayer: 2,
    semanticCallback: { behavior: "no-op" }, semanticProfiles: false
  }));

  for (const surface of ["metadata-encoder", "tree-ordered", "tree-sorted", "content-manifest", "bundle-ordered", "bundle-memory-encoder"]) {
    operationModeCases.set(`mode-${surface}-selector-missing`, baseModeRequest(surface));
    operationModeCases.set(`mode-${surface}-selector-read`, baseModeRequest(surface, { operation: "read" }));
    operationModeCases.set(`mode-${surface}-selector-invalid`, baseModeRequest(surface, { operation: "invalid" }));
    operationModeCases.set(`mode-${surface}-missing-registry`, baseModeRequest(surface, {
      operation: "conformance", registry: "absent"
    }));
    operationModeCases.set(emitterProductionConformanceId(surface), baseModeRequest(surface, {
      ...emitterLifecycleCarrier(surface),
      operation: "production-write",
      registryFixture: { path: "registries/index.json", scenarioId: "registry-conformance-production" }
    }));
    for (const variant of ["partial", "forged"]) {
      operationModeCases.set(`mode-${surface}-${variant}-registry`, baseModeRequest(surface, {
        ...invalidRegistryVariant(variant), operation: "conformance",
        ...(sourceForSurface(surface) ? { source: "malformed/nonminimal-unsigned.cbor" } : {})
      }));
    }
  }
  const lifecycleFixtures = [
    ["deprecated-read-accept", "read", "profile-state.test/deprecated@1", 2, "registry-deprecated-read"],
    ["conformance-read-rejected", "read", "profile-state.test/conformance@1", 1, "registry-conformance-mode"],
    ["conformance-accept", "conformance", "profile-state.test/conformance@1", 1, "registry-conformance-mode"],
    ["deprecated-production-write-rejected", "production-write", "profile-state.test/deprecated@1", 2, "registry-deprecated-write"],
    ["conformance-production-write-rejected", "production-write", "profile-state.test/conformance@1", 1, "registry-conformance-production"]
  ];
  for (const surface of ["tree-file", "metadata-decoder", "bundle-memory-verifier", "bundle-stream-verifier"]) {
    for (const [suffix, operation, profileText, requiredFeature, scenarioId] of lifecycleFixtures) {
      operationModeCases.set(codecLifecycleId(surface, suffix), baseModeRequest(surface, {
        ...(surface === "tree-file"
          ? lifecycleFeatureCarrier(requiredFeature)
          : lifecycleProfileCarrier(surface, profileText)),
        operation,
        registryFixture: { path: "registries/index.json", scenarioId },
        requestedLayer: 3,
        semanticProfiles: true
      }));
    }
    operationModeCases.set(`mode-${surface}-registry-operation-omitted`, baseModeRequest(surface, {
      requestedLayer: 3, semanticProfiles: true
    }));
    operationModeCases.set(`mode-${surface}-registry-operation-invalid`, baseModeRequest(surface, {
      operation: "invalid", requestedLayer: 3, semanticProfiles: true
    }));
    operationModeCases.set(`mode-${surface}-missing-registry`, baseModeRequest(surface, {
      operation: "conformance", registry: "absent", requestedLayer: 3,
      semanticProfiles: true, source: "malformed/nonminimal-unsigned.cbor"
    }));
    operationModeCases.set(`mode-${surface}-semantic-disabled`, baseModeRequest(surface, {
      operation: "conformance", requestedLayer: 3, semanticProfiles: false
    }));
    if (surface !== "tree-file") {
      operationModeCases.set(`mode-${surface}-registry-free-layer2`, baseModeRequest(surface, {
        registry: "absent", requestedLayer: 2, semanticProfiles: false
      }));
      operationModeCases.set(`mode-${surface}-registry-free-wrong-family`, baseModeRequest(surface, {
        ...lifecycleProfileCarrier(surface, "content-policy.test/opaque@1"),
        registry: "absent", requestedLayer: 2, semanticProfiles: false
      }));
    }
    const unknownId = surface === "tree-file"
      ? `mode-${surface}-unknown-feature`
      : `mode-${surface}-unknown-profile`;
    operationModeCases.set(unknownId, baseModeRequest(surface, {
      ...(surface === "tree-file"
        ? lifecycleFeatureCarrier(3)
        : lifecycleProfileCarrier(surface, "unknown.example/path@1")),
      operation: "read", requestedLayer: 3, semanticProfiles: true
    }));
    for (const variant of ["partial", "forged"]) {
      operationModeCases.set(`mode-${surface}-${variant}-registry`, baseModeRequest(surface, {
        ...invalidRegistryVariant(variant), operation: "conformance", requestedLayer: 3,
        semanticProfiles: true, source: "malformed/nonminimal-unsigned.cbor"
      }));
    }
  }
  operationModeCases.set("mode-tree-schema-decoder-registry-free-layer2", baseModeRequest("tree-schema-decoder", {
    registry: "absent", requestedLayer: 2, semanticProfiles: false
  }));
  operationModeCases.set("mode-tree-file-order-before-feature-lifecycle", baseModeRequest("tree-file", {
    operation: "production-write",
    registryFixture: { path: "registries/index.json", scenarioId: "registry-conformance-production" },
    requestedLayer: 3,
    semanticProfiles: true,
    source: lifecycleTreeOrderBeforeFeatureSource
  }));
  operationModeCases.set("mode-tree-file-order-before-descriptor-mismatch", baseModeRequest("tree-file", {
    operation: "conformance",
    repositoryDescriptor: lifecycleDescriptors.get("profile-state.test/conformance@1").objectRef,
    requestedLayer: 3,
    semanticProfiles: true,
    source: lifecycleTreeOrderBeforeDescriptorSource
  }));
  operationModeCases.set("mode-tree-file-target-before-duplicate-fileid", baseModeRequest("tree-file", {
    operation: "conformance",
    requestedLayer: 3,
    semanticProfiles: true,
    source: lifecycleTreeTargetBeforeDuplicateFileIdSource
  }));
  operationModeCases.set("mode-tree-file-feature-before-duplicate-fileid", baseModeRequest("tree-file", {
    operation: "production-write",
    registryFixture: { path: "registries/index.json", scenarioId: "registry-conformance-production" },
    requestedLayer: 3,
    semanticProfiles: true,
    source: lifecycleTreeFeatureBeforeDuplicateFileIdSource
  }));
  for (const order of ["forward", "reverse"]) {
    operationModeCases.set(`mode-tree-file-known-schema-before-order-${order}`,
      baseModeRequest("tree-file", {
        operation: "conformance",
        requestedLayer: 3,
        semanticProfiles: true,
        source: lifecycleTreeKnownSchemaBeforeOrderSources.get(order)
      }));
  }
  operationModeCases.set("mode-manifest-verify-missing-reference-before-profile-lifecycle",
    baseModeRequest("manifest-verify", {
      manifest: lifecycleManifestMissingChunkRefText,
      mode: "production",
      registryFixture: { path: "registries/index.json", scenarioId: "registry-conformance-production" },
      requestedLayer: 3,
      semanticProfiles: true,
      source: lifecycleManifestMissingChunkSource
    }));
  for (const order of ["forward", "reverse"]) {
    const orderedLookup = order === "forward"
      ? [[lookupValidateAllProfileRef, lookupValidateAllProfileSource], [lookupValidateAllSchemaRef, lookupValidateAllSchemaSource]]
      : [[lookupValidateAllSchemaRef, lookupValidateAllSchemaSource], [lookupValidateAllProfileRef, lookupValidateAllProfileSource]];
    operationModeCases.set(`lookup-validate-all-known-schema-before-profile-lifecycle-${order}`,
      baseModeRequest("repository-lookup-validate-all", {
        lookupOrder: orderedLookup.map(([reference]) => reference),
        mode: "production",
        registryFixture: {
          path: "registries/index.json",
          scenarioId: "registry-conformance-production"
        },
        requestedLayer: 3,
        semanticProfiles: true,
        sources: orderedLookup.map(([, source]) => source)
      }));
  }
  const rawImportBaseEntries = [
    ["schema", "ogvcs.repository-format.v1.fileid-operation-input.v1"],
    ["operation", "import-file-id"],
    ["importerProfile", "importer.test/fixture-adapter@1"],
    ["sourceNamespaceDigest", hex(digest(0x71))],
    ["sourceIdentityDigest", hex(digest(0x72))],
    ["requestedFileId", hex(id128(0x77))]
  ];
  for (const [field, malformedValue] of [
    ["sourceNamespaceDigest", "00"],
    ["sourceIdentityDigest", "00"],
    ["requestedFileId", "00"]
  ]) {
    const malformed = rawImportBaseEntries.map(([key, value]) => [key, key === field ? malformedValue : value]);
    const importerIndex = malformed.findIndex(([key]) => key === "importerProfile");
    const malformedIndex = malformed.findIndex(([key]) => key === field);
    const lifecycleFirst = [...malformed];
    const schemaFirst = [...malformed];
    [schemaFirst[importerIndex], schemaFirst[malformedIndex]] = [schemaFirst[malformedIndex], schemaFirst[importerIndex]];
    const id = `import-request-raw-${field.replaceAll(/[A-Z]/g, match => `-${match.toLowerCase()}`)}-schema-before-profile-lifecycle`;
    operationModeCases.set(id, baseModeRequest("import-request-raw", {
      lifetimeContext: { importMappings: [], lifetimeRecords: [], workingLifetimeAdditions: [] },
      mode: "production",
      objectLookup: "scenario.context.objectLookup",
      rawImportRequestOrders: [lifecycleFirst, schemaFirst],
      repositoryDescriptor: operationModeDescriptor,
      requestedLayer: 3,
      semanticProfiles: true
    }));
  }
  const rawLifetimeEvidence = {
    descriptor: operationModeDescriptor,
    fileId: hex(id128(0x11)),
    firstChangeSet: objectText("change-set", changeId),
    firstOperation: 0,
    origin: "native-create"
  };
  const rawImportNamespace = digest(0x71);
  const rawImportIdentity = digest(0x72);
  const rawImportMappingKey = sha256(Buffer.concat([
    IMPORT_MAPPING_DOMAIN,
    uint16be(1),
    cbor([descriptorRef, profile("importer.test", "fixture-adapter"),
      rawImportNamespace, rawImportIdentity])
  ]));
  const rawImportMapping = {
    descriptor: operationModeDescriptor,
    fileId: hex(id128(0x73)),
    importerProfile: "importer.test/fixture-adapter@1",
    mappingKey: hex(rawImportMappingKey),
    sourceIdentityDigest: hex(rawImportIdentity),
    sourceNamespaceDigest: hex(rawImportNamespace),
    state: "materialized"
  };
  const rawWorkingAddition = {
    descriptor: operationModeDescriptor,
    fileId: hex(id128(0x11)),
    firstChangeSet: objectText("change-set", changeId),
    firstOperation: 0,
    origin: "native-create"
  };
  for (const [id, collection, valid, malformed] of [
    ["lifetime-raw-lifetime-record-schema-before-duplicate", "lifetimeRecords",
      rawLifetimeEvidence, { ...rawLifetimeEvidence, fileId: undefined }],
    ["lifetime-raw-import-mapping-schema-before-conflict", "importMappings",
      rawImportMapping, { ...rawImportMapping, descriptor: undefined }],
    ["lifetime-raw-working-addition-schema-before-duplicate", "workingLifetimeAdditions",
      rawWorkingAddition, { ...rawWorkingAddition, firstOperation: undefined }]
  ]) {
    // Stable JSON omits the deliberately undefined field, materializing an
    // exact malformed plain-object row without a descriptive oracle label.
    const semanticFirst = [structuredClone(valid), structuredClone(valid), structuredClone(malformed)];
    const schemaFirst = [structuredClone(malformed), structuredClone(valid), structuredClone(valid)];
    const makeContext = (rows) => ({
      importMappings: collection === "importMappings" ? rows : [],
      lifetimeRecords: collection === "lifetimeRecords" ? rows : [],
      workingLifetimeAdditions: collection === "workingLifetimeAdditions" ? rows : []
    });
    operationModeCases.set(id, baseModeRequest("lifetime-and-imports-raw", {
      mode: "conformance",
      objectLookup: "scenario.context.objectLookup",
      rawLifetimeContextOrders: [makeContext(semanticFirst), makeContext(schemaFirst)],
      repositoryDescriptor: operationModeDescriptor,
      requestedLayer: 3,
      semanticProfiles: true
    }));
  }
  for (const [suffix, collection, valid, malformed] of [
    ["lifetime-record", "lifetimeRecords", rawLifetimeEvidence,
      { ...rawLifetimeEvidence, fileId: undefined }],
    ["import-mapping", "importMappings", rawImportMapping,
      { ...rawImportMapping, descriptor: undefined }]
  ]) {
    const makeContext = (rows) => ({
      importMappings: collection === "importMappings" ? rows : [],
      lifetimeRecords: collection === "lifetimeRecords" ? rows : [],
      workingLifetimeAdditions: []
    });
    operationModeCases.set(`import-request-raw-context-${suffix}-schema-before-profile-lifecycle`,
      baseModeRequest("import-request-context-raw", {
        importRequest: Object.fromEntries(rawImportBaseEntries),
        mode: "production",
        objectLookup: "scenario.context.objectLookup",
        rawLifetimeContextOrders: [
          makeContext([structuredClone(valid), structuredClone(malformed)]),
          makeContext([structuredClone(malformed), structuredClone(valid)])
        ],
        repositoryDescriptor: operationModeDescriptor,
        requestedLayer: 3,
        semanticProfiles: true
      }));
  }
  for (const [label, sourceName] of [["lifetime", "file-id-lifetime"], ["import-mapping", "import-mapping"]]) {
    for (const suffix of [
      "version-selector-invalid", "type-selector-invalid", "extra-field-22", "extra-field-999"
    ]) {
      const id = `logical-record-${label}-${suffix}`;
      operationModeCases.set(id, baseModeRequest("logical-record-map-raw", {
        registry: "absent",
        requestedLayer: 2,
        semanticProfiles: false,
        source: logicalRecordRawMapSources.get(`logical-record-${sourceName}-${suffix}`)
      }));
    }
  }
  operationModeCases.set("mode-tree-schema-decoder-registry-free-wrong-family", baseModeRequest("tree-schema-decoder", {
    expectedProfileFamily: "content-policy", profile: "path.test/opaque@1",
    registry: "absent", requestedLayer: 2, semanticProfiles: false,
    source: lifecycleWrongFamilyTreeSource
  }));
  for (const surface of ["tree-schema-decoder", "metadata-decoder", "bundle-memory-verifier", "bundle-stream-verifier"]) {
    operationModeCases.set(`mode-${surface}-authority-omitted`, authorityOmittedRequest(surface));
    operationModeCases.set(`mode-${surface}-semantic-false-with-registry`, baseModeRequest(surface, {
      requestedLayer: 2, semanticProfiles: false
    }));
    operationModeCases.set(`mode-${surface}-semantic-false-with-operation`, baseModeRequest(surface, {
      operation: "read", registry: "absent", requestedLayer: 2, semanticProfiles: false
    }));
  }
  const groupInput = {
    externalKeyProfile: "external-key.test/opaque@1",
    externalKeyValueHex: "01",
    fileIds: [hex(id128(0x21))],
    groupId: hex(id128(0x51)),
    groupProfile: "group.test/opaque@1",
    roleProfile: "group-role.test/member@1"
  };
  for (const id of [...operationModeCases.keys()].filter((value) => value.startsWith("mode-asset-groups-"))) {
    operationModeCases.set(id, { ...operationModeCases.get(id), groupInput });
  }
  for (const [suffix, profileField, profileValue] of [
    ["unknown-group-profile", "groupProfile", "unknown.example/group@1"],
    ["unknown-role-profile", "roleProfile", "unknown.example/role@1"],
    ["unknown-external-key-profile", "externalKeyProfile", "unknown.example/external-key@1"],
    ["wrong-family-group-profile", "groupProfile", "content-policy.test/opaque@1"],
    ["wrong-family-role-profile", "roleProfile", "group.test/opaque@1"],
    ["wrong-family-external-key-profile", "externalKeyProfile", "group-role.test/member@1"]
  ]) {
    operationModeCases.set(`group-standalone-${suffix}`, baseModeRequest("asset-groups", {
      groupInput: { ...groupInput, [profileField]: profileValue },
      mode: "conformance", requestedLayer: 3, semanticProfiles: true
    }));
  }
  const groupInputWrongFamily = {
    ...groupInput,
    fileIds: [hex(id128(0x22))],
    groupId: hex(id128(0x52)),
    groupProfile: "content-policy.test/opaque@1"
  };
  for (const order of ["forward", "reverse"]) {
    operationModeCases.set(`group-standalone-known-schema-before-profile-lifecycle-${order}`,
      baseModeRequest("asset-groups", {
        groupInputs: order === "forward"
          ? [groupInput, groupInputWrongFamily]
          : [groupInputWrongFamily, groupInput],
        mode: "production",
        requestedLayer: 3,
        semanticProfiles: true
      }));
  }
  for (const [suffix, malformedCarrier] of [
    ["later-group-non-map", { kind: "non-map-group", value: null }],
    ["later-member-non-map", { kind: "non-map-member", value: null }],
    ["later-external-key-non-map", { kind: "non-map-external-key", value: null }],
    ["later-proxy", {
      assertCallerCodeNotInvoked: true,
      kind: "map-proxy-with-throwing-get-prototype-of",
      marker: "OGVCS_CALLER_TRAP_MUST_NOT_RUN"
    }],
    ["groups-container-proxy", {
      assertCallerCodeNotInvoked: true,
      kind: "groups-map-proxy-with-throwing-get-prototype-of",
      marker: "OGVCS_CALLER_TRAP_MUST_NOT_RUN"
    }],
    ["members-array-proxy", {
      assertCallerCodeNotInvoked: true,
      kind: "members-array-proxy-with-throwing-get-own-property-descriptor",
      marker: "OGVCS_CALLER_TRAP_MUST_NOT_RUN"
    }],
    ["external-keys-array-proxy", {
      assertCallerCodeNotInvoked: true,
      kind: "external-keys-array-proxy-with-throwing-get-own-property-descriptor",
      marker: "OGVCS_CALLER_TRAP_MUST_NOT_RUN"
    }]
  ]) {
    operationModeCases.set(`group-standalone-raw-${suffix}-before-profile-lifecycle`,
      baseModeRequest("asset-groups-raw", {
        firstGroupInput: groupInput,
        laterGroupInput: {
          ...groupInput,
          fileIds: [hex(id128(0x22))],
          groupId: hex(id128(0x52))
        },
        malformedCarrier,
        mode: "production",
        requestedLayer: 3,
        semanticProfiles: true
      }));
  }
  operationModeCases.set("asset-groups-config-proxy-no-caller-code",
    baseModeRequest("asset-groups-raw", {
      firstGroupInput: groupInput,
      laterGroupInput: {
        ...groupInput,
        fileIds: [hex(id128(0x22))],
        groupId: hex(id128(0x52))
      },
      malformedCarrier: {
        assertCallerCodeNotInvoked: true,
        kind: "options-proxy-with-throwing-get-own-property-descriptor",
        marker: "OGVCS_CALLER_TRAP_MUST_NOT_RUN"
      },
      mode: "conformance",
      requestedLayer: 3,
      semanticProfiles: true
    }));
  operationModeCases.set("repository-lookup-zero-time", baseModeRequest("repository-lookup-layer2", {
    limits: { maxTimeMs: 0 }, registry: "absent", requestedLayer: 2, semanticProfiles: false
  }));
  const pathProfileDecisionCases = new Map([
    ["tree-ratified-path-profile-missing-platform-key", {
      api: "validate-path-profile-decision",
      adapter: {
        caseMode: "case-sensitive",
        decision: { accepted: true, repositoryKey: "safe" },
        profile: "path.opengamevcs/portable@1"
      },
      caseMode: "case-sensitive",
      profile: "path.opengamevcs/portable@1",
      schema: "ogvcs.repository-format.v1.path-profile-decision-input.v1",
      segments: ["safe"]
    }],
    ["tree-ratified-path-profile-missing-repository-key", {
      api: "validate-path-profile-decision",
      adapter: {
        caseMode: "case-sensitive",
        decision: { accepted: true, platformKey: "safe" },
        profile: "path.opengamevcs/portable@1"
      },
      caseMode: "case-sensitive",
      profile: "path.opengamevcs/portable@1",
      schema: "ogvcs.repository-format.v1.path-profile-decision-input.v1",
      segments: ["safe"]
    }],
    ["tree-ratified-path-profile-missing-case-mode", {
      adapter: {
        decision: { accepted: true, platformKey: "safe", repositoryKey: "safe" },
        profile: "path.opengamevcs/portable@1"
      },
      api: "validate-path-profile-decision",
      caseMode: "case-sensitive",
      profile: "path.opengamevcs/portable@1",
      schema: "ogvcs.repository-format.v1.path-profile-decision-input.v1",
      segments: ["safe"]
    }],
    ["tree-ratified-path-profile-wrong-case-mode", {
      adapter: {
        caseMode: "case-sensitive",
        decision: { accepted: true, platformKey: "safe", repositoryKey: "safe" },
        profile: "path.opengamevcs/portable@1"
      },
      api: "validate-path-profile-decision",
      caseMode: "case-folded",
      profile: "path.opengamevcs/portable@1",
      schema: "ogvcs.repository-format.v1.path-profile-decision-input.v1",
      segments: ["safe"]
    }]
  ]);
  const treeGroupsMemoryCases = new Map([
    ["tree-groups-combined-memory", {
      api: "validate-tree-groups-memory",
      assertNoPartialState: true,
      evidenceRequired: {
        eachComponentAloneFit: true,
        noPartialState: true,
        routeEvidence: [{
          noPartialState: true,
          recoveryKind: "same-authority-instance",
          route: "validate-tree-groups-memory",
          succeeded: true
        }]
      },
      memoryCeiling: {
        derivation: "one-byte-below-simultaneous-retained-tree-group-membership-and-collision-index",
        requireEachComponentAloneToFit: true
      },
      routes: ["validate-tree-groups-memory"],
      schema: "ogvcs.repository-format.v1.tree-groups-memory-input.v1"
    }]
  ]);
  const recoveryKindByRoute = Object.freeze({
    "expand-tree-edge-budget": "same-authority-instance",
    "expand-tree-scratch-budget": "same-authority-instance",
    "replay-change-set": "same-authority-instance",
    "repository-object-lookup-validate-all": "stateless-reinvoke",
    "validate-asset-groups": "stateless-reinvoke",
    "validate-conflict-set": "same-authority-instance",
    "validate-import-request": "fresh-operation-after-deadline",
    "validate-known-schema": "stateless-reinvoke",
    "validate-lifetime-and-imports": "same-authority-instance",
    "validate-snapshot-graph": "same-authority-instance",
    "verify-tree-file-stream": "same-authority-instance",
    "validate-tree-groups-memory": "same-authority-instance"
  });
  const routeEvidence = (routes) => routes.map((route) => ({
    noPartialState: true,
    recoveryKind: recoveryKindByRoute[route],
    route,
    succeeded: true
  }));
  const resourceReservationCases = new Map([
    ["resource-replay-base-memory", ["replay-base", ["replay-change-set"]]],
    ["resource-fileid-lifetime-import-indexes-memory", ["fileid-lifetime-import-indexes", ["validate-lifetime-and-imports"]]],
    ["resource-graph-workspace-indexes-memory", ["graph-workspace-indexes", ["validate-snapshot-graph"]]],
    ["resource-conflict-group-indexes-memory", ["conflict-group-indexes", ["validate-conflict-set", "validate-asset-groups"]]],
    ["resource-many-invalid-error-selection-memory", ["many-invalid-error-selection", ["repository-object-lookup-validate-all", "validate-known-schema"]]]
  ].map(([id, [cluster, routes]]) => [id, {
    api: "validate-resource-reservation",
    assertNoPartialState: true,
    evidenceRequired: { noPartialState: true, routeEvidence: routeEvidence(routes) },
    cluster,
    fixture: "bounded-reduced-retention-v1",
    memoryCeiling: { derivation: "one-byte-below-conservative-retained-cost-v1" },
    routes,
    schema: "ogvcs.repository-format.v1.resource-reservation-input.v1"
  }]));
  resourceReservationCases.set("resource-replay-base-memory", {
    ...resourceReservationCases.get("resource-replay-base-memory"),
    baseState: {
      groups: "empty",
      tree: operationModeTree
    },
    changeSet: replayBaseChangeText
  });
  resourceReservationCases.set("resource-many-invalid-error-selection-memory", {
    ...resourceReservationCases.get("resource-many-invalid-error-selection-memory"),
    diagnosticWorkspace: {
      assertInputUnchanged: true,
      derivation: "one-byte-below-conservative-retained-cost-v1",
      recoveryExpected: {
        code: "SCHEMA_FIELD_UNKNOWN",
        layer: 2,
        stage: "known-schema"
      },
      unknownFieldCount: 64
    }
  });
  resourceReservationCases.set("resource-conflict-group-indexes-memory", {
    ...resourceReservationCases.get("resource-conflict-group-indexes-memory"),
    conflictFixture: {
      reference: "ogvcs:v1:conflict-set:sha256:562aa353fa3bfcf681e7e4a218f66c9f3c1157c490508cb81f4320f271be25cf",
      scenario: "conflict-choice-base"
    }
  });
  const edgeRecoveryManifestPayload = addCbor(files, expectations,
    "scenarios/objects/resource-lookup-edge-counter-rollback/recovery-manifest.cbor",
    metadata(2, [
      [16, chunk.length],
      [17, typedDigest(sha256(chunk))],
      [18, chunkProfile],
      [19, [map([[0, objectRef(1, chunkId)], [1, chunk.length]])]]
    ]), acceptSchema);
  const edgeRecoveryManifestId = objectDigest(2, edgeRecoveryManifestPayload);
  const edgeRecoveryManifestText = objectText("content-manifest", edgeRecoveryManifestId);
  const scratchRecoveryTreePayload = addCbor(files, expectations,
    "scenarios/objects/resource-lookup-scratch-counter-rollback/recovery-tree.cbor",
    metadata(3, [[16, descriptorRef], [17, [treeValue.get(17)[0]]]]), acceptSchema);
  const scratchRecoveryTreeId = objectDigest(3, scratchRecoveryTreePayload);
  const scratchRecoveryTreeText = objectText("tree", scratchRecoveryTreeId);
  const counterRouteEvidence = (route) => [{
    counterBaselineRestored: true,
    noPartialState: true,
    recoveryKind: recoveryKindByRoute[route],
    route,
    succeeded: true
  }];
  resourceReservationCases.set("resource-lookup-edge-counter-rollback", {
    api: "validate-resource-reservation",
    assertCounterBaselineAfterFailure: true,
    assertCounterBaselineAfterRecovery: true,
    assertNoPartialState: true,
    cluster: "lookup-edge-counter-rollback",
    configuredLimit: { field: "maxEdges", value: 1 },
    evidenceRequired: {
      noPartialState: true,
      routeEvidence: counterRouteEvidence("expand-tree-edge-budget")
    },
    failureTree: operationModeTree,
    recovery: {
      api: "verify-manifest",
      reference: edgeRecoveryManifestText
    },
    routes: ["expand-tree-edge-budget"],
    schema: "ogvcs.repository-format.v1.resource-reservation-input.v1"
  });
  resourceReservationCases.set("resource-lookup-scratch-counter-rollback", {
    api: "validate-resource-reservation",
    assertCounterBaselineAfterFailure: true,
    assertCounterBaselineAfterRecovery: true,
    assertNoPartialState: true,
    cluster: "lookup-scratch-counter-rollback",
    configuredLimit: { field: "maxScratchBytes", value: 64 },
    evidenceRequired: {
      noPartialState: true,
      routeEvidence: counterRouteEvidence("expand-tree-scratch-budget")
    },
    failureTree: operationModeTree,
    recovery: {
      api: "expand-tree",
      recoveryTree: scratchRecoveryTreeText
    },
    routes: ["expand-tree-scratch-budget"],
    schema: "ogvcs.repository-format.v1.resource-reservation-input.v1"
  });
  resourceReservationCases.set("resource-tree-stream-transaction-composite-memory", {
    api: "validate-resource-reservation",
    assertNoPartialState: true,
    cluster: "tree-stream-transaction-composite-memory",
    evidenceRequired: {
      noPartialState: true,
      routeEvidence: [{
        compositeMemoryBounded: true,
        indexInstanceReused: true,
        noPartialState: true,
        recoveryKind: "same-authority-instance",
        route: "verify-tree-file-stream",
        scratchIndexReusableAfterAbort: true,
        succeeded: true,
        targetUnchanged: true
      }]
    },
    failure: {
      api: "verify-tree-file",
      source: "objects/03-tree.cbor",
      failurePoint: "after-at-least-one-fileid-index-insertion"
    },
    memoryCeiling: {
      derivation: "one-byte-below-reader-current-entry-and-fileid-index-composite-v1",
      indexCapacity: "remaining-composite-budget-not-full-operation-ceiling"
    },
    operation: "conformance",
    recovery: {
      api: "verify-tree-file",
      reuseTreeFileIdIndex: true,
      source: "scenarios/objects/resource-lookup-scratch-counter-rollback/recovery-tree.cbor"
    },
    registryFixture: {
      path: "registries/index.json",
      scenarioId: "registry-conformance-production"
    },
    routes: ["verify-tree-file-stream"],
    schema: "ogvcs.repository-format.v1.resource-reservation-input.v1",
    transaction: {
      scratchIndexReusableAfterAbortDrop: true,
      targetBytesUnchanged: true
    }
  });
  resourceReservationCases.set("resource-import-request-many-mappings-deadline", {
    api: "validate-resource-reservation",
    assertNoPartialState: true,
    evidenceRequired: {
      noPartialState: true,
      routeEvidence: routeEvidence(["validate-import-request"])
    },
    cluster: "fileid-import-many-mappings-deadline",
    fixture: "bounded-many-import-mappings-v1",
    routes: ["validate-import-request"],
    schema: "ogvcs.repository-format.v1.resource-reservation-input.v1",
    timeCeiling: { derivation: "one-checkpoint-before-final-bounded-mapping-v1" }
  });
  const typedReferenceAuthorityCases = new Map([
    ["typed-reference-arbitrary-kind-map-relabel", {
      case: "arbitrary-kind-map-relabel",
      kindCode: 3,
      kindMap: [[3, "evil"]],
      text: `ogvcs:v1:evil:sha256:${hex(treeId)}`
    }],
    ["typed-reference-duplicate-kind-token", {
      case: "duplicate-kind-token",
      registryMutation: {
        action: "replace-entry-field",
        field: "textToken",
        file: "object-kinds.json",
        selector: { code: 3 },
        value: "content-manifest"
      }
    }],
    ["typed-reference-durable-overlength-colon-dense", {
      case: "durable-text-overlength-colon-dense",
      maximumBytes: 144,
      text: `ogvcs:v1:${"tree:".repeat(30)}sha256:${"0".repeat(64)}`
    }]
  ]);
  const genericCanonicalScanCases = new Map([
    ["unicode-age-15-assigned", unicodeAssignedSource],
    ["unicode-age-frozen-unassigned", "malformed/unicode-age-frozen-unassigned.cbor"],
    ["unicode-age-newer-canonical", "malformed/unicode-age-newer-canonical.cbor"],
    ["unicode-age-newer-composition-pair", "malformed/unicode-age-newer-composition-pair.cbor"],
    ["unicode-age-newer-decomposed", "malformed/unicode-age-newer-decomposed.cbor"]
  ].map(([id, source]) => [id, {
    api: "canonical-scan",
    schema: "ogvcs.repository-format.v1.canonical-scan-input.v1",
    source,
    surface: "generic-cbor-item"
  }]));

  const commonLookup = objectRows.map((row) => {
    const bytes = files.get(row.payloadPath);
    return {
      artifact: { bytes: bytes.length, mediaType: mediaType(row.payloadPath), path: row.payloadPath, sha256: hex(sha256(bytes)) },
      ref: objectText(row.name, Buffer.from(row.objectId, "hex"))
    };
  });
  commonLookup.push({
    artifact: { bytes: childTreePayload.length, mediaType: "application/cbor", path: "objects/03-tree-child.cbor", sha256: hex(sha256(childTreePayload)) },
    ref: objectText("tree", childTreeId)
  });
  const replayBaseChangeLookup = {
    artifact: {
      bytes: replayBaseChangePayload.length,
      mediaType: "application/cbor",
      path: replayBaseChangePath,
      sha256: hex(sha256(replayBaseChangePayload))
    },
    ref: replayBaseChangeText
  };
  function seedLifetimeEvidence(scenarioId) {
    assert(typeof scenarioId === "string" && scenarioId.length > 0);
    const refText = objectText("change-set", changeId);
    return {
      lifetimes: rootStates.map((value, firstOperation) => ({ fileId: hex(value.get(2)), firstChangeSet: refText, firstOperation, origin: "native-create" })),
      ref: refText
    };
  }
  const outputIdsByFamily = {
    attestation: objectText("attestation", objectDigest(10, attestationPayload)),
    bundle: hex(validBundle.transcriptDigest),
    conflict: objectText("conflict-set", conflictId),
    fileid: fileIdText(id128(0x53)),
    group: objectText("asset-group-set", groupId),
    limit: descriptorDigest({ corpus: "limits", version: 1 }),
    manifest: objectText("content-manifest", manifestId),
    mutation: descriptorDigest({ corpus: "mutations", version: 1 }),
    provenance: objectText("provenance", provenanceId),
    registry: registrySetSha256,
    repository: objectText("snapshot", snapshotId),
    shelf: objectText("shelf-revision", shelfId),
    tree: objectText("tree", treeId)
  };
  const objectKindNames = new Map(objectRows.map((row) => [row.kind, row.name]));
  function materializeClosureAccumulatorScenario(item) {
    const match = /^closure-(manifest|tree|replay|conflict|snapshot|provenance|shelf)-identity-before-missing-(forward|reverse)$/.exec(item.id);
    if (!match) return undefined;
    const [, route, order] = match;
    const localLookup = [];
    function emit(kind, label, value) {
      const payload = Buffer.isBuffer(value) ? value : cbor(value);
      const id = objectDigest(kind, payload);
      const relative = `scenarios/objects/${item.id}/${label}.${kind === 1 ? "bin" : "cbor"}`;
      files.set(relative, payload);
      expectations.set(relative, acceptSchema);
      const artifact = {
        bytes: payload.length,
        mediaType: mediaType(relative),
        path: relative,
        sha256: hex(sha256(payload))
      };
      const result = {
        artifact,
        id,
        ref: objectRef(kind, id),
        refText: objectText(objectKindNames.get(kind), id)
      };
      localLookup.push({ artifact, ref: result.refText });
      return result;
    }
    let lookupMutation;
    function corruptAlias(kind, source, fill) {
      const payload = files.get(source);
      assert(payload, `${item.id}: missing corrupt-alias source ${source}`);
      const ref = objectRef(kind, digest(fill));
      const refText = objectText(objectKindNames.get(kind), digest(fill));
      localLookup.push({
        artifact: {
          bytes: payload.length,
          mediaType: mediaType(source),
          path: source,
          sha256: hex(sha256(payload))
        },
        ref: refText
      });
      lookupMutation = {
        action: "replace-payload-preserve-reference",
        reference: refText,
        sourceArtifact: source
      };
      return { ref, refText };
    }
    const orderedFaults = (kind, source) => {
      // Set-valued outbound-reference fields still have to retain canonical
      // encoded order. Vary which canonical identity is absent/corrupt rather
      // than reversing the encoded references themselves.
      const missingFill = order === "forward" ? 0xfc : 0xfd;
      const corruptFill = order === "forward" ? 0xfd : 0xfc;
      const missing = {
        ref: objectRef(kind, digest(missingFill)),
        refText: objectText(objectKindNames.get(kind), digest(missingFill))
      };
      const corrupt = corruptAlias(kind, source, corruptFill);
      return order === "forward" ? [missing, corrupt] : [corrupt, missing];
    };
    let candidate;
    let routeRequest;
    if (route === "manifest") {
      const [first, second] = orderedFaults(1, "objects/01-chunk.bin");
      candidate = emit(2, "manifest", metadata(2, [
        [16, 2], [17, typedDigest(digest(0xfa))], [18, chunkProfile],
        [19, [map([[0, first.ref], [1, 1]]), map([[0, second.ref], [1, 1]])]]
      ]));
      routeRequest = { api: "verify-manifest", manifest: candidate.refText };
    } else if (route === "tree") {
      const [first, second] = orderedFaults(2, "objects/02-content-manifest.cbor");
      const entry = (name, fill, target) => map([
        [0, name], [1, 2], [2, id128(fill)], [3, 2], [4, target], [5, 1], [6, contentProfile]
      ]);
      candidate = emit(3, "tree", metadata(3, [[16, descriptorRef], [17, [
        entry("a", 0x71, first.ref), entry("b", 0x72, second.ref)
      ]]]));
      routeRequest = {
        api: "expand-tree", caseMode: "case-sensitive",
        repositoryDescriptor: objectText("repository-descriptor", descriptorId),
        tree: candidate.refText, verifyContent: true
      };
    } else if (route === "replay") {
      const [first, second] = orderedFaults(2, "objects/02-content-manifest.cbor");
      const emptyTree = emit(3, "base-tree", metadata(3, [[16, descriptorRef], [17, []]]));
      const state = (name, fill, target) => map([
        [0, [name]], [1, 2], [2, id128(fill)], [3, 2], [4, target], [5, 1], [6, contentProfile]
      ]);
      const allocation = map([[0, descriptorRef], [1, 1]]);
      candidate = emit(4, "change-set", metadata(4, [[16, descriptorRef], [18, [
        map([[0, 0], [1, 1], [3, state("a", 0x71, first.ref)], [5, allocation]]),
        map([[0, 1], [1, 1], [3, state("b", 0x72, second.ref)], [5, allocation]])
      ]]]));
      routeRequest = {
        api: "replay-change-set", baseState: { groups: "empty", tree: emptyTree.refText },
        changeSet: candidate.refText,
        repositoryDescriptor: objectText("repository-descriptor", descriptorId)
      };
    } else if (route === "conflict") {
      const [first, second] = orderedFaults(2, "objects/02-content-manifest.cbor");
      const state = (fill, target) => map([
        [0, ["asset"]], [1, 2], [2, id128(fill)], [3, 2], [4, target], [5, 1], [6, contentProfile]
      ]);
      const subject = [1, [id128(0x71)], [["asset"]]];
      const baseSide = map([[0, 1], [1, state(0x71, first.ref)]]);
      const leftSide = map([[0, 1], [1, state(0x71, second.ref)]]);
      const rightSide = map([[0, 1], [1, state(0x71, manifestRef)]]);
      const keyed = map([[0, 1], [1, subject], [2, baseSide], [3, leftSide], [4, rightSide]]);
      const conflictId = sha256(Buffer.concat([CONFLICT_DOMAIN, uint16be(1), cbor(keyed)]));
      candidate = emit(11, "conflict-set", metadata(11, [[16, descriptorRef], [17, [map([
        [0, conflictId], [1, 1], [2, subject], [3, baseSide], [4, leftSide], [5, rightSide], [6, map([[0, 0]])]
      ])]]]));
      routeRequest = {
        api: "validate-conflict-set", conflictSet: candidate.refText,
        repositoryDescriptor: objectText("repository-descriptor", descriptorId)
      };
    } else if (route === "snapshot") {
      const [first, second] = orderedFaults(7, "objects/07-snapshot.cbor");
      candidate = emit(7, "snapshot", metadata(7, [
        [16, descriptorRef], [17, [first.ref, second.ref]], [18, treeRef], [19, changeRef],
        [21, identity()], [22, identity(0x32)], [23, 1], [24, 1],
        [25, item.id], [26, policyResult()]
      ]));
      routeRequest = {
        api: "validate-snapshot-graph", candidateSnapshot: candidate.refText,
        designatedRoot: candidate.refText,
        repositoryDescriptor: objectText("repository-descriptor", descriptorId)
      };
    } else if (route === "provenance") {
      const [first, second] = orderedFaults(9, "objects/09-provenance.cbor");
      candidate = emit(9, "provenance", metadata(9, [
        [16, profile("provenance.test", "opaque")], [17, [manifestRef]],
        [18, typedDigest(sha256(Buffer.from(item.id, "ascii")))]
      ]));
      routeRequest = { api: "validate-provenance-graph", forbidden: [], roots: [first.refText, second.refText] };
    } else {
      const [first, second] = orderedFaults(9, "objects/09-provenance.cbor");
      candidate = emit(8, "shelf-revision", metadata(8, [
        [16, descriptorRef], [17, id128(0x81)], [18, 1], [20, snapshotRef], [21, changeRef],
        [22, treeRef], [23, objectRef(5, groupId)], [24, objectRef(11, conflictId)],
        [25, identity()], [26, 1], [27, item.id], [28, policyResult()], [29, [first.ref, second.ref]]
      ]));
      routeRequest = {
        api: "validate-shelf-revision", callerVerifyContent: true,
        forceContentComplete: true, shelfRevision: candidate.refText
      };
    }
    assert(lookupMutation, `${item.id}: missing corrupt lookup mutation`);
    routeRequest.lookupMutations = [lookupMutation];
    const context = {
      caseMode: "case-sensitive",
      lifetimeRecords: route === "shelf" ? seedLifetimeEvidence(item.id).lifetimes : [],
      objectLookup: [...commonLookup, ...localLookup],
      repositoryDescriptor: objectText("repository-descriptor", descriptorId),
      workingLifetimeAdditions: route === "replay" ? [
        { fileId: hex(id128(0x71)), firstChangeSet: candidate.refText, firstOperation: 0, origin: "native-create" },
        { fileId: hex(id128(0x72)), firstChangeSet: candidate.refText, firstOperation: 1, origin: "native-create" }
      ] : []
    };
    if (route === "snapshot") {
      context.candidateSnapshot = candidate.refText;
      context.designatedRoot = candidate.refText;
    }
    return { candidate, context, resultIdentity: candidate.refText, routeRequest };
  }
  function materializeTransitionScenario(item) {
    if (!(item.id.startsWith("transition-") || ["error-changeset-transition-invalid", "error-fileid-lifetime-evidence-invalid", "fileid-move-source-forgery", "fileid-restore-invalid-ancestry", "fileid-restore-source-forgery", "fileid-cross-repository-proof", "group-member-invalid", "group-membership-overlap", "group-required-role-missing", "group-external-key-duplicate"].includes(item.id))) return undefined;
    const localLookup = [];
    const emitted = [];
    const carrierId = item.carrierId ?? item.id;
    function emit(kind, label, value) {
      const payload = Buffer.isBuffer(value) ? value : cbor(value);
      const objectId = objectDigest(kind, payload);
      const relative = `scenarios/objects/${carrierId}/${label}.cbor`;
      files.set(relative, payload);
      expectations.set(relative, acceptSchema);
      const artifact = { bytes: payload.length, mediaType: mediaType(relative), path: relative, sha256: hex(sha256(payload)) };
      const result = { artifact, id: objectId, ref: objectRef(kind, objectId), refText: objectText(objectKindNames.get(kind), objectId) };
      localLookup.push({ artifact, ref: result.refText });
      emitted.push(result);
      return result;
    }
    const makeState = (segments, fill, kind = 2, mode = 2) => {
      const fields = [[0, segments], [1, kind], [2, id128(fill)], [3, mode]];
      if (kind !== 1) fields.push([4, carrierId === "replay-entry-target-wrong-kind" ? objectRef(1, chunkId) : manifestRef]);
      fields.push([5, kind === 1 ? 0 : repeatedBytes.length], [6, contentProfile]);
      return map(fields);
    };
    function buildTree(states, label) {
      const byPath = new Map(states.map((value) => [value.get(0).join("/"), value]));
      function directory(prefix) {
        const depth = prefix.length;
        const children = [...byPath.values()].filter((value) => value.get(0).length === depth + 1 && value.get(0).slice(0, depth).join("/") === prefix.join("/"));
        const entries = children.map((value) => {
          const kind = value.get(1);
          const target = kind === 1 ? directory(value.get(0)).ref : value.get(4);
          return map([[0, value.get(0).at(-1)], [1, kind], [2, value.get(2)], [3, value.get(3)], [4, target], [5, value.get(5)], [6, value.get(6)]]);
        }).sort((a, b) => compareBytes(Buffer.from(a.get(0), "utf8"), Buffer.from(b.get(0), "utf8")));
        return emit(3, `${label}-tree-${prefix.length === 0 ? "root" : prefix.join("-")}`, metadata(3, [[16, descriptorRef], [17, entries]]));
      }
      return directory([]);
    }
    const allocation = map([[0, descriptorRef], [1, 1]]);
    const rootCreateOps = (states) => states.slice().sort((a, b) => a.get(0).length - b.get(0).length || a.get(0).join("/").localeCompare(b.get(0).join("/"), "en"))
      .map((value, index) => map([[0, index], [1, 1], [3, value], [5, allocation]]));
    const groupSet = (groups, label) => groups.length === 0 ? undefined : emit(5, label, metadata(5, [[16, descriptorRef], [17, groups]]));
    let beforeStates = [];
    let afterStates = [];
    let operation;
    let resolvedConflict;
    let beforeGroups = [];
    let afterGroups = [];
    const regular = makeState(["asset"], 0x21);
    if (item.id === "transition-create") {
      afterStates = [regular];
      operation = map([[0, 0], [1, 1], [3, regular], [5, allocation]]);
    } else if (item.id === "error-fileid-lifetime-evidence-invalid") {
      // The create is otherwise coherent, but the candidate context deliberately
      // omits its required immutable working lifetime addition.
      afterStates = [regular];
      operation = map([[0, 0], [1, 1], [3, regular], [5, allocation]]);
    } else if (item.id === "error-changeset-transition-invalid") {
      // A modify whose before and after states are identical is schema-valid but
      // violates the exact transition contract.
      beforeStates = afterStates = [regular];
      operation = map([[0, 0], [1, 2], [2, regular], [3, regular]]);
    } else if (item.id === "transition-modify") {
      beforeStates = [regular];
      const changed = makeState(["asset"], 0x21, 3, 3);
      afterStates = [changed];
      operation = map([[0, 0], [1, 2], [2, regular], [3, changed]]);
    } else if (item.id === "transition-copy") {
      beforeStates = [regular];
      const copied = makeState(["asset-copy"], 0x22);
      afterStates = [regular, copied];
      operation = map([[0, 0], [1, 3], [3, copied], [4, regular], [5, allocation]]);
    } else if (item.id === "transition-move") {
      const left = makeState(["left"], 0x31, 1, 1);
      const right = makeState(["right"], 0x32, 1, 1);
      const source = makeState(["left", "asset"], 0x21);
      const moved = makeState(["right", "asset"], 0x21);
      beforeStates = [left, right, source];
      afterStates = [left, right, moved];
      operation = map([[0, 0], [1, 4], [2, source], [3, moved]]);
    } else if (item.id === "transition-rename") {
      beforeStates = [regular];
      const renamed = makeState(["asset-renamed"], 0x21);
      afterStates = [renamed];
      operation = map([[0, 0], [1, 5], [2, regular], [3, renamed]]);
    } else if (item.id === "transition-delete") {
      beforeStates = [regular];
      afterStates = [];
      operation = map([[0, 0], [1, 6], [2, regular]]);
    } else if (item.id === "fileid-move-source-forgery") {
      const left = makeState(["left"], 0x31, 1, 1);
      const right = makeState(["right"], 0x32, 1, 1);
      const source = makeState(["left", "asset"], 0x21);
      const forgedSource = makeState(["left", "asset"], 0x22);
      // Preserve the forged FileID across the declared move so this scenario
      // isolates lookup/source evidence rather than also violating the
      // state-independent move relationship.
      const moved = makeState(["right", "asset"], 0x22);
      beforeStates = [left, right, source];
      afterStates = [left, right, moved];
      operation = map([[0, 0], [1, 4], [2, forgedSource], [3, moved]]);
    } else if (["transition-restore", "fileid-restore-invalid-ancestry", "fileid-restore-source-forgery", "fileid-cross-repository-proof"].includes(item.id)) {
      beforeStates = [];
      afterStates = [regular];
    } else if (item.id === "transition-merge-resolution") {
      beforeStates = afterStates = [regular];
      const alternateManifestBytes = chunk;
      const alternateManifest = emit(2, "alternate-manifest", metadata(2, [
        [16, alternateManifestBytes.length], [17, typedDigest(sha256(alternateManifestBytes))], [18, chunkProfile],
        [19, [map([[0, objectRef(1, chunkId)], [1, alternateManifestBytes.length]])]]
      ]));
      const baseSide = map([[0, 1], [1, regular]]);
      const rightState = new Map(regular).set(4, alternateManifest.ref).set(5, alternateManifestBytes.length);
      const rightSide = map([[0, 1], [1, rightState]]);
      const subject = [1, [regular.get(2)], [regular.get(0)]];
      const keyed = map([[0, 1], [1, subject], [2, baseSide], [3, baseSide], [4, rightSide]]);
      const mergeConflictId = sha256(Buffer.concat([CONFLICT_DOMAIN, uint16be(1), cbor(keyed)]));
      const resolvedRecord = map([[0, mergeConflictId], [1, 1], [2, subject], [3, baseSide], [4, baseSide], [5, rightSide], [6, map([[0, 1], [1, 1], [2, baseSide]])]]);
      resolvedConflict = emit(11, "resolved-conflict", metadata(11, [[16, descriptorRef], [17, [resolvedRecord]]]));
      operation = map([[0, 0], [1, 11], [9, mergeConflictId], [10, 1], [11, regular]]);
    } else if (item.id === "transition-group-create") {
      beforeStates = afterStates = [regular];
      const group = new Map(assetGroup).set(2, id128(0x21)).set(3, [map([[0, id128(0x21)], [1, roleProfile]])]);
      afterGroups = [group];
      operation = map([[0, 0], [1, 8], [8, group]]);
    } else if (item.id === "transition-group-update") {
      beforeStates = afterStates = [regular];
      const group = new Map(assetGroup).set(2, id128(0x21)).set(3, [map([[0, id128(0x21)], [1, roleProfile]])]);
      const updated = new Map(group).set(4, [map([[0, externalProfile], [1, Buffer.from("external-key-updated", "ascii")]])]);
      beforeGroups = [group];
      afterGroups = [updated];
      operation = map([[0, 0], [1, 9], [7, group], [8, updated]]);
    } else if (item.id === "transition-group-delete") {
      beforeStates = afterStates = [regular];
      const group = new Map(assetGroup).set(2, id128(0x21)).set(3, [map([[0, id128(0x21)], [1, roleProfile]])]);
      beforeGroups = [group];
      operation = map([[0, 0], [1, 10], [7, group]]);
    } else if (item.id === "group-member-invalid") {
      beforeStates = afterStates = [regular];
      const invalidGroup = new Map(assetGroup).set(0, id128(0x61)).set(2, id128(0x22)).set(3, [map([[0, id128(0x21)], [1, roleProfile]])]);
      afterGroups = [invalidGroup];
      operation = map([[0, 0], [1, 8], [8, invalidGroup]]);
    } else if (item.id === "group-membership-overlap") {
      beforeStates = afterStates = [regular];
      const firstGroup = new Map(assetGroup).set(0, id128(0x61)).set(2, id128(0x21)).set(3, [map([[0, id128(0x21)], [1, roleProfile]])]);
      firstGroup.delete(4);
      const secondGroup = new Map(firstGroup).set(0, id128(0x62));
      beforeGroups = [firstGroup];
      afterGroups = [firstGroup, secondGroup];
      operation = map([[0, 0], [1, 8], [8, secondGroup]]);
    } else if (item.id === "group-required-role-missing") {
      beforeStates = afterStates = [regular];
      const invalidGroup = map([[0, id128(0x61)], [1, fixtureAssetMetaGroupProfile], [2, id128(0x21)], [3, [map([[0, id128(0x21)], [1, fixturePrimaryRoleProfile]])]]]);
      afterGroups = [invalidGroup];
      operation = map([[0, 0], [1, 8], [8, invalidGroup]]);
    } else if (item.id === "group-external-key-duplicate") {
      const second = makeState(["meta"], 0x22);
      beforeStates = afterStates = [regular, second];
      const external = [map([[0, fixtureSyntheticGuidProfile], [1, Buffer.from("same-guid", "ascii")]])];
      const firstGroup = map([[0, id128(0x61)], [1, fixtureAssetGroupProfile], [2, id128(0x21)], [3, [map([[0, id128(0x21)], [1, fixtureMemberRoleProfile]])]], [4, external]]);
      const secondGroup = map([[0, id128(0x62)], [1, fixtureAssetGroupProfile], [2, id128(0x22)], [3, [map([[0, id128(0x22)], [1, fixtureMemberRoleProfile]])]], [4, external]]);
      beforeGroups = [firstGroup];
      afterGroups = [firstGroup, secondGroup];
      operation = map([[0, 0], [1, 8], [8, secondGroup]]);
    } else if (item.id === "transition-exact-result-mismatch") {
      beforeStates = [];
      afterStates = [];
      operation = map([[0, 0], [1, 1], [3, regular], [5, allocation]]);
    } else if (item.id === "transition-sequence-gap") {
      beforeStates = [];
      afterStates = [regular];
      operation = map([[0, 1], [1, 1], [3, regular], [5, allocation]]);
    } else return undefined;
    if (["transition-restore", "fileid-restore-invalid-ancestry", "fileid-restore-source-forgery", "fileid-cross-repository-proof"].includes(item.id)) {
      const sourceTree = buildTree([regular], "source");
      const sourceChange = emit(4, "source-change", metadata(4, [[16, descriptorRef], [18, rootCreateOps([regular])]]));
      const sourceSnapshotTree = carrierId === "replay-restore-missing-source-tree-before-profile-lifecycle"
        ? objectRef(3, digest(0xef))
        : sourceTree.ref;
      const sourceSnapshot = emit(7, "source-snapshot", metadata(7, [
        [16, descriptorRef], [17, []], [18, sourceSnapshotTree], [19, sourceChange.ref], [21, identity()], [22, identity(0x32)],
        [23, 0], [24, 0], [25, "restore source"], [26, policyResult()]
      ], ["replay-restore-missing-source-tree-before-profile-lifecycle", "replay-restore-missing-proof-descriptor-before-cross-repository"].includes(carrierId) ? [1] : []));
      const deletedTree = buildTree([], "deleted");
      const deleteOperation = map([[0, 0], [1, 6], [2, regular]]);
      const deleteChange = emit(4, "delete-change", metadata(4, [[16, descriptorRef], [17, sourceSnapshot.ref], [18, [deleteOperation]]]));
      const deleteSnapshot = emit(7, "delete-snapshot", metadata(7, [
        [16, descriptorRef], [17, [sourceSnapshot.ref]], [18, deletedTree.ref], [19, deleteChange.ref], [21, identity()], [22, identity(0x32)],
        [23, 1], [24, 1], [25, "ancestral delete"], [26, policyResult()]
      ]));
      let restoredState = regular;
      if (item.id === "fileid-restore-source-forgery") {
        const alternateManifestBytes = chunk;
        const alternateManifest = emit(2, "forged-manifest", metadata(2, [
          [16, alternateManifestBytes.length], [17, typedDigest(sha256(alternateManifestBytes))], [18, chunkProfile],
          [19, [map([[0, objectRef(1, chunkId)], [1, alternateManifestBytes.length]])]]
        ]));
        restoredState = new Map(regular).set(4, alternateManifest.ref).set(5, alternateManifestBytes.length);
      }
      let proofDelete = deleteSnapshot;
      if (item.id === "fileid-restore-invalid-ancestry") {
        const siblingChange = emit(4, "sibling-change", metadata(4, [[16, descriptorRef], [17, sourceSnapshot.ref], [18, [deleteOperation]]]));
        proofDelete = emit(7, "sibling-delete", metadata(7, [
          [16, descriptorRef], [17, [sourceSnapshot.ref]], [18, deletedTree.ref], [19, siblingChange.ref], [21, identity()], [22, identity(0x32)],
          [23, 1], [24, 1], [25, "non-ancestral delete"], [26, policyResult()]
        ]));
      }
      let proofDescriptor = descriptorRef;
      if (item.id === "fileid-cross-repository-proof") {
        const foreignDescriptor = emit(6, "foreign-descriptor", metadata(6, [[16, id128(0x62)], [17, pathProfile], [18, [contentProfile]], [19, [groupProfile]], [20, [chunkProfile]]]));
        proofDescriptor = foreignDescriptor.ref;
      } else if (carrierId === "replay-restore-missing-proof-descriptor-before-cross-repository") {
        proofDescriptor = objectRef(6, digest(0xee));
      }
      const restoredTree = buildTree([restoredState], "restored");
      const restoreProof = map([[0, proofDescriptor], [1, sourceSnapshot.ref], [2, ["asset"]], [3, proofDelete.ref]]);
      const restoreOperation = map([[0, 0], [1, 7], [3, restoredState], [6, restoreProof]]);
      const candidateChange = emit(4, "candidate-change", metadata(4, [[16, descriptorRef], [17, deleteSnapshot.ref], [18, [restoreOperation]]]));
      const candidate = emit(7, "candidate-snapshot", metadata(7, [
        [16, descriptorRef], [17, [deleteSnapshot.ref]], [18, restoredTree.ref], [19, candidateChange.ref], [21, identity()], [22, identity(0x32)],
        [23, 2], [24, 2], [25, item.id], [26, policyResult()]
      ]));
      return {
        candidate,
        context: {
          candidateSnapshot: candidate.refText,
          designatedRoot: sourceSnapshot.refText,
          lifetimeRecords: [{ fileId: hex(regular.get(2)), firstChangeSet: sourceChange.refText, firstOperation: 0, origin: "native-create" }],
          objectLookup: [...commonLookup.filter((entry) => [objectText("repository-descriptor", descriptorId), objectText("content-manifest", manifestId), objectText("chunk", chunkId)].includes(entry.ref)), ...localLookup],
          repositoryDescriptor: objectText("repository-descriptor", descriptorId),
          workingLifetimeAdditions: []
        },
        emitted,
        resultIdentity: restoredTree.refText
      };
    }
    const baseTree = buildTree(beforeStates, "base");
    const baseGroups = groupSet(beforeGroups, "base-groups");
    const rootOperations = rootCreateOps(beforeStates);
    for (const group of beforeGroups) {
      rootOperations.push(map([[0, rootOperations.length], [1, 8], [8, group]]));
    }
    const rootChange = emit(4, "root-change", metadata(4, [[16, descriptorRef], [18, rootOperations]]));
    const rootFields = [[16, descriptorRef], [17, []], [18, baseTree.ref], [19, rootChange.ref], [21, identity()], [22, identity(0x32)], [23, 0], [24, 0], [25, "scenario root"], [26, policyResult()]];
    if (baseGroups) rootFields.splice(4, 0, [20, baseGroups.ref]);
    const rootSnapshot = emit(7, "root-snapshot", metadata(7, rootFields));
    const resultTree = buildTree(afterStates, "result");
    const resultGroups = groupSet(afterGroups, "result-groups");
    const candidateChange = emit(4, "candidate-change", metadata(4,
      [[16, descriptorRef], [17, rootSnapshot.ref], [18, [operation]]],
      carrierId === "replay-missing-reference-before-profile-lifecycle" ? [1] : []));
    const candidateFields = [[16, descriptorRef], [17, [rootSnapshot.ref]], [18, resultTree.ref], [19, candidateChange.ref], [21, identity()], [22, identity(0x32)], [23, 1], [24, 1], [25, item.id], [26, policyResult()]];
    if (resultGroups) candidateFields.splice(4, 0, [20, resultGroups.ref]);
    if (resolvedConflict) candidateFields.push([28, resolvedConflict.ref]);
    const candidate = emit(7, "candidate-snapshot", metadata(7, candidateFields));
    const orderedBaseStates = beforeStates.slice().sort((a, b) => a.get(0).length - b.get(0).length || a.get(0).join("/").localeCompare(b.get(0).join("/"), "en"));
    const lifetimeRecords = orderedBaseStates.map((value, index) => ({ fileId: hex(value.get(2)), firstChangeSet: rootChange.refText, firstOperation: index, origin: "native-create" }));
    const workingLifetimeAdditions = [];
    if (["transition-create", "transition-copy", "transition-sequence-gap", "transition-exact-result-mismatch"].includes(item.id)) {
      const allocated = item.id === "transition-copy" ? id128(0x22) : id128(0x21);
      workingLifetimeAdditions.push({ fileId: hex(allocated), firstChangeSet: candidateChange.refText, firstOperation: 0, origin: item.id === "transition-copy" ? "native-copy" : "native-create" });
    }
    return {
      candidate,
      context: {
        candidateSnapshot: candidate.refText,
        designatedRoot: rootSnapshot.refText,
        lifetimeRecords,
        objectLookup: [...commonLookup.filter((entry) => [objectText("repository-descriptor", descriptorId), objectText("content-manifest", manifestId), objectText("chunk", chunkId)].includes(entry.ref)), ...localLookup],
        repositoryDescriptor: objectText("repository-descriptor", descriptorId),
        workingLifetimeAdditions
      },
      emitted,
      resultIdentity: item.resultFamily === "group" ? (resultGroups?.refText ?? "empty-group-state") : resultTree.refText
    };
  }
  function materializeHistoryScenario(item) {
    if ((!item.id.startsWith("history-") && !["snapshot-graph-missing-change-before-profile-lifecycle", "snapshot-graph-missing-descriptor-before-descriptor-mismatch"].includes(item.id) && !item.id.startsWith("snapshot-graph-second-root-before-missing-parent-") && !item.id.startsWith("repository-candidate-missing-")) || item.id === "history-parent-cycle") return undefined;
    const localLookup = [];
    function emit(kind, label, value) {
      const payload = cbor(value);
      const id = objectDigest(kind, payload);
      const relative = `scenarios/objects/${item.id}/${label}.cbor`;
      files.set(relative, payload);
      expectations.set(relative, acceptSchema);
      const artifact = { bytes: payload.length, mediaType: mediaType(relative), path: relative, sha256: hex(sha256(payload)) };
      const result = { artifact, id, ref: objectRef(kind, id), refText: objectText(objectKindNames.get(kind), id) };
      localLookup.push({ artifact, ref: result.refText });
      return result;
    }
    const emptyTree = emit(3, "empty-tree", metadata(3, [[16, descriptorRef], [17, []]]));
    const rootChange = emit(4, "root-change", metadata(4, [[16, descriptorRef], [18, []]]));
    const snapshotFields = (descriptor, parents, tree, change, message) => metadata(7, [
      [16, descriptor], [17, parents], [18, tree], [19, change], [21, identity()], [22, identity(0x32)],
      [23, 0], [24, 0], [25, message], [26, policyResult()]
    ]);
    const root = emit(7, "designated-root", snapshotFields(descriptorRef, [], emptyTree.ref, rootChange.ref, "root"));
    if (item.id === "snapshot-graph-missing-change-before-profile-lifecycle") {
      const candidate = emit(7, "candidate", metadata(7, [
        [16, descriptorRef], [17, []], [18, emptyTree.ref], [19, objectRef(4, digest(0xec))],
        [21, identity()], [22, identity(0x32)], [23, 0], [24, 0],
        [25, item.id], [26, policyResult()]
      ], [1]));
      return {
        candidate,
        context: {
          candidateSnapshot: candidate.refText,
          designatedRoot: candidate.refText,
          lifetimeRecords: [],
          objectLookup: [
            ...commonLookup.filter((entry) => entry.ref === objectText("repository-descriptor", descriptorId)),
            ...localLookup.filter((entry) => entry.ref !== rootChange.refText && entry.ref !== root.refText)
          ],
          repositoryDescriptor: objectText("repository-descriptor", descriptorId),
          workingLifetimeAdditions: []
        },
        resultIdentity: candidate.refText
      };
    }
    if (item.id === "snapshot-graph-missing-descriptor-before-descriptor-mismatch") {
      const missingDescriptor = objectRef(6, digest(0xed));
      const candidate = emit(7, "candidate", snapshotFields(
        missingDescriptor, [], emptyTree.ref, rootChange.ref, item.id));
      return {
        candidate,
        context: {
          candidateSnapshot: candidate.refText,
          designatedRoot: candidate.refText,
          lifetimeRecords: [],
          objectLookup: [
            ...commonLookup.filter((entry) => entry.ref === objectText("repository-descriptor", descriptorId)),
            ...localLookup.filter((entry) => entry.ref !== root.refText)
          ],
          repositoryDescriptor: objectText("repository-descriptor", descriptorId),
          workingLifetimeAdditions: []
        },
        resultIdentity: candidate.refText
      };
    }
    if (item.id.startsWith("snapshot-graph-second-root-before-missing-parent-")) {
      const secondRoot = emit(7, "second-root", snapshotFields(descriptorRef, [], emptyTree.ref, rootChange.ref, "second root"));
      const missingParent = objectRef(7, digest(0xeb));
      const parents = item.id.endsWith("-forward")
        ? [secondRoot.ref, missingParent]
        : [missingParent, secondRoot.ref];
      const candidateChange = emit(4, "candidate-change", metadata(4, [[16, descriptorRef], [17, secondRoot.ref], [18, []]]));
      const candidate = emit(7, "candidate", snapshotFields(descriptorRef, parents, emptyTree.ref, candidateChange.ref, item.id));
      return {
        candidate,
        context: {
          candidateSnapshot: candidate.refText,
          designatedRoot: root.refText,
          lifetimeRecords: [],
          objectLookup: [
            ...commonLookup.filter((entry) => entry.ref === objectText("repository-descriptor", descriptorId)),
            ...localLookup
          ],
          repositoryDescriptor: objectText("repository-descriptor", descriptorId),
          workingLifetimeAdditions: []
        },
        resultIdentity: candidate.refText
      };
    }
    if (item.id === "repository-candidate-missing-tree-before-second-root") {
      const candidateChange = emit(4, "candidate-change", metadata(4, [[16, descriptorRef], [18, []]]));
      const candidate = emit(7, "candidate", snapshotFields(descriptorRef, [], objectRef(3, digest(0xea)), candidateChange.ref, item.id));
      return {
        candidate,
        context: {
          candidateSnapshot: candidate.refText,
          designatedRoot: root.refText,
          lifetimeRecords: [],
          objectLookup: [
            ...commonLookup.filter((entry) => entry.ref === objectText("repository-descriptor", descriptorId)),
            ...localLookup
          ],
          repositoryDescriptor: objectText("repository-descriptor", descriptorId),
          workingLifetimeAdditions: []
        },
        resultIdentity: candidate.refText
      };
    }
    if (item.id === "repository-candidate-missing-change-before-profile-lifecycle") {
      const candidate = emit(7, "candidate", metadata(7, [
        [16, descriptorRef], [17, [root.ref]], [18, emptyTree.ref], [19, objectRef(4, digest(0xea))],
        [21, identity()], [22, identity(0x32)], [23, 1], [24, 1], [25, item.id], [26, policyResult()]
      ], [1]));
      return {
        candidate,
        context: {
          candidateSnapshot: candidate.refText,
          designatedRoot: root.refText,
          lifetimeRecords: [],
          objectLookup: [
            ...commonLookup.filter((entry) => entry.ref === objectText("repository-descriptor", descriptorId)),
            ...localLookup
          ],
          repositoryDescriptor: objectText("repository-descriptor", descriptorId),
          workingLifetimeAdditions: []
        },
        resultIdentity: candidate.refText
      };
    }
    if (item.id === "repository-candidate-missing-change-base") {
      const missingBase = objectRef(7, digest(0xe9));
      const candidateChange = emit(4, "candidate-change", metadata(4, [
        [16, descriptorRef], [17, missingBase], [18, []]
      ]));
      const candidate = emit(7, "candidate",
        snapshotFields(descriptorRef, [root.ref], emptyTree.ref, candidateChange.ref, item.id));
      return {
        candidate,
        context: {
          candidateSnapshot: candidate.refText,
          designatedRoot: root.refText,
          lifetimeRecords: [],
          objectLookup: [
            ...commonLookup.filter((entry) => entry.ref === objectText("repository-descriptor", descriptorId)),
            ...localLookup
          ],
          repositoryDescriptor: objectText("repository-descriptor", descriptorId),
          workingLifetimeAdditions: []
        },
        resultIdentity: candidate.refText
      };
    }
    let parents = [];
    let candidateDescriptor = descriptorRef;
    if (item.id === "history-zero-parent-root") return {
      candidate: root,
      context: { candidateSnapshot: root.refText, designatedRoot: root.refText, lifetimeRecords: [], objectLookup: [...commonLookup.filter((entry) => entry.ref === objectText("repository-descriptor", descriptorId)), ...localLookup], repositoryDescriptor: objectText("repository-descriptor", descriptorId), workingLifetimeAdditions: [] },
      resultIdentity: root.refText
    };
    if (item.id === "history-one-parent" || item.id === "history-base-mismatch") parents = [root.ref];
    if (["history-two-parent", "history-eight-parent", "history-ninth-parent"].includes(item.id)) {
      const count = item.id === "history-two-parent" ? 2 : item.id === "history-eight-parent" ? 8 : 9;
      parents = [root.ref];
      const sideChange = emit(4, "side-change", metadata(4, [[16, descriptorRef], [17, root.ref], [18, []]]));
      for (let index = 1; index < count; index += 1) {
        const side = emit(7, `side-${index}`, snapshotFields(descriptorRef, [root.ref], emptyTree.ref, sideChange.ref, `side ${index}`));
        parents.push(side.ref);
      }
    }
    if (item.id === "history-duplicate-parent") parents = [root.ref, root.ref];
    if (item.id === "history-missing-parent") parents = [objectRef(7, digest(0xee))];
    if (item.id === "history-cross-repository-parent") {
      const foreignDescriptor = emit(6, "foreign-descriptor", metadata(6, [[16, id128(0x61)], [17, pathProfile], [18, [contentProfile]], [19, [groupProfile]], [20, [chunkProfile]]]));
      const foreignTree = emit(3, "foreign-tree", metadata(3, [[16, foreignDescriptor.ref], [17, []]]));
      // Keep the foreign snapshot parented to the designated local root so
      // this case isolates cross-repository ancestry instead of also creating
      // a second zero-parent root (which has earlier error precedence).
      const foreignChange = emit(4, "foreign-change", metadata(4, [[16, foreignDescriptor.ref], [17, root.ref], [18, []]]));
      const foreignParent = emit(7, "foreign-parent", snapshotFields(foreignDescriptor.ref, [root.ref], foreignTree.ref, foreignChange.ref, "foreign parent"));
      parents = [foreignParent.ref];
      candidateDescriptor = descriptorRef;
    }
    if (item.id === "history-second-root") parents = [];
    let baseForChange = parents[0];
    if (item.id === "history-base-mismatch") {
      // Materialize the mismatching base as a valid, reachable snapshot so
      // this row isolates CHANGESET_BASE_MISMATCH rather than an earlier
      // missing-reference failure.
      const alternateChange = emit(4, "alternate-base-change",
        metadata(4, [[16, descriptorRef], [17, root.ref], [18, []]]));
      const alternateBase = emit(7, "alternate-base",
        snapshotFields(descriptorRef, [root.ref], emptyTree.ref, alternateChange.ref,
          "alternate present base"));
      baseForChange = alternateBase.ref;
    }
    const candidateChangeFields = [[16, candidateDescriptor]];
    if (baseForChange) candidateChangeFields.push([17, baseForChange]);
    candidateChangeFields.push([18, []]);
    const candidateChange = emit(4, "candidate-change", metadata(4, candidateChangeFields));
    const candidate = emit(7, "candidate", snapshotFields(candidateDescriptor, parents, emptyTree.ref, candidateChange.ref, item.id));
    return {
      candidate,
      context: { candidateSnapshot: candidate.refText, designatedRoot: root.refText, lifetimeRecords: [], objectLookup: [...commonLookup.filter((entry) => entry.ref === objectText("repository-descriptor", descriptorId)), ...localLookup], repositoryDescriptor: objectText("repository-descriptor", descriptorId), workingLifetimeAdditions: [] },
      resultIdentity: candidate.refText
    };
  }
  function materializeManifestScenario(item) {
    if (!item.id.startsWith("manifest-") || item.id === "manifest-one-tib") return undefined;
    const localLookup = [];
    function emit(kind, label, payloadOrValue) {
      const payload = Buffer.isBuffer(payloadOrValue) ? payloadOrValue : cbor(payloadOrValue);
      const id = objectDigest(kind, payload);
      const extension = kind === 1 ? "bin" : "cbor";
      const relative = `scenarios/objects/${item.id}/${label}.${extension}`;
      files.set(relative, payload);
      expectations.set(relative, kind === 1 ? acceptFraming : acceptSchema);
      const artifact = { bytes: payload.length, mediaType: mediaType(relative), path: relative, sha256: hex(sha256(payload)) };
      const result = { artifact, id, ref: objectRef(kind, id), refText: objectText(objectKindNames.get(kind), id) };
      localLookup.push({ artifact, ref: result.refText });
      return result;
    }
    let chunks = [];
    if (item.id !== "manifest-empty" && item.id !== "manifest-logical-ceiling") {
      const chunkBytes = item.id === "manifest-multi-chunk" ? [Buffer.from("A"), Buffer.from("BC"), Buffer.from("DEF")] : [Buffer.from("manifest-case", "ascii")];
      chunks = chunkBytes.map((bytes, index) => ({ bytes, object: emit(1, `chunk-${index}`, bytes) }));
      if (item.id === "manifest-repeated-chunk" || item.id === "manifest-annotation-invariance") chunks.push(chunks[0]);
    }
    const content = Buffer.concat(chunks.map((part) => part.bytes));
    let logicalLength = content.length;
    let wholeDigest = sha256(content);
    let chunkParts = chunks.map((part) => map([[0, part.object.ref], [1, part.bytes.length]]));
    let selectedProfile = chunkProfile;
    if (item.id === "manifest-corrupt-chunk") wholeDigest = digest(0xc1);
    if (item.id === "manifest-chunk-length" && chunkParts.length > 0) {
      chunkParts[0] = map([[0, chunks[0].object.ref], [1, chunks[0].bytes.length + 1]]);
      logicalLength += 1;
    }
    if (item.id === "manifest-length-sum-mismatch") logicalLength += 1;
    if (item.id === "manifest-logical-ceiling") logicalLength = 1099511627777;
    if (item.id === "manifest-unknown-profile") selectedProfile = profile("chunking.unknown", "missing");
    const manifest = emit(2, "manifest", metadata(2, [[16, logicalLength], [17, typedDigest(wholeDigest)], [18, selectedProfile], [19, chunkParts]]));
    const extraInputs = [];
    if (item.id === "manifest-annotation-invariance") {
      for (const [label, bytes] of [["a", Buffer.from("hint-a", "ascii")], ["b", Buffer.from("hint-b", "ascii")]]) {
        const payload = cbor(map([[0, 1], [1, 8], [16, manifest.ref], [17, profile("annotation.test", "opaque")], [18, bytes]]));
        const relative = `scenarios/objects/${item.id}/annotation-${label}.cbor`;
        files.set(relative, payload);
        expectations.set(relative, acceptSchema);
        extraInputs.push({ bytes: payload.length, mediaType: "application/cbor", path: relative, sha256: hex(sha256(payload)) });
      }
    }
    return {
      candidate: manifest,
      context: { objectLookup: localLookup },
      extraInputs,
      resultIdentity: manifest.refText
    };
  }
  function materializeSemanticObjectScenario(item) {
    if (!["attestation-unsigned", "attestation-signed", "attestation-signature-shape", "provenance-acyclic", "provenance-missing-reference-before-profile-lifecycle", "provenance-reaches-snapshot", "provenance-cycle-branch-before-missing-input-forward", "provenance-cycle-branch-before-missing-input-reverse", "shelf-revision-chain", "shelf-chain-invalid", "shelf-verify-content-false", "shelf-content-missing", "shelf-missing-previous-before-chain-invalid", "shelf-unrelated-known-schema-object-ignored", "shelf-unrelated-profile-object-ignored", "hash-tampered-object"].includes(item.id)) return undefined;
    const localLookup = [];
    function emit(kind, label, value, claimedRefText) {
      const payload = Buffer.isBuffer(value) ? value : cbor(value);
      const id = objectDigest(kind, payload);
      const relative = `scenarios/objects/${item.id}/${label}.cbor`;
      files.set(relative, payload);
      expectations.set(relative, item.code ? { code: item.code, layer: item.layer, stage: item.stage, result: "reject" } : acceptSchema);
      const artifact = { bytes: payload.length, mediaType: mediaType(relative), path: relative, sha256: hex(sha256(payload)) };
      const result = { artifact, id, ref: objectRef(kind, id), refText: claimedRefText ?? objectText(objectKindNames.get(kind), id) };
      localLookup.push({ artifact, ref: result.refText });
      return result;
    }
    let candidate;
    let semanticContext;
    let semanticResultIdentity;
    if (item.id.startsWith("attestation-")) {
      const fields = [[16, snapshotRef], [17, profile("attestation.test", "opaque")], [18, identity()], [19, 2], [20, Buffer.from("attestation scenario", "ascii")]];
      if (item.id !== "attestation-unsigned") fields.push([21, profile("signature.test", "opaque")]);
      if (item.id === "attestation-signed") fields.push([22, Buffer.from([1, 2, 3])]);
      candidate = emit(10, "attestation", metadata(10, fields));
    } else if (item.id.startsWith("provenance-")) {
      if (item.id.startsWith("provenance-cycle-branch-before-missing-input-")) {
        const cycleRoot = emit(9, "cycle-root", metadata(9, [
          [16, profile("provenance.test", "opaque")], [17, [manifestRef]],
          [18, typedDigest(sha256(Buffer.from(`${item.id}:cycle`, "ascii")))]
        ]));
        const missingRoot = emit(9, "missing-root", metadata(9, [
          [16, profile("provenance.test", "opaque")], [17, [objectRef(2, digest(0xeb))]],
          [18, typedDigest(sha256(Buffer.from(`${item.id}:missing`, "ascii")))]
        ]));
        candidate = cycleRoot;
      } else {
      const inputs = item.id === "provenance-reaches-snapshot" ? [snapshotRef]
        : item.id === "provenance-missing-reference-before-profile-lifecycle"
          ? [objectRef(2, digest(0xe3))]
          : [manifestRef];
      const value = metadata(9, [[16, profile("provenance.test", "opaque")], [17, inputs], [18, typedDigest(sha256(Buffer.from(item.id, "ascii")))]]);
      const provenance = emit(9, "provenance", value, item.id === "provenance-reaches-snapshot" ? objectText("provenance", provenanceId) : undefined);
      candidate = provenance;
      if (["provenance-acyclic", "provenance-missing-reference-before-profile-lifecycle"].includes(item.id)) {
        const emptyTree = emit(3, "root-tree", metadata(3, [[16, descriptorRef], [17, []]]));
        const rootChange = emit(4, "root-change", metadata(4, [[16, descriptorRef], [18, []]]));
        const rootSnapshot = emit(7, "root-snapshot", metadata(7, [
          [16, descriptorRef], [17, []], [18, emptyTree.ref], [19, rootChange.ref], [21, identity()], [22, identity(0x32)],
          [23, 0], [24, 0], [25, "provenance root"], [26, policyResult()]
        ]));
        const state = map([[0, ["asset"]], [1, 2], [2, id128(0x21)], [3, 2], [4, manifestRef], [5, repeatedBytes.length], [6, contentProfile]]);
        const resultTree = emit(3, "result-tree", metadata(3, [[16, descriptorRef], [17, [map([
          [0, "asset"], [1, 2], [2, id128(0x21)], [3, 2], [4, manifestRef], [5, repeatedBytes.length], [6, contentProfile]
        ])]]]));
        const operation = map([[0, 0], [1, 1], [3, state], [5, map([[0, descriptorRef], [1, 1]])]]);
        const candidateChange = emit(4, "candidate-change", metadata(4, [[16, descriptorRef], [17, rootSnapshot.ref], [18, [operation]]]));
        candidate = emit(7, "candidate-snapshot", metadata(7, [
          [16, descriptorRef], [17, [rootSnapshot.ref]], [18, resultTree.ref], [19, candidateChange.ref], [21, identity()], [22, identity(0x32)],
          [23, 1], [24, 1], [25, item.id], [26, policyResult()], [27, [provenance.ref]]
        ]));
        semanticContext = {
          candidateSnapshot: candidate.refText,
          designatedRoot: rootSnapshot.refText,
          lifetimeRecords: [],
          repositoryDescriptor: objectText("repository-descriptor", descriptorId),
          workingLifetimeAdditions: [{ fileId: hex(id128(0x21)), firstChangeSet: candidateChange.refText, firstOperation: 0, origin: "native-create" }]
        };
        semanticResultIdentity = provenance.refText;
      }
      }
    } else if (item.id === "hash-tampered-object") {
      const tampered = Buffer.from(manifestPayload);
      tampered[tampered.length - 1] ^= 1;
      candidate = emit(2, "tampered-manifest", tampered, objectText("content-manifest", manifestId));
    } else {
      const alternateManifestBytes = chunk;
      const alternateManifest = emit(2, "alternate-manifest", metadata(2, [
        [16, alternateManifestBytes.length], [17, typedDigest(sha256(alternateManifestBytes))], [18, chunkProfile],
        [19, [map([[0, objectRef(1, chunkId)], [1, alternateManifestBytes.length]])]]
      ]));
      const alternateState = new Map(entryState).set(4, alternateManifest.ref).set(5, alternateManifestBytes.length);
      const baseSide = conflictSide;
      const leftSide = conflictSide;
      const rightSide = map([[0, 1], [1, alternateState]]);
      const shelfPreimage = map([[0, 1], [1, conflictSubject], [2, baseSide], [3, leftSide], [4, rightSide]]);
      const shelfConflictId = sha256(Buffer.concat([CONFLICT_DOMAIN, uint16be(1), cbor(shelfPreimage)]));
      const shelfConflict = emit(11, "unresolved-conflict", metadata(11, [[16, descriptorRef], [17, [map([
        [0, shelfConflictId], [1, 1], [2, conflictSubject], [3, baseSide], [4, leftSide], [5, rightSide], [6, map([[0, 0]])]
      ])]]]));
      const shelfChange = emit(4, "working-change", metadata(4, [[16, descriptorRef], [17, snapshotRef], [18, []]]));
      const revisionValue = (number, label, predecessor) => metadata(8, [
        [16, descriptorRef], [17, id128(0x81)], [18, number], ...(predecessor ? [[19, predecessor.ref]] : []), [20, snapshotRef], [21, shelfChange.ref],
        [22, treeRef], [23, objectRef(5, groupId)], [24, shelfConflict.ref], [25, identity()], [26, 1], [27, label], [28, policyResult()], [29, [objectRef(9, provenanceId)]]
      ]);
      const revision = (number, label, predecessor) => emit(8, label, revisionValue(number, label, predecessor));
      const first = revision(1, "revision-1");
      if (item.id === "shelf-chain-invalid") {
        let label;
        for (let nonce = 0; nonce < 1024; nonce += 1) {
          const candidateLabel = `revision-3-${nonce}`;
          const candidateId = objectDigest(8, cbor(revisionValue(3, candidateLabel, first)));
          if (compareBytes(candidateId, first.id) < 0) { label = candidateLabel; break; }
        }
        assert(label, "failed to sort invalid shelf candidate before its predecessor");
        candidate = revision(3, label, first);
      } else if (item.id === "shelf-missing-previous-before-chain-invalid") {
        candidate = revision(3, "revision-3-missing", { ref: objectRef(8, digest(0xea)) });
      } else candidate = revision(2, "revision-2", first);
      if (item.id === "shelf-unrelated-known-schema-object-ignored") {
        const unrelated = emit(3, "unrelated-known-schema", metadata(3, [
          [16, descriptorRef], [17, []], [999, 0]
        ]));
        expectations.set(unrelated.artifact.path, {
          code: "SCHEMA_FIELD_UNKNOWN", layer: 2, result: "reject", stage: "known-schema"
        });
      } else if (item.id === "shelf-unrelated-profile-object-ignored") {
        const unrelatedEntry = map([
          [0, "unrelated"], [1, 2], [2, id128(0x7d)], [3, 2],
          [4, manifestRef], [5, repeatedBytes.length], [6, profile("unknown.example", "content")]
        ]);
        const unrelated = emit(3, "unrelated-profile", metadata(3, [
          [16, descriptorRef], [17, [unrelatedEntry]]
        ]));
        expectations.set(unrelated.artifact.path, {
          code: "PROFILE_UNKNOWN", layer: 3, result: "reject", stage: "registry-semantics"
        });
      }
    }
    const dependencies = commonLookup.filter((entry) => entry.ref !== candidate.refText
      && (!semanticContext || [objectText("repository-descriptor", descriptorId), objectText("content-manifest", manifestId), objectText("chunk", chunkId)].includes(entry.ref))
      && (!item.id.startsWith("shelf-") || (!entry.ref.includes(":shelf-revision:") && entry.ref !== objectText("conflict-set", conflictId))));
      const lifetimeEvidence = item.id.startsWith("shelf-") ? seedLifetimeEvidence(item.id) : undefined;
      return {
        candidate,
        context: {
          ...(lifetimeEvidence ? { lifetimeRecords: lifetimeEvidence.lifetimes } : {}),
          ...semanticContext,
          ...(item.id.startsWith("shelf-") ? { repositoryDescriptor: objectText("repository-descriptor", descriptorId) } : {}),
          objectLookup: [...dependencies, ...localLookup]
        },
      resultIdentity: semanticResultIdentity ?? candidate.refText
    };
  }
  function materializeConflictScenario(item) {
    if (!(item.id.startsWith("conflict-") || item.id === "error-conflict-subject-invalid")) return undefined;
    const localLookup = [];
    function emit(kind, label, value) {
      const payload = Buffer.isBuffer(value) ? value : cbor(value);
      const id = objectDigest(kind, payload);
      const relative = `scenarios/objects/${item.id}/${label}.${kind === 1 ? "bin" : "cbor"}`;
      files.set(relative, payload);
      expectations.set(relative, item.code ? { code: item.code, layer: item.layer, stage: item.stage, result: "reject" } : acceptSchema);
      const artifact = { bytes: payload.length, mediaType: mediaType(relative), path: relative, sha256: hex(sha256(payload)) };
      const result = { artifact, id, ref: objectRef(kind, id), refText: objectText(objectKindNames.get(kind), id) };
      localLookup.push({ artifact, ref: result.refText });
      return result;
    }
    const kindNames = ["content", "divergent-move", "delete-modify", "type", "mode", "policy", "group", "path-collision"];
    const matchedKind = kindNames.findIndex((name) => item.id.startsWith(`conflict-${name}-`));
    const conflictKind = matchedKind < 0 ? 1 : matchedKind + 1;
    const groupConflict = conflictKind === 7;
    const state = (segments, fileId, kind, mode, target, policy = contentProfile, size = repeatedBytes.length) => map([[0, segments], [1, kind], [2, fileId], [3, mode], [4, target], [5, size], [6, policy]]);
    const leftBytes = Buffer.from("left", "ascii");
    const rightBytes = Buffer.from("right", "ascii");
    const leftChunk = emit(1, "left-chunk", leftBytes);
    const rightChunk = emit(1, "right-chunk", rightBytes);
    const makeManifest = (label, chunkObject, bytes) => emit(2, `${label}-manifest`, metadata(2, [[16, bytes.length], [17, typedDigest(sha256(bytes))], [18, chunkProfile], [19, [map([[0, chunkObject.ref], [1, bytes.length]])]]]));
    const leftManifest = makeManifest("left", leftChunk, leftBytes);
    const rightManifest = makeManifest("right", rightChunk, rightBytes);
    let subject = conflictSubject;
    let baseSide = conflictSide;
    let leftSide = map([[0, 1], [1, state(["file"], id128(0x12), 2, 2, leftManifest.ref, contentProfile, leftBytes.length)]]);
    let rightSide = map([[0, 1], [1, state(["file"], id128(0x12), 2, 2, rightManifest.ref, contentProfile, rightBytes.length)]]);
    const standaloneEntryTargetCarrier = new Set([
      "conflict-entry-target-missing",
      "conflict-entry-target-missing-before-profile-lifecycle",
      "conflict-entry-target-wrong-kind"
    ]).has(item.id);
    if (standaloneEntryTargetCarrier) {
      const selectedTarget = item.id === "conflict-entry-target-wrong-kind"
        ? leftChunk.ref
        : objectRef(2, digest(0xe4));
      const selectedProfile = item.id === "conflict-entry-target-missing-before-profile-lifecycle"
        ? lifecycleContentConformance
        : contentProfile;
      leftSide = map([[0, 1], [1, state(["file"], id128(0x12), 2, 2,
        selectedTarget, selectedProfile, leftBytes.length)]]);
    }
    if (item.id === "error-conflict-subject-invalid") {
      // Content conflicts identify exactly one FileID. This remains a valid
      // typed entry subject but deliberately names a second ID.
      subject = [1, [id128(0x12), id128(0x13)], [["file"]]];
    }
    if (item.id === "conflict-choice-delete") {
      subject = [1, [id128(0x14)], [["run"]]];
      baseSide = map([[0, 1], [1, state(["run"], id128(0x14), 3, 3, manifestRef)]]);
      leftSide = map([[0, 1], [1, state(["run"], id128(0x14), 3, 3, leftManifest.ref, contentProfile, leftBytes.length)]]);
      rightSide = map([[0, 1], [1, state(["run"], id128(0x14), 3, 3, rightManifest.ref, contentProfile, rightBytes.length)]]);
    } else if (conflictKind === 2) {
      subject = [1, [id128(0x12)], [["file"], ["left"], ["right"]]];
      leftSide = map([[0, 1], [1, state(["left"], id128(0x12), 2, 2, leftManifest.ref, contentProfile, leftBytes.length)]]);
      rightSide = map([[0, 1], [1, state(["right"], id128(0x12), 2, 2, rightManifest.ref, contentProfile, rightBytes.length)]]);
    } else if (conflictKind === 3) {
      leftSide = undefined;
    } else if (conflictKind === 4) {
      leftSide = map([[0, 1], [1, state(["file"], id128(0x12), 2, 2, leftManifest.ref, contentProfile, leftBytes.length)]]);
      rightSide = map([[0, 1], [1, state(["file"], id128(0x12), 4, 4, rightManifest.ref, contentProfile, rightBytes.length)]]);
    } else if (conflictKind === 5) {
      leftSide = map([[0, 1], [1, state(["file"], id128(0x12), 2, 2, leftManifest.ref, contentProfile, leftBytes.length)]]);
      rightSide = map([[0, 1], [1, state(["file"], id128(0x12), 2, 2, rightManifest.ref, contentProfile, rightBytes.length)]]);
    } else if (conflictKind === 6) {
      leftSide = map([[0, 1], [1, state(["file"], id128(0x12), 2, 2, leftManifest.ref, contentProfile, leftBytes.length)]]);
      rightSide = map([[0, 1], [1, state(["file"], id128(0x12), 2, 2, leftManifest.ref, alternateContentProfile, leftBytes.length)]]);
    } else if (conflictKind === 7) {
      const leftGroup = new Map(assetGroup).set(4, [map([[0, externalProfile], [1, Buffer.from("left", "ascii")]])]);
      const rightGroup = new Map(assetGroup).set(4, [map([[0, externalProfile], [1, Buffer.from("right", "ascii")]])]);
      subject = [2, id128(0x51)];
      baseSide = map([[0, 2], [2, assetGroup]]);
      leftSide = map([[0, 2], [2, leftGroup]]);
      rightSide = map([[0, 2], [2, rightGroup]]);
    } else if (conflictKind === 8) {
      subject = [1, [id128(0x12), id128(0x13)], [["file"]]];
      baseSide = undefined;
      leftSide = map([[0, 1], [1, state(["file"], id128(0x12), 2, 2, leftManifest.ref, contentProfile, leftBytes.length)]]);
      rightSide = map([[0, 1], [1, state(["file"], id128(0x13), 2, 2, rightManifest.ref, contentProfile, rightBytes.length)]]);
    }
    const preimageEntries = [[0, conflictKind], [1, subject]];
    if (baseSide) preimageEntries.push([2, baseSide]);
    if (leftSide) preimageEntries.push([3, leftSide]);
    if (rightSide) preimageEntries.push([4, rightSide]);
    const preimageValue = map(preimageEntries);
    const exactConflictId = sha256(Buffer.concat([CONFLICT_DOMAIN, uint16be(1), cbor(preimageValue)]));
    const choiceName = ["base", "left", "right", "delete", "custom"].find((name) => item.id === `conflict-choice-${name}`);
    const choice = choiceName ? { base: 1, left: 2, right: 3, delete: 4, custom: 5 }[choiceName] : item.id === "conflict-custom-driver" ? 5 : conflictKind === 8 ? 2 : 1;
    const unresolved = item.id.includes("unresolved");
    let resolution = map([[0, 0]]);
    if (!unresolved) {
      const fields = [[0, 1], [1, choice]];
      if (choice !== 4) fields.push([2, choice <= 3 ? ({ 1: baseSide, 2: leftSide, 3: rightSide }[choice]) : rightSide]);
      if (choice === 5) fields.push([3, profile("conflict-driver.test", "opaque")]);
      resolution = map(fields);
    }
    const declaredConflictId = item.id === "conflict-id-mismatch" ? digest(0xcf) : exactConflictId;
    const recordEntries = [[0, declaredConflictId], [1, conflictKind], [2, subject]];
    if (baseSide) recordEntries.push([3, baseSide]);
    if (leftSide) recordEntries.push([4, leftSide]);
    if (rightSide) recordEntries.push([5, rightSide]);
    recordEntries.push([6, resolution]);
    const record = map(recordEntries);
    const conflict = emit(11, "conflict-set", metadata(11, [[16, descriptorRef], [17, [record]]]));
    let candidate = conflict;
    if (item.id.endsWith("unresolved-shelf") && conflictKind !== 5) {
      const shelfChange = emit(4, "unresolved-shelf-change", metadata(4, [
        [16, descriptorRef], [17, snapshotRef], [18, []]
      ]));
      candidate = emit(8, "unresolved-shelf", metadata(8, [
        [16, descriptorRef], [17, id128(0x82)], [18, 1], [20, snapshotRef], [21, shelfChange.ref], [22, treeRef], [23, objectRef(5, groupId)],
        [24, conflict.ref], [25, identity()], [26, 1], [27, item.id], [28, policyResult()], [29, [objectRef(9, provenanceId)]]
      ]));
    } else if (conflictKind !== 5 && item.id !== "conflict-id-mismatch" && !standaloneEntryTargetCarrier) {
      const resultSide = choice <= 3 ? ({ 1: baseSide, 2: leftSide, 3: rightSide }[choice]) : rightSide;
      const resultValue = choice === 4 ? undefined : resultSide.get(groupConflict ? 2 : 1);
      const operationFields = [[0, 0], [1, 11], [9, exactConflictId], [10, groupConflict ? 2 : 1]];
      if (resultValue) operationFields.push([11, resultValue]);
      if (item.id === "conflict-resolution-mismatch") operationFields[2] = [9, digest(0xce)];
      const mergeChange = emit(4, "merge-change", metadata(4, [[16, descriptorRef], [17, snapshotRef], [18, [map(operationFields)]]]));
      let resultTreeReference = treeRef;
      if (!groupConflict && choice !== 1 && item.id !== "conflict-resolution-mismatch") {
        const subjectBasename = subject[2][0].at(-1);
        const entries = treeValue.get(17).filter((value) => value.get(0) !== subjectBasename).map((value) => new Map(value));
        if (resultValue) entries.push(map([
          [0, resultValue.get(0).at(-1)], [1, resultValue.get(1)], [2, resultValue.get(2)], [3, resultValue.get(3)],
          [4, resultValue.get(4)], [5, resultValue.get(5)], [6, resultValue.get(6)]
        ]));
        entries.sort((a, b) => compareBytes(Buffer.from(a.get(0), "utf8"), Buffer.from(b.get(0), "utf8")));
        resultTreeReference = emit(3, "result-tree", metadata(3, [[16, descriptorRef], [17, entries]])).ref;
      }
      candidate = emit(7, "published-snapshot", metadata(7, [
        [16, descriptorRef], [17, [snapshotRef]], [18, resultTreeReference], [19, mergeChange.ref], [20, objectRef(5, groupId)], [21, identity()], [22, identity(0x32)],
        [23, 1], [24, 1], [25, item.id], [26, policyResult()], [28, conflict.ref]
      ]));
    }
    const lifetimeEvidence = seedLifetimeEvidence(item.id);
    return {
      candidate,
      context: {
        lifetimeRecords: lifetimeEvidence.lifetimes,
        repositoryDescriptor: objectText("repository-descriptor", descriptorId),
        ...(candidate.refText.includes(":snapshot:") ? { candidateSnapshot: candidate.refText, designatedRoot: objectText("snapshot", snapshotId) } : {}),
        objectLookup: [...commonLookup.filter((entry) => entry.ref !== objectText("conflict-set", conflictId)), ...localLookup]
      },
      resultIdentity: candidate.refText
    };
  }
  function materializeTreeScenario(item) {
    if (!(item.id.startsWith("tree-") || ["error-repository-descriptor-mismatch", "fileid-zero", "fileid-duplicate-expanded-tree"].includes(item.id)) || item.id === "tree-million-entries") return undefined;
    const localLookup = [...commonLookup.filter((entry) => [objectText("repository-descriptor", descriptorId), objectText("content-manifest", manifestId), objectText("chunk", chunkId)].includes(entry.ref))];
    function emitObject(kind, label, value) {
      const payload = cbor(value);
      const id = objectDigest(kind, payload);
      const relative = `scenarios/objects/${item.id}/${label}.cbor`;
      files.set(relative, payload);
      expectations.set(relative, acceptSchema);
      const artifact = { bytes: payload.length, mediaType: "application/cbor", path: relative, sha256: hex(sha256(payload)) };
      const result = { artifact, id, ref: objectRef(kind, id), refText: objectText(objectKindNames.get(kind), id) };
      localLookup.push({ artifact, ref: result.refText });
      return result;
    }
    const emit = (label, value) => emitObject(3, label, value);
    const treeEntry = (name, kind, fill, mode, target = manifestRef, size = repeatedBytes.length,
      policy = contentProfile) => map([[0, name], [1, kind], [2, Buffer.isBuffer(fill) ? fill : id128(fill)], [3, mode], [4, target], [5, size], [6, policy]]);
    let entries = [];
    let descriptorForTree = descriptorRef;
    let descriptorTextForTree = objectText("repository-descriptor", descriptorId);
    const ratifiedPathScenario = item.id.startsWith("tree-ratified-path-profile-");
    if (item.id === "tree-path-profile" || ratifiedPathScenario) {
      const selectedPathProfile = ratifiedPathScenario ? ratifiedPathProfile : rejectingPathProfile;
      const value = metadata(6, [
        [16, id128(0x60)], [17, selectedPathProfile], [18, [contentProfile, alternateContentProfile]],
        [19, [groupProfile, fixtureAssetGroupProfile, fixtureAssetMetaGroupProfile]], [20, [chunkProfile]]
      ]);
      const payload = cbor(value);
      const id = objectDigest(6, payload);
      const relative = `scenarios/objects/${item.id}/repository-descriptor.cbor`;
      files.set(relative, payload);
      expectations.set(relative, acceptSchema);
      const artifact = { bytes: payload.length, mediaType: "application/cbor", path: relative, sha256: hex(sha256(payload)) };
      descriptorForTree = objectRef(6, id);
      descriptorTextForTree = objectText("repository-descriptor", id);
      localLookup.push({ artifact, ref: descriptorTextForTree });
      entries = item.id.includes("empty") ? [] : ["tree-ratified-path-profile-case-sensitive-distinct", "tree-ratified-path-profile-case-folded-collision"].includes(item.id)
        ? [treeEntry("A", 2, 0x21, 2), treeEntry("a", 2, 0x22, 2)]
        : item.id === "tree-ratified-path-profile-opaque-keys"
          ? [treeEntry("a", 2, 0x21, 2), treeEntry("b", 2, 0x22, 2)]
        : [treeEntry(ratifiedPathScenario
          ? item.id === "tree-ratified-path-profile-reject" ? "blocked" : "safe"
          : "reserved", 2, 0x21, 2)];
    }
    if (item.id === "fileid-zero") entries = [treeEntry("zero", 2, Buffer.alloc(16), 2)];
    else if (item.id === "tree-missing-reference-before-profile-lifecycle") {
      entries = [treeEntry("missing", 2, 0x21, 2, objectRef(2, digest(0xe2)))];
    }
    else if (item.id === "tree-ratified-path-profile-missing-child-before-missing-validator") {
      entries = [treeEntry("missing-child", 1, 0x21, 1, objectRef(3, digest(0xe5)), 0)];
    }
    else if (item.id === "tree-ratified-path-profile-missing-manifest-before-wrong-validator") {
      entries = [treeEntry("missing-manifest", 2, 0x21, 2, objectRef(2, digest(0xe6)))];
    }
    else if (item.id === "tree-ratified-path-profile-missing-chunk-before-missing-validator") {
      const missingChunkManifest = emitObject(2, "missing-chunk-manifest", metadata(2, [
        [16, 1], [17, typedDigest(digest(0xe7))], [18, chunkProfile],
        [19, [map([[0, objectRef(1, digest(0xe7))], [1, 1]])]]
      ]));
      entries = [treeEntry("missing-chunk", 2, 0x21, 2, missingChunkManifest.ref, 1)];
    }
    else if (item.id === "tree-missing-target-before-path-profile-lifecycle") {
      const selectedPathProfile = profile("profile-state.test", "conformance");
      const descriptorValue = metadata(6, [
        [16, id128(0x6c)], [17, selectedPathProfile], [18, [lifecycleContentRatified]], [19, []], [20, [chunkProfile]]
      ]);
      const descriptor = emitObject(6, "repository-descriptor", descriptorValue);
      descriptorForTree = descriptor.ref;
      descriptorTextForTree = descriptor.refText;
      entries = [treeEntry("missing", 2, 0x21, 2, objectRef(2, digest(0xe8)), repeatedBytes.length,
        lifecycleContentRatified)];
    }
    else if (item.id === "tree-missing-manifest-before-descriptor-mismatch") {
      const foreign = lifecycleDescriptors.get("profile-state.test/conformance@1");
      const payload = files.get(foreign.descriptorSource);
      localLookup.push({
        artifact: { bytes: payload.length, mediaType: "application/cbor", path: foreign.descriptorSource, sha256: hex(sha256(payload)) },
        ref: foreign.objectRef
      });
      descriptorForTree = foreign.ref;
      entries = [treeEntry("missing", 2, 0x21, 2, objectRef(2, digest(0xe9)))];
    }
    else if (item.id === "tree-missing-child-before-duplicate-fileid") {
      entries = [
        treeEntry("a", 1, 0x21, 1, objectRef(3, digest(0xea)), 0),
        treeEntry("b", 2, 0x21, 2)
      ];
    }
    else if (item.id === "fileid-duplicate-expanded-tree") entries = [treeEntry("a", 2, 0x21, 2), treeEntry("b", 2, 0x21, 2)];
    else if (item.id === "tree-unicode") entries = [treeEntry("é", 2, 0x21, 2), treeEntry("日本語", 2, 0x22, 2), treeEntry("🎮", 2, 0x23, 2)]
      .sort((a, b) => compareBytes(Buffer.from(a.get(0), "utf8"), Buffer.from(b.get(0), "utf8")));
    if (item.id === "tree-all-entry-kinds-modes") {
      const child = emit("child-empty", metadata(3, [[16, descriptorRef], [17, []]]));
      entries = [
        treeEntry("dir", 1, 0x11, 1, child.ref, 0), treeEntry("file", 2, 0x12, 2),
        treeEntry("link", 4, 0x13, 4), treeEntry("run", 3, 0x14, 3)
      ];
    }
    if (item.id === "tree-entry-order") entries = [treeEntry("b", 2, 0x21, 2), treeEntry("a", 2, 0x22, 2)];
    if (item.id === "tree-entry-target") entries = [treeEntry("bad", 2, 0x21, 3)];
    if (item.id === "tree-manifest-length-mismatch") entries = [treeEntry("bad-size", 2, 0x21, 2, manifestRef, repeatedBytes.length + 1)];
    if (item.id === "tree-path-core") {
      const segment = "a".repeat(241);
      let child = emit("path-16", metadata(3, [[16, descriptorRef], [17, [treeEntry(segment, 2, 0x31, 2)]]]));
      for (let depth = 15; depth >= 0; depth -= 1) {
        child = emit(`path-${String(depth).padStart(2, "0")}`, metadata(3, [[16, descriptorRef], [17, [
          treeEntry(segment, 1, 0x40 + depth, 1, child.ref, 0)
        ]]]));
      }
      return {
        candidate: child,
        context: { objectLookup: localLookup, repositoryDescriptor: objectText("repository-descriptor", descriptorId) },
        resultIdentity: child.refText
      };
    }
    if (item.id === "tree-path-core-deep-chain") {
      const deepFileId = (ordinal) => {
        const value = Buffer.alloc(16);
        value.writeUInt16BE(ordinal, 14);
        return value;
      };
      let child = emit("deep-path-256", metadata(3, [[16, descriptorRef], [17, [
        treeEntry("leaf", 2, deepFileId(1), 2)
      ]]]));
      for (let depth = 255; depth >= 0; depth -= 1) {
        child = emit(`deep-path-${String(depth).padStart(3, "0")}`, metadata(3, [[16, descriptorRef], [17, [
          treeEntry("a", 1, deepFileId(257 - depth), 1, child.ref, 0)
        ]]]));
      }
      return {
        candidate: child,
        context: {
          caseMode: "case-sensitive",
          objectLookup: localLookup,
          repositoryDescriptor: objectText("repository-descriptor", descriptorId)
        },
        resultIdentity: child.refText
      };
    }
    if (item.id === "error-repository-descriptor-mismatch") {
      const foreignDescriptor = emitObject(6, "foreign-descriptor", metadata(6, [
        [16, id128(0xdd)], [17, pathProfile], [18, [contentProfile]],
        [19, [groupProfile]], [20, [chunkProfile]]
      ]));
      // The referenced descriptor is fully supplied and valid. The mismatch
      // is solely against the caller's authenticated repository descriptor.
      descriptorForTree = foreignDescriptor.ref;
    }
    const tree = emit("tree", metadata(3, [[16, descriptorForTree], [17, entries]]));
    const caseMode = pathProfileDecisionCases.get(item.id)?.caseMode ??
      (item.id === "tree-ratified-path-profile-case-folded-collision" ? "case-folded" : "case-sensitive");
    const pathProfileValidator = ratifiedPathScenario && item.operation !== "validate-path-profile-decision" && !item.id.endsWith("missing-validator") ? {
      caseMode,
      invocations: item.id.includes("empty") || item.id.includes("before-wrong-validator") ? [] : item.id === "tree-ratified-path-profile-opaque-keys" ? [{
        decision: { accepted: true, platformKey: "日本語", repositoryKey: "e\u0301" },
        segments: ["a"]
      }, {
        decision: { accepted: true, platformKey: "日本語-2", repositoryKey: "é" },
        segments: ["b"]
      }] : item.id === "tree-ratified-path-profile-case-sensitive-distinct" ? [{
        decision: { accepted: true, platformKey: "A", repositoryKey: "A" },
        segments: ["A"]
      }, {
        decision: { accepted: true, platformKey: "a", repositoryKey: "a" },
        segments: ["a"]
      }] : item.id === "tree-ratified-path-profile-case-folded-collision" ? [{
        decision: { accepted: true, platformKey: "A", repositoryKey: "a" },
        segments: ["A"]
      }, {
        decision: { accepted: true, platformKey: "a", repositoryKey: "a" },
        segments: ["a"]
      }] : [{
        decision: item.id === "tree-ratified-path-profile-accept"
          ? { accepted: true, platformKey: "safe", repositoryKey: "safe" }
          : { accepted: false },
        segments: [item.id === "tree-ratified-path-profile-accept" ? "safe" : "blocked"]
      }],
      profile: item.id.includes("before-wrong-validator")
        ? "path.opengamevcs/windows@1"
        : "path.opengamevcs/portable@1"
    } : undefined;
    return {
      candidate: tree,
      context: {
        caseMode,
        objectLookup: localLookup,
        ...(pathProfileValidator ? { pathProfileValidator } : {}),
        repositoryDescriptor: descriptorTextForTree
      },
      resultIdentity: tree.refText
    };
  }
  const scenarioRows = [];
  for (const item of scenarioCases.sort((a, b) => a.id.localeCompare(b.id, "en"))) {
    const seed = sha256(Buffer.from(`OGVCS-002 validation scenario v1\0${item.id}`, "utf8"));
    const descriptorText = objectText("repository-descriptor", descriptorId);
    const snapshotText = objectText("snapshot", snapshotId);
    const changeText = objectText("change-set", changeId);
    const context = {
      asOf: "immediately-before-candidate-snapshot",
      caseMode: "case-sensitive",
      importMappings: [],
      lifetimeRecords: [],
      mode: item.mode,
      objectLookup: [...commonLookup],
      registrySnapshot: { formatVersion: 1, registrySetSha256, registryVersion: 1 },
      requestedLayer: item.layer,
      roots: [],
      workingLifetimeAdditions: []
    };
    if (["validate-repository", "replay-change-set", "allocate-file-id", "import-file-id"].includes(item.operation)) context.repositoryDescriptor = descriptorText;
    if (["validate-repository", "replay-change-set"].includes(item.operation)) {
      context.candidateSnapshot = snapshotText;
      context.designatedRoot = snapshotText;
    }
    if (item.operation === "validate-bundle") {
      context.roots = [
        { identity: objectText("content-manifest", manifestId), kind: "object", roleProfile: "bundle-role.test/root@1" },
        { identity: hex(validBundle.logicals[0].identityBytes), kind: "logical-record", roleProfile: "bundle-role.test/root@1" }
      ];
      if (item.id === "bundle-zero-sections") context.roots = [];
      if (item.id === "bundle-multi-root-disambiguation") context.roots = [
        { identity: objectText("chunk", chunkId), kind: "object", roleProfile: "bundle-role.test/root@1" },
        { identity: objectText("content-manifest", manifestId), kind: "object", roleProfile: "bundle-role.test/root@1" }
      ];
    }
    if (/fileid-(?:create-reuse|copy-reuse|delete-recreate-reuse)/.test(item.id)) {
      context.lifetimeRecords.push({ fileId: hex(id128(0x21)), firstChangeSet: changeText, firstOperation: 0, origin: item.id.includes("copy") ? "native-copy" : "native-create" });
    }
    if (item.id.startsWith("fileid-import-")) {
      context.objectLookup = [...commonLookup];
      const mappingSourceIdentity = item.id === "fileid-import-native-collision" ? digest(0x55) : digest(0x52);
      const mappingFileId = item.id === "fileid-import-native-collision" ? id128(0x54) : id128(0x53);
      const mappingKey = sha256(Buffer.concat([
        IMPORT_MAPPING_DOMAIN,
        uint16be(1),
        cbor([descriptorRef, profile("importer.test", "fixture-adapter"), digest(0x51), mappingSourceIdentity])
      ]));
      context.importMappings.push({
        descriptor: descriptorText,
        fileId: hex(mappingFileId),
        importerProfile: "importer.test/fixture-adapter@1",
        mappingKey: hex(mappingKey),
        sourceIdentityDigest: hex(mappingSourceIdentity),
        sourceNamespaceDigest: hex(digest(0x51)),
        state: "materialized"
      });
      const addEvidence = (label, fileId, allocationKind, importKey) => {
        const state = map([[0, [`${label}-asset`]], [1, 2], [2, fileId], [3, 2], [4, manifestRef], [5, repeatedBytes.length], [6, contentProfile]]);
        const proofEntries = [[0, descriptorRef], [1, allocationKind]];
        if (importKey) proofEntries.push([2, importKey]);
        const operation = map([[0, 0], [1, 1], [3, state], [5, map(proofEntries)]]);
        const payload = cbor(metadata(4, [[16, descriptorRef], [18, [operation]]]));
        const id = objectDigest(4, payload);
        const relative = `scenarios/objects/${item.id}/${label}-evidence-change.cbor`;
        files.set(relative, payload);
        expectations.set(relative, acceptSchema);
        const refText = objectText("change-set", id);
        context.objectLookup.push({ artifact: { bytes: payload.length, mediaType: "application/cbor", path: relative, sha256: hex(sha256(payload)) }, ref: refText });
        context.lifetimeRecords.push({
          fileId: hex(fileId),
          firstChangeSet: refText,
          firstOperation: 0,
          ...(importKey ? { importMappingKey: hex(importKey), origin: "import" } : { origin: "native-create" })
        });
      };
      addEvidence("import", mappingFileId, 2, mappingKey);
      if (item.id === "fileid-import-native-collision") addEvidence("native", id128(0x53), 1);
    }
    const priorImportMatch = item.id.match(/^fileid-prior-import-mapping-(lifetime|request|candidate)-(conformance|wrong-family|production-conformance-only|foreign-repository)$/);
    let priorImportFixture;
    if (priorImportMatch) {
      const [, surface, variant] = priorImportMatch;
      context.repositoryDescriptor = descriptorText;
      context.candidateSnapshot = snapshotText;
      context.designatedRoot = snapshotText;
      const foreign = variant === "foreign-repository";
      let mappingDescriptorRef = descriptorRef;
      let mappingDescriptorText = descriptorText;
      if (foreign) {
        const foreignDescriptorPayload = cbor(metadata(6, [
          [16, id128(0x62)], [17, pathProfile], [18, [contentProfile]],
          [19, [groupProfile]], [20, [chunkProfile]]
        ]));
        const foreignDescriptorId = objectDigest(6, foreignDescriptorPayload);
        mappingDescriptorRef = objectRef(6, foreignDescriptorId);
        mappingDescriptorText = objectText("repository-descriptor", foreignDescriptorId);
        const foreignDescriptorSource = `scenarios/objects/${item.id}/foreign-descriptor.cbor`;
        files.set(foreignDescriptorSource, foreignDescriptorPayload);
        expectations.set(foreignDescriptorSource, acceptSchema);
        context.objectLookup.push({
          artifact: {
            bytes: foreignDescriptorPayload.length,
            mediaType: "application/cbor",
            path: foreignDescriptorSource,
            sha256: hex(sha256(foreignDescriptorPayload))
          },
          ref: mappingDescriptorText
        });
      }
      const importerProfileText = variant === "wrong-family"
        ? "content-policy.test/opaque@1"
        : "importer.test/fixture-adapter@1";
      const importerProfileRef = variant === "wrong-family"
        ? contentProfile
        : profile("importer.test", "fixture-adapter");
      const sourceNamespaceDigest = digest(0x71);
      const sourceIdentityDigest = digest(0x72);
      const mappedFileId = id128(0x73);
      const mappingKey = sha256(Buffer.concat([
        IMPORT_MAPPING_DOMAIN,
        uint16be(1),
        cbor([mappingDescriptorRef, importerProfileRef, sourceNamespaceDigest, sourceIdentityDigest])
      ]));
      const mappedState = map([
        [0, ["prior-import"]], [1, 2], [2, mappedFileId], [3, 2],
        [4, manifestRef], [5, repeatedBytes.length], [6, contentProfile]
      ]);
      const importProof = map([[0, mappingDescriptorRef], [1, 2], [2, mappingKey]]);
      const importOperation = map([[0, 0], [1, 1], [3, mappedState], [5, importProof]]);
      const evidencePayload = cbor(metadata(4, [[16, mappingDescriptorRef], [18, [importOperation]]]));
      const evidenceId = objectDigest(4, evidencePayload);
      const evidenceText = objectText("change-set", evidenceId);
      const evidenceSource = `scenarios/objects/${item.id}/import-evidence-change.cbor`;
      files.set(evidenceSource, evidencePayload);
      expectations.set(evidenceSource, acceptSchema);
      context.objectLookup.push({
        artifact: {
          bytes: evidencePayload.length,
          mediaType: "application/cbor",
          path: evidenceSource,
          sha256: hex(sha256(evidencePayload))
        },
        ref: evidenceText
      });
      context.importMappings = [{
        descriptor: mappingDescriptorText,
        fileId: hex(mappedFileId),
        importerProfile: importerProfileText,
        mappingKey: hex(mappingKey),
        sourceIdentityDigest: hex(sourceIdentityDigest),
        sourceNamespaceDigest: hex(sourceNamespaceDigest),
        state: "materialized"
      }];
      context.lifetimeRecords = [{
        fileId: hex(mappedFileId),
        firstChangeSet: evidenceText,
        firstOperation: 0,
        importMappingKey: hex(mappingKey),
        origin: "import"
      }];
      priorImportFixture = {
        importRequest: {
          importerProfile: importerProfileText,
          requestedFileId: hex(mappedFileId),
          sourceIdentityDigest: hex(sourceIdentityDigest),
          sourceNamespaceDigest: hex(sourceNamespaceDigest)
        },
        surface
      };
      if (surface === "candidate") {
        // The carried candidate is the ordinary format root. Its ChangeSet
        // performs four native creates, so high-level candidate validation
        // must receive the exact pending lifetime additions rather than an
        // empty surrogate context.
        context.workingLifetimeAdditions = structuredClone(baseRootWorkingLifetimeAdditions);
      }
    }
    if (item.id === "fileid-concurrent-loser") {
      context.workingLifetimeAdditions.push({ fileId: hex(id128(0x21)), firstChangeSet: changeText, firstOperation: 0, origin: "native-create" });
    }
    const transitionAlias = {
      "fileid-create-reuse": "transition-create",
      "fileid-copy-reuse": "transition-copy",
      "fileid-delete-recreate-reuse": "transition-create",
      "fileid-move-rename-preserves": "transition-move",
      "fileid-copy-fresh": "transition-copy",
      "fileid-ancestral-restore": "transition-restore",
      "group-create": "transition-group-create",
      "group-update": "transition-group-update",
      "group-delete": "transition-group-delete",
      "replay-missing-reference-before-profile-lifecycle": "transition-create",
      "replay-entry-target-wrong-kind": "transition-create",
      "replay-restore-missing-source-tree-before-profile-lifecycle": "transition-restore",
      "replay-restore-missing-proof-descriptor-before-cross-repository": "transition-restore",
      "repository-candidate-verify-content-false": "transition-create",
      "repository-candidate-content-missing": "transition-create",
      "tree-groups-combined-memory": "transition-group-create"
    }[item.id];
    const distinctTransitionCarrier = new Set([
      "replay-entry-target-wrong-kind",
      "replay-missing-reference-before-profile-lifecycle",
      "replay-restore-missing-source-tree-before-profile-lifecycle",
      "replay-restore-missing-proof-descriptor-before-cross-repository",
      "repository-candidate-verify-content-false",
      "repository-candidate-content-missing"
    ]).has(item.id);
    const materialized = materializeClosureAccumulatorScenario(item) ?? (transitionAlias
      ? materializeTransitionScenario({ ...item, ...(distinctTransitionCarrier ? { carrierId: item.id } : {}), id: transitionAlias })
      : materializeTransitionScenario(item)) ?? materializeHistoryScenario(item) ?? materializeManifestScenario(item) ?? materializeSemanticObjectScenario(item) ?? materializeConflictScenario(item) ?? materializeTreeScenario(item);
    if (materialized) Object.assign(context, materialized.context);
    if (item.id === "replay-missing-reference-before-profile-lifecycle" ||
        item.id === "conflict-missing-reference-before-profile-lifecycle") {
      context.objectLookup = context.objectLookup.filter((entry) =>
        entry.ref !== objectText("content-manifest", manifestId));
    }
    if (item.id === "replay-restore-missing-source-tree-before-profile-lifecycle") {
      context.objectLookup = context.objectLookup.filter((entry) =>
        !entry.artifact.path.endsWith("/source-tree-root.cbor"));
    }
    if (["repository-candidate-content-missing", "shelf-content-missing"].includes(item.id)) {
      context.objectLookup = context.objectLookup.filter((entry) =>
        entry.ref !== objectText("chunk", chunkId));
      context.verifyContent = true;
    }
    if (["repository-candidate-verify-content-false", "shelf-verify-content-false"].includes(item.id)) {
      context.verifyContent = false;
    }
    if (item.id.startsWith("fileid-lifetime-first-change-")) {
      context.repositoryDescriptor = descriptorText;
      let firstChangeSet = objectText("change-set", changeId);
      if (item.id.endsWith("-missing")) firstChangeSet = objectText("change-set", digest(0xed));
      else if (item.id.endsWith("-wrong-kind")) firstChangeSet = objectText("content-manifest", manifestId);
      else if (item.id.endsWith("-object-id-mismatch")) {
        firstChangeSet = objectText("change-set", digest(0xee));
        context.objectLookup.push({
          artifact: {
            bytes: changePayload.length,
            mediaType: "application/cbor",
            path: "objects/04-change-set.cbor",
            sha256: hex(sha256(changePayload))
          },
          ref: firstChangeSet
        });
      } else if (item.id.endsWith("-bad-schema")) {
        firstChangeSet = lifetimeBadSchemaText;
        context.objectLookup.push({
          artifact: {
            bytes: lifetimeBadSchemaPayload.length,
            mediaType: "application/cbor",
            path: lifetimeBadSchemaSource,
            sha256: hex(sha256(lifetimeBadSchemaPayload))
          },
          ref: firstChangeSet
        });
      } else if (item.id.endsWith("-profile-lifecycle")) {
        firstChangeSet = lifetimeProfileChangeText;
        context.objectLookup.push({
          artifact: {
            bytes: lifetimeProfileChangePayload.length,
            mediaType: "application/cbor",
            path: lifetimeProfileChangeSource,
            sha256: hex(sha256(lifetimeProfileChangePayload))
          },
          ref: firstChangeSet
        });
      }
      context.lifetimeRecords = [{
        fileId: hex(rootStates[0].get(2)),
        firstChangeSet,
        firstOperation: 0,
        origin: "native-create"
      }];
    }
    if (item.id === "mode-manifest-verify-missing-reference-before-profile-lifecycle") {
      context.objectLookup = [...commonLookup, {
        artifact: lifecycleManifestMissingChunkArtifact,
        ref: lifecycleManifestMissingChunkRefText
      }];
    }
    if (item.id === "mode-tree-file-order-before-descriptor-mismatch") {
      const foreign = lifecycleDescriptors.get("profile-state.test/conformance@1");
      const payload = files.get(foreign.descriptorSource);
      context.objectLookup = [...commonLookup, {
        artifact: {
          bytes: payload.length,
          mediaType: mediaType(foreign.descriptorSource),
          path: foreign.descriptorSource,
          sha256: hex(sha256(payload))
        },
        ref: foreign.objectRef
      }];
    }
    if (materialized && ["fileid-create-reuse", "fileid-copy-reuse", "fileid-delete-recreate-reuse"].includes(item.id)) {
      const candidateChangeEntry = context.objectLookup.find((entry) => entry.artifact.path.endsWith("/candidate-change.cbor"));
      assert(candidateChangeEntry);
      const reused = transitionAlias === "transition-copy" ? id128(0x22) : id128(0x21);
      context.lifetimeRecords.push({ fileId: hex(reused), firstChangeSet: candidateChangeEntry.ref, firstOperation: 0, origin: transitionAlias === "transition-copy" ? "native-copy" : "native-create" });
      context.workingLifetimeAdditions = [];
    }
    const lookupRefBySuffix = (suffix) => context.objectLookup.find((entry) =>
      entry.artifact.path.endsWith(suffix))?.ref;
    let repositoryRouteRequest;
    if (item.operation === "validate-repository-route") {
      const commonRoute = {
        authorityContext: "scenario.context",
        schema: "ogvcs.repository-format.v1.repository-route-input.v1"
      };
      if (materialized?.routeRequest) {
        repositoryRouteRequest = { ...commonRoute, ...materialized.routeRequest };
      } else if (item.id.startsWith("fileid-lifetime-first-change-")) {
        repositoryRouteRequest = {
          ...commonRoute,
          api: "validate-lifetime-and-imports",
          repositoryDescriptor: context.repositoryDescriptor
        };
      } else if (priorImportFixture) {
        repositoryRouteRequest = priorImportFixture.surface === "lifetime" ? {
          ...commonRoute,
          api: "validate-lifetime-and-imports",
          repositoryDescriptor: context.repositoryDescriptor
        } : priorImportFixture.surface === "request" ? {
          ...commonRoute,
          api: "validate-import-request",
          importRequest: priorImportFixture.importRequest,
          repositoryDescriptor: context.repositoryDescriptor
        } : {
          ...commonRoute,
          api: "validate-repository-candidate",
          callerVerifyContent: true,
          candidateSnapshot: context.candidateSnapshot,
          forceContentComplete: true
        };
      } else if (item.id.startsWith("tree-")) {
        repositoryRouteRequest = {
          ...commonRoute,
          api: "expand-tree",
          caseMode: context.caseMode,
          repositoryDescriptor: context.repositoryDescriptor,
          tree: materialized.candidate.refText,
          verifyContent: true
        };
      } else if (["replay-entry-target-wrong-kind", "replay-missing-reference-before-profile-lifecycle", "replay-restore-missing-source-tree-before-profile-lifecycle", "replay-restore-missing-proof-descriptor-before-cross-repository"].includes(item.id)) {
        repositoryRouteRequest = {
          ...commonRoute,
          api: "replay-change-set",
          baseState: {
            groups: "empty",
            tree: lookupRefBySuffix(item.id.startsWith("replay-restore-")
              ? "/deleted-tree-root.cbor"
              : "/base-tree-root.cbor")
          },
          changeSet: lookupRefBySuffix("/candidate-change.cbor"),
          repositoryDescriptor: context.repositoryDescriptor
        };
      } else if (item.id.startsWith("conflict-entry-target-")) {
        repositoryRouteRequest = {
          ...commonRoute,
          api: "validate-conflict-set",
          conflictSet: materialized.candidate.refText,
          repositoryDescriptor: context.repositoryDescriptor
        };
      } else if (item.id.startsWith("provenance-cycle-branch-before-missing-input-")) {
        const cycleRoot = lookupRefBySuffix("/cycle-root.cbor");
        const missingRoot = lookupRefBySuffix("/missing-root.cbor");
        repositoryRouteRequest = {
          ...commonRoute,
          api: "validate-provenance-graph",
          forbidden: [objectText("content-manifest", manifestId)],
          roots: item.id.endsWith("-forward")
            ? [cycleRoot, missingRoot]
            : [missingRoot, cycleRoot]
        };
      } else if (item.id === "provenance-missing-reference-before-profile-lifecycle") {
        repositoryRouteRequest = {
          ...commonRoute,
          api: "validate-provenance-graph",
          forbidden: [],
          roots: [lookupRefBySuffix("/provenance.cbor")]
        };
      } else if (["repository-candidate-verify-content-false", "repository-candidate-content-missing", "repository-candidate-missing-tree-before-second-root", "repository-candidate-missing-change-before-profile-lifecycle", "repository-candidate-missing-change-base"].includes(item.id)) {
        repositoryRouteRequest = {
          ...commonRoute,
          api: "validate-repository-candidate",
          candidateSnapshot: context.candidateSnapshot,
          callerVerifyContent: item.id.endsWith("verify-content-false") ? false : true,
          forceContentComplete: true
        };
      } else if (["snapshot-graph-missing-change-before-profile-lifecycle", "snapshot-graph-missing-descriptor-before-descriptor-mismatch"].includes(item.id) || item.id.startsWith("snapshot-graph-second-root-before-missing-parent-")) {
        repositoryRouteRequest = {
          ...commonRoute,
          api: "validate-snapshot-graph",
          candidateSnapshot: context.candidateSnapshot,
          designatedRoot: context.designatedRoot,
          repositoryDescriptor: context.repositoryDescriptor
        };
      } else if (["shelf-verify-content-false", "shelf-content-missing", "shelf-missing-previous-before-chain-invalid", "shelf-unrelated-known-schema-object-ignored", "shelf-unrelated-profile-object-ignored"].includes(item.id)) {
        repositoryRouteRequest = {
          ...commonRoute,
          api: "validate-shelf-revision",
          callerVerifyContent: item.id.endsWith("verify-content-false") ? false : true,
          forceContentComplete: true,
          shelfRevision: materialized.candidate.refText
        };
      }
      assert(repositoryRouteRequest, `${item.id}: missing exact public repository-route request`);
      for (const mutation of repositoryRouteRequest.lookupMutations ?? []) {
        assert.equal(mutation.action, "replace-payload-preserve-reference",
          `${item.id}: unsupported repository-route lookup mutation`);
        assert(context.objectLookup.some((entry) => entry.ref === mutation.reference),
          `${item.id}: lookup mutation reference is absent from the authenticated lookup`);
        assert(files.has(mutation.sourceArtifact),
          `${item.id}: lookup mutation source is absent from the authenticated vector tree`);
      }
    }
    let operationRequestArtifact;
    const operationSupplementalArtifacts = [];
    if (repositoryRouteRequest) {
      const requestBytes = stableJson(repositoryRouteRequest);
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
      for (const mutation of repositoryRouteRequest.lookupMutations ?? []) {
        const sourceBytes = files.get(mutation.sourceArtifact);
        assert(sourceBytes, `${item.id}: missing repository-route lookup mutation source`);
        operationSupplementalArtifacts.push({
          bytes: sourceBytes.length,
          mediaType: mediaType(mutation.sourceArtifact),
          path: mutation.sourceArtifact,
          sha256: hex(sha256(sourceBytes))
        });
      }
    }
    if (["allocate-file-id", "import-file-id"].includes(item.operation)) {
      const request = item.operation === "import-file-id" ? {
        importerProfile: "importer.test/fixture-adapter@1",
        operation: item.operation,
        requestedFileId: hex(id128(item.id === "fileid-import-conflict" ? 0x54 : 0x53)),
        sourceIdentityDigest: hex(digest(0x52)),
        sourceNamespaceDigest: hex(digest(0x51))
      } : {
        candidateFileId: hex(id128(0x21)),
        operation: item.operation,
        phase: item.id === "fileid-concurrent-loser" ? "finalize" : "generate",
        retryLimit: item.code === "FILEID_ALLOCATION_EXHAUSTED" ? 16 : 1
      };
      if (item.id === "error-fileid-allocation-exhausted") {
        request.entropyRecipe = {
          candidateFileIds: [hex(id128(0x21))],
          exhaustedBehavior: "repeat-last-candidate",
          isConsumed: [hex(id128(0x21))]
        };
      }
      if (item.id === "error-fileid-entropy-unavailable") {
        request.entropyRecipe = {
          failAtCall: 0,
          failure: "operating-system-entropy-unavailable"
        };
      }
      const requestBytes = stableJson({ schema: "ogvcs.repository-format.v1.fileid-operation-input.v1", ...request });
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
    }
    if (item.operation === "write-content-manifest") {
      const request = manifestWriterCases.get(item.id);
      assert(request, `${item.id}: missing manifest writer recipe`);
      const requestBytes = stableJson(request);
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
      const providerSources = request.chunkArtifacts ??
        [request.chunkArtifact];
      for (const source of [...new Set(providerSources)]) {
        const chunkBytes = files.get(source);
        assert(chunkBytes, `${item.id}: missing manifest writer chunk artifact`);
        operationSupplementalArtifacts.push({ bytes: chunkBytes.length, mediaType: mediaType(source), path: source, sha256: hex(sha256(chunkBytes)) });
      }
      if (request.registryFixture) {
        const fixtureBytes = files.get(request.registryFixture.path);
        assert(fixtureBytes, `${item.id}: missing manifest writer registry fixture`);
        operationSupplementalArtifacts.push({ bytes: fixtureBytes.length, mediaType: mediaType(request.registryFixture.path), path: request.registryFixture.path, sha256: hex(sha256(fixtureBytes)) });
      }
    }
    if (item.operation === "write-tree") {
      const request = treeWriterCases.get(item.id);
      assert(request, `${item.id}: missing tree writer recipe`);
      const requestBytes = stableJson(request);
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
      if (request.registryFixture) {
        const fixtureBytes = files.get(request.registryFixture.path);
        assert(fixtureBytes, `${item.id}: missing tree writer registry fixture`);
        operationSupplementalArtifacts.push({ bytes: fixtureBytes.length, mediaType: mediaType(request.registryFixture.path), path: request.registryFixture.path, sha256: hex(sha256(fixtureBytes)) });
      }
    }
    if (item.operation === "write-logical-bundle") {
      const request = bundleWriterCases.get(item.id);
      assert(request, `${item.id}: missing logical-bundle writer recipe`);
      const requestBytes = stableJson(request);
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
      const sourceBytes = files.get(request.source);
      assert(sourceBytes, `${item.id}: missing logical-bundle writer source`);
      operationSupplementalArtifacts.push({ bytes: sourceBytes.length, mediaType: mediaType(request.source), path: request.source, sha256: hex(sha256(sourceBytes)) });
      for (const mutation of request.objectMutations) {
        if (!mutation.sourceArtifact) continue;
        const artifactBytes = files.get(mutation.sourceArtifact);
        assert(artifactBytes, `${item.id}: missing logical-bundle writer mutation source artifact`);
        operationSupplementalArtifacts.push({ bytes: artifactBytes.length, mediaType: mediaType(mutation.sourceArtifact), path: mutation.sourceArtifact, sha256: hex(sha256(artifactBytes)) });
      }
      for (const logical of request.logicalRecordInputs ?? []) {
        const artifactBytes = files.get(logical.sourceArtifact);
        assert(artifactBytes, `${item.id}: missing logical-bundle writer logical-record source artifact`);
        operationSupplementalArtifacts.push({ bytes: artifactBytes.length, mediaType: mediaType(logical.sourceArtifact), path: logical.sourceArtifact, sha256: hex(sha256(artifactBytes)) });
      }
      if (request.registryFixture) {
        const fixtureBytes = files.get(request.registryFixture.path);
        assert(fixtureBytes, `${item.id}: missing logical-bundle writer registry fixture`);
        operationSupplementalArtifacts.push({ bytes: fixtureBytes.length, mediaType: mediaType(request.registryFixture.path), path: request.registryFixture.path, sha256: hex(sha256(fixtureBytes)) });
      }
    }
    if (item.operation === "validate-operation-mode") {
      const request = operationModeCases.get(item.id);
      assert(request, `${item.id}: missing operation mode recipe`);
      if (request.objectLookup === "scenario.context.objectLookup") {
        assert(context.objectLookup.length > 0, `${item.id}: real route requires a materialized object lookup`);
        for (const field of ["repositoryDescriptor", "candidateSnapshot", "designatedRoot", "tree", "manifest"]) {
          if (request[field] !== undefined) {
            assert(context.objectLookup.some((entry) => entry.ref === request[field]),
              `${item.id}: ${field} is absent from the authenticated object lookup`);
          }
        }
      }
      if (request.repositoryDescriptor !== undefined) context.repositoryDescriptor = request.repositoryDescriptor;
      if (request.candidateSnapshot !== undefined) context.candidateSnapshot = request.candidateSnapshot;
      if (request.designatedRoot !== undefined) context.designatedRoot = request.designatedRoot;
      if (request.importContext !== undefined) {
        context.importMappings = structuredClone(request.importContext.importMappings);
        context.lifetimeRecords = structuredClone(request.importContext.lifetimeRecords);
        context.workingLifetimeAdditions = structuredClone(request.importContext.workingLifetimeAdditions);
      }
      if (request.lifetimeContext !== undefined) {
        context.importMappings = structuredClone(request.lifetimeContext.importMappings);
        context.lifetimeRecords = structuredClone(request.lifetimeContext.lifetimeRecords);
        context.workingLifetimeAdditions = structuredClone(request.lifetimeContext.workingLifetimeAdditions);
      }
      const requestBytes = stableJson(request);
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
      if (request.source) {
        const sourceBytes = files.get(request.source);
        assert(sourceBytes, `${item.id}: missing operation mode source`);
        operationSupplementalArtifacts.push({ bytes: sourceBytes.length, mediaType: mediaType(request.source), path: request.source, sha256: hex(sha256(sourceBytes)) });
      }
      if (request.sources) {
        assert(Array.isArray(request.sources) && request.sources.length === request.lookupOrder?.length,
          `${item.id}: ordered lookup sources differ from the authenticated reference order`);
        for (const [index, source] of request.sources.entries()) {
          const sourceBytes = files.get(source);
          assert(sourceBytes, `${item.id}: missing ordered lookup source ${source}`);
          const artifact = { bytes: sourceBytes.length, mediaType: mediaType(source), path: source, sha256: hex(sha256(sourceBytes)) };
          operationSupplementalArtifacts.push(artifact);
          context.objectLookup.push({ artifact, ref: request.lookupOrder[index] });
        }
      }
      if (request.registryFixture) {
        const fixtureBytes = files.get(request.registryFixture.path);
        assert(fixtureBytes, `${item.id}: missing operation mode registry fixture`);
        operationSupplementalArtifacts.push({ bytes: fixtureBytes.length, mediaType: mediaType(request.registryFixture.path), path: request.registryFixture.path, sha256: hex(sha256(fixtureBytes)) });
      }
    }
    if (item.operation === "validate-path-profile-decision") {
      const request = pathProfileDecisionCases.get(item.id);
      assert(request, `${item.id}: missing path-profile decision recipe`);
      const requestBytes = stableJson(request);
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
    }
    if (item.operation === "validate-tree-groups-memory") {
      const request = treeGroupsMemoryCases.get(item.id);
      assert(request, `${item.id}: missing tree/groups memory recipe`);
      const requestBytes = stableJson(request);
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
    }
    if (item.operation === "validate-resource-reservation") {
      const request = resourceReservationCases.get(item.id);
      assert(request, `${item.id}: missing resource reservation recipe`);
      if (request.cluster === "conflict-group-indexes") {
        const fixture = materializeConflictScenario({ ...item, code: undefined, id: "conflict-choice-base", layer: 3, stage: undefined });
        assert(fixture, `${item.id}: missing valid conflict fixture`);
        context.objectLookup = fixture.context.objectLookup;
        context.lifetimeRecords = fixture.context.lifetimeRecords;
        context.repositoryDescriptor = fixture.context.repositoryDescriptor;
        assert(context.objectLookup.some((entry) => entry.ref === request.conflictFixture.reference),
          `${item.id}: valid conflict fixture reference is absent from the authenticated lookup`);
      }
      if (request.cluster === "replay-base") {
        assert.equal(request.changeSet, replayBaseChangeLookup.ref);
        assert.equal(request.baseState?.tree, operationModeTree);
        context.objectLookup = [...context.objectLookup, replayBaseChangeLookup];
      }
      if (request.cluster === "lookup-scratch-counter-rollback") {
        context.objectLookup = [...context.objectLookup, {
          artifact: {
            bytes: scratchRecoveryTreePayload.length,
            mediaType: "application/cbor",
            path: "scenarios/objects/resource-lookup-scratch-counter-rollback/recovery-tree.cbor",
            sha256: hex(sha256(scratchRecoveryTreePayload))
          },
          ref: scratchRecoveryTreeText
        }];
      }
      if (request.cluster === "tree-stream-transaction-composite-memory") {
        context.objectLookup = [...context.objectLookup, {
          artifact: {
            bytes: scratchRecoveryTreePayload.length,
            mediaType: "application/cbor",
            path: "scenarios/objects/resource-lookup-scratch-counter-rollback/recovery-tree.cbor",
            sha256: hex(sha256(scratchRecoveryTreePayload))
          },
          ref: scratchRecoveryTreeText
        }];
      }
      if (request.cluster === "lookup-edge-counter-rollback") {
        context.objectLookup = [...context.objectLookup, {
          artifact: {
            bytes: edgeRecoveryManifestPayload.length,
            mediaType: "application/cbor",
            path: "scenarios/objects/resource-lookup-edge-counter-rollback/recovery-manifest.cbor",
            sha256: hex(sha256(edgeRecoveryManifestPayload))
          },
          ref: edgeRecoveryManifestText
        }];
      }
      const requestBytes = stableJson(request);
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
      if (request.registryFixture) {
        const fixtureBytes = files.get(request.registryFixture.path);
        assert(fixtureBytes, `${item.id}: missing resource registry fixture`);
        operationSupplementalArtifacts.push({
          bytes: fixtureBytes.length,
          mediaType: mediaType(request.registryFixture.path),
          path: request.registryFixture.path,
          sha256: hex(sha256(fixtureBytes))
        });
      }
    }
    if (item.operation === "validate-typed-reference-authority") {
      const request = typedReferenceAuthorityCases.get(item.id);
      assert(request, `${item.id}: missing typed-reference authority recipe`);
      const requestBytes = stableJson(request);
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
    }
    if (item.operation === "canonical-scan" && genericCanonicalScanCases.has(item.id)) {
      const request = genericCanonicalScanCases.get(item.id);
      const requestBytes = stableJson(request);
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
      const sourceBytes = files.get(request.source);
      assert(sourceBytes, `${item.id}: missing generic canonical-scan source`);
      operationSupplementalArtifacts.push({ bytes: sourceBytes.length, mediaType: mediaType(request.source), path: request.source, sha256: hex(sha256(sourceBytes)) });
    }
    if (item.id === "bundle-export-claim") {
      const requestBytes = stableJson({
        claim: "fidelity-export",
        operation: "validate-bundle-claim",
        schema: "ogvcs.repository-format.v1.bundle-claim-input.v1"
      });
      const relative = `scenarios/operations/${item.id}.json`;
      files.set(relative, requestBytes);
      operationRequestArtifact = { bytes: requestBytes.length, mediaType: "application/json", path: relative, sha256: hex(sha256(requestBytes)) };
    }
    let bundleInputArtifact;
    let bundleMaterialization = "none";
    if (item.operation === "validate-bundle") {
      const explicitBundleByScenario = {
        "bundle-closure-extra": "logical-bundles/invalid-closure-extra.cborseq",
        "bundle-closure-missing": "logical-bundles/invalid-closure-missing.cborseq",
        "bundle-duplicate": "logical-bundles/invalid-duplicate-identity.cborseq",
        "error-logical-record-type-unsupported": "logical-bundles/invalid-logical-record-type.cborseq",
        "bundle-sort-order": "logical-bundles/invalid-section-order.cborseq",
        "bundle-trailer": "logical-bundles/invalid-trailer-mismatch.cborseq",
        "bundle-wrong-kind": "logical-bundles/invalid-reference-wrong-kind.cborseq"
      };
      const exactRelative = explicitBundleByScenario[item.id] ?? generatedBundleInputs.get(item.id) ??
        configuredResourceCases.get(item.id)?.source;
      const relative = exactRelative ?? "logical-bundles/valid-supplied-closure.cborseq";
      const bytes = files.get(relative);
      assert(bytes, `missing bundle input ${relative}`);
      bundleInputArtifact = { bytes: bytes.length, mediaType: "application/cbor-seq", path: relative, sha256: hex(sha256(bytes)) };
      bundleMaterialization = configuredResourceCases.has(item.id)
        ? "executable-configured-resource-constructor"
        : exactRelative
          ? "byte-materialized-bundle-case-specific"
          : "virtual-constructor-shared-bundle-baseline";
    }
    let abstractGraphArtifact;
    if (item.operation === "validate-abstract-reference-graph") {
      const provenanceGraph = item.id.startsWith("provenance-");
      const graph = {
        assumedValidation: "canonical-framing-schema-and-identity-prevalidated",
        graphKind: provenanceGraph ? "provenance-input" : "snapshot-parent",
        nodes: [
          { edges: [{ kind: provenanceGraph ? "provenance-input" : "parent", target: "node-b" }], id: "node-a", type: provenanceGraph ? "provenance" : "snapshot" },
          { edges: [{ kind: provenanceGraph ? "provenance-input" : "parent", target: "node-a" }], id: "node-b", type: provenanceGraph ? "provenance" : "snapshot" }
        ],
        roots: ["node-a"],
        schemaVersion: "ogvcs.repository-format/abstract-reference-graph/v1"
      };
      const graphBytes = stableJson(graph);
      const relative = `scenarios/graphs/${item.id}.json`;
      files.set(relative, graphBytes);
      abstractGraphArtifact = { bytes: graphBytes.length, mediaType: "application/vnd.opengamevcs.abstract-reference-graph+json", path: relative, sha256: hex(sha256(graphBytes)) };
      context.objectLookup = [];
    }
    let directInputArtifact;
    const registryRecipeScenarios = new Set([
      "registry-conformance-mode", "registry-conformance-production", "registry-deprecated-read",
      "registry-deprecated-write", "registry-duplicate", "registry-invalid-entry",
      "registry-ratified-read-write", "registry-reassigned", "registry-reserved", "registry-unknown-profile"
    ]);
    const directInputPath = {
      "malformed-complete-corpus": "malformed/index.json",
      "mutation-systematic-single-bit": "mutations/single-bit.json",
      "registry-unknown-extension-preserve": "registries/unknown-optional-extension.cbor",
      "registry-unknown-feature-forward": "registries/unknown-required-feature.cbor",
      "truncation-every-prefix": "mutations/truncation.json",
    }[item.id] ?? (registryRecipeScenarios.has(item.id) ? "registries/index.json" : undefined);
    if (directInputPath) {
      const bytes = files.get(directInputPath);
      directInputArtifact = { bytes: bytes.length, mediaType: mediaType(directInputPath), path: directInputPath, sha256: hex(sha256(bytes)) };
    }
    let stableErrorArtifact;
    if (item.code && !abstractGraphArtifact && !operationRequestArtifact && !bundleInputArtifact && !materialized && !directInputArtifact) {
      const isolatedStableErrorArtifactPath = {
        "error-schema-field-unknown": "schema/invalid-unknown-field.cbor"
      }[item.id];
      const match = isolatedStableErrorArtifactPath === undefined
        ? [...expectations.entries()].find(([_relative, expected]) => expected?.code === item.code)
        : [isolatedStableErrorArtifactPath, expectations.get(isolatedStableErrorArtifactPath)];
      if (match) {
        const [relative] = match;
        const bytes = files.get(relative);
        stableErrorArtifact = { bytes: bytes.length, mediaType: mediaType(relative), path: relative, sha256: hex(sha256(bytes)) };
      }
    }
    context.objectLookup.sort((a, b) => a.ref.localeCompare(b.ref, "en"));
    context.lifetimeRecords.sort((a, b) => a.fileId.localeCompare(b.fileId, "en"));
    context.workingLifetimeAdditions.sort((a, b) => a.fileId.localeCompare(b.fileId, "en"));
    context.importMappings.sort((a, b) => a.mappingKey.localeCompare(b.mappingKey, "en"));
    context.roots.sort((a, b) => `${a.kind}\0${a.identity}\0${a.roleProfile ?? ""}`.localeCompare(`${b.kind}\0${b.identity}\0${b.roleProfile ?? ""}`, "en"));
    const inventoryOnlyScalePlan = ["manifest-one-tib", "tree-million-entries"].includes(item.id);
    const outputState = {
      resultFamily: item.resultFamily,
      rootState: item.code ? "unchanged-no-trusted-output" : inventoryOnlyScalePlan ? "inventory-only-no-executed-output" : "accepted-exact-constructor-result",
      scenarioId: item.id,
      stableOutputIdentity: inventoryOnlyScalePlan ? `inventory-only:not-executed:${item.id}` : materialized?.resultIdentity ?? outputIdsByFamily[item.resultFamily] ?? objectText("snapshot", snapshotId)
    };
    const outputBytes = stableJson({ schema: "ogvcs.repository-format.v1.scenario-output.v1", ...outputState });
    const outputRelative = `scenarios/outputs/${item.id}.json`;
    if (!item.code) files.set(outputRelative, outputBytes);
    const state = (segments, fileId, kind = 2, mode = 2) => map([
      [0, segments], [1, kind], [2, fileId], [3, mode], [4, manifestRef], [5, repeatedBytes.length], [6, contentProfile]
    ]);
    const regularBefore = state(["asset"], id128(0x21));
    const operationValues = {
      "transition-create": map([[0, 0], [1, 1], [3, regularBefore], [5, map([[0, descriptorRef], [1, 1]])]]),
      "transition-modify": map([[0, 0], [1, 2], [2, regularBefore], [3, state(["asset"], id128(0x21), 3, 3)]]),
      "transition-copy": map([[0, 0], [1, 3], [3, state(["asset-copy"], id128(0x22))], [4, regularBefore], [5, map([[0, descriptorRef], [1, 1]])]]),
      "transition-move": map([[0, 0], [1, 4], [2, state(["dir", "asset"], id128(0x21))], [3, state(["other", "asset"], id128(0x21))]]),
      "transition-rename": map([[0, 0], [1, 5], [2, regularBefore], [3, state(["asset-renamed"], id128(0x21))]]),
      "transition-delete": map([[0, 0], [1, 6], [2, regularBefore]]),
      "transition-restore": map([[0, 0], [1, 7], [3, regularBefore], [6, map([[0, descriptorRef], [1, snapshotRef], [2, ["asset"]], [3, snapshotRef]])]]),
      "transition-group-create": map([[0, 0], [1, 8], [8, assetGroup]]),
      "transition-group-update": map([[0, 0], [1, 9], [7, assetGroup], [8, new Map(assetGroup).set(4, [map([[0, externalProfile], [1, Buffer.from("external-key-updated", "ascii")]])])]]),
      "transition-group-delete": map([[0, 0], [1, 10], [7, assetGroup]]),
      "transition-merge-resolution": map([[0, 0], [1, 11], [9, conflictRows[7].record.get(0)], [10, 1], [11, regularBefore]])
    };
    const constructorValues = {};
    if (repositoryRouteRequest) constructorValues.repositoryRoute = repositoryRouteRequest;
    if (operationValues[item.id]) constructorValues.operation = diagnosticValue(operationValues[item.id]);
    if (configuredResourceCases.has(item.id)) {
      constructorValues.configuredResource = configuredResourceCases.get(item.id);
    }
    if (manifestWriterCases.has(item.id)) {
      constructorValues.manifestWriter = manifestWriterCases.get(item.id);
    }
    if (treeWriterCases.has(item.id)) {
      constructorValues.treeWriter = treeWriterCases.get(item.id);
    }
    if (bundleWriterCases.has(item.id)) {
      constructorValues.bundleWriter = bundleWriterCases.get(item.id);
    }
    if (operationModeCases.has(item.id)) {
      constructorValues.operationMode = operationModeCases.get(item.id);
    }
    if (pathProfileDecisionCases.has(item.id)) {
      constructorValues.pathProfileDecision = pathProfileDecisionCases.get(item.id);
    }
    if (treeGroupsMemoryCases.has(item.id)) {
      constructorValues.treeGroupsMemory = treeGroupsMemoryCases.get(item.id);
    }
    if (resourceReservationCases.has(item.id)) {
      constructorValues.resourceReservation = resourceReservationCases.get(item.id);
    }
    if (typedReferenceAuthorityCases.has(item.id)) {
      constructorValues.typedReferenceAuthority = typedReferenceAuthorityCases.get(item.id);
    }
    if (genericCanonicalScanCases.has(item.id)) {
      constructorValues.genericCanonicalScan = genericCanonicalScanCases.get(item.id);
    }
    if (fixtureAdapterCases.has(item.id)) {
      constructorValues.fixtureAdapter = fixtureAdapterCases.get(item.id);
    }
    if (registryRecipeScenarios.has(item.id)) constructorValues.registryCase = {
      path: "registries/index.json",
      scenarioId: item.id
    };
    const limitMatch = /^limit-(.+)-(max|max-plus-one)$/.exec(item.id);
    if (limitMatch) {
      constructorValues.virtualLimit = {
        case: limitMatch[1],
        recipe: "limits/virtual-constructors.json",
        variant: limitMatch[2] === "max" ? "maximum" : "maximum-plus-one"
      };
    }
    const enumeratedRecipe = {
      "malformed-complete-corpus": { path: "malformed/index.json", totalCases: malformedRows.length },
      "mutation-systematic-single-bit": { path: "mutations/single-bit.json", totalCases: totalSingleBitMutations },
      "truncation-every-prefix": { path: "mutations/truncation.json", totalCases: totalTruncationCases }
    }[item.id];
    if (enumeratedRecipe) constructorValues.enumeratedRecipe = enumeratedRecipe;
    const parentMatch = /^history-(zero|one|two|eight)-parent(?:-root)?$/.exec(item.id);
    if (parentMatch) {
      const count = { zero: 0, one: 1, two: 2, eight: 8 }[parentMatch[1]];
      constructorValues.orderedParents = diagnosticValue(Array.from({ length: count }, (_, index) => objectRef(7, sha256(Buffer.concat([seed, Buffer.from([index])])))));
    }
    if (item.id === "tree-million-entries") {
      constructorValues.scalePlan = {
        cborSizingRules: {
          containerEncoding: "deterministic CBOR definite-length map and array headers use the shortest additional-information width for the mathematical element count",
          entryEncoding: "each entry is the deterministic-CBOR map {0:basename,1:2,2:fileId,3:2,4:target,5:logicalBytes,6:contentProfile}; map keys are encoded in ascending integer order",
          objectEnvelope: "the tree payload is the deterministic-CBOR map {0:1,1:3,2:[],16:repositoryDescriptor,17:entries}; map keys are encoded in ascending integer order",
          textAndBytes: "UTF-8 text and byte strings use definite lengths and the shortest deterministic-CBOR length header; no indefinite-length item is permitted"
        },
        expectedStreamingIdentity: null,
        fixedFields: {
          contentProfile: diagnosticValue(contentProfile),
          entryKind: 2,
          entryLogicalBytes: String(repeatedBytes.length),
          entryMode: 2,
          entryTarget: objectText("content-manifest", manifestId),
          formatVersion: 1,
          objectKind: 3,
          optionalExtensions: [],
          repositoryDescriptor: objectText("repository-descriptor", descriptorId)
        },
        recurrence: {
          basename: "for i in [0,999999], ASCII 'e' followed by i as exactly six zero-padded decimal digits; this bytewise UTF-8 order is the entry order",
          fileId: "for each i, let attempt start at 0; candidate=first16(SHA-256(seed || 0x46 || uint64be(i) || uint32be(attempt))); increment attempt until candidate is not 16 zero bytes, then emit candidate",
          index: "i advances by one from 0 through 999999 inclusive",
          seed: hex(seed)
        },
        status: "inventory-only-not-executed",
        streamCardinality: "1000000"
      };
    }
    if (item.id === "manifest-one-tib") {
      constructorValues.scalePlan = {
        cborSizingRules: {
          chunkObject: "each raw chunk is an object-kind-1 payload; its ObjectRef digest is SHA-256(ASCII 'OpenGameVCS object' || 0x00 || uint16be(1) || uint16be(1) || rawChunkBytes)",
          containerEncoding: "deterministic CBOR definite-length map and array headers use the shortest additional-information width for the mathematical element count",
          manifestEnvelope: "the manifest payload is the deterministic-CBOR map {0:1,1:2,2:[],16:logicalBytes,17:wholeFileDigest,18:chunkingProfile,19:parts}; map keys are encoded in ascending integer order",
          partEncoding: "every part i is the same deterministic-CBOR map {0:repeatedChunkObjectRef,1:1048576}; map keys are encoded in ascending integer order",
          textAndBytes: "UTF-8 text and byte strings use definite lengths and the shortest deterministic-CBOR length header; no indefinite-length item is permitted"
        },
        expectedStreamingIdentity: null,
        fixedFields: {
          chunkBytes: "1048576",
          chunkCount: "1048576",
          chunkObjectRef: "ogvcs:v1:chunk:sha256:8d40b35dab2f8ff4305af64230cecf10c9c7616c2ca75e606ced44114aa9224a",
          chunkingProfile: diagnosticValue(chunkProfile),
          formatVersion: 1,
          logicalBytes: "1099511627776",
          objectKind: 2,
          optionalExtensions: [],
          rawChunkSha256: "223066858638b498e56e28ecc6fb8a0cd5d1c7d1ac99c3c4ce286df776bedc3f",
          repeatedBlockSha256: "8e5a7fde9a212a4bdab640aaa5541de91d981498ac28bc8d8a901722ca807a24"
        },
        recurrence: {
          chunkByte: "block=SHA-256(seed || 0x43 || ASCII 'repeated-chunk-v1'); rawChunk is block repeated 32768 times to exactly 1048576 bytes",
          chunkOrder: "emit the same repeatedChunkObjectRef and logical length 1048576 exactly 1048576 times in ordinal order",
          seed: hex(seed),
          wholeFileDigest: "SHA-256 over the exact 1048576-byte rawChunk repeated 1048576 times, with no separator or length prefix"
        },
        status: "inventory-only-not-executed"
      };
    }
    const scaleResourceAccounting = inventoryOnlyScalePlan ? {
      classification: "inventory-only-scale-plan",
      measured: {
        executionCompleted: false,
        outputBytes: null,
        peakMemoryBytes: null,
        scratchBytes: null,
        streamingIdentity: null,
        wallTimeNanoseconds: null
      },
      planned: item.id === "tree-million-entries" ? {
        expectedOutputBytes: null,
        expectedStreamingIdentity: null,
        expectedStreamingSummarySha256: null,
        immediateEntries: "1000000",
        streamedObjects: "1",
        traversalEdges: "1000001"
      } : {
        chunkBytes: "1048576",
        chunks: "1048576",
        expectedOutputBytes: null,
        expectedStreamingIdentity: null,
        expectedStreamingSummarySha256: null,
        logicalBytes: "1099511627776",
        streamedObjectOccurrences: "1048577",
        traversalEdges: "1048576",
        uniqueObjects: "2"
      },
      promotionCondition: "implement the scale runner, execute this exact recurrence, record independently checked output identity and non-null measured resource high-water marks, then reclassify",
      summaryScope: "the scenario resource summary covers only checked-in definition and lookup artifacts; zero runtime counters are sentinels, not measurements"
    } : undefined;
    const definition = {
      algorithm: { id: "ogvcs.repository-validation-scenario-constructor", version: 1 },
      arithmetic: "mathematical nonnegative integers with explicit uint64 decode bounds; no host-width overflow is a semantic test oracle",
      detail: item.detail,
      exactConstructorValues: constructorValues,
      expectedRootState: outputState,
      failurePrecedence: "errors-v1-layer-stage-code-offset-subject",
      ...(item.implementationScope ? { implementationScope: item.implementationScope } : {}),
      normativeContext: context,
      operation: item.operation,
      parameters: item.parameters,
      registrySetSha256,
      ...(scaleResourceAccounting ? { resourceAccounting: scaleResourceAccounting } : {}),
      scenarioId: item.id,
      seedHex: hex(seed),
      suppliedResourceCatalogue: {
        baseObjectArtifacts: context.objectLookup.map((entry) => entry.artifact.path),
        logicalRecordArtifacts: item.id.startsWith("bundle-logical-") || item.id === "bundle-edge-families" ? logicalRows.map((row) => row.payloadPath) : [],
        mutationRecipe: item.id.includes("mutation") ? "mutations/single-bit.json" : item.id.includes("truncation") ? "mutations/truncation.json" : "none",
        virtualLimitRecipe: item.id.startsWith("limit-") ? "limits/virtual-constructors.json" : "none"
      },
      validation: { mode: item.mode, requestedLayer: item.layer }
    };
    const definitionBytes = stableJson(definition);
    const definitionRelative = `scenarios/definitions/${item.id}.json`;
    files.set(definitionRelative, definitionBytes);
    const summaryArtifactPaths = new Set([
      abstractGraphArtifact?.path,
      operationRequestArtifact?.path,
      ...operationSupplementalArtifacts.map((artifact) => artifact.path),
      bundleInputArtifact?.path,
      directInputArtifact?.path,
      stableErrorArtifact?.path,
      ...(materialized?.extraInputs ?? []).map((artifact) => artifact.path),
      ...context.objectLookup.map((entry) => entry.artifact.path),
      ...(item.id.startsWith("bundle-logical-") || item.id === "bundle-edge-families" ? logicalRows.map((row) => row.payloadPath) : [])
    ].filter(Boolean));
    const summaryFields = {
      bytes: definitionBytes.length + [...summaryArtifactPaths].reduce((sum, relative) => sum + files.get(relative).length, 0),
      indexEntries: 0,
      items: context.objectLookup.length + (item.id.startsWith("bundle-logical-") || item.id === "bundle-edge-families" ? logicalRows.length : 0),
      peakMemoryBytes: 0,
      scratchBytes: 0,
      traversalEdges: 0
    };
    const summarySha256 = hex(sha256(Buffer.concat([
      RESOURCE_SUMMARY_DOMAIN,
      uint16be(1),
      uint64be(summaryFields.bytes),
      uint64be(summaryFields.items),
      uint64be(summaryFields.traversalEdges),
      uint64be(summaryFields.indexEntries),
      uint64be(summaryFields.peakMemoryBytes),
      uint64be(summaryFields.scratchBytes)
    ])));
    const resourceSummary = { ...summaryFields, summarySha256 };
    const expectedResourceEvidence = item.operation === "validate-resource-reservation"
      ? resourceReservationCases.get(item.id)?.evidenceRequired
      : item.operation === "validate-tree-groups-memory"
        ? treeGroupsMemoryCases.get(item.id)?.evidenceRequired
        : undefined;
    const scenario = {
      context,
      expected: item.code ? {
        code: item.code,
        ...(expectedResourceEvidence ? { evidence: expectedResourceEvidence } : {}),
        layer: item.layer,
        stage: item.stage,
        result: "reject"
      } : {
        highestLayer: item.layer,
        output: {
          artifact: { bytes: outputBytes.length, mediaType: "application/json", path: outputRelative, sha256: hex(sha256(outputBytes)) },
          summarySha256
        },
        result: "accept"
      },
      failurePrecedence: "errors-v1-layer-stage-code-offset-subject",
      ...(item.implementationScope ? { implementationScope: item.implementationScope } : {}),
      inputs: [...(abstractGraphArtifact ? [abstractGraphArtifact] : operationRequestArtifact ? [operationRequestArtifact, ...operationSupplementalArtifacts] : bundleInputArtifact ? [bundleInputArtifact] : materialized ? [materialized.candidate.artifact, ...(materialized.extraInputs ?? [])] : directInputArtifact ? [directInputArtifact] : stableErrorArtifact ? [stableErrorArtifact] : []), { bytes: definitionBytes.length, mediaType: "application/json", path: definitionRelative, sha256: hex(sha256(definitionBytes)) }],
      operation: item.operation,
      requirementIds: item.requirements,
      resources: {
        recipe: {
          generator: "ogvcs.repository-validation-scenario-constructor/v1",
          parameters: { definition: definitionRelative, definitionSha256: hex(sha256(definitionBytes)), runtimeHighWaterMarks: inventoryOnlyScalePlan ? "not-measured-inventory-only" : "not-asserted" },
          seed: hex(seed)
        },
        summary: resourceSummary
      },
      scenarioId: item.id,
      schemaVersion: "ogvcs.repository-format/validation-scenario/v1"
    };
    assert.deepEqual(Object.keys(scenario).sort(), ["context", "expected", "failurePrecedence", "inputs", "operation", "requirementIds", "resources", "scenarioId", "schemaVersion", ...(item.implementationScope ? ["implementationScope"] : [])].sort());
    assert.equal(scenario.failurePrecedence, "errors-v1-layer-stage-code-offset-subject");
    assert.equal(scenario.schemaVersion, "ogvcs.repository-format/validation-scenario/v1");
    assert(["adapt-fixture", "allocate-file-id", "canonical-scan", "import-file-id", "replay-change-set", "validate-abstract-reference-graph", "validate-bundle", "validate-bundle-claim", "validate-object", "validate-operation-mode", "validate-path-profile-decision", "validate-repository", "validate-repository-route", "validate-resource-reservation", "validate-tree-groups-memory", "validate-typed-reference-authority", "write-content-manifest", "write-logical-bundle", "write-tree"].includes(scenario.operation));
    assert.deepEqual(scenario.requirementIds, [...new Set(scenario.requirementIds)].sort());
    assert(scenario.requirementIds.every((value) => /^OGVCS-[0-9]{3}-(?:AC|FR|NFR)-[0-9]{2}$/.test(value)));
    assert.equal(scenario.context.registrySnapshot.registrySetSha256, registrySetSha256);
    assert(scenario.context.objectLookup.every((entry) => /^ogvcs:v1:[a-z][a-z0-9-]*:sha256:[0-9a-f]{64}$/.test(entry.ref)));
    assert(item.code ? scenario.expected.result === "reject" : scenario.expected.result === "accept");
    const scenarioRelative = `scenarios/cases/${item.id}.json`;
    files.set(scenarioRelative, stableJson(scenario));
    const materialization = abstractGraphArtifact ? "prevalidated-abstract-graph"
      : operationRequestArtifact ? "byte-materialized-operation-request"
        : item.id.startsWith("limit-") ? "executable-virtual-limit-constructor"
          : fixtureAdapterCases.has(item.id) ? "executable-fixture-adapter-constructor"
          : bundleInputArtifact ? bundleMaterialization
          : materialized ? "byte-materialized-object-graph"
            : directInputArtifact ? registryRecipeScenarios.has(item.id) ? "executable-enumerated-registry-recipe" : "byte-materialized-direct-artifact"
            : stableErrorArtifact ? "byte-materialized-stable-error-artifact"
            : ["mutation-systematic-single-bit", "truncation-every-prefix", "hash-tampered-object", "malformed-complete-corpus"].includes(item.id) ? "executable-enumerated-mutation-recipe"
              : "virtual-constructor";
    scenarioRows.push({
      artifact: scenarioRelative,
      code: item.code,
      expected: scenario.expected,
      ...(item.implementationScope ? { implementationScope: item.implementationScope } : {}),
      materialization,
      obligationTags: item.obligationTags,
      operation: item.operation,
      requirementIds: item.requirements,
      scenarioId: item.id
    });
  }

  const requiredObligations = [
    ...["create", "modify", "copy", "move", "rename", "delete", "restore", "group-create", "group-update", "group-delete", "merge-resolution"].map((name) => `transition:${name}`),
    "transition:exact-replay", "transition:result-mismatch",
    "history:parents-0", "history:parents-1", "history:parents-2", "history:parents-8", "history:second-root", "history:missing-parent", "history:duplicate-parent", "history:cycle", "history:cross-repository", "history:parents-9",
    "fileid:zero", "fileid:duplicate", "fileid:create-reuse", "fileid:copy-reuse", "fileid:source-forgery", "fileid:move-rename", "fileid:copy", "fileid:delete-recreate", "fileid:restore-ancestry", "fileid:restore-invalid-ancestry", "fileid:restore-forgery", "fileid:cross-repository", "fileid:import-retry", "fileid:import-conflict", "fileid:import-native-collision", "fileid:concurrent-loser-state",
    ...["missing", "wrong-kind", "object-id-mismatch", "bad-schema", "profile-lifecycle"]
      .map((suffix) => `fileid:lifetime-first-change-${suffix}`),
    ...["lifetime", "request", "candidate"].flatMap((surface) =>
      ["conformance", "wrong-family", "production-conformance-only", "foreign-repository"]
        .map((variant) => `fileid:prior-import-mapping-${surface}-${variant}`)),
    "fileid:raw-lifetime-record-schema-before-duplicate",
    "fileid:raw-import-mapping-schema-before-conflict",
    "fileid:raw-working-addition-schema-before-duplicate",
    ...["lifetime", "import-mapping"].flatMap((label) => [
      "version-selector-invalid", "type-selector-invalid", "extra-field-22", "extra-field-999"
    ].map((suffix) => `fileid:serialized-${label}-${suffix}`)),
    "tree:empty", "tree:unicode", "tree:all-entry-kinds", "tree:all-modes", "tree:million-entries",
    "unicode:age-15-assigned", "unicode:newer-composition-pair", "unicode:newer-decomposed",
    "unicode:newer-canonical", "unicode:frozen-unassigned",
    "tree:ratified-path-profile-accept", "tree:ratified-path-profile-reject",
    "tree:ratified-path-profile-empty-accept", "tree:ratified-path-profile-empty-missing-validator",
    "tree:ratified-path-profile-opaque-keys",
    "tree:ratified-path-profile-case-sensitive-distinct", "tree:ratified-path-profile-case-folded-collision",
    "tree:ratified-path-profile-missing-repository-key", "tree:ratified-path-profile-missing-platform-key",
    "tree:ratified-path-profile-missing-case-mode", "tree:ratified-path-profile-wrong-case-mode",
    "tree:missing-child-before-missing-path-adapter", "tree:missing-manifest-before-wrong-path-adapter",
    "tree:missing-chunk-before-missing-path-adapter", "tree:missing-target-before-path-profile-lifecycle",
    "tree:missing-manifest-before-descriptor-mismatch", "tree:missing-child-before-duplicate-fileid",
    ...repositorySemanticSurfaces.flatMap((surface) => [
      `mode:${surface}-conformance-accept`,
      `mode:${surface}-read-rejected`, `mode:${surface}-invalid-rejected`,
      `mode:${surface}-omitted-rejected`, `mode:${surface}-production-conformance-rejected`,
      `mode:${surface}-partial-registry-rejected`, `mode:${surface}-forged-registry-rejected`
    ]),
    ...repositorySemanticSurfaces.flatMap((surface) => [
      `mode:${surface}-registry-required`, `mode:${surface}-semantic-disabled-rejected`
    ]),
    "mode:tree-expand-case-mode-missing-rejected", "mode:tree-expand-case-mode-invalid-rejected",
    "mode:repository-lookup-layer2-registry-free", "mode:repository-lookup-layer2-authority-omitted-rejected",
    "mode:bundle-visitor-read-rejected", "mode:bundle-visitor-invalid-rejected", "mode:bundle-visitor-omitted",
    "bundle:semantic-callback-does-not-promote",
    ...operationEmitterSurfaces.flatMap((surface) => [
      `mode:${surface}-selector-missing-rejected`, `mode:${surface}-selector-read-rejected`,
      `mode:${surface}-selector-invalid-rejected`, `mode:${surface}-registry-required`,
      `mode:${surface}-production-conformance-rejected`,
      `mode:${surface}-partial-registry-rejected`, `mode:${surface}-forged-registry-rejected`
    ]),
    ...semanticCodecSurfaces.flatMap((surface) => {
      const authority = (suffix) => `mode:${surface}-${surface === "tree-file" ? "feature-" : ""}${suffix}`;
      return [
      authority("deprecated-read-accept"), authority("conformance-read-rejected"),
      authority("conformance-accept"), authority("deprecated-production-write-rejected"),
      authority("conformance-production-write-rejected"),
      `mode:${surface}-registry-operation-required`, `mode:${surface}-registry-operation-invalid-rejected`,
      `mode:${surface}-registry-required`, `mode:${surface}-semantic-disabled-rejected`,
      `mode:${surface}-unknown-${surface === "tree-file" ? "feature" : "profile"}-rejected`, `mode:${surface}-partial-registry-rejected`,
      `mode:${surface}-forged-registry-rejected`
    ];
    }),
    ...codecLayerTwoSurfaces.flatMap((surface) => [
      `mode:${surface}-registry-free-layer2`, `mode:${surface}-registry-free-wrong-family-rejected`,
      `mode:${surface}-authority-omitted-rejected`,
      `mode:${surface}-semantic-false-with-registry-rejected`,
      `mode:${surface}-semantic-false-with-operation-rejected`
    ]),
    ...["unknown-group-profile", "unknown-role-profile", "unknown-external-key-profile",
      "wrong-family-group-profile", "wrong-family-role-profile", "wrong-family-external-key-profile"]
      .map((suffix) => `group:standalone-${suffix}`),
    "group:standalone-known-schema-before-profile-lifecycle-forward",
    "group:standalone-known-schema-before-profile-lifecycle-reverse",
    ...["later-group-non-map", "later-member-non-map", "later-external-key-non-map", "later-proxy",
      "groups-container-proxy", "members-array-proxy", "external-keys-array-proxy"]
      .map((suffix) => `group:standalone-raw-${suffix}-before-profile-lifecycle`),
    "group:asset-groups-config-proxy-no-caller-code",
    "import-request:raw-context-lifetime-record-schema-before-profile-lifecycle",
    "import-request:raw-context-import-mapping-schema-before-profile-lifecycle",
    "limits:repository-lookup-zero-time", "limits:tree-groups-combined-memory",
    "limits:replay-base-memory", "limits:fileid-lifetime-import-indexes-memory",
    "limits:import-request-many-mappings-deadline",
    "limits:graph-workspace-indexes-memory", "limits:conflict-group-indexes-memory",
    "limits:many-invalid-error-selection-memory", "limits:lookup-edge-counter-rollback",
    "limits:lookup-scratch-counter-rollback",
    "limits:tree-stream-transaction-composite-memory",
    "typed-reference:arbitrary-kind-map-relabel", "typed-reference:duplicate-kind-token",
    "typed-reference:durable-overlength-colon-dense",
    "group:create", "group:update", "group:delete", "group:cardinality", "group:external-key",
    ...conflictKinds.filter((kind) => kind !== "mode").map((kind) => `conflict:kind-${kind}`), "conflict:tombstoned-kind-mode-rejected", ...["base", "left", "right", "delete", "custom"].map((choice) => `conflict:choice-${choice}`), "conflict:resolved", "conflict:unresolved", "conflict:custom-driver",
    "shelf:revision-chain", "provenance:acyclic", "provenance:cycle", "provenance:snapshot-cycle", "attestation:unsigned", "attestation:signed", "attestation:signature-shape",
    "manifest:empty", "manifest:repeated-chunk", "manifest:multi-chunk", "manifest:corrupt-chunk", "manifest:chunk-length", "manifest:length-sum-mismatch", "manifest:logical-ceiling", "manifest:unknown-profile", "manifest:one-tib", "manifest:annotation-invariance", "manifest:writer-too-few-parts", "manifest:writer-too-many-parts",
    "tree:writer-ordered-too-many-entries", "tree:writer-sorted-too-many-entries",
    "tree:writer-ordered-count-before-feature-lifecycle", "tree:writer-sorted-count-before-feature-lifecycle",
    "tree:writer-ordered-count-before-entry-profile-lifecycle", "tree:writer-sorted-count-before-entry-profile-lifecycle",
    "tree:writer-ordered-count-before-duplicate-fileid", "tree:writer-sorted-count-before-duplicate-fileid",
    "manifest:writer-count-before-profile-lifecycle",
    "manifest:writer-object-id-before-profile-lifecycle",
    "manifest:writer-known-schema-before-chunk-length-forward",
    "manifest:writer-known-schema-before-chunk-length-reverse",
    "manifest:writer-content-object-id-before-chunk-length-forward",
    "manifest:writer-content-object-id-before-chunk-length-reverse",
    "manifest:writer-limit-before-kind",
    "manifest:writer-count-before-kind-forward", "manifest:writer-count-before-kind-reverse",
    "tree:writer-ordered-limit-before-count-and-feature-lifecycle", "tree:writer-sorted-limit-before-count-and-feature-lifecycle",
    "manifest:writer-limit-before-count-and-profile-lifecycle",
    "bundle:writer-sequence-before-object-id", "bundle:writer-object-id-before-unknown-kind",
    "bundle:writer-object-id-before-feature-lifecycle",
    ...["forward", "reverse"].flatMap((order) => [
      `bundle:writer-section-object-id-before-feature-lifecycle-${order}`,
      `bundle:writer-section-root-order-before-role-lifecycle-${order}`,
      `bundle:writer-section-sequence-before-logical-schema-${order}`
    ]),
    "mode:tree-file-order-before-feature-lifecycle",
    "mode:tree-file-order-before-descriptor-mismatch",
    "mode:tree-file-target-before-duplicate-fileid",
    "mode:tree-file-feature-before-duplicate-fileid",
    "mode:tree-file-known-schema-before-order-forward",
    "mode:tree-file-known-schema-before-order-reverse",
    "tree:writer-ordered-kind-before-order-forward",
    "tree:writer-ordered-kind-before-order-reverse",
    "tree:writer-ordered-limit-before-kind",
    "tree:writer-sorted-family-before-kind-forward", "tree:writer-sorted-family-before-kind-reverse",
    "mode:manifest-verify-missing-reference-before-profile-lifecycle",
    "lookup:validate-all-known-schema-before-profile-lifecycle-forward",
    "lookup:validate-all-known-schema-before-profile-lifecycle-reverse",
    "import-request:raw-sourceNamespaceDigest-schema-before-profile-lifecycle",
    "import-request:raw-sourceIdentityDigest-schema-before-profile-lifecycle",
    "import-request:raw-requestedFileId-schema-before-profile-lifecycle",
    "tree:missing-reference-before-profile-lifecycle",
    "transition:missing-reference-before-profile-lifecycle",
    "transition:entry-target-wrong-kind",
    "conflict:missing-reference-before-profile-lifecycle",
    "conflict:entry-target-missing", "conflict:entry-target-wrong-kind",
    "conflict:entry-target-missing-before-profile-lifecycle",
    "provenance:missing-reference-before-profile-lifecycle",
    ...["manifest", "tree", "replay", "conflict", "snapshot", "provenance", "shelf"]
      .flatMap((route) => ["forward", "reverse"]
        .map((order) => `closure:${route}-identity-before-missing-${order}`)),
    "provenance:cycle-branch-before-missing-input-forward",
    "provenance:cycle-branch-before-missing-input-reverse",
    "snapshot-graph:missing-change-before-profile-lifecycle",
    "snapshot-graph:second-root-before-missing-parent-forward",
    "snapshot-graph:second-root-before-missing-parent-reverse",
    "repository:candidate-verify-content-false-rejected",
    "repository:candidate-content-complete-missing-chunk",
    "repository:candidate-missing-tree-before-second-root",
    "repository:candidate-missing-change-before-profile-lifecycle",
    "repository:candidate-missing-change-base",
    "shelf:verify-content-false-rejected", "shelf:content-complete-missing-chunk",
    "shelf:missing-previous-before-chain-invalid", "shelf:unrelated-known-schema-object-ignored",
    "shelf:unrelated-profile-object-ignored",
    "snapshot-graph:missing-descriptor-before-descriptor-mismatch",
    "transition:restore-missing-source-tree-before-profile-lifecycle",
    "transition:restore-missing-proof-descriptor-before-cross-repository",
    "tree:path-core-deep-chain",
    ...["header", "object", "logical-record", "root", "trailer"].map((kind) => `bundle:item-${kind}`),
    "bundle:zero-sections", "bundle:logical-preservation", "bundle:multi-root-sort", "bundle:sort", "bundle:count", "bundle:ordinal", "bundle:mode", "bundle:budget", "bundle:declared-accounting", "bundle:visitor-item-budget", "bundle:visitor-count-budget", "bundle:visitor-nested-key-capture-memory", "bundle:transcript-budget", "bundle:object-id", "bundle:record-id", "bundle:root-invalid", "bundle:trailer", "bundle:eof", "bundle:duplicate", "bundle:closure-missing", "bundle:closure-extra", "bundle:wrong-kind", "bundle:forbidden-claim", "bundle:every-edge-family", "bundle:every-root-family", ...objectRows.map((row) => `bundle:edge-object-kind-${row.kind}`), ...logicalRows.map((row) => `bundle:logical-type-${row.type}`), "bundle:root-kind-object", "bundle:root-kind-logical-record",
    "mutation:single-bit", "hash:tamper", "truncation:every-prefix", "malformed:complete", "limits:all",
    "registry:duplicate", "registry:reassigned", "registry:invalid-entry", "registry:reserved", "registry:ratified", "registry:deprecated-read", "registry:deprecated-write", "registry:conformance", "registry:conformance-production", "registry:unknown-profile", "registry:unknown-feature", "registry:unknown-feature-forward", "registry:unknown-extension-preserve"
  ];
  const coveredObligations = new Set(scenarioRows.flatMap((row) => row.obligationTags));
  const missingObligations = requiredObligations.filter((tag) => !coveredObligations.has(tag));
  const representedErrors = new Set(scenarioRows.filter((row) => row.code).map((row) => row.code));
  const missingErrors = errors.map((error) => error.code).filter((code) => !representedErrors.has(code));
  assert.deepEqual(missingObligations, [], `unrepresented normative obligations: ${missingObligations.join(", ")}`);
  assert.deepEqual(missingErrors, [], `unrepresented stable errors: ${missingErrors.join(", ")}`);
  files.set("scenarios/index.json", stableJson({
    cases: scenarioRows,
    registrySnapshot: "registries/live-snapshot.json",
    schema: "ogvcs.repository-format.v1.validation-scenario-index.v1"
  }));
  files.set("coverage-matrix.json", stableJson({
    obligations: requiredObligations.sort().map((obligation) => ({
      obligation,
      scenarios: scenarioRows.filter((row) => row.obligationTags.includes(obligation)).map((row) => row.scenarioId)
    })),
    requirementIds: ["OGVCS-002-FR-04", "OGVCS-002-FR-06", "OGVCS-002-FR-09", "OGVCS-002-FR-11", "OGVCS-002-FR-13", "OGVCS-002-NFR-01", "OGVCS-002-NFR-04", "OGVCS-002-AC-03", "OGVCS-002-AC-04", "OGVCS-002-AC-06", "OGVCS-002-AC-07", "OGVCS-002-AC-08", "OGVCS-002-AC-09", "OGVCS-002-AC-10", "OGVCS-002-AC-11"].map((requirementId) => ({
      requirementId,
      scenarios: scenarioRows.filter((row) => row.requirementIds.includes(requirementId)).map((row) => row.scenarioId)
    })),
    schema: "ogvcs.repository-format.v1.machine-coverage-matrix.v1",
    stableErrors: errors.map((error) => ({ code: error.code, scenarios: scenarioRows.filter((row) => row.code === error.code).map((row) => row.scenarioId) })),
    totals: {
      materialization: Object.fromEntries([...new Set(scenarioRows.map((row) => row.materialization))].sort().map((kind) => [kind, scenarioRows.filter((row) => row.materialization === kind).length])),
      obligations: requiredObligations.length,
      scenarios: scenarioRows.length,
      stableErrors: errors.length
    }
  }));

  files.set("routing.json", stableJson({
    artifacts: {
      coverage: "coverage-matrix.json",
      decodedDiagnostics: "diagnostics/decoded-values.json",
      durableTextValues: "diagnostics/text-values.json",
      expectations: "expectations.json",
      hardLimits: "limits/virtual-constructors.json",
      inventory: "manifest.json",
      malformed: "malformed/index.json",
      mutation: "mutations/single-bit.json",
      registrySnapshot: "registries/live-snapshot.json",
      scenarios: "scenarios/index.json",
      truncation: "mutations/truncation.json",
      unicodeAuthority: "unicode/index.json"
    },
    normativeSchemas: {
      abstractReferenceGraph: "../abstract-reference-graph.schema.json",
      scenario: "../validation-scenario.schema.json",
      vectorManifest: "../vector-manifest.schema.json"
    },
    schema: "ogvcs.repository-format.v1.vector-routing.v1"
  }));
  files.set("README.md", Buffer.from(`# Repository-format v1 normative vectors\n\nThis directory is generated by \`${COMMAND}\`. Run \`${COMMAND} --check\` from the repository root to prove the checked-in tree is byte-for-byte current. Start with [routing.json](routing.json), [coverage-matrix.json](coverage-matrix.json), [scenarios/index.json](scenarios/index.json), and the frozen [Unicode authority](unicode/index.json). Abstract cycle defenses route through \`../abstract-reference-graph.schema.json\`; they are algorithm-only inputs and are not canonical object-byte interoperability vectors.\n\nEach file under \`scenarios/cases/\` conforms to \`../validation-scenario.schema.json\` and directly states its operation, requested validation layer, mode, exact registry-set digest, supplied object lookup, deterministic resource recipe, expected stable error or output artifact, failure precedence, and OGVCS requirement IDs. Definitions under \`scenarios/definitions/\` are language-neutral constructor inputs; accepted root/output states are under \`scenarios/outputs/\`. Large boundary plans are intentionally not giant checked-in files.\n\nThe \`materialization\` field in [scenarios/index.json](scenarios/index.json) is the audit boundary. \`byte-materialized-*\` cases carry case-specific bytes; \`prevalidated-abstract-graph\` cases carry the typed cycle graph; and \`executable-*\` cases carry a complete streaming/enumeration algorithm. The fixture-adapter constructors are explicitly scoped to JavaScript because the PRD assigns that package the adapter boundary; Rust reports them as not applicable rather than inventory-only. A bare \`virtual-constructor\` or \`virtual-constructor-shared-bundle-baseline\` is inventory coverage only and MUST NOT be cited as executed semantic proof. In particular, \`tree-million-entries\` and \`manifest-one-tib\` publish exact deterministic scale plans but remain \`virtual-constructor\` inventory entries until a scale runner records independently checked output identities and measured resource high-water marks. The all-family bundle is a closed 43-item sequence with 12 objects, 9 logical records, 20 roots, 53 field-occurrence traversal edges, and 21 index entries.\n\nThe mutation corpus enumerates a deterministic loop rather than storing every derivative. It covers every byte and bit of each small object, logical record, bundle item shape, and the whole seed sequence. The truncation corpus covers every proper prefix and specifies the item-boundary precedence. The hard-limit corpus publishes 25 maximum and 25 maximum-plus-one constructors, with small constructor inputs materialized under \`limits/materialized/\`. Unicode text first passes shortest-form scalar decoding, then the manifest-bound Unicode 15.0 Age repertoire, and only then the host NFC check; newer-host assignments cannot change format-v1 acceptance.\n\n\`allocate-file-id\` operation inputs distinguish \`phase: \"generate\"\` from \`phase: \"finalize\"\`. Generate-phase inputs carry an \`entropyRecipe\`: \`candidateFileIds\` is consumed in order, \`repeat-last-candidate\` supplies the final candidate until the declared retry limit, \`isConsumed\` is the exact repository-consumed set, and \`failAtCall\` is a zero-based injected entropy failure. Finalize-phase inputs validate the caller-selected candidate against the immutable prior and working lifetime context. These recipes are test injection contracts only; production allocation still uses the documented operating-system CSPRNG.\n\nThe top-level [manifest.json](manifest.json) inventories every generated artifact with byte length, media type, and SHA-256; [expectations.json](expectations.json) routes non-scenario artifact dispositions. The manifest is reproduced byte-for-byte by \`--check\`; a recursive self-hash is intentionally impossible. The generator contains an independent deterministic-CBOR encoder so its bytes do not depend on a production codec. Generator self-consistency is not independent semantic validation; the clean-room Rust and JavaScript codecs are responsible for executing the executable scenarios and publishing language-tagged conformance results; inventory-only rows remain explicit non-evidence.\n`, "utf8"));

  files.set("README.md", Buffer.from(files.get("README.md").toString("utf8")
    .replace("53 field-occurrence traversal edges", "60 field-occurrence traversal edges")
    .replace("The top-level [manifest.json]", "The independent auditor recomputes every object, logical-record, and conflict preimage and the exact hand-auditable seed invariant without using either production codec. The top-level [manifest.json]"), "utf8"));

  files.set("coverage.json", stableJson({
    coverageMatrix: "coverage-matrix.json",
    generatedScenarioCases: scenarioRows.length,
    representedNormativeObligations: requiredObligations.length,
    representedStableErrors: errors.length,
    boundaryCases: { hardLimits: limits.length, maximum: limits.length, maximumPlusOne: limits.length, virtualConstructors: virtualCases.length },
    conflictPresenceCombinations: conflictRows.length,
    deterministicCborMalformedCases: malformedRows.length,
    independentlyReproduciblePreimages: {
      conflicts: conflictRows.length,
      logicalRecords: logicalRows.length,
      objects: objectRows.length
    },
    logicalBundles: { negative: 7, positive: 1 },
    logicalRecordTypes: logicalRows.map((row) => row.type),
    metadataObjectKinds: objectRows.filter((row) => row.kind > 1).map((row) => row.kind),
    profileFamilies: profileUses.map((row) => row.family),
    rawChunkKinds: [1],
    registryEvolutionBehaviors: [
      "unknown-required-feature-forwarding-and-semantic-rejection",
      "unknown-optional-extension-byte-preservation",
      "reserved-rejection",
      "ratified-read-and-write",
      "deprecated-read-and-production-write-rejection",
      "conformance-only-test-acceptance-and-production-rejection",
      "unknown-profile-rejection"
    ],
    schema: "ogvcs.repository-format.v1.coverage.v2",
    wrongFamilyCases: wrongFamilyRows.length
  }));

  writeTree(output, files, expectations);
}

function main() {
  const args = process.argv.slice(2);
  const check = args.includes("--check");
  const outputIndex = args.indexOf("--output");
  const requestedOutput = outputIndex >= 0 ? path.resolve(args[outputIndex + 1]) : DEFAULT_OUTPUT;
  if (outputIndex >= 0 && !args[outputIndex + 1]) throw new Error("--output requires a directory");
  for (const arg of args) {
    if (arg !== "--check" && arg !== "--output" && (outputIndex < 0 || arg !== args[outputIndex + 1])) throw new Error(`unknown argument: ${arg}`);
  }
  if (!check) {
    generate(requestedOutput);
    process.stdout.write(`reference-vector-generator: wrote ${path.relative(REPO_ROOT, requestedOutput)}\n`);
    return;
  }
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "ogvcs-vectors-"));
  try {
    generate(temporary);
    const differences = compareTrees(requestedOutput, temporary);
    if (differences.length > 0) {
      process.stderr.write(`reference-vector-generator: drift detected\n${differences.map((item) => `- ${item}`).join("\n")}\n`);
      process.exitCode = 1;
      return;
    }
    process.stdout.write("reference-vector-generator: vectors current\n");
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

main();
