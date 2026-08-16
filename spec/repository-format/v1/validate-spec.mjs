#!/usr/bin/env node

import fs from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const FORMAT_VERSION = 1;
const REGISTRY_VERSION = 1;
const STATES = new Set(["reserved", "conformance-only", "ratified", "deprecated"]);
const VALIDATION_STAGES = [
  "configured-resource-preflight",
  "canonical-framing",
  "sequence-shape-and-order",
  "declared-identity",
  "transcript-authentication",
  "known-schema",
  "closure-and-reference-resolution",
  "declared-accounting",
  "registry-semantics",
  "repository-semantics"
];
const PROFILE_FAMILIES = new Set([
  "annotation-payload",
  "attestation-predicate",
  "bundle-root-role",
  "chunking",
  "conflict-driver",
  "content-policy",
  "external-key",
  "fixture-content-policy",
  "fixture-event",
  "fixture-external-key",
  "fixture-group",
  "fixture-group-role",
  "group",
  "group-role",
  "identity",
  "importer",
  "path",
  "policy",
  "provenance",
  "signature"
]);
const PROFILE_TOKEN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const PROFILE_NAMESPACE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+$/;

const SEMANTIC_ENUMS = {
  "allocation-kind": [[1, "native"], [2, "import"]],
  "bundle-item-type": [[1, "header"], [2, "object"], [3, "logical-record"], [4, "root"], [5, "trailer"]],
  "bundle-mode": [[1, "supplied-closure"]],
  "bundle-root-kind": [[1, "object"], [2, "logical-record"]],
  "conflict-resolution-choice": [[1, "base"], [2, "left"], [3, "right"], [4, "delete"], [5, "custom"]],
  "conflict-resolution-state": [[0, "unresolved"], [1, "resolved"]],
  "conflict-side-kind": [[1, "entry"], [2, "group"]],
  "conflict-subject-kind": [[1, "entry"], [2, "group"]],
  "conflict-kind": [[1, "content"], [2, "divergent-move"], [3, "delete-modify"], [4, "type"], [5, "mode", "reserved"], [6, "policy"], [7, "group"], [8, "path-collision"]],
  "import-state": [[1, "reserved"], [2, "materialized"], [3, "published"]],
  "lifetime-origin": [[1, "native-create"], [2, "native-copy"], [3, "import"]],
  "lock-target-kind": [[1, "file-id"], [2, "group-id"]],
  operation: [[1, "create"], [2, "modify"], [3, "copy"], [4, "move"], [5, "rename"], [6, "delete"], [7, "restore"], [8, "group-create"], [9, "group-update"], [10, "group-delete"], [11, "merge-resolution"]],
  "policy-decision": [[1, "pass"], [2, "override"]],
  "ref-kind": [[1, "branch"], [2, "tag"]]
};

const OBJECT_KINDS = [
  [1, "chunk", "raw-bytes"],
  [2, "content-manifest", "deterministic-cbor"],
  [3, "tree", "deterministic-cbor"],
  [4, "change-set", "deterministic-cbor"],
  [5, "asset-group-set", "deterministic-cbor"],
  [6, "repository-descriptor", "deterministic-cbor"],
  [7, "snapshot", "deterministic-cbor"],
  [8, "shelf-revision", "deterministic-cbor"],
  [9, "provenance", "deterministic-cbor"],
  [10, "attestation", "deterministic-cbor"],
  [11, "conflict-set", "deterministic-cbor"]
];

const OBJECT_DEFINITIONS = {
  "content-manifest": { code: 2, fields: [16, 17, 18, 19], optional: [] },
  tree: { code: 3, fields: [16, 17], optional: [] },
  "change-set": { code: 4, fields: [16, 17, 18], optional: [17] },
  "group-set": { code: 5, prose: "asset-group set", fields: [16, 17], optional: [] },
  "repository-descriptor": { code: 6, fields: [16, 17, 18, 19, 20], optional: [20] },
  snapshot: { code: 7, fields: [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28], optional: [20, 27, 28] },
  "shelf-revision": { code: 8, fields: [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29], optional: [19, 23, 24, 29] },
  provenance: { code: 9, fields: [16, 17, 18, 19], optional: [19] },
  attestation: { code: 10, fields: [16, 17, 18, 19, 20, 21, 22], optional: [21, 22] },
  "conflict-set": { code: 11, fields: [16, 17], optional: [] }
};

const LOGICAL_RECORDS = [
  [1, "repository-root", [0, 1, 16, 17]],
  [2, "mutable-ref", [0, 1, 16, 17, 18, 19, 20]],
  [3, "shelf-pointer", [0, 1, 16, 17, 18, 19]],
  [4, "file-id-lifetime", [0, 1, 16, 17, 18, 19, 20, 21]],
  [5, "import-mapping", [0, 1, 16, 17, 18, 19, 20, 21]],
  [6, "pending-change-reference", [0, 1, 16, 17, 18, 19, 20]],
  [7, "lock-reference", [0, 1, 16, 17, 18, 19, 20]],
  [8, "annotation", [0, 1, 16, 17, 18]],
  [9, "fixture-event", [0, 1, 16, 17, 18, 19, 20]]
];

const LIMITS = [
  ["bundle-sequence-bytes", "bytes", 2199023255552, "BUNDLE_BUDGET_EXCEEDED"],
  ["bundle-largest-item-bytes", "bytes", 536871424, "BUNDLE_BUDGET_EXCEEDED"],
  ["bundle-objects", "objects", 10000000],
  ["bundle-logical-records", "records", 10000000],
  ["bundle-roots", "roots", 20000000],
  ["bundle-total-items", "items", 40000002],
  ["bundle-traversal-edges", "edges", 100000000],
  ["bundle-index-entries", "entries", 20000000],
  ["cbor-nesting-depth", "levels", 32],
  ["metadata-payload-bytes", "bytes", 536870912],
  ["chunk-payload-bytes", "bytes", 67108864],
  ["generic-text-or-byte-value-bytes", "bytes", 16777216],
  ["snapshot-message-bytes", "utf8-bytes", 1048576],
  ["extensions-per-object", "entries", 128],
  ["extension-aggregate-bytes-per-object", "encoded-bytes", 16777216],
  ["path-segment-bytes", "utf8-bytes", 255],
  ["path-bytes", "utf8-bytes", 4096],
  ["path-segments", "segments", 256],
  ["tree-entries", "entries", 1000000],
  ["snapshot-parents", "parents", 8],
  ["change-set-operations", "operations", 1000000],
  ["asset-groups", "groups", 10000],
  ["asset-group-members", "members-per-group", 64],
  ["manifest-chunks", "chunks", 1048576],
  ["logical-file-bytes", "bytes", 1099511627776]
];

const EXPECTED_FILES = [
  "LICENSE",
  "spec/repository-format/v1/LICENSE",
  "spec/repository-format/v1/README.md",
  "spec/repository-format/v1/abstract-reference-graph.schema.json",
  "spec/repository-format/v1/conformance-profiles.md",
  "spec/repository-format/v1/encoding.md",
  "spec/repository-format/v1/errors.json",
  "spec/repository-format/v1/fixture-adapter.md",
  "spec/repository-format/v1/logical-bundle.md",
  "spec/repository-format/v1/object-model.md",
  "spec/repository-format/v1/package.json",
  "spec/repository-format/v1/repository-format.cddl",
  "spec/repository-format/v1/validation-scenario.schema.json",
  "spec/repository-format/v1/vector-manifest.schema.json",
  "spec/repository-format/v1/validate-spec.mjs",
  "spec/repository-format/v1/validate-spec.test.mjs",
  "spec/repository-format/v1/registries/common-fields.json",
  "spec/repository-format/v1/registries/entry-kinds.json",
  "spec/repository-format/v1/registries/entry-modes.json",
  "spec/repository-format/v1/registries/extensions.json",
  "spec/repository-format/v1/registries/hash-algorithms.json",
  "spec/repository-format/v1/registries/kind-fields.json",
  "spec/repository-format/v1/registries/limits.json",
  "spec/repository-format/v1/registries/logical-record-types.json",
  "spec/repository-format/v1/registries/object-kinds.json",
  "spec/repository-format/v1/registries/profiles.json",
  "spec/repository-format/v1/registries/required-features.json",
  "spec/repository-format/v1/registries/semantic-enums.json",
  "adr/README.md",
  "adr/0008-format-v1-deterministic-cbor-and-object-identity.md",
  "adr/0009-format-v1-object-graph-and-fileid-validation.md",
  "adr/0010-core-profile-registries-and-logical-bundle-boundary.md"
];

class Validation {
  constructor(root) {
    this.root = root;
    this.errors = [];
  }

  fail(scope, message) {
    this.errors.push(`${scope}: ${message}`);
  }

  check(condition, scope, message) {
    if (!condition) this.fail(scope, message);
  }

  absolute(relative) {
    return path.join(this.root, relative);
  }

  raw(relative) {
    try {
      return fs.readFileSync(this.absolute(relative));
    } catch (error) {
      this.fail(relative, `cannot read required file (${error.code ?? error.message})`);
      return null;
    }
  }

  text(relative, { stableJson = false, lexicographicKeys = false } = {}) {
    const bytes = this.raw(relative);
    if (bytes === null) return null;
    this.check(!(bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf), relative, "UTF-8 BOM is forbidden");
    const value = bytes.toString("utf8");
    this.check(!value.includes("\r"), relative, "only LF line endings are allowed");
    this.check(value.endsWith("\n") && !value.endsWith("\n\n"), relative, "file must end in exactly one LF");
    if (stableJson) {
      const parsed = parseJsonStrict(value, relative, this.errors);
      if (parsed !== null) {
        this.check(`${JSON.stringify(parsed, null, 2)}\n` === value, relative, "JSON must use stable two-space formatting");
        if (lexicographicKeys) checkLexicographicObjectKeys(parsed, relative, this.errors);
      }
      return parsed;
    }
    return value;
  }
}

function parseJsonStrict(source, scope, errors) {
  try {
    scanJsonForDuplicateKeys(source);
  } catch (error) {
    errors.push(`${scope}: ${error.message}`);
    return null;
  }
  let value;
  try {
    value = JSON.parse(source);
  } catch (error) {
    errors.push(`${scope}: invalid JSON (${error.message})`);
    return null;
  }
  walk(value, "$", (node, location) => {
    if (typeof node === "number" && (!Number.isSafeInteger(node) || !Number.isInteger(node))) {
      errors.push(`${scope}: ${location} must be an exactly representable integer`);
    }
  });
  return value;
}

function scanJsonForDuplicateKeys(source) {
  let index = 0;
  const whitespace = () => { while (/\s/.test(source[index] ?? "")) index += 1; };
  const string = () => {
    const start = index;
    if (source[index++] !== '"') throw new Error(`invalid JSON token at byte ${start}`);
    while (index < source.length) {
      const char = source[index++];
      if (char === '"') return JSON.parse(source.slice(start, index));
      if (char === "\\") {
        if (source[index] === "u") index += 5;
        else index += 1;
      } else if (char < " ") throw new Error(`invalid JSON string at byte ${start}`);
    }
    throw new Error(`unterminated JSON string at byte ${start}`);
  };
  const value = () => {
    whitespace();
    if (source[index] === "{") return object();
    if (source[index] === "[") return array();
    if (source[index] === '"') { string(); return; }
    const match = source.slice(index).match(/^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)/);
    if (!match) throw new Error(`invalid JSON value at byte ${index}`);
    index += match[0].length;
  };
  const object = () => {
    index += 1;
    whitespace();
    const keys = new Set();
    if (source[index] === "}") { index += 1; return; }
    while (true) {
      whitespace();
      const offset = index;
      const key = string();
      if (keys.has(key)) throw new Error(`duplicate JSON key ${JSON.stringify(key)} at byte ${offset}`);
      keys.add(key);
      whitespace();
      if (source[index++] !== ":") throw new Error(`missing ':' after JSON key at byte ${index - 1}`);
      value();
      whitespace();
      const separator = source[index++];
      if (separator === "}") return;
      if (separator !== ",") throw new Error(`invalid JSON object separator at byte ${index - 1}`);
    }
  };
  const array = () => {
    index += 1;
    whitespace();
    if (source[index] === "]") { index += 1; return; }
    while (true) {
      value();
      whitespace();
      const separator = source[index++];
      if (separator === "]") return;
      if (separator !== ",") throw new Error(`invalid JSON array separator at byte ${index - 1}`);
    }
  };
  value();
  whitespace();
  if (index !== source.length) throw new Error(`trailing JSON token at byte ${index}`);
}

function walk(value, location, visit) {
  visit(value, location);
  if (Array.isArray(value)) value.forEach((item, index) => walk(item, `${location}[${index}]`, visit));
  else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) walk(item, `${location}.${key}`, visit);
  }
}

function checkLexicographicObjectKeys(value, scope, errors, location = "$") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => checkLexicographicObjectKeys(item, scope, errors, `${location}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  const keys = Object.keys(value);
  const sorted = [...keys].sort((a, b) => a.localeCompare(b, "en"));
  if (keys.some((key, index) => key !== sorted[index])) errors.push(`${scope}: ${location} object keys are not lexicographically ordered`);
  for (const [key, item] of Object.entries(value)) checkLexicographicObjectKeys(item, scope, errors, `${location}.${key}`);
}

function assertRegistryHeader(v, relative, expectedName) {
  if (!v) return;
  v.check(expectedName.formatVersion === FORMAT_VERSION, relative, `formatVersion must be ${FORMAT_VERSION}`);
  v.check(expectedName.registryVersion === REGISTRY_VERSION, relative, `registryVersion must be ${REGISTRY_VERSION}`);
}

function uniqueAndOrdered(v, scope, entries, field, comparator = (a, b) => a - b) {
  const seen = new Set();
  let previous;
  entries.forEach((entry, index) => {
    const value = entry?.[field];
    v.check(!seen.has(value), scope, `duplicate ${field} ${JSON.stringify(value)}`);
    seen.add(value);
    if (index > 0) v.check(comparator(previous, value) < 0, scope, `${field} values must be strictly ordered`);
    previous = value;
  });
}

function unique(v, scope, entries, field) {
  const seen = new Set();
  for (const entry of entries) {
    const value = entry?.[field];
    v.check(!seen.has(value), scope, `duplicate ${field} ${JSON.stringify(value)}`);
    seen.add(value);
  }
}

function validateRanges(v, scope, registry, maximum) {
  const all = [];
  for (const group of ["reserved", "unassigned"]) {
    const ranges = registry[group] ?? [];
    let prior = -1;
    for (const range of ranges) {
      v.check(Number.isSafeInteger(range.from) && Number.isSafeInteger(range.to), scope, `${group} bounds must be safe integers`);
      v.check(range.from >= 0 && range.to <= maximum && range.from <= range.to, scope, `${group} range ${range.from}..${range.to} is invalid`);
      v.check(range.from > prior, scope, `${group} ranges must be ordered and non-overlapping`);
      prior = range.to;
      all.push([range.from, range.to, group]);
    }
  }
  all.sort((a, b) => a[0] - b[0]);
  for (let index = 1; index < all.length; index += 1) {
    v.check(all[index][0] > all[index - 1][1], scope, `${all[index - 1][2]} and ${all[index][2]} ranges overlap`);
  }
  for (const entry of registry.entries ?? []) {
    v.check(Number.isSafeInteger(entry.code) && entry.code >= 0 && entry.code <= maximum, scope, `code ${entry.code} is outside uint range`);
    for (const [from, to] of all) v.check(entry.code < from || entry.code > to, scope, `assigned code ${entry.code} overlaps a reserved or unassigned range`);
  }
}

function validateStates(v, scope, entries) {
  for (const entry of entries) {
    v.check(STATES.has(entry.state), scope, `unknown state ${JSON.stringify(entry.state)}`);
    if (Object.hasOwn(entry, "productionWriteAllowed")) {
      v.check(typeof entry.productionWriteAllowed === "boolean", scope, "productionWriteAllowed must be boolean");
      v.check(entry.productionWriteAllowed === (entry.state === "ratified"), scope, `state ${entry.state} is inconsistent with productionWriteAllowed`);
    }
  }
}

function validateNumericRegistry(v, scope, registry, maximum) {
  if (!registry) return;
  uniqueAndOrdered(v, scope, registry.entries ?? [], "code");
  unique(v, scope, registry.entries ?? [], "name");
  validateRanges(v, scope, registry, maximum);
  validateStates(v, scope, registry.entries ?? []);
}

function sameArray(actual, expected) {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function exactRanges(v, scope, actual, expected, label) {
  const pairs = (actual ?? []).map((range) => [range.from, range.to]);
  v.check(pairs.length === expected.length && pairs.every((pair, index) => sameArray(pair, expected[index])), scope, `${label} ranges disagree with the frozen v1 allocation`);
}

function extractCddlMap(text, definition) {
  const marker = new RegExp(`^${definition.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*=\\s*\\{`, "m");
  const match = marker.exec(text);
  if (!match) return null;
  let cursor = match.index + match[0].length - 1;
  let depth = 0;
  let end = cursor;
  for (; end < text.length; end += 1) {
    if (text[end] === "{") depth += 1;
    if (text[end] === "}") {
      depth -= 1;
      if (depth === 0) { end += 1; break; }
    }
  }
  const body = text.slice(cursor + 1, end - 1);
  const fields = [];
  for (const line of body.split("\n")) {
    const field = line.match(/^\s*(\?\s*)?(\d+)\s*:/);
    if (field) fields.push({ key: Number(field[2]), optional: Boolean(field[1]), line });
  }
  return { body, fields };
}

function stripCddlComments(text) {
  return text.split("\n").map((line) => {
    let quoted = false;
    let escaped = false;
    for (let index = 0; index < line.length; index += 1) {
      const character = line[index];
      if (escaped) { escaped = false; continue; }
      if (character === "\\" && quoted) { escaped = true; continue; }
      if (character === '"') quoted = !quoted;
      if (character === ";" && !quoted) return line.slice(0, index);
    }
    return line;
  }).join("\n");
}

function splitTopLevel(text, separator) {
  const values = [];
  let start = 0;
  let square = 0;
  let round = 0;
  let curly = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (escaped) { escaped = false; continue; }
    if (character === "\\" && quoted) { escaped = true; continue; }
    if (character === '"') { quoted = !quoted; continue; }
    if (quoted) continue;
    if (character === "[") square += 1;
    else if (character === "]") square -= 1;
    else if (character === "(") round += 1;
    else if (character === ")") round -= 1;
    else if (character === "{") curly += 1;
    else if (character === "}") curly -= 1;
    else if (character === separator && square === 0 && round === 0 && curly === 0) {
      values.push(text.slice(start, index));
      start = index + 1;
    }
  }
  values.push(text.slice(start));
  return values;
}

function normalizeCddlType(type) {
  return type.trim().replace(/\s+/g, " ").replace(/\s*\.\.\s*/g, "..");
}

function parseCddlNumericMaps(text) {
  const source = stripCddlComments(text);
  const definitions = [...source.matchAll(/^([a-z][a-z0-9-]*)\s*=/gm)];
  const maps = new Map();
  const rules = new Set(definitions.map((match) => match[1]));
  for (let definitionIndex = 0; definitionIndex < definitions.length; definitionIndex += 1) {
    const match = definitions[definitionIndex];
    const rule = match[1];
    const end = definitions[definitionIndex + 1]?.index ?? source.length;
    const value = source.slice(match.index + match[0].length, end);
    const variants = [];
    let depth = 0;
    let start = -1;
    let quoted = false;
    let escaped = false;
    for (let index = 0; index < value.length; index += 1) {
      const character = value[index];
      if (escaped) { escaped = false; continue; }
      if (character === "\\" && quoted) { escaped = true; continue; }
      if (character === '"') { quoted = !quoted; continue; }
      if (quoted) continue;
      if (character === "{") {
        if (depth === 0) start = index + 1;
        depth += 1;
      } else if (character === "}") {
        depth -= 1;
        if (depth === 0 && start >= 0) {
          const fields = [];
          for (const part of splitTopLevel(value.slice(start, index), ",")) {
            const field = part.match(/^\s*(\?\s*)?(\d+)\s*:\s*([\s\S]*?)\s*$/);
            if (field) fields.push({ key: Number(field[2]), optional: Boolean(field[1]), type: normalizeCddlType(field[3]) });
          }
          if (fields.length > 0) variants.push(fields);
          start = -1;
        }
      }
    }
    if (variants.length === 0) continue;
    const keys = [...new Set(variants.flatMap((variant) => variant.map((field) => field.key)))].sort((a, b) => a - b);
    const fields = keys.map((key) => {
      const occurrences = variants.flatMap((variant) => variant.filter((field) => field.key === key));
      const types = [...new Set(occurrences.map((field) => field.type))];
      return {
        key,
        optional: occurrences.some((field) => field.optional) || occurrences.length < variants.length,
        type: types.join(" / ")
      };
    });
    maps.set(rule, { fields, variants });
  }
  return { maps, rules };
}

function extractProseKindFields(text, code) {
  const heading = new RegExp(`^### .*kind ${code}\\s*$`, "im").exec(text);
  if (!heading) return null;
  const start = heading.index + heading[0].length;
  const next = /^#{2,3} /m.exec(text.slice(start));
  const section = text.slice(start, next ? start + next.index : text.length);
  return [...section.matchAll(/^\|\s*(\d+)\s*\|/gm)].map((match) => Number(match[1])).filter((key) => key >= 16);
}

function validateLocalLinks(v, relative, text) {
  const source = v.absolute(relative);
  for (const match of text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    let target = match[1].trim();
    if (!target || /^(?:[a-z]+:|#)/i.test(target)) continue;
    if (target.startsWith("<") && target.endsWith(">")) target = target.slice(1, -1);
    target = decodeURIComponent(target.split("#", 1)[0]);
    const resolved = path.resolve(path.dirname(source), target);
    v.check(resolved.startsWith(`${v.root}${path.sep}`) || resolved === v.root, relative, `local link escapes repository: ${match[1]}`);
    v.check(fs.existsSync(resolved), relative, `broken local link: ${match[1]}`);
  }
}

function validateAdrStatus(v) {
  const indexRelative = "adr/README.md";
  const indexBytes = v.raw(indexRelative);
  const index = indexBytes?.toString("utf8") ?? null;
  if (index === null) return;
  const rows = [...index.matchAll(/^\| \[([0-9]{4})\]\(([^)]+)\) \| ([A-Za-z-]+) \|/gm)];
  v.check(rows.length >= 10, indexRelative, "ADR status table is incomplete");
  const seen = new Set();
  for (const row of rows) {
    const [, number, link, status] = row;
    v.check(!seen.has(number), indexRelative, `duplicate ADR table row ${number}`);
    seen.add(number);
    const relative = path.posix.join("adr", link);
    const documentBytes = v.raw(relative);
    const document = documentBytes?.toString("utf8") ?? null;
    if (document === null) continue;
    const declared = /^\*\*Status:\*\*\s*([^\n]+)$/m.exec(document)?.[1]?.trim();
    v.check(declared === status, indexRelative, `ADR-${number} table status ${status} disagrees with file status ${declared ?? "missing"}`);
  }
  for (const number of ["0008", "0009", "0010"]) {
    v.check(seen.has(number), indexRelative, `missing governing ADR-${number} status row`);
  }
}

function validateKindFields(v, registry, common, objectKinds, logicalRecords, cddl, scope) {
  if (!registry || !common || !objectKinds || !logicalRecords || !cddl) return;
  const entries = registry.entries ?? [];
  v.check(entries.length === 304, scope, "kind-field registry must contain exactly 304 frozen assignments");
  v.check(entries.every((entry) => entry.state === "ratified"), scope, "every initial kind-field assignment must remain ratified");
  const orderedScopes = [...new Set(entries.map((entry) => entry.scope))];
  v.check(orderedScopes.length === 65, scope, "kind-field registry must contain exactly 65 CDDL scopes");
  const seen = new Set();
  let previous = "";
  for (const entry of entries) {
    const identity = `${entry.scope}\u0000${String(entry.code).padStart(10, "0")}`;
    v.check(!seen.has(identity), scope, `duplicate scope/code assignment ${entry.scope}:${entry.code}`);
    seen.add(identity);
    v.check(previous === "" || previous < identity, scope, "assignments must be ordered by scope then numeric code");
    previous = identity;
    v.check(entry.scope === `repository-format.cddl#${entry.cddlRule}`, scope, `scope ${entry.scope} disagrees with cddlRule ${entry.cddlRule}`);
    v.check(Number.isInteger(entry.code) && entry.code >= 0 && entry.code <= 4095, scope, `invalid field code ${entry.scope}:${entry.code}`);
    v.check(PROFILE_TOKEN.test(entry.name), scope, `invalid field name ${JSON.stringify(entry.name)} at ${entry.scope}:${entry.code}`);
    v.check(["required", "optional", "conditional"].includes(entry.requirement), scope, `invalid requirement at ${entry.scope}:${entry.code}`);
    v.check(typeof entry.type === "string" && entry.type.length > 0, scope, `missing type at ${entry.scope}:${entry.code}`);
  }
  const nameAssignment = entries.map((entry) => [entry.scope, entry.code, entry.name].join("\u0000")).join("\n");
  const nameDigest = createHash("sha256").update(nameAssignment).digest("hex");
  v.check(nameDigest === "faf60941bbad5390532b1f5a43026e38f9228e53c68dcc597098e08ea0497659", scope, "frozen field-name assignments changed");

  const conditional = new Set([
    "allocation-proof:2", "attestation:22", "change-set:17",
    "conflict-resolution:1", "conflict-resolution:2", "conflict-resolution:3",
    "entry-state:4", "fileid-lifetime-record:21", "shelf-revision:19"
  ]);
  for (const entry of entries) {
    const shouldBeConditional = conditional.has(`${entry.cddlRule}:${entry.code}`);
    v.check((entry.requirement === "conditional") === shouldBeConditional, scope, `conditional requirement drift at ${entry.scope}:${entry.code}`);
  }

  const parsed = parseCddlNumericMaps(cddl);
  const registryRules = new Set(entries.map((entry) => entry.cddlRule));
  v.check(registryRules.size === 65, scope, "scope names do not map one-to-one to CDDL rules");
  const numericRules = new Set([...parsed.maps].filter(([, map]) => map.fields.every((field) => Number.isInteger(field.key))).map(([rule]) => rule));
  v.check(numericRules.size === 65 && [...registryRules].every((rule) => numericRules.has(rule)) && [...numericRules].every((rule) => registryRules.has(rule)), scope, "registry scopes and numeric-key CDDL map rules differ");

  const inheritance = registry.commonFieldInheritance;
  const expectedInheritedRules = Object.keys(OBJECT_DEFINITIONS).sort();
  const inheritedRules = (inheritance?.appliesToScopes ?? []).map((value) => value.replace("repository-format.cddl#", ""));
  v.check(sameArray(inheritedRules, expectedInheritedRules), scope, "common-envelope inheritance scope list is invalid");
  v.check(inheritance?.registry === "ogvcs.repository-format.common-fields" && inheritance?.commonKeyRange?.from === 0 && inheritance?.commonKeyRange?.to === 3 && inheritance?.reservedKeyRange?.from === 4 && inheritance?.reservedKeyRange?.to === 15, scope, "common-envelope inheritance metadata is invalid");

  const commonFields = common.entries.map((entry) => ({
    key: entry.code,
    requirement: entry.required ? "required" : "optional",
    type: entry.code === 0 ? "1" : entry.code === 1 ? null : entry.code === 2 ? "required-features" : "extensions"
  }));
  for (const rule of registryRules) {
    const registered = entries.filter((entry) => entry.cddlRule === rule);
    const actual = parsed.maps.get(rule)?.fields;
    v.check(Boolean(actual), scope, `CDDL map rule is missing for ${rule}`);
    if (!actual) continue;
    const inherited = inheritedRules.includes(rule);
    const expected = inherited ? [...commonFields, ...registered.map((entry) => ({ key: entry.code, requirement: entry.requirement, type: entry.type }))] : registered.map((entry) => ({ key: entry.code, requirement: entry.requirement, type: entry.type }));
    v.check(sameArray(actual.map((field) => field.key), expected.map((field) => field.key)), scope, `${rule} field codes disagree with CDDL`);
    for (const field of expected) {
      const cddlField = actual.find((candidate) => candidate.key === field.key);
      if (!cddlField) continue;
      const optional = field.requirement !== "required";
      v.check(cddlField.optional === optional, scope, `${rule}:${field.key} requirement ${field.requirement} disagrees with CDDL`);
      if (inherited && field.key === 1) {
        const kind = OBJECT_DEFINITIONS[rule]?.code;
        v.check(cddlField.type === String(kind), scope, `${rule}:1 object-kind discriminator must be ${kind}`);
      } else if (field.type !== null) {
        const expectedType = normalizeCddlType(field.type);
        const alias = new RegExp(`^${expectedType.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*=\\s*([^\\n]+)$`, "m").exec(stripCddlComments(cddl))?.[1];
        v.check(cddlField.type === expectedType || (alias && cddlField.type === normalizeCddlType(alias)), scope, `${rule}:${field.key} type ${field.type} disagrees with CDDL type ${cddlField.type}`);
      }
    }
  }

  const knownTypes = parsed.rules;
  const primitiveTypes = new Set(["bstr", "tstr", "uint", "int", "bool", "size", "ge", "le"]);
  for (const entry of entries) {
    for (const identifier of entry.type.match(/[a-z][a-z0-9-]*/g) ?? []) {
      v.check(primitiveTypes.has(identifier) || knownTypes.has(identifier), scope, `unknown CDDL type reference ${identifier} at ${entry.scope}:${entry.code}`);
    }
  }

  for (const [rule, definition] of Object.entries(OBJECT_DEFINITIONS)) {
    const fields = entries.filter((entry) => entry.cddlRule === rule);
    v.check(fields.length > 0 && fields.every((entry) => entry.objectKind === definition.code), scope, `${rule} objectKind metadata must be ${definition.code}`);
  }
  for (const [code, name] of LOGICAL_RECORDS) {
    const rule = `${name.replace("file-id", "fileid")}-record`;
    const fields = entries.filter((entry) => entry.cddlRule === rule);
    v.check(fields.length > 0 && fields.every((entry) => entry.logicalRecordType === code), scope, `${rule} logicalRecordType metadata must be ${code}`);
    v.check(fields.find((entry) => entry.code === 1)?.type === String(code), scope, `${rule}:1 logical-record discriminator must be ${code}`);
  }
  const bundleItems = { "bundle-header": 1, "bundle-object": 2, "bundle-logical-record": 3, "bundle-root": 4, "bundle-trailer": 5 };
  for (const [rule, code] of Object.entries(bundleItems)) {
    const fields = entries.filter((entry) => entry.cddlRule === rule);
    v.check(fields.length > 0 && fields.every((entry) => entry.itemType === code), scope, `${rule} itemType metadata must be ${code}`);
    v.check(fields.find((entry) => entry.code === 1)?.type === String(code), scope, `${rule}:1 bundle-item discriminator must be ${code}`);
  }
  const operations = { "create-operation": 1, "modify-operation": 2, "copy-operation": 3, "move-operation": 4, "rename-operation": 5, "delete-operation": 6, "restore-operation": 7, "group-create-operation": 8, "group-update-operation": 9, "group-delete-operation": 10, "merge-resolution-operation": 11 };
  for (const [rule, code] of Object.entries(operations)) {
    v.check(entries.find((entry) => entry.cddlRule === rule && entry.code === 1)?.type === String(code), scope, `${rule}:1 operation discriminator must be ${code}`);
  }
  const refs = { "chunk-ref": 1, "manifest-ref": 2, "tree-ref": 3, "change-set-ref": 4, "group-set-ref": 5, "descriptor-ref": 6, "snapshot-ref": 7, "shelf-revision-ref": 8, "provenance-ref": 9, "attestation-ref": 10, "conflict-set-ref": 11 };
  for (const [rule, code] of Object.entries(refs)) {
    v.check(entries.find((entry) => entry.cddlRule === rule && entry.code === 1)?.type === String(code), scope, `${rule}:1 expected-kind discriminator must be ${code}`);
  }
  v.check(/^repository-format-cbor-item =\n  metadata-object \/\n  logical-record \/\n  logical-bundle-item \/\n  conflict-id-preimage$/m.test(cddl), "spec/repository-format/v1/repository-format.cddl", "public CBOR item union must contain metadata-object, logical-record, logical-bundle-item, and conflict-id-preimage in order");
}

function validateSpec(root) {
  const v = new Validation(path.resolve(root));
  for (const relative of EXPECTED_FILES) v.check(fs.existsSync(v.absolute(relative)), relative, "required artifact is missing");

  const workspaceLicense = v.text("LICENSE");
  const formatLicense = v.text("spec/repository-format/v1/LICENSE");
  v.check(workspaceLicense?.startsWith("MIT License\n") === true, "LICENSE", "workspace license must be MIT");
  v.check(formatLicense === workspaceLicense, "spec/repository-format/v1/LICENSE", "format package license must match the workspace license");
  const formatPackage = v.text("spec/repository-format/v1/package.json", { stableJson: true });
  if (formatPackage) {
    v.check(formatPackage.name === "@opengamevcs/repository-format-v1", "spec/repository-format/v1/package.json", "package name is invalid");
    v.check(formatPackage.license === "MIT", "spec/repository-format/v1/package.json", "package license must be MIT");
    v.check(formatPackage.files?.includes("LICENSE") === true, "spec/repository-format/v1/package.json", "packed files must include LICENSE");
  }

  const registryPaths = [
    "common-fields", "entry-kinds", "entry-modes", "extensions",
    "hash-algorithms", "kind-fields", "limits", "logical-record-types", "object-kinds",
    "profiles", "required-features", "semantic-enums"
  ];
  const registries = {};
  for (const name of registryPaths) {
    const relative = `spec/repository-format/v1/registries/${name}.json`;
    registries[name] = v.text(relative, { stableJson: true, lexicographicKeys: true });
    if (registries[name]) {
      v.check(registries[name].formatVersion === FORMAT_VERSION, relative, `formatVersion must be ${FORMAT_VERSION}`);
      v.check(registries[name].registryVersion === REGISTRY_VERSION, relative, `registryVersion must be ${REGISTRY_VERSION}`);
      v.check(registries[name].registry === `ogvcs.repository-format.${name === "limits" ? "hard-limits" : name}`, relative, "registry identity is invalid");
    }
  }

  const objectKinds = registries["object-kinds"];
  validateNumericRegistry(v, "object-kinds", objectKinds, 65535);
  if (objectKinds) {
    v.check(objectKinds.entries.length === OBJECT_KINDS.length, "object-kinds", "v1 must assign exactly object kinds 1..11");
    OBJECT_KINDS.forEach(([code, name, payload], index) => {
      const entry = objectKinds.entries[index] ?? {};
      v.check(entry.code === code && entry.name === name && entry.textToken === name && entry.payload === payload && entry.state === "ratified", "object-kinds", `code ${code} assignment must remain ${name}/${payload} and ratified`);
    });
    unique(v, "object-kinds", objectKinds.entries, "textToken");
    exactRanges(v, "object-kinds", objectKinds.reserved, [[0, 0]], "reserved");
    exactRanges(v, "object-kinds", objectKinds.unassigned, [[12, 65535]], "unassigned");
  }

  const hashes = registries["hash-algorithms"];
  validateNumericRegistry(v, "hash-algorithms", hashes, 65535);
  if (hashes) {
    v.check(hashes.entries.length === 1 && hashes.entries[0].code === 1 && hashes.entries[0].name === "sha256" && hashes.entries[0].digestBytes === 32 && hashes.entries[0].state === "ratified", "hash-algorithms", "v1 hash assignment must be ratified code 1 SHA-256 with 32 bytes");
    exactRanges(v, "hash-algorithms", hashes.reserved, [[0, 0]], "reserved");
    exactRanges(v, "hash-algorithms", hashes.unassigned, [[2, 65535]], "unassigned");
  }

  const common = registries["common-fields"];
  validateNumericRegistry(v, "common-fields", common, 15);
  if (common) {
    const expected = [[0, "format-version", true, "uint"], [1, "object-kind", true, "uint"], [2, "required-features", true, "array<uint>"], [3, "extensions", false, "map<tstr,value>"]];
    v.check(common.kindFieldRange?.from === 16 && common.kindFieldRange?.to === 4095, "common-fields", "kindFieldRange must be 16..4095");
    expected.forEach(([code, name, required, type], index) => {
      const entry = common.entries[index] ?? {};
      v.check(entry.code === code && entry.name === name && entry.required === required && entry.type === type && entry.state === "ratified", "common-fields", `common key ${code} assignment is inconsistent`);
    });
    exactRanges(v, "common-fields", common.reserved, [[4, 15]], "reserved");
  }

  const entryKinds = registries["entry-kinds"];
  const entryModes = registries["entry-modes"];
  validateNumericRegistry(v, "entry-kinds", entryKinds, 65535);
  validateNumericRegistry(v, "entry-modes", entryModes, 65535);
  if (entryKinds && entryModes && objectKinds) {
    const objectNames = new Set(objectKinds.entries.map((entry) => entry.name));
    for (const kind of entryKinds.entries) {
      v.check(objectNames.has(kind.targetKind), "entry-kinds", `targetKind ${kind.targetKind} is not an object kind`);
      uniqueAndOrdered(v, "entry-kinds", kind.allowedModeCodes.map((code) => ({ code })), "code");
      for (const code of kind.allowedModeCodes) {
        const mode = entryModes.entries.find((candidate) => candidate.code === code);
        v.check(Boolean(mode) && mode.allowedEntryKindCodes.includes(kind.code), "entry-kinds", `kind ${kind.code}/mode ${code} relationship is not symmetric`);
      }
    }
    for (const mode of entryModes.entries) {
      uniqueAndOrdered(v, "entry-modes", mode.allowedEntryKindCodes.map((code) => ({ code })), "code");
      for (const code of mode.allowedEntryKindCodes) {
        const kind = entryKinds.entries.find((candidate) => candidate.code === code);
        v.check(Boolean(kind) && kind.allowedModeCodes.includes(mode.code), "entry-modes", `mode ${mode.code}/kind ${code} relationship is not symmetric`);
      }
    }
    v.check(entryKinds.entries.every((entry) => entry.state === "ratified") && entryModes.entries.every((entry) => entry.state === "ratified"), "entry-kinds", "initial entry kinds and modes must remain ratified");
    exactRanges(v, "entry-kinds", entryKinds.reserved, [[0, 0]], "reserved");
    exactRanges(v, "entry-kinds", entryKinds.unassigned, [[5, 65535]], "unassigned");
    exactRanges(v, "entry-modes", entryModes.reserved, [[0, 0]], "reserved");
    exactRanges(v, "entry-modes", entryModes.unassigned, [[5, 65535]], "unassigned");
  }

  const features = registries["required-features"];
  validateNumericRegistry(v, "required-features", features, 4294967295);
  if (features) {
    v.check(features.entries.length === 0, "required-features", "initial v1 required-feature registry must be empty");
    v.check(features.reserved?.length === 1 && features.reserved[0].from === 0 && features.reserved[0].to === 0, "required-features", "feature zero must remain reserved");
    v.check(features.unassigned?.length === 1 && features.unassigned[0].from === 1 && features.unassigned[0].to === 4294967295, "required-features", "feature IDs 1..uint32 max must remain unassigned in this draft");
  }

  const semanticEnums = registries["semantic-enums"];
  if (semanticEnums) {
    const expectedDomains = Object.entries(SEMANTIC_ENUMS);
    v.check(semanticEnums.domains?.length === expectedDomains.length, "semantic-enums", "semantic enum domain count is invalid");
    expectedDomains.forEach(([name, assignments], domainIndex) => {
      const domain = semanticEnums.domains?.[domainIndex] ?? {};
      v.check(domain.name === name, "semantic-enums", `domain ${domainIndex} must remain ${name}`);
      v.check(domain.entries?.length === assignments.length, "semantic-enums", `${name} assignment count is invalid`);
      uniqueAndOrdered(v, `semantic-enums:${name}`, domain.entries ?? [], "code");
      unique(v, `semantic-enums:${name}`, domain.entries ?? [], "name");
      validateStates(v, `semantic-enums:${name}`, domain.entries ?? []);
      assignments.forEach(([code, entryName, expectedState = "ratified"], entryIndex) => {
        const entry = domain.entries?.[entryIndex] ?? {};
        v.check(entry.code === code && entry.name === entryName && entry.state === expectedState, "semantic-enums", `${name} code ${code} must remain ${expectedState} ${entryName}`);
      });
    });
  }

  const profiles = registries.profiles;
  if (profiles) {
    validateStates(v, "profiles", profiles.entries);
    const tuple = (entry) => `${entry.namespace}\u0000${entry.id}\u0000${String(entry.major).padStart(10, "0")}`;
    uniqueAndOrdered(v, "profiles", profiles.entries.map((entry) => ({ tuple: tuple(entry) })), "tuple", (a, b) => a < b ? -1 : a > b ? 1 : 0);
    for (const entry of profiles.entries) {
      v.check(PROFILE_NAMESPACE.test(entry.namespace) && Buffer.byteLength(entry.namespace) <= 253, "profiles", `invalid profile namespace ${JSON.stringify(entry.namespace)}`);
      v.check(PROFILE_TOKEN.test(entry.id) && Buffer.byteLength(entry.id) <= 63, "profiles", `invalid profile id ${JSON.stringify(entry.id)}`);
      v.check(Number.isInteger(entry.major) && entry.major >= 1 && entry.major <= 4294967295, "profiles", `invalid profile major ${entry.major}`);
      v.check(PROFILE_FAMILIES.has(entry.family), "profiles", `unknown profile family ${JSON.stringify(entry.family)}`);
      v.check(/^OGVCS-[0-9]{3}$/.test(entry.owner), "profiles", `invalid owner PRD ${JSON.stringify(entry.owner)}`);
      const ownerExists = ["todo", "done"].some((state) => {
        const directory = v.absolute(`prd/${state}`);
        return fs.existsSync(directory) && fs.readdirSync(directory).some((name) => name.startsWith(`${entry.owner}-`) && name.endsWith(".md"));
      });
      v.check(ownerExists, "profiles", `owner PRD ${entry.owner} does not exist in prd/todo or prd/done`);
    }
    v.check(profiles.states?.length === 4 && profiles.states.every((state, index) => state === [...STATES][index]), "profiles", "profile states are not the canonical state list");
    const shape = profiles.profileRef;
    v.check(shape?.namespacePattern === PROFILE_NAMESPACE.source && shape?.idPattern === PROFILE_TOKEN.source, "profiles", "ProfileRef grammar metadata disagrees with the normative grammar");
    v.check(shape?.namespaceUtf8BytesMaximum === 253 && shape?.idUtf8BytesMaximum === 63 && shape?.textKey === "<namespace>/<id>@<major>", "profiles", "ProfileRef bounds or text rendering metadata is invalid");
    v.check(sameArray((shape?.fields ?? []).map((field) => field.code), [0, 1, 2]), "profiles", "ProfileRef wire keys must be 0,1,2");
  }

  const extensions = registries.extensions;
  if (extensions) {
    validateStates(v, "extensions", extensions.entries);
    v.check(sameArray(extensions.states ?? [], [...STATES]), "extensions", "extension states are not the canonical state list");
    const key = extensions.extensionKey;
    v.check(key?.namespacePattern === PROFILE_NAMESPACE.source && key?.idPattern === PROFILE_TOKEN.source, "extensions", "extension key grammar must equal ProfileRef grammar");
    v.check(key?.namespaceUtf8BytesMaximum === 253 && key?.idUtf8BytesMaximum === 63 && key?.majorMinimum === 1 && key?.majorMaximum === 4294967295 && key?.textKey === "<namespace>/<id>@<major>", "extensions", "extension key limits or rendering are invalid");
    const extensionTuple = (entry) => `${entry.namespace}\u0000${entry.id}\u0000${String(entry.major).padStart(10, "0")}`;
    uniqueAndOrdered(v, "extensions", extensions.entries.map((entry) => ({ tuple: extensionTuple(entry) })), "tuple", (a, b) => a < b ? -1 : a > b ? 1 : 0);
    for (const entry of extensions.entries) {
      v.check(PROFILE_NAMESPACE.test(entry.namespace) && Buffer.byteLength(entry.namespace) <= 253, "extensions", `invalid extension namespace ${JSON.stringify(entry.namespace)}`);
      v.check(PROFILE_TOKEN.test(entry.id) && Buffer.byteLength(entry.id) <= 63, "extensions", `invalid extension id ${JSON.stringify(entry.id)}`);
      v.check(Number.isInteger(entry.major) && entry.major >= 1 && entry.major <= 4294967295, "extensions", `invalid extension major ${entry.major}`);
      v.check(/^OGVCS-[0-9]{3}$/.test(entry.owner), "extensions", `invalid owner PRD ${JSON.stringify(entry.owner)}`);
    }
  }

  const limits = registries.limits;
  if (limits) {
    unique(v, "limits", limits.entries, "name");
    v.check(limits.entries.length === LIMITS.length, "limits", "hard-limit table has an unexpected size");
    LIMITS.forEach(([name, unit, value], index) => {
      const entry = limits.entries[index] ?? {};
      v.check(entry.name === name && entry.unit === unit && entry.value === value, "limits", `hard limit ${name} is missing, reordered, or reassigned`);
      v.check(Number.isSafeInteger(entry.value) && entry.value > 0, "limits", `${name} must be a positive safe integer`);
      v.check(/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/.test(entry.errorCode), "limits", `${name} must declare a stable errorCode`);
    });
  }

  const logical = registries["logical-record-types"];
  validateNumericRegistry(v, "logical-record-types", logical, 65535);
  if (logical) {
    v.check(logical.identity === "not-an-object-id", "logical-record-types", "logical records must remain outside ObjectID identity");
    v.check(logical.entries.length === LOGICAL_RECORDS.length, "logical-record-types", "logical record assignment count is invalid");
    LOGICAL_RECORDS.forEach(([code, name], index) => {
      const entry = logical.entries[index] ?? {};
      const state = code === 9 ? "conformance-only" : "ratified";
      v.check(entry.code === code && entry.name === name && entry.state === state, "logical-record-types", `logical record code ${code} must remain ${state} ${name}`);
    });
    exactRanges(v, "logical-record-types", logical.reserved, [[0, 0]], "reserved");
    exactRanges(v, "logical-record-types", logical.unassigned, [[10, 65535]], "unassigned");
  }

  const errorsRelative = "spec/repository-format/v1/errors.json";
  const errorCatalogue = v.text(errorsRelative, { stableJson: true });
  if (errorCatalogue) {
    v.check(errorCatalogue.schemaVersion === "ogvcs.repository-format/errors/v1" && errorCatalogue.formatVersion === 1, errorsRelative, "error catalogue version is invalid");
    uniqueAndOrdered(v, errorsRelative, errorCatalogue.errors, "number");
    unique(v, errorsRelative, errorCatalogue.errors, "code");
    v.check(errorCatalogue.precedence?.betweenLayers === "lowest-layer-first" &&
      errorCatalogue.precedence?.withinLayer === "stage-order-then-errors-array-order" &&
      errorCatalogue.precedence?.occurrenceTieBreak === "smallest-input-offset-then-frozen-subject-comparator" &&
      JSON.stringify(errorCatalogue.precedence?.stageOrder) === JSON.stringify(VALIDATION_STAGES),
    errorsRelative, "failure precedence contract is invalid");
    const knownStages = new Set(VALIDATION_STAGES);
    for (const error of errorCatalogue.errors) {
      v.check(Number.isInteger(error.number) && error.number > 0, errorsRelative, "error numbers must be positive integers");
      v.check(/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/.test(error.code), errorsRelative, `invalid error code ${JSON.stringify(error.code)}`);
      v.check(typeof error.class === "string" && error.class.length > 0 && typeof error.retryability === "string" && error.retryability.length > 0 && typeof error.description === "string" && error.description.endsWith("."), errorsRelative, `error ${error.code} has incomplete metadata`);
      v.check(Array.isArray(error.sites) && error.sites.length > 0, errorsRelative, `error ${error.code} must declare at least one exact validation site`);
      const pairs = new Set();
      let previousStage = -1;
      for (const site of error.sites ?? []) {
        const keys = site && typeof site === "object" && !Array.isArray(site) ? Object.keys(site).sort() : [];
        v.check(sameArray(keys, ["layers", "stage"]), errorsRelative, `error ${error.code} site must contain only stage and layers`);
        const stageIndex = VALIDATION_STAGES.indexOf(site?.stage);
        v.check(knownStages.has(site?.stage), errorsRelative, `error ${error.code} references unknown stage ${JSON.stringify(site?.stage)}`);
        v.check(stageIndex > previousStage, errorsRelative, `error ${error.code} sites must follow precedence.stageOrder without duplicates`);
        previousStage = stageIndex;
        v.check(Array.isArray(site?.layers) && site.layers.length > 0 &&
          site.layers.every((layer) => Number.isInteger(layer) && layer >= 1 && layer <= 3) &&
          new Set(site.layers).size === site.layers.length &&
          site.layers.every((layer, index) => index === 0 || site.layers[index - 1] < layer),
        errorsRelative, `error ${error.code} site ${JSON.stringify(site?.stage)} has invalid layers`);
        for (const layer of site?.layers ?? []) {
          const pair = `${site.stage}\0${layer}`;
          v.check(!pairs.has(pair), errorsRelative, `error ${error.code} repeats validation site ${site.stage}/layer-${layer}`);
          pairs.add(pair);
        }
      }
    }
    const registeredErrorCodes = new Set(errorCatalogue.errors.map((error) => error.code));
    for (const limit of limits?.entries ?? []) v.check(registeredErrorCodes.has(limit.errorCode), "limits", `${limit.name} references unknown errorCode ${limit.errorCode}`);
  }

  const cddlRelative = "spec/repository-format/v1/repository-format.cddl";
  const cddl = v.text(cddlRelative);
  const objectModelRelative = "spec/repository-format/v1/object-model.md";
  const objectModel = v.text(objectModelRelative);
  const logicalBundleRelative = "spec/repository-format/v1/logical-bundle.md";
  const logicalBundle = v.text(logicalBundleRelative);
  validateKindFields(v, registries["kind-fields"], common, objectKinds, logical, cddl, "kind-fields");
  if (cddl && objectModel) {
    v.check(/^format-v1 = 1$/m.test(cddl) && /^sha256-algorithm = 1$/m.test(cddl) && /^digest = bstr \.size 32$/m.test(cddl), cddlRelative, "format/hash/digest CDDL constants disagree with registries");
    v.check(/^required-features = \[\* feature-id\]$/m.test(cddl) && /^feature-id = uint \.le 4294967295$/m.test(cddl), cddlRelative, "required-feature CDDL shape or range is invalid");
    v.check(sameArray(extractCddlMap(cddl, "typed-digest")?.fields.map((field) => field.key) ?? [], [0, 1]), cddlRelative, "typed-digest wire keys must be 0,1");
    v.check(sameArray(extractCddlMap(cddl, "object-ref")?.fields.map((field) => field.key) ?? [], [0, 1, 2, 3]), cddlRelative, "ObjectRef wire keys must be 0,1,2,3");
    v.check(sameArray(extractCddlMap(cddl, "profile-ref")?.fields.map((field) => field.key) ?? [], [0, 1, 2]), cddlRelative, "ProfileRef wire keys must be 0,1,2");
    v.check(/^object-kind = 1\.\.11$/m.test(cddl), cddlRelative, "object-kind range must be 1..11");
    v.check(/^allocation-kind = 1\.\.2 /m.test(cddl) && /^conflict-kind = 1\.\.4 \/ 6\.\.8$/m.test(cddl), cddlRelative, "allocation/conflict enum ranges disagree with semantic-enums");
    v.check(/^\s*18: 1\.\.3, ; native-create, native-copy, import$/m.test(extractCddlMap(cddl, "fileid-lifetime-record")?.body ?? ""), cddlRelative, "lifetime origin enum disagrees with semantic-enums");
    v.check(/^\s*21: 1\.\.3 ; reserved, materialized, published$/m.test(extractCddlMap(cddl, "import-mapping-record")?.body ?? ""), cddlRelative, "import state enum disagrees with semantic-enums");
    v.check(/^\s*2: 1\.\.2, ; pass, explicit override$/m.test(extractCddlMap(cddl, "policy-result")?.body ?? ""), cddlRelative, "policy decision enum disagrees with semantic-enums");
    v.check(/^\s*2: 1, ; supplied-closure bundle mode$/m.test(extractCddlMap(cddl, "bundle-header")?.body ?? "") && /^\s*3: 1\.\.2, ; object, logical record$/m.test(extractCddlMap(cddl, "bundle-root")?.body ?? ""), cddlRelative, "bundle mode/root enums disagree with semantic-enums");
    v.check(/^entry-conflict-subject = \[1, \[1\*3 file-id\], \[1\*3 path-value\]\]$/m.test(cddl) && /^group-conflict-subject = \[2, group-id\]$/m.test(cddl), cddlRelative, "typed conflict subject shape is invalid");
    v.check(/conflict-resolution =\n  \{0: 0\} \/\n  \{0: 1, 1: 1\.\.3, 2: conflict-side\} \/\n  \{0: 1, 1: 4\} \/\n  \{0: 1, 1: 5, 2: conflict-side, 3: profile-ref\}/m.test(cddl), cddlRelative, "conflict resolution choices disagree with semantic-enums");
    const union = /^metadata-object =\n((?:  [a-z-]+ \/\n)+  [a-z-]+)$/m.exec(cddl)?.[1]?.match(/[a-z][a-z-]+/g) ?? [];
    v.check(sameArray(union, Object.keys(OBJECT_DEFINITIONS)), cddlRelative, "metadata-object union disagrees with registered non-chunk kinds");
    for (const [definition, expected] of Object.entries(OBJECT_DEFINITIONS)) {
      const map = extractCddlMap(cddl, definition);
      v.check(Boolean(map), cddlRelative, `missing ${definition} definition`);
      if (!map) continue;
      const keys = map.fields.map((field) => field.key);
      v.check(sameArray(keys, [0, 1, 2, 3, ...expected.fields]), cddlRelative, `${definition} wire keys are missing, reordered, duplicated, or reassigned`);
      v.check(map.fields.find((field) => field.key === 3)?.optional === true, cddlRelative, `${definition} extensions key 3 must be optional`);
      v.check(sameArray(map.fields.filter((field) => field.optional && field.key >= 16).map((field) => field.key), expected.optional), cddlRelative, `${definition} optional field assignments disagree with the object model`);
      v.check(new RegExp(`^\\s*1:\\s*${expected.code},?`, "m").test(map.body), cddlRelative, `${definition} kind discriminator must be ${expected.code}`);
      const proseKeys = extractProseKindFields(objectModel, expected.code);
      v.check(Boolean(proseKeys), objectModelRelative, `missing prose kind-${expected.code} field table`);
      if (proseKeys) v.check(sameArray(proseKeys, expected.fields), objectModelRelative, `kind-${expected.code} prose fields disagree with CDDL/registry assignment`);
    }
    for (const [code, name, expectedKeys] of LOGICAL_RECORDS) {
      const definition = `${name.replace("file-id", "fileid")}-record`;
      const map = extractCddlMap(cddl, definition);
      v.check(Boolean(map), cddlRelative, `missing ${definition} definition`);
      if (!map) continue;
      const keys = map.fields.map((field) => field.key);
      v.check(sameArray(keys, expectedKeys), cddlRelative, `${definition} wire keys are missing, reordered, duplicated, or reassigned`);
      v.check(new RegExp(`^\\s*1:\\s*${code},?`, "m").test(map.body), cddlRelative, `${definition} type discriminator must be ${code}`);
      const registryEntry = logical?.entries?.find((entry) => entry.code === code);
      if (registryEntry?.wireShape) {
        v.check(sameArray(Object.keys(registryEntry.wireShape).map(Number), expectedKeys), "logical-record-types", `${name} wireShape keys disagree with CDDL`);
      }
    }
    const mutableRef = extractCddlMap(cddl, "mutable-ref-record");
    v.check(/^nonempty-text-value = tstr \.size \(1\.\.16777216\)$/m.test(cddl) &&
      /^\s*18: nonempty-text-value,/m.test(mutableRef?.body ?? ""), cddlRelative,
    "mutable-ref name must be nonempty text within the generic text-value ceiling");
    const cddlLimits = [
      ["bundle-sequence-bytes", 2199023255552],
      ["bundle-largest-item-bytes", 536871424],
      ["bundle-object-count", 10000000],
      ["bundle-logical-record-count", 10000000],
      ["bundle-root-count", 20000000],
      ["bundle-total-item-count", 40000002],
      ["bundle-traversal-edge-count", 100000000],
      ["bundle-index-entry-count", 20000000]
    ];
    for (const [name, maximum] of cddlLimits) {
      v.check(new RegExp(`^${name} = (?:0|2)\\.\\.${maximum}$`, "m").test(cddl), cddlRelative, `${name} disagrees with the hard-limit registry`);
    }
    const kindRows = [...objectModel.matchAll(/^\|\s*(\d+)\s*\|\s*(?:raw chunk|content manifest|tree|change set|asset-group set|repository descriptor|snapshot|shelf revision|provenance|attestation|conflict set)\s*\|$/gm)].map((match) => Number(match[1]));
    v.check(sameArray(kindRows, OBJECT_KINDS.map(([code]) => code)), objectModelRelative, "object-kind prose table disagrees with the registry");
  }
  if (cddl) {
    const compile = spawnSync("cddl", ["--ci", "compile-cddl", "--cddl", v.absolute(cddlRelative)], { encoding: "utf8" });
    if (!compile.error || compile.error.code !== "ENOENT") {
      v.check(compile.status === 0, cddlRelative, `optional cddl compiler rejected schema: ${(compile.stderr || compile.stdout || `exit ${compile.status}`).trim()}`);
    }
  }
  if (logicalBundle) {
    const rows = [...logicalBundle.matchAll(/^\|\s*(\d+)\s*\|\s*`([^`]+)`\s*\|/gm)].map((match) => [Number(match[1]), match[2]]);
    v.check(rows.length === LOGICAL_RECORDS.length && rows.every(([code, name], index) => code === LOGICAL_RECORDS[index][0] && name === LOGICAL_RECORDS[index][1]), logicalBundleRelative, "logical-record prose assignments disagree with the registry");
  }

  const scenarioSchemaRelative = "spec/repository-format/v1/validation-scenario.schema.json";
  const scenarioSchema = v.text(scenarioSchemaRelative, { stableJson: true });
  if (scenarioSchema) {
    v.check(scenarioSchema.$schema === "https://json-schema.org/draft/2020-12/schema" && scenarioSchema.$id?.endsWith("/validation-scenario.schema.json"), scenarioSchemaRelative, "scenario schema identity is invalid");
    v.check(scenarioSchema.additionalProperties === false && scenarioSchema.type === "object", scenarioSchemaRelative, "scenario root must be a closed object");
    v.check(sameArray(scenarioSchema.required ?? [], ["schemaVersion", "scenarioId", "operation", "requirementIds", "inputs", "context", "resources", "expected", "failurePrecedence"]), scenarioSchemaRelative, "scenario required fields are missing or reordered");
    v.check(sameArray(scenarioSchema.properties?.operation?.enum ?? [], ["adapt-fixture", "allocate-file-id", "canonical-scan", "import-file-id", "replay-change-set", "validate-abstract-reference-graph", "validate-bundle", "validate-bundle-claim", "validate-object", "validate-repository"]), scenarioSchemaRelative, "scenario operation enum is invalid");
    v.check(sameArray(scenarioSchema.properties?.implementationScope?.items?.enum ?? [], ["javascript", "rust"]), scenarioSchemaRelative, "scenario implementation scope is invalid");
    v.check(scenarioSchema.properties?.failurePrecedence?.const === "errors-v1-layer-stage-code-offset-subject", scenarioSchemaRelative, "scenario failure precedence selector is invalid");
    const rejectingExpected = scenarioSchema.$defs?.expected?.oneOf?.[1];
    v.check(sameArray(rejectingExpected?.required ?? [], ["result", "layer", "stage", "code"]) &&
      sameArray(rejectingExpected?.properties?.stage?.enum ?? [], VALIDATION_STAGES),
    scenarioSchemaRelative, "scenario rejecting result must expose the exact validation stage");
    const contextRequired = ["mode", "requestedLayer", "asOf", "registrySnapshot", "objectLookup", "roots", "lifetimeRecords", "workingLifetimeAdditions", "importMappings"];
    v.check(sameArray(scenarioSchema.$defs?.context?.required ?? [], contextRequired), scenarioSchemaRelative, "scenario context required fields are missing or reordered");
    v.check(scenarioSchema.$defs?.context?.properties?.asOf?.const === "immediately-before-candidate-snapshot", scenarioSchemaRelative, "scenario temporal convention is invalid");
    const lookup = scenarioSchema.$defs?.context?.properties?.objectLookup?.items;
    v.check(lookup?.additionalProperties === false && sameArray(lookup?.required ?? [], ["ref", "artifact"]), scenarioSchemaRelative, "scenario object lookup must bind each ObjectRef to one artifact");
    v.check(scenarioSchema.$defs?.lifetime?.oneOf?.length === 2 && sameArray(scenarioSchema.$defs?.lifetime?.oneOf?.[1]?.required ?? [], ["importMappingKey"]), scenarioSchemaRelative, "scenario lifetime origin/import-key coupling is missing");
    v.check((scenarioSchema.$defs?.importMapping?.required ?? []).includes("mappingKey"), scenarioSchemaRelative, "scenario import mapping must carry its derived mapping key");
    v.check(sameArray(scenarioSchema.$defs?.resources?.required ?? [], ["recipe", "summary"]), scenarioSchemaRelative, "scenario resource contract is incomplete");
  }

  const abstractGraphSchemaRelative = "spec/repository-format/v1/abstract-reference-graph.schema.json";
  const abstractGraphSchema = v.text(abstractGraphSchemaRelative, { stableJson: true });
  if (abstractGraphSchema) {
    v.check(abstractGraphSchema.$schema === "https://json-schema.org/draft/2020-12/schema" && abstractGraphSchema.$id?.endsWith("/abstract-reference-graph.schema.json"), abstractGraphSchemaRelative, "abstract graph schema identity is invalid");
    v.check(abstractGraphSchema.additionalProperties === false && abstractGraphSchema.type === "object", abstractGraphSchemaRelative, "abstract graph root must be a closed object");
    v.check(abstractGraphSchema.properties?.assumedValidation?.const === "canonical-framing-schema-and-identity-prevalidated", abstractGraphSchemaRelative, "abstract graph prevalidation marker is invalid");
    v.check(sameArray(abstractGraphSchema.properties?.graphKind?.enum ?? [], ["provenance-input", "snapshot-parent"]), abstractGraphSchemaRelative, "abstract graph kind enum is invalid");
    v.check(sameArray(abstractGraphSchema.required ?? [], ["schemaVersion", "assumedValidation", "graphKind", "roots", "nodes"]), abstractGraphSchemaRelative, "abstract graph required fields are missing or reordered");
  }

  const manifestSchemaRelative = "spec/repository-format/v1/vector-manifest.schema.json";
  const manifestSchema = v.text(manifestSchemaRelative, { stableJson: true });
  if (manifestSchema) {
    v.check(manifestSchema.$schema === "https://json-schema.org/draft/2020-12/schema" && manifestSchema.$id?.endsWith("/vector-manifest.schema.json"), manifestSchemaRelative, "vector manifest schema identity is invalid");
    v.check(manifestSchema.additionalProperties === false && manifestSchema.type === "object", manifestSchemaRelative, "vector manifest root must be a closed object");
    v.check(sameArray(manifestSchema.required ?? [], ["manifestVersion", "generator", "scenarios", "artifacts"]), manifestSchemaRelative, "vector manifest required fields are missing or reordered");
    v.check(manifestSchema.properties?.manifestVersion?.const === "ogvcs.repository-format/vector-manifest/v1", manifestSchemaRelative, "vector manifest version is invalid");
    v.check(sameArray(manifestSchema.properties?.generator?.required ?? [], ["implementation", "version", "sourceSha256"]), manifestSchemaRelative, "vector generator provenance fields are incomplete");
    v.check(manifestSchema.properties?.scenarios?.minItems === 1, manifestSchemaRelative, "vector manifest must require at least one scenario");
  }

  const formatDirectory = v.absolute("spec/repository-format/v1");
  const discoveredSpecSources = fs.existsSync(formatDirectory) ? fs.readdirSync(formatDirectory, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.(?:md|cddl|json)$/.test(entry.name))
    .map((entry) => path.relative(v.root, path.join(entry.parentPath ?? entry.path, entry.name))) : [];
  const sourceFiles = [...new Set([...EXPECTED_FILES.filter((relative) => /\.(?:md|cddl|json)$/.test(relative)), ...discoveredSpecSources])];
  for (const relative of sourceFiles) {
    const text = v.text(relative);
    if (text === null) continue;
    if (relative.endsWith(".md")) validateLocalLinks(v, relative, text);
    const stale = /\b(?:TODO|TBD|FIXME|XXX|TKTK|CHANGEME|REPLACE_ME)\b/i.exec(text);
    v.check(!stale, relative, `stale specification token ${stale?.[0] ?? ""}`.trim());
  }
  const readme = fs.existsSync(v.absolute("spec/repository-format/v1/README.md")) ? fs.readFileSync(v.absolute("spec/repository-format/v1/README.md"), "utf8") : "";
  for (const artifact of ["encoding.md", "object-model.md", "conformance-profiles.md", "logical-bundle.md", "fixture-adapter.md", "repository-format.cddl", "abstract-reference-graph.schema.json", "validation-scenario.schema.json", "vector-manifest.schema.json", "errors.json", ...registryPaths.map((name) => `registries/${name}.json`)]) {
    v.check(readme.includes(`](${artifact})`), "spec/repository-format/v1/README.md", `normative artifact is not routed: ${artifact}`);
  }
  validateAdrStatus(v);
  return v.errors;
}

function parseArguments(argv) {
  let root;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--repo-root") {
      root = argv[index + 1];
      index += 1;
    } else throw new Error(`unknown argument: ${argv[index]}`);
  }
  if (root) return root;
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
}

export function validateRepositoryFormat(root) {
  return validateSpec(root);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let root;
  try {
    root = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(`repository-format-v1: ${error.message}`);
    process.exitCode = 2;
  }
  if (root) {
    const errors = validateSpec(root);
    if (errors.length > 0) {
      console.error(`repository-format-v1: invalid (${errors.length} error${errors.length === 1 ? "" : "s"})`);
      errors.forEach((error) => console.error(`- ${error}`));
      process.exitCode = 1;
    } else console.log("repository-format-v1: valid");
  }
}
