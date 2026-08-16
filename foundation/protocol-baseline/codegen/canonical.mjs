// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.
// Minimal, dependency-free RFC 8785 emitter for the protocol generator.

import { createHash } from "node:crypto";

function assertUnicodeScalarString(value, path) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`${path} contains an unpaired high surrogate`);
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new TypeError(`${path} contains an unpaired low surrogate`);
    }
  }
}

function emit(value, path, active) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    assertUnicodeScalarString(value, path);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      throw new TypeError(`${path} must be a finite I-JSON safe integer`);
    }
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) {
    if (active.has(value)) throw new TypeError(`${path} is cyclic`);
    active.add(value);
    const result = `[${value.map((entry, index) => emit(entry, `${path}[${index}]`, active)).join(",")}]`;
    active.delete(value);
    return result;
  }
  if (typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError(`${path} must be a plain JSON object`);
    }
    if (active.has(value)) throw new TypeError(`${path} is cyclic`);
    active.add(value);
    const keys = Object.keys(value).sort();
    const members = keys.map((key) => {
      assertUnicodeScalarString(key, `${path} key`);
      const member = value[key];
      if (member === undefined) throw new TypeError(`${path}.${key} is undefined`);
      return `${JSON.stringify(key)}:${emit(member, `${path}.${key}`, active)}`;
    });
    active.delete(value);
    return `{${members.join(",")}}`;
  }
  throw new TypeError(`${path} contains unsupported ${typeof value}`);
}

export function canonicalize(value) {
  return emit(value, "$", new Set());
}

export function canonicalBytes(value) {
  return Buffer.from(canonicalize(value), "utf8");
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function canonicalSha256(value) {
  return sha256(canonicalBytes(value));
}

export function semanticFingerprint(domain, value) {
  if (!/^[a-z0-9][a-z0-9./@_-]{0,127}$/.test(domain)) {
    throw new TypeError("fingerprint domain is invalid");
  }
  const prefix = Buffer.from(`${domain}\u0000`, "utf8");
  return sha256(Buffer.concat([prefix, canonicalBytes(value)]));
}

export function canonicalJsonLine(value) {
  return `${canonicalize(value)}\n`;
}
