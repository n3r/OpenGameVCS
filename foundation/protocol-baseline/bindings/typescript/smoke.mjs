// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.
import { CONTRACT_MANIFEST_SHA256, FIELD_ASSIGNMENTS, FIELD_DESCRIPTORS, MESSAGE_DESCRIPTORS, PROTOCOL_VERSION } from "./index.js";
if (CONTRACT_MANIFEST_SHA256.length !== 64) throw new Error("manifest digest is not pinned");
if (PROTOCOL_VERSION !== "ogvcs.control.https-json@1") throw new Error("protocol mismatch");
if (FIELD_ASSIGNMENTS.CapabilityAxes.fields.protocolVersions !== 1) throw new Error("field assignment mismatch");
if (MESSAGE_DESCRIPTORS.reduce((sum, entry) => sum + entry.fieldCount, 0) !== FIELD_DESCRIPTORS.length) throw new Error("descriptor count mismatch");
const seen = new Set();
for (const field of FIELD_DESCRIPTORS) {
  const owner = MESSAGE_DESCRIPTORS.find((entry) => entry.code === field.messageCode);
  const key = `${field.messageCode}:${field.number}`;
  if (!owner || owner.name !== field.messageName || seen.has(key)) throw new Error("descriptor ownership mismatch");
  if (field.required !== (field.presence === "required") || ((field.reference !== null) !== field.normalizedType.includes("reference"))) throw new Error("descriptor policy mismatch");
  seen.add(key);
}
