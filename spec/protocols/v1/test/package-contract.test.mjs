// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.

import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const execFile = promisify(execFileCallback);
const SPEC_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPOSITORY_ROOT = path.resolve(SPEC_ROOT, "../../..");
const BINDINGS_ROOT = path.join(REPOSITORY_ROOT, "foundation/protocol-baseline/bindings");
const GENERATOR = path.join(REPOSITORY_ROOT, "foundation/protocol-baseline/codegen/generate.mjs");

function npmInvocation(arguments_) {
  const npmCli = process.env.npm_execpath
    ?? (process.platform === "win32" ? path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js") : undefined);
  if (typeof npmCli === "string" && npmCli.length > 0) return [process.execPath, [npmCli, ...arguments_]];
  return ["npm", arguments_];
}

async function execNpm(arguments_, options) {
  const [executable, args] = npmInvocation(arguments_);
  return execFile(executable, args, options);
}

test("checked-in generation is byte-for-byte clean", async () => {
  const { stdout } = await execFile(process.execPath, [GENERATOR, "--check"], { cwd: REPOSITORY_ROOT });
  assert.match(stdout, /verified 92 contract and 29 binding artifacts; 360 bounded scenarios/);
});

test("contract packs and installs offline with every normative artifact", async (context) => {
  const temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "ogvcs-protocol-pack-"));
  context.after(() => fs.rm(temporaryRoot, { recursive: true, force: true }));
  const environment = { ...process.env, npm_config_cache: path.join(temporaryRoot, "npm-cache") };
  const packed = await execNpm(["pack", "--json", "--ignore-scripts", "--pack-destination", temporaryRoot, SPEC_ROOT], { cwd: REPOSITORY_ROOT, env: environment, maxBuffer: 8 * 1024 * 1024 });
  const report = JSON.parse(packed.stdout)[0];
  assert.equal(report.name, "@opengamevcs/protocol-contract-v1");
  assert.equal(report.version, "1.0.0-rc.1");
  const packedPaths = new Set(report.files.map((entry) => entry.path));
  const manifest = JSON.parse(await fs.readFile(path.join(SPEC_ROOT, "manifest.json"), "utf8"));
  for (const artifact of manifest.artifacts) assert.ok(packedPaths.has(artifact.path), `packed artifact missing: ${artifact.path}`);
  assert.ok(packedPaths.has("manifest.json"));
  assert.ok(packedPaths.has("adapter-execution-view.json"));
  assert.ok(packedPaths.has("validate-spec.mjs"));
  const archivePath = path.join(temporaryRoot, report.filename);
  assert.equal((await fs.stat(archivePath)).isFile(), true);

  const consumer = path.join(temporaryRoot, "consumer");
  await fs.mkdir(consumer);
  await fs.writeFile(path.join(consumer, "package.json"), '{"name":"offline-consumer","private":true,"version":"1.0.0"}');
  await execNpm(["install", "--offline", "--ignore-scripts", "--no-package-lock", archivePath], { cwd: consumer, env: environment, maxBuffer: 8 * 1024 * 1024 });
  const installedManifest = JSON.parse(await fs.readFile(path.join(consumer, "node_modules/@opengamevcs/protocol-contract-v1/manifest.json"), "utf8"));
  assert.equal(installedManifest.registrySetSha256, manifest.registrySetSha256);
  const installedPackageRoot = path.join(consumer, "node_modules/@opengamevcs/protocol-contract-v1");
  assert.equal((await fs.stat(path.join(installedPackageRoot, "validate-spec.mjs"))).isFile(), true);
  const installedPackage = JSON.parse(await fs.readFile(path.join(installedPackageRoot, "package.json"), "utf8"));
  assert.equal(installedPackage.scripts.generate, undefined);
  assert.equal(installedPackage.scripts.check, "node validate-spec.mjs");
  assert.equal(installedPackage.scripts.test, "node validate-spec.mjs");
  const selfCheck = await execNpm(["run", "check"], { cwd: installedPackageRoot, env: environment, maxBuffer: 8 * 1024 * 1024 });
  assert.match(selfCheck.stdout, /validated protocol contract [0-9a-f]{64}: 90 artifacts, 46 schemas, 360 scenarios/);
});

test("binding manifest pins all four generated type packages and TypeScript smoke passes", async () => {
  const manifest = JSON.parse(await fs.readFile(path.join(BINDINGS_ROOT, "manifest.json"), "utf8"));
  assert.deepEqual(manifest.languages.map((entry) => entry.language).sort(), ["cpp", "csharp", "rust", "typescript"]);
  const contractBytes = await fs.readFile(path.join(SPEC_ROOT, "manifest.json"));
  const { createHash } = await import("node:crypto");
  assert.equal(manifest.contractManifestSha256, createHash("sha256").update(contractBytes).digest("hex"));
  assert.ok(manifest.artifacts.some((entry) => entry.path === "csharp/NuGet.Config"));
  assert.ok(manifest.artifacts.some((entry) => entry.path === "descriptors.json"));
  const descriptors = JSON.parse(await fs.readFile(path.join(BINDINGS_ROOT, "descriptors.json"), "utf8"));
  assert.deepEqual([descriptors.messages.length, descriptors.fields.length], [46, 352]);
  await execFile(process.execPath, [path.join(BINDINGS_ROOT, "typescript/smoke.mjs")], { cwd: REPOSITORY_ROOT });
  const constantsUrl = pathToFileURL(path.join(BINDINGS_ROOT, "typescript/index.js"));
  constantsUrl.searchParams.set("test", String(Date.now()));
  const constants = await import(constantsUrl.href);
  assert.equal(Object.isFrozen(constants.FIELD_ASSIGNMENTS), true);
  assert.equal(Object.isFrozen(constants.FIELD_ASSIGNMENTS.CapabilityAxes), true);
  assert.equal(Object.isFrozen(constants.FIELD_ASSIGNMENTS.CapabilityAxes.fields), true);
  assert.equal(Object.isFrozen(constants.MESSAGE_DESCRIPTORS), true);
  assert.equal(Object.isFrozen(constants.FIELD_DESCRIPTORS), true);
  assert.equal(constants.FIELD_DESCRIPTORS.length, 352);
  assert.equal(constants.FIELD_DESCRIPTORS.every((entry) => Object.isFrozen(entry)), true);
  const cppCmake = await fs.readFile(path.join(BINDINGS_ROOT, "cpp/CMakeLists.txt"), "utf8");
  const cppTypes = await fs.readFile(path.join(BINDINGS_ROOT, "cpp/include/opengamevcs/protocol/v1/types.hpp"), "utf8");
  assert.doesNotMatch(cppCmake, /project\([^\n]*\bVERSION\b/u);
  assert.match(cppTypes, /contract_version = "1\.0\.0-rc\.1"/u);
});
