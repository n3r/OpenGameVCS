import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const sourceValidator = path.join(sourceRoot, "spec/repository-format/v1/validate-spec.mjs");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ogvcs-spec-v1-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.cpSync(path.join(sourceRoot, "adr"), path.join(root, "adr"), { recursive: true });
  fs.copyFileSync(path.join(sourceRoot, "architecture.md"), path.join(root, "architecture.md"));
  fs.copyFileSync(path.join(sourceRoot, "LICENSE"), path.join(root, "LICENSE"));
  fs.cpSync(path.join(sourceRoot, "prd"), path.join(root, "prd"), { recursive: true });
  fs.mkdirSync(path.join(root, "spec/repository-format"), { recursive: true });
  fs.cpSync(path.join(sourceRoot, "spec/repository-format/v1"), path.join(root, "spec/repository-format/v1"), { recursive: true });
  return root;
}

function validate(root, env = process.env) {
  try {
    const stdout = execFileSync(process.execPath, [sourceValidator, "--repo-root", root], { encoding: "utf8", env, stdio: ["ignore", "pipe", "pipe"] });
    return { status: 0, output: stdout };
  } catch (error) {
    return { status: error.status, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
  }
}

function rewriteJson(root, relative, mutate) {
  const file = path.join(root, relative);
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  mutate(value);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

test("the checked-in format-v1 specification validates in an isolated copy", (t) => {
  const root = fixture(t);
  const result = validate(root);
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /repository-format-v1: valid/);
});

test("the optional cddl hook uses the cddl 0.10 compile command", (t) => {
  const root = fixture(t);
  const argumentsFile = path.join(root, "cddl-arguments.txt");
  const driver = path.join(root, "cddl-test-driver.mjs");
  fs.writeFileSync(driver, "import fs from 'node:fs';\nfs.writeFileSync(process.env.OGVCS_CDDL_ARGUMENTS, process.argv.slice(2).join('\\n') + '\\n');\n");
  const result = validate(root, {
    ...process.env,
    OGVCS_CDDL_ARGUMENTS: argumentsFile,
    OGVCS_CDDL_TEST_DRIVER: driver
  });
  assert.equal(result.status, 0, result.output);
  assert.deepEqual(fs.readFileSync(argumentsFile, "utf8").trim().split("\n"), [
    "--ci",
    "compile-cddl",
    "--cddl",
    path.join(root, "spec/repository-format/v1/repository-format.cddl")
  ]);
});

const mutations = [
  {
    name: "duplicate JSON key",
    expected: /duplicate JSON key/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/registries/object-kinds.json");
      const source = fs.readFileSync(file, "utf8");
      fs.writeFileSync(file, source.replace('  "formatVersion": 1,', '  "formatVersion": 1,\n  "formatVersion": 1,'));
    }
  },
  {
    name: "object-kind reassignment",
    expected: /code 2 assignment must remain content-manifest/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/object-kinds.json", (value) => { value.entries[1].name = "manifest-v2"; value.entries[1].textToken = "manifest-v2"; });
    }
  },
  {
    name: "kind-field name drift",
    expected: /frozen field-name assignments changed/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/kind-fields.json", (value) => {
        value.entries.find((entry) => entry.cddlRule === "typed-digest" && entry.code === 1).name = "digest-value";
      });
    }
  },
  {
    name: "kind-field code drift",
    expected: /typed-digest field codes disagree with CDDL/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/kind-fields.json", (value) => {
        value.entries.find((entry) => entry.cddlRule === "typed-digest" && entry.code === 1).code = 2;
      });
    }
  },
  {
    name: "kind-field requirement drift",
    expected: /typed-digest:0 requirement optional disagrees with CDDL/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/kind-fields.json", (value) => {
        value.entries.find((entry) => entry.cddlRule === "typed-digest" && entry.code === 0).requirement = "optional";
      });
    }
  },
  {
    name: "kind-field type drift",
    expected: /typed-digest:1 type bstr disagrees with CDDL type digest/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/kind-fields.json", (value) => {
        value.entries.find((entry) => entry.cddlRule === "typed-digest" && entry.code === 1).type = "bstr";
      });
    }
  },
  {
    name: "kind-field scope drift",
    expected: /scope repository-format\.cddl#typed-digest-drift disagrees with cddlRule typed-digest/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/kind-fields.json", (value) => {
        value.entries.find((entry) => entry.cddlRule === "typed-digest" && entry.code === 1).scope = "repository-format.cddl#typed-digest-drift";
      });
    }
  },
  {
    name: "error catalogue order",
    expected: /number values must be strictly ordered/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/errors.json", (value) => { [value.errors[0], value.errors[1]] = [value.errors[1], value.errors[0]]; });
    }
  },
  {
    name: "error validation sites are mandatory",
    expected: /CBOR_TRUNCATED must declare at least one exact validation site/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/errors.json", (value) => { value.errors[0].sites = []; });
    }
  },
  {
    name: "error validation site stages are closed",
    expected: /CBOR_TRUNCATED references unknown stage/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/errors.json", (value) => { value.errors[0].sites[0].stage = "implementation-choice"; });
    }
  },
  {
    name: "error validation site pairs are unique",
    expected: /CBOR_TRUNCATED sites must follow precedence\.stageOrder without duplicates|CBOR_TRUNCATED repeats validation site/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/errors.json", (value) => { value.errors[0].sites.push(structuredClone(value.errors[0].sites[0])); });
    }
  },
  {
    name: "assigned and unassigned range overlap",
    expected: /assigned code 11 overlaps/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/object-kinds.json", (value) => { value.unassigned[0].from = 11; });
    }
  },
  {
    name: "invalid ProfileRef grammar",
    expected: /invalid profile id/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/profiles.json", (value) => { value.entries[0].id = "Bad_ID"; });
    }
  },
  {
    name: "profile state and production-write inconsistency",
    expected: /state ratified is inconsistent with productionWriteAllowed/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/profiles.json", (value) => { value.entries[0].state = "ratified"; });
    }
  },
  {
    name: "semantic enum reassignment",
    expected: /operation code 7 must remain ratified restore/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/semantic-enums.json", (value) => {
        value.domains.find((domain) => domain.name === "operation").entries.find((entry) => entry.code === 7).name = "revive";
      });
    }
  },
  {
    name: "scenario temporal context drift",
    expected: /scenario temporal convention is invalid/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/validation-scenario.schema.json", (value) => {
        value.$defs.context.properties.asOf.const = "after-candidate-snapshot";
      });
    }
  },
  {
    name: "scenario rejection loses validation stage",
    expected: /scenario rejecting result must expose the exact validation stage/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/validation-scenario.schema.json", (value) => {
        value.$defs.expected.oneOf[1].required = value.$defs.expected.oneOf[1].required.filter((field) => field !== "stage");
      });
    }
  },
  {
    name: "scenario object lookup loses reference binding",
    expected: /scenario object lookup must bind each ObjectRef to one artifact/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/validation-scenario.schema.json", (value) => {
        value.$defs.context.properties.objectLookup.items.required = ["artifact"];
      });
    }
  },
  {
    name: "abstract graph prevalidation marker drift",
    expected: /abstract graph prevalidation marker is invalid/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/abstract-reference-graph.schema.json", (value) => {
        value.properties.assumedValidation.const = "object-identity-not-checked";
      });
    }
  },
  {
    name: "vector generator provenance drift",
    expected: /vector generator provenance fields are incomplete/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/vector-manifest.schema.json", (value) => {
        value.properties.generator.required = ["implementation", "version"];
      });
    }
  },
  {
    name: "failure precedence drift",
    expected: /failure precedence contract is invalid/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/errors.json", (value) => {
        value.precedence.betweenLayers = "implementation-choice";
      });
    }
  },
  {
    name: "ADR status disagreement",
    expected: /table status Proposed disagrees with file status Accepted/,
    apply(root) {
      const file = path.join(root, "adr/0008-format-v1-deterministic-cbor-and-object-identity.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("**Status:** Proposed", "**Status:** Accepted"));
    }
  },
  {
    name: "CDDL kind discriminator reassignment",
    expected: /content-manifest kind discriminator must be 2/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/repository-format.cddl");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("content-manifest = {\n  0: 1,\n  1: 2,", "content-manifest = {\n  0: 1,\n  1: 3,"));
    }
  },
  {
    name: "logical-record wire key reassignment",
    expected: /annotation-record wire keys/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/repository-format.cddl");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("annotation-record = {\n  0: 1,\n  1: 8,\n  16: object-ref,\n  17: profile-ref,\n  18: bstr", "annotation-record = {\n  0: 1,\n  1: 8,\n  16: object-ref,\n  17: profile-ref,\n  19: bstr"));
    }
  },
  {
    name: "mutable-ref empty name admitted",
    expected: /mutable-ref name must be nonempty text/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/repository-format.cddl");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("  18: nonempty-text-value,", "  18: tstr,"));
    }
  },
  {
    name: "broken specification link",
    expected: /broken local link: absent.md/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/README.md");
      fs.appendFileSync(file, "\n[broken](absent.md)\n");
    }
  },
  {
    name: "stale TODO token",
    expected: /stale specification token TODO/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/object-model.md");
      fs.appendFileSync(file, "\nTODO\n");
    }
  },
  {
    name: "noncanonical CRLF JSON",
    expected: /only LF line endings are allowed/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/registries/limits.json");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replaceAll("\n", "\r\n"));
    }
  },
  {
    name: "limit errorCode missing from the catalogue",
    expected: /bundle-sequence-bytes references unknown errorCode LIMIT_NOT_REGISTERED/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/limits.json", (value) => { value.entries[0].errorCode = "LIMIT_NOT_REGISTERED"; });
    }
  },
  {
    name: "missing required artifact",
    expected: /conformance-profiles\.md: required artifact is missing/,
    apply(root) {
      fs.unlinkSync(path.join(root, "spec/repository-format/v1/conformance-profiles.md"));
    }
  }
];

for (const mutation of mutations) {
  test(`rejects ${mutation.name}`, (t) => {
    const root = fixture(t);
    mutation.apply(root);
    const result = validate(root);
    assert.equal(result.status, 1, result.output);
    assert.match(result.output, mutation.expected);
  });
}
