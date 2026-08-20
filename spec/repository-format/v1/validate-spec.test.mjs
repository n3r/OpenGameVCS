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
    name: "duplicate object-kind text token",
    expected: /duplicate textToken "content-manifest"/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/registries/object-kinds.json", (value) => {
        value.entries.find((entry) => entry.code === 3).textToken = "content-manifest";
      });
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
    name: "scenario validator mode admits registry read",
    expected: /scenario validation mode must be exactly conformance or production/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/validation-scenario.schema.json", (value) => {
        value.$defs.context.properties.mode.enum.push("read");
      });
    }
  },
  {
    name: "scenario repository case mode becomes optional",
    expected: /scenario context required fields are missing or reordered/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/validation-scenario.schema.json", (value) => {
        value.$defs.context.required = value.$defs.context.required.filter((field) => field !== "caseMode");
      });
    }
  },
  {
    name: "ratified path callback accepts one collision key",
    expected: /ratified path-profile validator recipe must remain closed, bounded/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/validation-scenario.schema.json", (value) => {
        value.$defs.pathProfileValidator.properties.invocations.items.properties.decision.oneOf[0].required = ["accepted", "repositoryKey"];
      });
    }
  },
  {
    name: "ratified path callback narrows OGVCS-004 key maximum",
    expected: /ratified path-profile validator recipe must remain closed, bounded|preserve the pinned OGVCS-004 collision-key authority/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/validation-scenario.schema.json", (value) => {
        value.$defs.pathProfileValidator.properties.invocations.items.properties.decision.oneOf[0].properties.repositoryKey.maxLength = 4096;
      });
    }
  },
  {
    name: "resource execution evidence becomes optional",
    expected: /resource reservation outcomes must require exact executed-state evidence/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/validation-scenario.schema.json", (value) => {
        const rule = value.allOf.find((entry) =>
          entry?.if?.properties?.operation?.const === "validate-resource-reservation");
        rule.then.properties.expected.required = [];
      });
    }
  },
  {
    name: "resource counter rollback evidence becomes unauthenticated",
    expected: /resource reservation outcomes must require exact executed-state evidence/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/validation-scenario.schema.json", (value) => {
        delete value.$defs.resourceRouteEvidence.properties.counterBaselineRestored;
      });
    }
  },
  {
    name: "combined tree/group component-fit evidence becomes optional",
    expected: /combined tree\/group memory outcomes must require exact component-fit evidence/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/validation-scenario.schema.json", (value) => {
        const rule = value.allOf.find((entry) =>
          entry?.if?.properties?.operation?.const === "validate-tree-groups-memory");
        rule.then.properties.expected.required = [];
      });
    }
  },
  {
    name: "registry prose omits extensions authority",
    expected: /registry prose inventory must list the exact twelve runtime authorities/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/encoding.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("- `registries/extensions.json`\n", ""));
    }
  },
  {
    name: "Unicode DerivedAge source drift",
    expected: /official Unicode 15\.0 DerivedAge digest changed|derived Unicode 15\.0 scalar repertoire count changed/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/unicode/DerivedAge-15.0.0.txt");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("0000..001F", "0000..001E"));
    }
  },
  {
    name: "Unicode package authority omitted",
    expected: /packed files must include the normative Unicode authority/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/package.json", (value) => {
        value.files = value.files.filter((entry) => entry !== "unicode");
      });
    }
  },
  {
    name: "Unicode compact interval table drift",
    expected: /compact Unicode interval table is not an exact derivation/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/vectors/unicode/age-15.0.0-intervals.json", (value) => {
        value.intervals[0][1] -= 1;
      });
    }
  },
  {
    name: "Unicode compact source binding drift",
    expected: /compact Unicode interval table is not an exact derivation/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/vectors/unicode/age-15.0.0-intervals.json", (value) => {
        value.sourceSha256 = "0".repeat(64);
      });
    }
  },
  {
    name: "Unicode evaluation order drift",
    expected: /Unicode authority index, evaluation order, or boundary case inventory changed/,
    apply(root) {
      rewriteJson(root, "spec/repository-format/v1/vectors/unicode/index.json", (value) => {
        value.evaluationOrder.reverse();
      });
    }
  },
  {
    name: "Unicode boundary vector drift",
    expected: /Unicode boundary CBOR bytes changed/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/vectors/malformed/unicode-age-newer-canonical.cbor");
      const bytes = fs.readFileSync(file);
      bytes[bytes.length - 1] ^= 1;
      fs.writeFileSync(file, bytes);
    }
  },
  {
    name: "Unicode repertoire prose removed",
    expected: /frozen Unicode 15\.0 repertoire or validation order is missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/encoding.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("freezes its text repertoire", "uses a host repertoire"));
    }
  },
  {
    name: "metadata emitter authority prose removed",
    expected: /metadata\/tree\/manifest\/bundle emitter authority prose is missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/encoding.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("authoritative metadata encoder and every ordered, sorted, or file-backed", "metadata encoder and selected writers"));
    }
  },
  {
    name: "real surface lifecycle evidence prose removed",
    expected: /real-surface lifecycle evidence and all-authority-omitted rules are missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/encoding.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("MUST discover the lifecycle-bearing profile or required feature from", "may consult a detached lifecycle label for"));
    }
  },
  {
    name: "complete registry authority prose removed",
    expected: /complete registry authority boundary is missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/encoding.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("complete runtime authority is exactly the validated twelve-document registry", "runtime authority may be partial"));
    }
  },
  {
    name: "emitter precedence prose removed",
    expected: /emitter failure-precedence and no-output boundary is missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/encoding.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("produces no successful commit or\nsummary", "may publish a successful commit before rejection"));
    }
  },
  {
    name: "writer item ceiling precedence removed",
    expected: /writer item-ceiling and declared-count precedence is missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/encoding.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("configured item ceiling is evaluated against\nthe actual iterator count", "configured item ceiling may be evaluated after lifecycle"));
    }
  },
  {
    name: "writer identity before lifecycle prose removed",
    expected: /emitter failure-precedence and no-output boundary is missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/encoding.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("declared object digest\nmismatch on a known tree likewise wins", "profile lifecycle may precede a bad object digest"));
    }
  },
  {
    name: "typed-reference token authority prose removed",
    expected: /typed-reference token authority boundary is missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/encoding.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("code-to-token assignment is immutable authority, not a caller customization", "code-to-token assignment may be customized by callers"));
    }
  },
  {
    name: "durable ObjectRef bound classification removed",
    expected: /durable ObjectRef bound and unsupported-format classification are missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/encoding.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("colon-dense value that cannot have the exact five-component", "colon-dense values may be split before bounding"));
    }
  },
  {
    name: "retained workspace resource prose removed",
    expected: /repository retained-workspace resource boundary is missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/object-model.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("Snapshot/provenance ancestry,\nshelf, abstract-graph, conflict, and group workspaces charge every retained", "Repository workspaces retain data"));
    }
  },
  {
    name: "derived working-memory ownership prose removed",
    expected: /derived working-memory ownership boundary is missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/object-model.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("Internal\nrepository consumers may hold tree, group, membership, and collision indexes simultaneously", "Internal consumers may hold indexes"));
    }
  },
  {
    name: "resource runtime evidence prose removed",
    expected: /resource runtime-result evidence boundary is missing/,
    apply(root) {
      const file = path.join(root, "spec/repository-format/v1/object-model.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("MUST report an ordered `routeEvidence` observation", "may trust recipe route labels"));
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
    expected: /table status Accepted disagrees with file status Proposed/,
    apply(root) {
      const file = path.join(root, "adr/0008-format-v1-deterministic-cbor-and-object-identity.md");
      fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace("**Status:** Accepted", "**Status:** Proposed"));
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
