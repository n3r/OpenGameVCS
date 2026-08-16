use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use ogvcs_object_model::{
    allocate_file_id_with, decode_canonical, evaluate_hard_limit, expand_tree, logical_record_id,
    object_id, scan_metadata, validate_abstract_reference_graph, validate_bundle_claim,
    validate_conflict_set, validate_file_id_allocation, validate_import_request,
    validate_logical_record, validate_metadata_schema, validate_repository_candidate,
    validate_semantic_object, validate_shelf_revision, verify_logical_bundle_stream,
    verify_manifest, EntropySource, Error, ErrorCode, FileId, FileIdAllocationRequest,
    ImportMapping, ImportRequest, ImportState, LifetimeOrigin, LifetimeRecord, Limits,
    LogicalBundleVerifyOptions, ObjectKind, ObjectRef, Operation, ProfileRef, Registry,
    RegistryEntry, RegistryState, RepositoryContext, RepositoryLimits, RepositoryObjectLookup,
    Result, ValidationMode, ValidationStage, HARD_LIMIT_NAMES, REGISTRY_FILES,
};
use serde_json::{json, Map, Value};

const REPORT_SCHEMA: &str = "ogvcs.object-model.scenario-execution-report/v1";
const DEFINITION_SEGMENT: &str = "scenarios/definitions/";

fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

fn run() -> std::result::Result<(), String> {
    let arguments = Arguments::parse(std::env::args().skip(1))?;
    let runner = Runner::new(arguments.vectors, arguments.registries)?;
    let report = if arguments.conformance {
        runner.execute_conformance()?
    } else {
        runner.execute_scenarios()?
    };
    let encoded = format!("{}\n", canonical_json(&report)?);
    if let Some(parent) = arguments.output.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&arguments.output)
        .and_then(|mut file| std::io::Write::write_all(&mut file, encoded.as_bytes()))
        .map_err(|error| format!("{}: {error}", arguments.output.display()))?;
    print!("{encoded}");
    let scenarios = if arguments.conformance {
        &report["conformance"]["scenarios"]
    } else {
        &report
    };
    if scenarios["failed"].as_u64() != Some(0) {
        let failures = scenarios["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|row| row["status"] == "failed")
            .filter_map(|row| row["scenarioId"].as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("scenario execution failed: {failures}"));
    }
    Ok(())
}

struct Arguments {
    vectors: PathBuf,
    registries: PathBuf,
    output: PathBuf,
    conformance: bool,
}

impl Arguments {
    fn parse(mut values: impl Iterator<Item = String>) -> std::result::Result<Self, String> {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let default_format_root = manifest.join("../../../spec/repository-format/v1");
        let mut vectors = std::env::var_os("OGVCS_VECTOR_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| default_format_root.join("vectors"));
        let mut registries = None;
        let mut output = None;
        let mut conformance = false;
        while let Some(option) = values.next() {
            if option == "--conformance" {
                conformance = true;
                continue;
            }
            let value = values
                .next()
                .ok_or_else(|| format!("missing value for {option}"))?;
            match option.as_str() {
                "--vectors" => vectors = PathBuf::from(value),
                "--registries" => registries = Some(PathBuf::from(value)),
                "--output" => output = Some(PathBuf::from(value)),
                _ => return Err(format!("unknown option {option}")),
            }
        }
        let output = output.ok_or_else(|| {
            "usage: object_model_scenario_report [--conformance] [--vectors <dir>] [--registries <dir>] --output <report.json>".to_owned()
        })?;
        let registries = registries.unwrap_or_else(|| {
            vectors
                .parent()
                .map(|parent| parent.join("registries"))
                .unwrap_or_else(|| default_format_root.join("registries"))
        });
        Ok(Self {
            vectors,
            registries,
            output,
            conformance,
        })
    }
}

struct Runner {
    vectors: PathBuf,
    registries: PathBuf,
    registry: Registry,
    limit_cases: BTreeMap<(String, String), Value>,
}

impl Runner {
    fn new(vectors: PathBuf, registries: PathBuf) -> std::result::Result<Self, String> {
        let registry = Registry::load_directory(&registries).map_err(display_error)?;
        let limits = read_json_at(&vectors.join("limits/virtual-constructors.json"))?;
        let mut limit_cases = BTreeMap::new();
        for case in json_array(&limits, "cases")? {
            limit_cases.insert(
                (
                    json_string(case, "case")?.to_owned(),
                    json_string(case, "variant")?.to_owned(),
                ),
                case.clone(),
            );
        }
        Ok(Self {
            vectors,
            registries,
            registry,
            limit_cases,
        })
    }

    fn json(&self, relative: &str) -> std::result::Result<Value, String> {
        read_json_at(&self.vectors.join(relative))
    }

    fn bytes(&self, relative: &str) -> std::result::Result<Vec<u8>, String> {
        fs::read(self.vectors.join(relative)).map_err(|error| format!("{relative}: {error}"))
    }

    fn result_json(&self, relative: &str) -> Result<Value> {
        self.json(relative)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
    }

    fn result_bytes(&self, relative: &str) -> Result<Vec<u8>> {
        self.bytes(relative)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
    }

    fn execute_conformance(&self) -> std::result::Result<Value, String> {
        let artifact = artifact_metadata(
            "OGVCS_IMPLEMENTATION_ARTIFACT",
            "ogvcs-object-model",
            env!("CARGO_PKG_VERSION"),
            "cargo-crate",
        )?;
        let format_artifact = artifact_metadata(
            "OGVCS_FORMAT_ARTIFACT",
            "@opengamevcs/repository-format-v1",
            "0.1.0",
            "npm-tarball",
        )?;
        let object_index = self.json("objects/index.json")?;
        let mut object_rows = Vec::new();
        for item in json_array(&object_index, "objects")? {
            let payload = self.bytes(json_string(item, "payloadPath")?)?;
            let kind = ObjectKind::from_code(
                item.get("kind")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "object vector has no kind".to_owned())?,
            )
            .map_err(display_error)?;
            let identity = object_id(kind, &payload).map_err(display_error)?;
            let identity = hex_lower(&identity);
            if item.get("objectId").and_then(Value::as_str) != Some(identity.as_str()) {
                return Err(format!(
                    "object identity mismatch for {}",
                    json_string(item, "name")?
                ));
            }
            if kind != ObjectKind::Chunk {
                let object = scan_metadata(&payload, Limits::METADATA).map_err(display_error)?;
                if validate_metadata_schema(&object).map_err(display_error)? != kind {
                    return Err(format!(
                        "object kind mismatch for {}",
                        json_string(item, "name")?
                    ));
                }
            }
            object_rows.push(json!({
                "bytes": payload.len(),
                "kind": kind.code(),
                "objectId": identity
            }));
        }
        let object_rows_json = Value::Array(object_rows);
        let objects = json!({
            "count": object_rows_json.as_array().map_or(0, Vec::len),
            "rowsSha256": hex_lower(&ogvcs_object_model::sha256(
                canonical_json(&object_rows_json)?.as_bytes()
            ))
        });

        let logical_index = self.json("logical-records/index.json")?;
        let mut logical_rows = Vec::new();
        for item in json_array(&logical_index, "records")? {
            let payload = self.bytes(json_string(item, "payloadPath")?)?;
            let record_type =
                validate_logical_record(&payload, Limits::METADATA).map_err(display_error)?;
            let identity = logical_record_id(record_type, &payload).map_err(display_error)?;
            let identity = hex_lower(&identity);
            if item.get("identity").and_then(Value::as_str) != Some(identity.as_str()) {
                return Err(format!(
                    "logical-record identity mismatch for {}",
                    json_string(item, "name")?
                ));
            }
            logical_rows.push(json!({
                "bytes": payload.len(),
                "digest": identity,
                "type": record_type
            }));
        }
        let logical_rows_json = Value::Array(logical_rows);
        let logical_records = json!({
            "count": logical_rows_json.as_array().map_or(0, Vec::len),
            "rowsSha256": hex_lower(&ogvcs_object_model::sha256(
                canonical_json(&logical_rows_json)?.as_bytes()
            ))
        });

        let mut bundle_rows = Vec::new();
        for path in [
            "logical-bundles/valid-supplied-closure.cborseq",
            "logical-bundles/valid-all-families.cborseq",
            "logical-bundles/scenario-bundle-zero-sections.cborseq",
        ] {
            let scratch = TempDirectory::new("conformance-bundle").map_err(display_error)?;
            let summary = verify_logical_bundle_stream(
                Cursor::new(self.bytes(path)?),
                LogicalBundleVerifyOptions::new(&scratch.path, &self.registry),
            )
            .map_err(display_error)?;
            bundle_rows.push(json!({
                "bytes": summary.bytes,
                "indexEntries": summary.index_entries,
                "items": summary.items,
                "logicalRecordCount": summary.logical_record_count,
                "objectCount": summary.object_count,
                "rootCount": summary.root_count,
                "transcriptDigest": hex_lower(&summary.transcript_digest),
                "traversalEdges": summary.traversal_edges
            }));
        }
        let bundles = json!({"count": bundle_rows.len(), "rows": bundle_rows});
        let corpus = json!({
            "coverageMatrixSha256": self.file_sha256("coverage-matrix.json")?,
            "manifestSha256": self.file_sha256("manifest.json")?,
            "scenarioIndexSha256": self.file_sha256("scenarios/index.json")?
        });
        let registry_digest = self
            .registry
            .registry_set_digest()
            .ok_or_else(|| "complete registry has no set digest".to_owned())?;
        let scenarios = self.execute_scenarios()?;
        let conformance = json!({
            "bundles": bundles,
            "corpus": corpus,
            "formatVersion": 1,
            "logicalRecords": logical_records,
            "objects": objects,
            "packageVersion": env!("CARGO_PKG_VERSION"),
            "registrySetDigest": hex_lower(registry_digest),
            "scenarios": scenarios
        });
        let conformance_digest = hex_lower(&ogvcs_object_model::sha256(
            canonical_json(&conformance)?.as_bytes(),
        ));
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            "windows" => "win32",
            other => other,
        };
        Ok(json!({
            "artifact": artifact,
            "conformance": conformance,
            "conformanceSha256": conformance_digest,
            "implementation": "ogvcs-object-model/rust",
            "formatArtifact": format_artifact,
            "platform": {"arch": std::env::consts::ARCH, "os": os},
            "runtime": env!("OGVCS_RUSTC_VERSION"),
            "schema": "ogvcs.object-model.conformance-report/v1",
            "sourceRevision": std::env::var("GITHUB_SHA").unwrap_or_else(|_| "working-tree".to_owned())
        }))
    }

    fn file_sha256(&self, relative: &str) -> std::result::Result<String, String> {
        Ok(hex_lower(&ogvcs_object_model::sha256(
            &self.bytes(relative)?,
        )))
    }

    fn execute_scenarios(&self) -> std::result::Result<Value, String> {
        let index = self.json("scenarios/index.json")?;
        let mut rows = Vec::new();
        for indexed in json_array(&index, "cases")? {
            let id = json_string(indexed, "scenarioId")?;
            let operation = json_string(indexed, "operation")?;
            let materialization = json_string(indexed, "materialization")?;
            let implementation_scope = indexed
                .get("implementationScope")
                .cloned()
                .unwrap_or_else(|| json!(["javascript", "rust"]));
            if implementation_scope
                .as_array()
                .is_some_and(|values| !values.iter().any(|value| value == "rust"))
            {
                rows.push(json!({
                    "implementationScope": implementation_scope,
                    "materialization": materialization,
                    "operation": operation,
                    "reason": "implementation-scope-excludes-rust",
                    "scenarioId": id,
                    "status": "not-applicable"
                }));
                continue;
            }
            if materialization == "virtual-constructor"
                || materialization == "virtual-constructor-shared-bundle-baseline"
                    && id != "bundle-export-claim"
            {
                rows.push(json!({
                    "implementationScope": implementation_scope,
                    "materialization": materialization,
                    "operation": operation,
                    "reason": "inventory-only-constructor",
                    "scenarioId": id,
                    "status": "not-executed"
                }));
                continue;
            }
            let scenario = self.json(json_string(indexed, "artifact")?)?;
            let actual = match self.execute_concrete(indexed, &scenario) {
                Ok(highest_layer) => json!({"highestLayer": highest_layer, "result": "accept"}),
                Err(error) => {
                    if !error.is_registered_site() {
                        return Err(format!(
                            "{id}: unregistered diagnostic site {}@{}:{}",
                            error.code.as_str(),
                            error.layer,
                            error.stage.as_str()
                        ));
                    }
                    json!({
                        "code": error.code.as_str(),
                        "layer": error.layer,
                        "result": "reject",
                        "stage": error.stage.as_str()
                    })
                }
            };
            let expected = normalized_expected(
                indexed
                    .get("expected")
                    .ok_or_else(|| format!("{id}: missing expected"))?,
            )?;
            let status = if actual == expected {
                "passed"
            } else {
                "failed"
            };
            rows.push(json!({
                "actual": actual,
                "expected": expected,
                "implementationScope": implementation_scope,
                "materialization": materialization,
                "operation": operation,
                "scenarioId": id,
                "status": status
            }));
        }
        let executed = rows
            .iter()
            .filter(|row| row["status"] == "passed" || row["status"] == "failed")
            .count();
        let failed = rows.iter().filter(|row| row["status"] == "failed").count();
        let inventory_only = rows
            .iter()
            .filter(|row| row["status"] == "not-executed")
            .count();
        let not_applicable = rows
            .iter()
            .filter(|row| row["status"] == "not-applicable")
            .count();
        let rows_json = Value::Array(rows);
        let rows_digest = hex_lower(&ogvcs_object_model::sha256(
            canonical_json(&rows_json)?.as_bytes(),
        ));
        Ok(json!({
            "executed": executed,
            "failed": failed,
            "inventoryOnly": inventory_only,
            "notApplicable": not_applicable,
            "resultsSha256": rows_digest,
            "rows": rows_json,
            "scenarios": rows_json.as_array().map_or(0, Vec::len),
            "schema": REPORT_SCHEMA
        }))
    }

    fn execute_concrete(&self, row: &Value, scenario: &Value) -> Result<u8> {
        let id = value_string(row, "scenarioId")?;
        let operation = value_string(row, "operation")?;
        let materialization = value_string(row, "materialization")?;
        if materialization == "executable-enumerated-registry-recipe" {
            return self.execute_registry_recipe(id);
        }
        if materialization == "executable-virtual-limit-constructor" {
            return self.execute_limit(id);
        }
        if id == "mutation-systematic-single-bit" {
            self.execute_mutation_recipe()?;
            return Ok(1);
        }
        if id == "truncation-every-prefix" {
            self.execute_truncation_recipe()?;
            return Ok(1);
        }
        if id == "malformed-complete-corpus" {
            self.execute_malformed_recipe()?;
            return Ok(1);
        }
        let input = primary_input(scenario)?;
        if materialization == "executable-configured-resource-constructor" {
            return self.execute_configured_resource(scenario, input);
        }
        if operation == "validate-bundle-claim" {
            let request = self.result_json(value_string(input, "path")?)?;
            validate_bundle_claim(value_string(&request, "claim")?)?;
            return Ok(3);
        }
        if operation == "validate-bundle" {
            return self.execute_bundle(
                value_string(input, "path")?,
                LogicalBundleVerifyOptions::new(
                    &TempDirectory::new("bundle")?.path,
                    &self.registry,
                ),
            );
        }
        if operation == "validate-abstract-reference-graph" {
            let graph = self.result_json(value_string(input, "path")?)?;
            return Ok(
                validate_abstract_reference_graph(&graph, RepositoryLimits::default())?
                    .highest_layer,
            );
        }
        if operation == "allocate-file-id" {
            self.execute_allocate(scenario, input)?;
            return Ok(3);
        }
        let lookup = self.lookup(scenario, RepositoryLimits::default())?;
        if operation == "canonical-scan" {
            if let Some(reference) = primary_reference(scenario, input)? {
                lookup.resolve(reference)?;
            } else {
                scan_metadata(
                    &self.result_bytes(value_string(input, "path")?)?,
                    Limits::METADATA,
                )?;
            }
            return Ok(1);
        }
        if operation == "import-file-id" {
            let lifetime = parse_lifetime_records(scenario, "lifetimeRecords")?;
            let working = parse_lifetime_records(scenario, "workingLifetimeAdditions")?;
            let mappings = parse_import_mappings(scenario)?;
            let context = repository_context(scenario, &lookup, &lifetime, &working, &mappings)?;
            let request = parse_import_request(&self.result_json(value_string(input, "path")?)?)?;
            validate_import_request(&context, &request)?;
            return Ok(3);
        }
        if operation == "validate-repository" || operation == "replay-change-set" {
            let lifetime = parse_lifetime_records(scenario, "lifetimeRecords")?;
            let working = parse_lifetime_records(scenario, "workingLifetimeAdditions")?;
            let mappings = parse_import_mappings(scenario)?;
            let context = repository_context(scenario, &lookup, &lifetime, &working, &mappings)?;
            let candidate = object_ref_json(context_value(scenario, "candidateSnapshot")?)?;
            return Ok(validate_repository_candidate(candidate, &context)?.highest_layer);
        }
        if operation != "validate-object" {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let path = value_string(input, "path")?;
        if let Some(reference) = primary_reference(scenario, input)? {
            match reference.kind {
                ObjectKind::ContentManifest => {
                    verify_manifest(reference, &lookup)?;
                }
                ObjectKind::Tree => {
                    let descriptor =
                        object_ref_json(context_value(scenario, "repositoryDescriptor")?)?;
                    expand_tree(reference, &lookup, descriptor, true)?;
                }
                ObjectKind::ShelfRevision => {
                    let lifetime = parse_lifetime_records(scenario, "lifetimeRecords")?;
                    let working = parse_lifetime_records(scenario, "workingLifetimeAdditions")?;
                    let mappings = parse_import_mappings(scenario)?;
                    let context =
                        repository_context(scenario, &lookup, &lifetime, &working, &mappings)?;
                    validate_shelf_revision(reference, &context)?;
                }
                ObjectKind::ConflictSet => {
                    let descriptor =
                        object_ref_json(context_value(scenario, "repositoryDescriptor")?)?;
                    validate_conflict_set(Some(reference), &lookup, descriptor, false)?;
                }
                _ => {
                    lookup.resolve(reference)?;
                }
            }
        } else {
            let object = scan_metadata(&self.result_bytes(path)?, Limits::METADATA)?;
            validate_semantic_object(&object, &self.registry, ValidationMode::Conformance)?;
        }
        Ok(3)
    }

    fn execute_bundle(&self, path: &str, options: LogicalBundleVerifyOptions<'_>) -> Result<u8> {
        let summary = verify_logical_bundle_stream(Cursor::new(self.result_bytes(path)?), options)?;
        Ok(summary.highest_layer)
    }

    fn execute_limit(&self, id: &str) -> Result<u8> {
        let suffix = id
            .strip_prefix("limit-")
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let (name, variant) = if let Some(name) = suffix.strip_suffix("-max-plus-one") {
            (name, "maximum-plus-one")
        } else if let Some(name) = suffix.strip_suffix("-max") {
            (name, "maximum")
        } else {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        };
        let case = self
            .limit_cases
            .get(&(name.to_owned(), variant.to_owned()))
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let name = HARD_LIMIT_NAMES
            .iter()
            .copied()
            .find(|candidate| *candidate == name)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let value = value_string(case, "valueDecimal")?
            .parse::<u64>()
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let decision = evaluate_hard_limit(&self.registry, name, value)?;
        if let Some(code) = decision.code {
            return Err(Error::new(code)
                .with_layer(decision.layer)
                .with_stage(decision.stage));
        }
        Ok(decision.layer)
    }

    fn execute_configured_resource(&self, scenario: &Value, input: &Value) -> Result<u8> {
        let definition = definition_input(scenario)?;
        let recipe = self.result_json(value_string(definition, "path")?)?;
        let recipe = recipe
            .pointer("/exactConstructorValues/configuredResource")
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if value_string(recipe, "api")? != "verify-logical-bundle-stream"
            || value_string(recipe, "source")? != value_string(input, "path")?
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let scratch = TempDirectory::new("configured")?;
        let mut options = LogicalBundleVerifyOptions::new(&scratch.path, &self.registry);
        let limits = recipe
            .get("limits")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if let Some(value) = limits.get("maxMemoryBytes").and_then(Value::as_u64) {
            options.limits.max_memory_bytes =
                usize::try_from(value).map_err(|_| Error::new(ErrorCode::LimitMemory))?;
        }
        if let Some(value) = limits.get("maxScratchBytes").and_then(Value::as_u64) {
            options.limits.max_scratch_bytes = value;
        }
        if let Some(value) = limits.get("maxTimeMs").and_then(Value::as_u64) {
            options.limits.max_elapsed = Some(Duration::from_millis(value));
        }
        self.execute_bundle(value_string(recipe, "source")?, options)
    }

    fn lookup(&self, scenario: &Value, limits: RepositoryLimits) -> Result<RepositoryObjectLookup> {
        let entries = context_array(scenario, "objectLookup")?
            .iter()
            .map(|entry| {
                Ok((
                    object_ref_json(field_value(entry, "ref")?)?,
                    self.result_bytes(value_string(field_value(entry, "artifact")?, "path")?)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        RepositoryObjectLookup::new(
            entries,
            self.registry.clone(),
            ValidationMode::Conformance,
            limits,
        )
    }

    fn execute_allocate(&self, scenario: &Value, input: &Value) -> Result<()> {
        let request = self.result_json(value_string(input, "path")?)?;
        let retry_limit = value_u64(&request, "retryLimit")? as usize;
        match value_string(&request, "phase")? {
            "finalize" => {
                let candidate = file_id_json(field_value(&request, "candidateFileId")?)?;
                let lifetime = parse_lifetime_records(scenario, "lifetimeRecords")?;
                let working = parse_lifetime_records(scenario, "workingLifetimeAdditions")?;
                validate_file_id_allocation(
                    FileIdAllocationRequest {
                        candidate_file_id: candidate,
                        retry_limit,
                    },
                    &lifetime
                        .iter()
                        .map(|record| record.file_id)
                        .collect::<Vec<_>>(),
                    &working
                        .iter()
                        .map(|record| record.file_id)
                        .collect::<Vec<_>>(),
                )?;
            }
            "generate" => {
                let recipe = field_value(&request, "entropyRecipe")?;
                let candidates = recipe
                    .get("candidateFileIds")
                    .and_then(Value::as_array)
                    .map(|values| values.iter().map(file_id_json).collect::<Result<Vec<_>>>())
                    .transpose()?
                    .unwrap_or_default();
                let consumed = recipe
                    .get("isConsumed")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .map(file_id_json)
                            .collect::<Result<BTreeSet<_>>>()
                    })
                    .transpose()?
                    .unwrap_or_default();
                let fail_at = recipe
                    .get("failAtCall")
                    .and_then(Value::as_u64)
                    .map(|v| v as usize);
                let repeat = recipe.get("exhaustedBehavior").and_then(Value::as_str)
                    == Some("repeat-last-candidate");
                let mut entropy = RecipeEntropy {
                    calls: 0,
                    candidates,
                    fail_at,
                    repeat,
                };
                allocate_file_id_with(
                    &mut entropy,
                    &mut |candidate| consumed.contains(candidate),
                    retry_limit,
                )?;
            }
            _ => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
        }
        Ok(())
    }

    fn execute_registry_recipe(&self, id: &str) -> Result<u8> {
        let index = self.result_json("registries/index.json")?;
        let recipe = json_array_result(&index, "cases")?
            .iter()
            .find(|recipe| recipe.get("scenarioId").and_then(Value::as_str) == Some(id))
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if recipe.get("operation").and_then(Value::as_str) == Some("validate-registry-set") {
            let mut documents = BTreeMap::new();
            for file in REGISTRY_FILES {
                documents.insert(
                    file,
                    read_json_at(&self.registries.join(file))
                        .map_err(|_| Error::new(ErrorCode::RegistryInvalid))?,
                );
            }
            mutate_registry_documents(&mut documents, field_value(recipe, "mutation")?)?;
            let encoded = documents
                .iter()
                .map(|(name, document)| {
                    serde_json::to_vec_pretty(document)
                        .map(|bytes| (*name, bytes))
                        .map_err(|_| Error::new(ErrorCode::RegistryInvalid))
                })
                .collect::<Result<Vec<_>>>()?;
            let borrowed = encoded
                .iter()
                .map(|(name, bytes)| (*name, bytes.as_slice()))
                .collect::<Vec<_>>();
            Registry::from_json_files(&borrowed)?;
            return Ok(3);
        }
        let snapshot = self.result_json(&format!(
            "registries/{}-snapshot.json",
            value_string(recipe, "snapshot")?
        ))?;
        let registry = registry_from_snapshot(&snapshot)?;
        let profile = ProfileRef::from_str(value_string(recipe, "profile")?)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        for operation in registry_operations(value_string(recipe, "operation")?)? {
            registry.check_profile(&profile, "path", operation)?;
        }
        Ok(3)
    }

    fn execute_malformed_recipe(&self) -> Result<()> {
        let index = self
            .json("malformed/index.json")
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        for case in json_array_result(&index, "explicitCases")? {
            let expected = expected_error(case)?;
            let actual = decode_canonical(
                &self.result_bytes(value_string(case, "artifact")?)?,
                Limits::METADATA,
            )
            .unwrap_err();
            require_same_error(actual, &expected)?;
        }
        Ok(())
    }

    fn execute_truncation_recipe(&self) -> Result<()> {
        let recipe = self
            .json("mutations/truncation.json")
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let mut executed = 0u64;
        for source in json_array_result(&recipe, "sources")? {
            let complete = self.result_bytes(value_string(source, "source")?)?;
            let offset = source
                .get("byteOffset")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            let length = value_u64(source, "byteLength")? as usize;
            let prefixes = field_value(source, "prefixes")?;
            let from = value_u64(prefixes, "fromInclusive")? as usize;
            let to = value_u64(prefixes, "toInclusive")? as usize;
            if offset
                .checked_add(length)
                .is_none_or(|end| end > complete.len())
                || to > length
            {
                return Err(Error::new(ErrorCode::SchemaFieldInvalid));
            }
            let expected = expected_error(source)?;
            for prefix in from..=to {
                let bytes = &complete[offset..offset + prefix];
                let actual = match value_string(source, "category")? {
                    "metadata-object" => scan_metadata(bytes, Limits::METADATA).unwrap_err(),
                    "logical-record" => {
                        validate_logical_record(bytes, Limits::METADATA).unwrap_err()
                    }
                    category if category.starts_with("bundle-") => {
                        decode_canonical(bytes, Limits::BUNDLE_ITEM).unwrap_err()
                    }
                    _ => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
                };
                require_same_error(actual, &expected)?;
                executed += 1;
            }
        }
        let whole = field_value(&recipe, "wholeSequence")?;
        let complete = self.result_bytes(value_string(whole, "source")?)?;
        for prefix in 0..complete.len() {
            let expected = json_array_result(whole, "ranges")?
                .iter()
                .find(|range| {
                    let from = value_u64(range, "fromInclusive").unwrap_or(u64::MAX) as usize;
                    let to = value_u64(range, "toInclusive").unwrap_or(0) as usize;
                    (from..=to).contains(&prefix)
                })
                .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
                .and_then(expected_error)?;
            let scratch = TempDirectory::new("truncation")?;
            let actual = verify_logical_bundle_stream(
                Cursor::new(&complete[..prefix]),
                LogicalBundleVerifyOptions::new(&scratch.path, &self.registry),
            )
            .unwrap_err();
            require_same_error(actual, &expected)?;
            executed += 1;
        }
        if executed != value_u64(&recipe, "totalCases")? {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(())
    }

    fn execute_mutation_recipe(&self) -> Result<()> {
        let recipe = self
            .json("mutations/single-bit.json")
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let objects = self
            .json("objects/index.json")
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let logical = self
            .json("logical-records/index.json")
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let mut sources = Vec::new();
        for entry in json_array_result(&objects, "objects")? {
            sources.push(MutationSource {
                path: value_string(entry, "payloadPath")?.to_owned(),
                kind: Some(ObjectKind::from_code(value_u64(entry, "kind")?)?),
                declared: hex_array(value_string(entry, "objectId")?)?,
            });
        }
        for entry in json_array_result(&logical, "records")? {
            sources.push(MutationSource {
                path: value_string(entry, "payloadPath")?.to_owned(),
                kind: None,
                declared: hex_array(value_string(entry, "identity")?)?,
            });
        }
        let declared_sources = json_array_result(&recipe, "sources")?;
        if sources.len() != declared_sources.len() {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let mut executed = 0u64;
        for (source, declared) in sources.iter().zip(declared_sources) {
            let original = self.result_bytes(&source.path)?;
            if original.len() as u64 != value_u64(declared, "byteLength")? {
                return Err(Error::new(ErrorCode::SchemaFieldInvalid));
            }
            for offset in 0..original.len() {
                for bit in 0..8 {
                    let mut changed = original.clone();
                    changed[offset] ^= 1 << bit;
                    let identity = if let Some(kind) = source.kind {
                        if kind == ObjectKind::Chunk {
                            object_id(kind, &changed).ok()
                        } else {
                            scan_metadata(&changed, Limits::METADATA)
                                .and_then(|object| {
                                    let actual = validate_metadata_schema(&object)?;
                                    if actual != kind {
                                        return Err(Error::new(
                                            ErrorCode::ObjectReferenceKindMismatch,
                                        ));
                                    }
                                    object_id(kind, &changed)
                                })
                                .ok()
                        }
                    } else {
                        validate_logical_record(&changed, Limits::METADATA)
                            .and_then(|record_type| logical_record_id(record_type, &changed))
                            .ok()
                    };
                    if identity == Some(source.declared) {
                        return Err(Error::new(ErrorCode::ObjectIdMismatch));
                    }
                    executed += 1;
                }
            }
        }
        // The item/whole-sequence mutations are each executed through the
        // bounded high-level verifier. Every changed byte must reject.
        let whole = field_value(&recipe, "wholeSequence")?;
        let bundle = self.result_bytes(value_string(whole, "source")?)?;
        let mut ranges = json_array_result(&recipe, "bundleItemShapes")?
            .iter()
            .map(|shape| {
                Ok((
                    value_u64(shape, "byteOffset")? as usize,
                    value_u64(shape, "byteLength")? as usize,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        ranges.push((0, bundle.len()));
        for (offset, length) in ranges {
            for relative in 0..length {
                for bit in 0..8 {
                    let mut changed = bundle.clone();
                    changed[offset + relative] ^= 1 << bit;
                    let scratch = TempDirectory::new("mutation")?;
                    if verify_logical_bundle_stream(
                        Cursor::new(changed),
                        LogicalBundleVerifyOptions::new(&scratch.path, &self.registry),
                    )
                    .is_ok()
                    {
                        return Err(Error::new(ErrorCode::BundleTrailerMismatch));
                    }
                    executed += 1;
                }
            }
        }
        if executed != value_u64(&recipe, "totalCases")? {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(())
    }
}

struct MutationSource {
    path: String,
    kind: Option<ObjectKind>,
    declared: [u8; 32],
}

struct RecipeEntropy {
    calls: usize,
    candidates: Vec<FileId>,
    fail_at: Option<usize>,
    repeat: bool,
}

impl EntropySource for RecipeEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> std::io::Result<()> {
        let call = self.calls;
        self.calls += 1;
        if self.fail_at == Some(call) {
            return Err(std::io::Error::other("recipe entropy failure"));
        }
        let candidate = self
            .candidates
            .get(call)
            .or_else(|| self.repeat.then(|| self.candidates.last()).flatten());
        let candidate = candidate.ok_or_else(|| std::io::Error::other("recipe exhausted"))?;
        bytes.copy_from_slice(candidate.as_bytes());
        Ok(())
    }
}

struct TempDirectory {
    path: PathBuf,
}

impl TempDirectory {
    fn new(label: &str) -> Result<Self> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let path =
            std::env::temp_dir().join(format!("ogvcs-rust-scenario-{label}-{}", hex_lower(&nonce)));
        fs::create_dir(&path).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        Ok(Self { path })
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn primary_input(scenario: &Value) -> Result<&Value> {
    scenario
        .get("inputs")
        .and_then(Value::as_array)
        .and_then(|inputs| {
            inputs.iter().find(|input| {
                input
                    .get("path")
                    .and_then(Value::as_str)
                    .is_some_and(|path| !path.contains(DEFINITION_SEGMENT))
            })
        })
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn definition_input(scenario: &Value) -> Result<&Value> {
    scenario
        .get("inputs")
        .and_then(Value::as_array)
        .and_then(|inputs| {
            inputs.iter().find(|input| {
                input
                    .get("path")
                    .and_then(Value::as_str)
                    .is_some_and(|path| path.starts_with(DEFINITION_SEGMENT))
            })
        })
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn primary_reference(scenario: &Value, input: &Value) -> Result<Option<ObjectRef>> {
    let path = value_string(input, "path")?;
    context_array(scenario, "objectLookup")?
        .iter()
        .find(|entry| entry.pointer("/artifact/path").and_then(Value::as_str) == Some(path))
        .map(|entry| object_ref_json(&entry["ref"]))
        .transpose()
}

fn repository_context<'a>(
    scenario: &Value,
    lookup: &'a RepositoryObjectLookup,
    lifetime: &'a [LifetimeRecord],
    working: &'a [LifetimeRecord],
    mappings: &'a [ImportMapping],
) -> Result<RepositoryContext<'a>> {
    let descriptor = object_ref_json(context_value(scenario, "repositoryDescriptor")?)?;
    let designated_root = scenario
        .get("context")
        .and_then(|context| context.get("designatedRoot"))
        .map(object_ref_json)
        .transpose()?
        .or_else(|| {
            context_array(scenario, "objectLookup")
                .ok()?
                .iter()
                .filter_map(|entry| entry.get("ref"))
                .filter_map(|value| object_ref_json(value).ok())
                .find(|reference| reference.kind == ObjectKind::Snapshot)
        })
        .unwrap_or(descriptor);
    let mut context = RepositoryContext::new(lookup, descriptor, designated_root);
    context.lifetime_records = lifetime;
    context.working_lifetime_additions = working;
    context.import_mappings = mappings;
    context.verify_content = true;
    Ok(context)
}

fn parse_lifetime_records(scenario: &Value, key: &str) -> Result<Vec<LifetimeRecord>> {
    context_array(scenario, key)?
        .iter()
        .map(|value| {
            Ok(LifetimeRecord {
                file_id: file_id_json(field_value(value, "fileId")?)?,
                origin: match value_string(value, "origin")? {
                    "native-create" => LifetimeOrigin::NativeCreate,
                    "native-copy" => LifetimeOrigin::NativeCopy,
                    "import" => LifetimeOrigin::Import,
                    _ => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
                },
                first_change_set: object_ref_json(field_value(value, "firstChangeSet")?)?,
                first_operation: value_u64(value, "firstOperation")?,
                import_mapping_key: value
                    .get("importMappingKey")
                    .map(|value| value_string_value(value).and_then(hex_array))
                    .transpose()?,
            })
        })
        .collect()
}

fn parse_import_mappings(scenario: &Value) -> Result<Vec<ImportMapping>> {
    context_array(scenario, "importMappings")?
        .iter()
        .map(|value| {
            Ok(ImportMapping {
                importer_profile: ProfileRef::from_str(value_string(value, "importerProfile")?)
                    .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
                source_namespace_digest: hex_array(value_string(value, "sourceNamespaceDigest")?)?,
                source_identity_digest: hex_array(value_string(value, "sourceIdentityDigest")?)?,
                file_id: file_id_json(field_value(value, "fileId")?)?,
                state: match value_string(value, "state")? {
                    "reserved" => ImportState::Reserved,
                    "materialized" => ImportState::Materialized,
                    "published" => ImportState::Published,
                    _ => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
                },
                declared_mapping_key: value
                    .get("mappingKey")
                    .map(|value| value_string_value(value).and_then(hex_array))
                    .transpose()?,
            })
        })
        .collect()
}

fn parse_import_request(value: &Value) -> Result<ImportRequest> {
    Ok(ImportRequest {
        importer_profile: ProfileRef::from_str(value_string(value, "importerProfile")?)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        source_namespace_digest: hex_array(value_string(value, "sourceNamespaceDigest")?)?,
        source_identity_digest: hex_array(value_string(value, "sourceIdentityDigest")?)?,
        requested_file_id: file_id_json(field_value(value, "requestedFileId")?)?,
    })
}

fn registry_from_snapshot(snapshot: &Value) -> Result<Registry> {
    let profiles =
        snapshot
            .pointer("/profiles/entries")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?
            .iter()
            .map(|entry| {
                let profile = format!(
                    "{}/{}@{}",
                    value_string(entry, "namespace")?,
                    value_string(entry, "id")?,
                    value_u64(entry, "major")?
                );
                Ok(RegistryEntry {
                    profile: ProfileRef::from_str(&profile)
                        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
                    family: value_string(entry, "family")?.to_owned(),
                    state: match value_string(entry, "state")? {
                        "reserved" => RegistryState::Reserved,
                        "conformance-only" => RegistryState::ConformanceOnly,
                        "ratified" => RegistryState::Ratified,
                        "deprecated" => RegistryState::Deprecated,
                        _ => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
                    },
                    production_write_allowed: field_value(entry, "productionWriteAllowed")?
                        .as_bool()
                        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
    let features = snapshot
        .pointer("/requiredFeatures/entries")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?
        .iter()
        .map(|entry| {
            value_u64(entry, "code").and_then(|value| {
                u32::try_from(value).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Registry::load(profiles, features)
}

fn registry_operations(value: &str) -> Result<Vec<Operation>> {
    Ok(match value {
        "read-or-write" | "read-or-new-write" => {
            vec![Operation::Read, Operation::ProductionWrite]
        }
        "read" => vec![Operation::Read],
        "new-write" | "production-write" => vec![Operation::ProductionWrite],
        "conformance" => vec![Operation::ConformanceWrite],
        _ => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    })
}

fn mutate_registry_documents(
    documents: &mut BTreeMap<&str, Value>,
    mutation: &Value,
) -> Result<()> {
    let file = value_string(mutation, "file")?;
    let entries = documents
        .get_mut(file)
        .and_then(|document| document.get_mut("entries"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?;
    match value_string(mutation, "action")? {
        "append-entry" => entries.push(field_value(mutation, "entry")?.clone()),
        "append-copy" => {
            let selector = field_value(mutation, "selector")?
                .as_object()
                .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?;
            let source = entries
                .iter()
                .find(|entry| {
                    selector
                        .iter()
                        .all(|(key, value)| entry.get(key) == Some(value))
                })
                .cloned()
                .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?;
            entries.push(source);
        }
        "replace-entry-field" => {
            let selector = field_value(mutation, "selector")?
                .as_object()
                .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?;
            let target = entries
                .iter_mut()
                .find(|entry| {
                    selector
                        .iter()
                        .all(|(key, value)| entry.get(key) == Some(value))
                })
                .and_then(Value::as_object_mut)
                .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?;
            target.insert(
                value_string(mutation, "field")?.to_owned(),
                field_value(mutation, "value")?.clone(),
            );
        }
        _ => return Err(Error::new(ErrorCode::RegistryInvalid)),
    }
    Ok(())
}

fn artifact_metadata(
    environment_name: &str,
    expected_name: &str,
    expected_version: &str,
    packed_type: &str,
) -> std::result::Result<Value, String> {
    let Some(encoded) = std::env::var_os(environment_name) else {
        return Ok(json!({
            "name": expected_name,
            "type": "workspace",
            "version": expected_version
        }));
    };
    let encoded = encoded
        .into_string()
        .map_err(|_| format!("{environment_name} is not UTF-8"))?;
    if encoded.len() > 1_024 {
        return Err(format!("{environment_name} is excessive"));
    }
    let value: Value = serde_json::from_str(&encoded)
        .map_err(|_| format!("{environment_name} is not valid JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("{environment_name} does not bind the installed package"))?;
    let digest = object.get("sha256").and_then(Value::as_str);
    let exact_keys = object.len() == 4
        && ["name", "sha256", "type", "version"]
            .iter()
            .all(|key| object.contains_key(*key));
    if !exact_keys
        || object.get("name").and_then(Value::as_str) != Some(expected_name)
        || object.get("version").and_then(Value::as_str) != Some(expected_version)
        || object.get("type").and_then(Value::as_str) != Some(packed_type)
        || digest.is_none_or(|digest| {
            digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(format!(
            "{environment_name} does not bind the installed package"
        ));
    }
    Ok(value)
}

fn normalized_expected(value: &Value) -> std::result::Result<Value, String> {
    match json_string(value, "result")? {
        "accept" => Ok(json!({
            "highestLayer": value.get("highestLayer").and_then(Value::as_u64)
                .ok_or_else(|| "accepted outcome has no highestLayer".to_owned())?,
            "result": "accept"
        })),
        "reject" => {
            let code_name = json_string(value, "code")?;
            let code = error_code(code_name).map_err(display_error)?;
            let layer = value
                .get("layer")
                .and_then(Value::as_u64)
                .and_then(|layer| u8::try_from(layer).ok())
                .ok_or_else(|| "rejected outcome has no valid layer".to_owned())?;
            let stage_name = json_string(value, "stage")?;
            let stage = validation_stage(stage_name).map_err(display_error)?;
            if !code.supports_site(layer, stage) {
                return Err(format!(
                    "rejected outcome uses unregistered site {code_name}@{layer}:{stage_name}"
                ));
            }
            Ok(json!({
                "code": code_name,
                "layer": layer,
                "result": "reject",
                "stage": stage_name
            }))
        }
        other => Err(format!("unsupported expected result {other}")),
    }
}

fn expected_error(value: &Value) -> Result<Error> {
    let expected = field_value(value, "expected")?;
    let code = error_code(value_string(expected, "code")?)?;
    let layer = value_u64(expected, "layer")? as u8;
    let stage = validation_stage(value_string(expected, "stage")?)?;
    let error = Error::new(code).with_layer(layer).with_stage(stage);
    if !error.is_registered_site() {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    Ok(error)
}

fn require_same_error(actual: Error, expected: &Error) -> Result<()> {
    if actual.code == expected.code
        && actual.layer == expected.layer
        && actual.stage == expected.stage
    {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::SchemaFieldInvalid))
    }
}

fn validation_stage(value: &str) -> Result<ValidationStage> {
    const STAGES: &[ValidationStage] = &[
        ValidationStage::ConfiguredResourcePreflight,
        ValidationStage::CanonicalFraming,
        ValidationStage::SequenceShapeAndOrder,
        ValidationStage::DeclaredIdentity,
        ValidationStage::TranscriptAuthentication,
        ValidationStage::KnownSchema,
        ValidationStage::ClosureAndReferenceResolution,
        ValidationStage::DeclaredAccounting,
        ValidationStage::RegistrySemantics,
        ValidationStage::RepositorySemantics,
    ];
    STAGES
        .iter()
        .copied()
        .find(|stage| stage.as_str() == value)
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn error_code(value: &str) -> Result<ErrorCode> {
    ErrorCode::ALL
        .iter()
        .copied()
        .find(|code| code.as_str() == value)
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn context_value<'a>(scenario: &'a Value, key: &str) -> Result<&'a Value> {
    scenario
        .get("context")
        .and_then(|context| context.get(key))
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn context_array<'a>(scenario: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    context_value(scenario, key)?
        .as_array()
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn field_value<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn value_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    field_value(value, key)?
        .as_str()
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn value_string_value(value: &Value) -> Result<&str> {
    value
        .as_str()
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn value_u64(value: &Value, key: &str) -> Result<u64> {
    field_value(value, key)?
        .as_u64()
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn object_ref_json(value: &Value) -> Result<ObjectRef> {
    ObjectRef::from_str(value_string_value(value)?)
}

fn file_id_json(value: &Value) -> Result<FileId> {
    FileId::from_str(&format!("fid:{}", value_string_value(value)?))
}

fn hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let nibble = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
        };
        *slot = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn canonical_json(value: &Value) -> std::result::Result<String, String> {
    serde_json::to_string(&sort_json(value)).map_err(|error| error.to_string())
}

fn sort_json(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(sort_json).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), sort_json(value)))
                .collect::<Map<_, _>>(),
        ),
        _ => value.clone(),
    }
}

fn read_json_at(path: &Path) -> std::result::Result<Value, String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn json_array<'a>(value: &'a Value, key: &str) -> std::result::Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array {key}"))
}

fn json_array_result<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn json_string<'a>(value: &'a Value, key: &str) -> std::result::Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string {key}"))
}

fn display_error(error: Error) -> String {
    format!(
        "{}@{}:{}",
        error.code.as_str(),
        error.layer,
        error.stage.as_str()
    )
}
