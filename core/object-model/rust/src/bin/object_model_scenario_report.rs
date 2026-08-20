use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use ogvcs_object_model::{
    allocate_file_id_with, decode_canonical, decode_metadata,
    encode_and_verify_content_manifest_stream, encode_canonical, encode_metadata,
    encode_ordered_tree_with_features, encode_tree_with_scratch_and_features, evaluate_hard_limit,
    expand_tree, expand_tree_with_path_profile_validator, logical_record_id, object_id,
    replay_change_set, scan_metadata, validate_abstract_reference_graph,
    validate_asset_groups_with_limits, validate_bundle_claim, validate_conflict_set,
    validate_file_id_allocation, validate_import_request, validate_lifetime_and_imports,
    validate_logical_record, validate_metadata_schema, validate_metadata_schema_with_limits,
    validate_provenance_graph, validate_repository_candidate, validate_semantic_object,
    validate_shelf_revision, validate_snapshot_graph, verify_logical_bundle_stream,
    verify_manifest, verify_tree_stream, visit_logical_bundle, AssetGroup, BundleItemInfo,
    BundleLimits, BundleTranscriptHashWriter, BundleVisitor, Cbor, EntropySource, Error, ErrorCode,
    FileId, FileIdAllocationRequest, ImportMapping, ImportRequest, ImportState, LifetimeOrigin,
    LifetimeRecord, Limits, LogicalBundleBudget, LogicalBundleVerifyOptions,
    LogicalBundleWriteOptions, LogicalBundleWritePlan, LogicalBundleWriter, ManifestStreamLimits,
    ManifestStreamPart, MetadataDecodeOptions, MetadataEncodeOptions, ObjectKind, ObjectRef,
    Operation, PathCaseMode, PathProfileDecision, PathProfileValidator, ProfileRef, Registry,
    RegistryEntry, RegistryState, RepositoryContext, RepositoryLimits, RepositoryObjectLookup,
    RepositoryState, Result, TreeFileIdIndex, TreeFileIdScratchIndex, TreeFileIdTransaction,
    TreeScratchMetrics, TreeStreamEntry, TreeStreamLimits, TypedDigest, ValidationMode,
    ValidationStage, HARD_LIMIT_NAMES, REGISTRY_FILES,
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
                LogicalBundleVerifyOptions::semantic(
                    &scratch.path,
                    &self.registry,
                    Operation::ConformanceWrite,
                ),
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
            let actual = if operation == "validate-resource-reservation"
                || operation == "validate-tree-groups-memory"
            {
                self.execute_resource_actual(indexed, &scenario)
                    .map_err(|error| format!("{id}: {}", display_error(error)))?
            } else {
                match self.execute_concrete(indexed, &scenario) {
                    Ok(highest_layer) => {
                        json!({"highestLayer": highest_layer, "result": "accept"})
                    }
                    Err(error) => diagnostic_outcome(id, error)?,
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
        if operation == "validate-operation-mode" {
            return self.execute_operation_mode(scenario);
        }
        if operation == "write-content-manifest" {
            return self.execute_manifest_writer(scenario);
        }
        if operation == "write-tree" {
            return self.execute_tree_writer(scenario);
        }
        if operation == "write-logical-bundle" {
            return self.execute_logical_bundle_writer(scenario);
        }
        if operation == "validate-path-profile-decision" {
            return self.execute_path_profile_decision(scenario);
        }
        if operation == "validate-typed-reference-authority" {
            return self.execute_typed_reference_authority(scenario);
        }
        if operation == "validate-repository-route" {
            return self.execute_repository_route(scenario);
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
            let scratch = TempDirectory::new("bundle")?;
            return self.execute_bundle(
                value_string(input, "path")?,
                LogicalBundleVerifyOptions::layer2(&scratch.path),
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
        if operation == "canonical-scan" && value_string(input, "mediaType")? == "application/json"
        {
            let request = self.result_json(value_string(input, "path")?)?;
            if value_string(&request, "api")? == "canonical-scan"
                && value_string(&request, "schema")?
                    == "ogvcs.repository-format.v1.canonical-scan-input.v1"
                && value_string(&request, "surface")? == "generic-cbor-item"
            {
                decode_canonical(
                    &self.result_bytes(value_string(&request, "source")?)?,
                    Limits::METADATA,
                )?;
                return Ok(1);
            }
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
        if operation == "replay-change-set" {
            return self.execute_replay_change_set(scenario);
        }
        if operation == "validate-repository" {
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
                    let adapter = RecipePathProfileValidator::from_scenario(scenario)?;
                    expand_tree_with_path_profile_validator(
                        reference,
                        &lookup,
                        descriptor,
                        true,
                        path_case_mode(scenario)?,
                        adapter
                            .as_ref()
                            .map(|adapter| adapter as &dyn PathProfileValidator),
                    )?;
                    if let Some(adapter) = &adapter {
                        adapter.assert_complete()?;
                    }
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

    fn execute_repository_route(&self, scenario: &Value) -> Result<u8> {
        let request = self.operation_request(scenario)?;
        if value_string(&request, "schema")?
            != "ogvcs.repository-format.v1.repository-route-input.v1"
            || value_string(&request, "authorityContext")? != "scenario.context"
        {
            return Err(configured_preflight_error());
        }
        let mode = scenario_validation_mode(scenario)?;
        let mut entries = self.lookup_entries(scenario)?;
        if let Some(mutations) = request.get("lookupMutations").and_then(Value::as_array) {
            for mutation in mutations {
                if value_string(mutation, "action")? != "replace-payload-preserve-reference" {
                    return Err(configured_preflight_error());
                }
                let reference = ObjectRef::from_str(value_string(mutation, "reference")?)?;
                let replacement = self.result_bytes(value_string(mutation, "sourceArtifact")?)?;
                let Some(entry) = entries
                    .iter_mut()
                    .find(|(current, _)| *current == reference)
                else {
                    return Err(configured_preflight_error());
                };
                entry.1 = replacement;
            }
        }
        let lookup = RepositoryObjectLookup::new(
            entries,
            self.registry.clone(),
            mode,
            RepositoryLimits::default(),
        )?;
        let api = value_string(&request, "api")?;
        // Provenance validation is an exact graph route and does not require
        // a repository descriptor/candidate context. Do not reject a valid
        // provenance-only carrier while constructing unrelated authority.
        if api == "validate-provenance-graph" {
            let roots = json_array_result(&request, "roots")?
                .iter()
                .map(object_ref_json)
                .collect::<Result<Vec<_>>>()?;
            let forbidden = json_array_result(&request, "forbidden")?
                .iter()
                .map(object_ref_json)
                .collect::<Result<Vec<_>>>()?;
            validate_provenance_graph(&roots, &lookup, &forbidden)?;
            return Ok(3);
        }
        let lifetime = parse_lifetime_records(scenario, "lifetimeRecords")?;
        let working = parse_lifetime_records(scenario, "workingLifetimeAdditions")?;
        let mappings = parse_import_mappings(scenario)?;
        let mut context = repository_context(scenario, &lookup, &lifetime, &working, &mappings)?;
        if let Some(value) = request.get("callerVerifyContent").and_then(Value::as_bool) {
            context.verify_content = value;
        }
        match api {
            "expand-tree" => {
                expand_tree(
                    ObjectRef::from_str(value_string(&request, "tree")?)?,
                    &lookup,
                    ObjectRef::from_str(value_string(&request, "repositoryDescriptor")?)?,
                    request.get("verifyContent").and_then(Value::as_bool) == Some(true),
                    path_case_mode_value(field_value(&request, "caseMode")?)?,
                )?;
            }
            "verify-manifest" => {
                verify_manifest(
                    ObjectRef::from_str(value_string(&request, "manifest")?)?,
                    &lookup,
                )?;
            }
            "replay-change-set" => {
                let descriptor =
                    ObjectRef::from_str(value_string(&request, "repositoryDescriptor")?)?;
                let tree = ObjectRef::from_str(value_string(
                    field_value(&request, "baseState")?,
                    "tree",
                )?)?;
                // Base-state materialization is authenticated setup, not part
                // of the route whose production lifecycle ordering is under
                // test. Use a separate conformance lookup so setup cannot hide
                // a later replay closure failure.
                let setup = self.lookup_with_registry(
                    scenario,
                    self.registry.clone(),
                    ValidationMode::Conformance,
                    RepositoryLimits::default(),
                )?;
                let expanded =
                    expand_tree(tree, &setup, descriptor, false, path_case_mode(scenario)?)?;
                let base = RepositoryState {
                    entries: expanded.entries,
                    groups: BTreeMap::new(),
                };
                let before = base.clone();
                replay_change_set(
                    ObjectRef::from_str(value_string(&request, "changeSet")?)?,
                    &base,
                    &context,
                    None,
                )?;
                if base != before {
                    return Err(configured_preflight_error());
                }
            }
            "validate-conflict-set" => {
                validate_conflict_set(
                    Some(ObjectRef::from_str(value_string(&request, "conflictSet")?)?),
                    &lookup,
                    ObjectRef::from_str(value_string(&request, "repositoryDescriptor")?)?,
                    false,
                )?;
            }
            "validate-snapshot-graph" => {
                context.descriptor =
                    ObjectRef::from_str(value_string(&request, "repositoryDescriptor")?)?;
                context.designated_root =
                    ObjectRef::from_str(value_string(&request, "designatedRoot")?)?;
                validate_snapshot_graph(
                    ObjectRef::from_str(value_string(&request, "candidateSnapshot")?)?,
                    &context,
                )?;
            }
            "validate-lifetime-and-imports" => {
                let change_set = lifetime
                    .first()
                    .or_else(|| working.first())
                    .map(|record| record.first_change_set)
                    .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
                validate_lifetime_and_imports(&context, change_set, &[], None)?;
            }
            "validate-import-request" => {
                validate_import_request(
                    &context,
                    &parse_import_request(field_value(&request, "importRequest")?)?,
                )?;
            }
            "validate-shelf-revision" => {
                validate_shelf_revision(
                    ObjectRef::from_str(value_string(&request, "shelfRevision")?)?,
                    &context,
                )?;
            }
            "validate-repository-candidate" => {
                validate_repository_candidate(
                    ObjectRef::from_str(value_string(&request, "candidateSnapshot")?)?,
                    &context,
                )?;
            }
            _ => return Err(configured_preflight_error()),
        }
        Ok(3)
    }

    fn execute_replay_change_set(&self, scenario: &Value) -> Result<u8> {
        let mode = scenario_validation_mode(scenario)?;
        let entries = self.lookup_entries(scenario)?;
        let setup = RepositoryObjectLookup::new(
            entries.clone(),
            self.registry.clone(),
            ValidationMode::Conformance,
            RepositoryLimits::default(),
        )?;
        let candidate = object_ref_json(context_value(scenario, "candidateSnapshot")?)?;
        let snapshot = setup.resolve_expected(candidate, ObjectKind::Snapshot)?;
        let snapshot_value = snapshot
            .value
            .as_deref()
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let change_set = ObjectRef::from_cbor(cbor_field(snapshot_value, 19)?)?;
        let change = setup.resolve_expected(change_set, ObjectKind::ChangeSet)?;
        let change_value = change
            .value
            .as_deref()
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let descriptor = object_ref_json(context_value(scenario, "repositoryDescriptor")?)?;
        let mut base = RepositoryState::default();
        if let Some(base_reference) = cbor_optional_field(change_value, 17) {
            let base_snapshot = setup
                .resolve_expected(ObjectRef::from_cbor(base_reference)?, ObjectKind::Snapshot)?;
            let base_value = base_snapshot
                .value
                .as_deref()
                .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
            let expanded = expand_tree(
                ObjectRef::from_cbor(cbor_field(base_value, 18)?)?,
                &setup,
                descriptor,
                true,
                path_case_mode(scenario)?,
            )?;
            base.entries = expanded.entries;
            if let Some(groups_reference) = cbor_optional_field(base_value, 20) {
                let groups = setup.resolve_expected(
                    ObjectRef::from_cbor(groups_reference)?,
                    ObjectKind::AssetGroupSet,
                )?;
                base.groups = asset_groups_from_value(
                    groups
                        .value
                        .as_deref()
                        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?,
                )?
                .0;
            }
        }
        let before = base.clone();
        let lookup = RepositoryObjectLookup::new(
            entries,
            self.registry.clone(),
            mode,
            RepositoryLimits::default(),
        )?;
        let lifetime = parse_lifetime_records(scenario, "lifetimeRecords")?;
        let working = parse_lifetime_records(scenario, "workingLifetimeAdditions")?;
        let mappings = parse_import_mappings(scenario)?;
        let context = repository_context(scenario, &lookup, &lifetime, &working, &mappings)?;
        let conflict = cbor_optional_field(snapshot_value, 28)
            .map(ObjectRef::from_cbor)
            .transpose()?
            .map(|reference| setup.resolve_expected(reference, ObjectKind::ConflictSet))
            .transpose()?;
        replay_change_set(
            change_set,
            &base,
            &context,
            conflict
                .as_ref()
                .and_then(|resolved| resolved.value.as_deref()),
        )?;
        if base != before {
            return Err(configured_preflight_error());
        }
        // Replay is the public route under test. The carried candidate is the
        // independent authenticated statement of the expected result roots;
        // bind the replay result to it just as the JavaScript report does.
        validate_repository_candidate(candidate, &context)?;
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
        if value_string(recipe, "source")? != value_string(input, "path")? {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let api = value_string(recipe, "api")?;
        let limits = recipe
            .get("limits")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let source = self.result_bytes(value_string(recipe, "source")?)?;
        if api == "visit-logical-bundle" {
            let mut configured = BundleLimits::HARD;
            if let Some(value) = limits.get("maxSequenceBytes").and_then(Value::as_u64) {
                configured.max_sequence_bytes = usize::try_from(value)
                    .map_err(|_| Error::new(ErrorCode::BundleBudgetExceeded))?;
            }
            if let Some(value) = limits.get("maxItemBytes").and_then(Value::as_u64) {
                configured.max_item_bytes = usize::try_from(value)
                    .map_err(|_| Error::new(ErrorCode::BundleBudgetExceeded))?;
            }
            if let Some(value) = limits.get("maxValueBytes").and_then(Value::as_u64) {
                configured.max_value_bytes =
                    usize::try_from(value).map_err(|_| Error::new(ErrorCode::LimitValueBytes))?;
            }
            if let Some(value) = limits.get("maxCaptureBytes").and_then(Value::as_u64) {
                configured.max_capture_bytes =
                    usize::try_from(value).map_err(|_| Error::new(ErrorCode::LimitMemory))?;
            }
            if let Some(value) = limits.get("maxNesting").and_then(Value::as_u64) {
                configured.max_nesting =
                    usize::try_from(value).map_err(|_| Error::new(ErrorCode::LimitNesting))?;
            }
            if let Some(value) = limits.get("maxItems").and_then(Value::as_u64) {
                configured.max_items = usize::try_from(value)
                    .map_err(|_| Error::new(ErrorCode::BundleBudgetExceeded))?;
            }
            let mut visitor = NoopBundleVisitor;
            visit_logical_bundle(Cursor::new(source), &mut visitor, configured)?;
            return Ok(1);
        }
        if api == "create-bundle-transcript-hash-writer" {
            let maximum = limits
                .get("maxBytes")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
            let mut writer = BundleTranscriptHashWriter::new(maximum);
            writer.update(&source)?;
            writer.finish()?;
            return Ok(1);
        }
        if api != "verify-logical-bundle-stream" {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let scratch = TempDirectory::new("configured")?;
        let mut options = LogicalBundleVerifyOptions::semantic(
            &scratch.path,
            &self.registry,
            Operation::ConformanceWrite,
        );
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
        let summary = verify_logical_bundle_stream(Cursor::new(source), options)?;
        Ok(summary.highest_layer)
    }

    fn execute_manifest_writer(&self, scenario: &Value) -> Result<u8> {
        let request = self.operation_request(scenario)?;
        if value_string(&request, "api")? != "write-content-manifest"
            || value_string(&request, "registry")? != "bundled"
        {
            return Err(configured_preflight_error());
        }
        let registry = self.lifecycle_registry(&request)?;
        let operation = write_operation(&request)?;
        let parts = json_array_result(&request, "parts")?
            .iter()
            .map(|part| {
                Ok(ManifestStreamPart {
                    chunk: ObjectRef::from_str(value_string(part, "chunk")?)?,
                    length: decimal_u64(value_string(part, "length")?)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let declared = decimal_u64(value_string(&request, "declaredParts")?)?;
        let chunk_profile = ProfileRef::from_str(value_string(&request, "chunkProfile")?)?;
        let chunks = if let Some(values) = request.get("chunkArtifacts").and_then(Value::as_array) {
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(configured_preflight_error)
                        .and_then(|path| self.result_bytes(path))
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            vec![self.result_bytes(value_string(&request, "chunkArtifact")?)?]
        };
        if chunks.len() != 1 && chunks.len() != parts.len() {
            return Err(configured_preflight_error());
        }
        let mut source = |index: u64,
                          _part: &ManifestStreamPart,
                          consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            let index = if chunks.len() == 1 {
                0
            } else {
                usize::try_from(index).map_err(|_| Error::new(ErrorCode::LimitCount))?
            };
            consume(chunks.get(index).ok_or_else(configured_preflight_error)?)
        };
        let limits = ManifestStreamLimits {
            max_parts: value_u64(&request, "maxItems")?,
            ..ManifestStreamLimits::default()
        };
        encode_and_verify_content_manifest_stream(
            Vec::new(),
            declared,
            || parts.clone(),
            &chunk_profile,
            decimal_u64(value_string(&request, "logicalLength")?)?,
            hex_array(value_string(&request, "wholeFileSha256")?)?,
            &mut source,
            &registry,
            operation,
            limits,
        )?;
        Ok(3)
    }

    fn execute_tree_writer(&self, scenario: &Value) -> Result<u8> {
        let request = self.operation_request(scenario)?;
        if value_string(&request, "api")? != "write-tree"
            || value_string(&request, "registry")? != "bundled"
        {
            return Err(configured_preflight_error());
        }
        let registry = self.lifecycle_registry(&request)?;
        let operation = write_operation(&request)?;
        let required_features = request
            .get("requiredFeatures")
            .and_then(Value::as_array)
            .map(|features| {
                features
                    .iter()
                    .map(|feature| {
                        u32::try_from(feature.as_u64().ok_or_else(configured_preflight_error)?)
                            .map_err(|_| configured_preflight_error())
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let entries = json_array_result(&request, "entries")?
            .iter()
            .map(tree_stream_entry)
            .collect::<Result<Vec<_>>>()?;
        let descriptor = ObjectRef::from_str(value_string(&request, "descriptor")?)?;
        let declared = decimal_u64(value_string(&request, "entryCount")?)?;
        let limits = TreeStreamLimits {
            max_entries: value_u64(&request, "maxItems")?,
            ..TreeStreamLimits::default()
        };
        match value_string(&request, "ordering")? {
            "ordered" => {
                let mut file_ids = BTreeSet::new();
                encode_ordered_tree_with_features(
                    Vec::new(),
                    descriptor,
                    &required_features,
                    declared,
                    entries,
                    &registry,
                    operation,
                    &mut file_ids,
                    limits,
                )?;
            }
            "sorted" => {
                let scratch = TempDirectory::new("tree-writer")?;
                let mut metrics = TreeScratchMetrics::default();
                encode_tree_with_scratch_and_features(
                    Vec::new(),
                    descriptor,
                    &required_features,
                    declared,
                    entries,
                    &registry,
                    operation,
                    &scratch.path,
                    limits,
                    &mut metrics,
                )?;
            }
            _ => return Err(configured_preflight_error()),
        }
        Ok(3)
    }

    fn execute_logical_bundle_writer(&self, scenario: &Value) -> Result<u8> {
        let request = self.operation_request(scenario)?;
        if value_string(&request, "api")? != "write-logical-bundle"
            || value_string(&request, "registry")? != "bundled"
            || !json_array_result(&request, "writerSurfaces")?
                .iter()
                .any(|surface| surface.as_str() == Some("bundle-ordered"))
        {
            return Err(configured_preflight_error());
        }
        let registry = self.lifecycle_registry(&request)?;
        let source = decode_bundle_items(&self.result_bytes(value_string(&request, "source")?)?)?;
        let source_objects = source
            .iter()
            .filter(|item| {
                cbor_field(item, 1)
                    .and_then(cbor_uint)
                    .is_ok_and(|value| value == 2)
            })
            .collect::<Vec<_>>();
        let mut mutations = json_array_result(&request, "objectMutations")?.clone();
        mutations.sort_by_key(|mutation| mutation.get("outputOrdinal").and_then(Value::as_u64));
        let mut objects = Vec::with_capacity(mutations.len());
        for mutation in mutations {
            let (mut reference, payload) = if let Some(source_artifact) =
                mutation.get("sourceArtifact").and_then(Value::as_str)
            {
                (
                    ObjectRef {
                        kind: ObjectKind::from_code(value_u64(&mutation, "kind")?)?,
                        digest: [0; 32],
                    },
                    self.result_bytes(source_artifact)?,
                )
            } else {
                let source_ordinal = usize::try_from(value_u64(&mutation, "sourceOrdinal")?)
                    .map_err(|_| configured_preflight_error())?;
                let item = *source_objects
                    .get(source_ordinal)
                    .ok_or_else(configured_preflight_error)?;
                (
                    ObjectRef::from_cbor(cbor_field(item, 3)?)?,
                    cbor_bytes(cbor_field(item, 4)?)?.to_vec(),
                )
            };
            if let Some(digest) = mutation
                .get("replaceDeclaredDigest")
                .and_then(Value::as_str)
            {
                reference.digest = hex_array(digest)?;
            }
            if mutation.get("replaceKind").is_some() {
                // Unknown numeric kinds are intentionally a JavaScript-only
                // carrier because Rust's ObjectKind makes them unconstructible.
                return Err(configured_preflight_error());
            }
            objects.push((reference, payload));
        }
        let mut logical_inputs = request
            .get("logicalRecordInputs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        logical_inputs.sort_by_key(|input| input.get("outputOrdinal").and_then(Value::as_u64));
        let logical_records = logical_inputs
            .iter()
            .map(|input| {
                decode_canonical(
                    &self.result_bytes(value_string(input, "sourceArtifact")?)?,
                    Limits::METADATA,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let roots = request
            .get("rootInputs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|input| {
                if value_u64(&input, "kind")? != 1 {
                    return Err(configured_preflight_error());
                }
                Ok((
                    ObjectRef::from_str(value_string(&input, "identity")?)?,
                    ProfileRef::from_str(value_string(&input, "roleProfile")?)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let plan_value = field_value(&request, "plan")?;
        let budget = field_value(plan_value, "budget")?;
        let plan = LogicalBundleWritePlan {
            object_count: value_u64(plan_value, "objectCount")?,
            logical_record_count: value_u64(plan_value, "logicalRecordCount")?,
            root_count: value_u64(plan_value, "rootCount")?,
            budget: LogicalBundleBudget {
                sequence_bytes: value_u64(budget, "sequenceBytes")?,
                largest_item_bytes: value_u64(budget, "largestItemBytes")?,
                traversal_edges: value_u64(budget, "traversalEdges")?,
                index_entries: value_u64(budget, "indexEntries")?,
            },
        };
        let mut options = LogicalBundleWriteOptions::new(&registry, write_operation(&request)?);
        options.limits.max_memory_bytes = usize::try_from(value_u64(&request, "maxMemoryBytes")?)
            .map_err(|_| configured_preflight_error())?;
        let mut staging = Vec::new();
        let mut writer = LogicalBundleWriter::new(&mut staging, plan, options)?;
        for (reference, payload) in objects {
            writer.write_object(reference, &payload)?;
        }
        for record in &logical_records {
            writer.write_logical_record(record)?;
        }
        for (identity, role) in &roots {
            writer.write_object_root(*identity, role)?;
        }
        writer.finish()?;
        Ok(3)
    }

    fn execute_path_profile_decision(&self, scenario: &Value) -> Result<u8> {
        let request = self.operation_request(scenario)?;
        if value_string(&request, "api")? != "validate-path-profile-decision" {
            return Err(configured_preflight_error());
        }
        let lookup = self.lookup(scenario, RepositoryLimits::default())?;
        let tree = context_array(scenario, "objectLookup")?
            .iter()
            .filter_map(|entry| entry.get("ref"))
            .map(object_ref_json)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .find(|reference| reference.kind == ObjectKind::Tree)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let adapter = RecipePathProfileValidator::from_request(&request)?;
        expand_tree_with_path_profile_validator(
            tree,
            &lookup,
            object_ref_json(context_value(scenario, "repositoryDescriptor")?)?,
            false,
            path_case_mode_value(field_value(&request, "caseMode")?)?,
            Some(&adapter),
        )?;
        Ok(3)
    }

    fn execute_typed_reference_authority(&self, scenario: &Value) -> Result<u8> {
        let request = self.operation_request(scenario)?;
        match value_string(&request, "case")? {
            "arbitrary-kind-map-relabel" => Err(configured_preflight_error()),
            "duplicate-kind-token" => {
                let mut documents = self.registry_documents()?;
                mutate_registry_documents(
                    &mut documents,
                    field_value(&request, "registryMutation")?,
                )?;
                registry_from_documents(&documents)?;
                Ok(3)
            }
            "durable-text-overlength-colon-dense" => {
                if value_u64(&request, "maximumBytes")? != 144
                    || value_string(&request, "text")?.len() <= 144
                {
                    return Err(configured_preflight_error());
                }
                ObjectRef::from_str(value_string(&request, "text")?)?;
                Ok(2)
            }
            _ => Err(configured_preflight_error()),
        }
    }

    fn operation_request(&self, scenario: &Value) -> Result<Value> {
        let input = operation_input(scenario)?;
        self.result_json(value_string(input, "path")?)
    }

    fn registry_documents(&self) -> Result<BTreeMap<&'static str, Value>> {
        let mut documents = BTreeMap::new();
        for file in REGISTRY_FILES {
            documents.insert(
                file,
                read_json_at(&self.registries.join(file))
                    .map_err(|_| Error::new(ErrorCode::RegistryInvalid))?,
            );
        }
        Ok(documents)
    }

    fn operation_registry(&self, request: &Value) -> Result<Option<Registry>> {
        match request.get("registry").and_then(Value::as_str) {
            None | Some("absent") => Ok(None),
            Some("partial" | "forged") => Ok(Some(Registry::load(
                Vec::<RegistryEntry>::new(),
                Vec::<u32>::new(),
            )?)),
            Some("bundled") => self.lifecycle_registry(request).map(Some),
            Some(_) => Err(configured_preflight_error()),
        }
    }

    fn lifecycle_registry(&self, request: &Value) -> Result<Registry> {
        let Some(fixture) = request.get("registryFixture") else {
            return Ok(self.registry.clone());
        };
        let index = self.result_json(value_string(fixture, "path")?)?;
        let scenario_id = value_string(fixture, "scenarioId")?;
        let recipe = json_array_result(&index, "cases")?
            .iter()
            .find(|entry| entry.get("scenarioId").and_then(Value::as_str) == Some(scenario_id))
            .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?;
        let snapshot = self.result_json(&format!(
            "registries/{}-snapshot.json",
            value_string(recipe, "snapshot")?
        ))?;
        let mut documents = self.registry_documents()?;
        append_snapshot_entries(
            documents
                .get_mut("profiles.json")
                .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?,
            snapshot.pointer("/profiles/entries"),
            true,
        )?;
        append_snapshot_entries(
            documents
                .get_mut("extensions.json")
                .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?,
            snapshot.pointer("/extensions/entries"),
            false,
        )?;
        append_feature_entries(
            documents
                .get_mut("required-features.json")
                .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?,
            snapshot.pointer("/requiredFeatures/entries"),
        )?;
        registry_from_documents(&documents)
    }

    fn execute_operation_mode(&self, scenario: &Value) -> Result<u8> {
        let request = self.operation_request(scenario)?;
        if value_string(&request, "api")? != "validate-operation-mode" {
            return Err(configured_preflight_error());
        }
        let authority = self.operation_registry(&request)?;
        match value_string(&request, "surface")? {
            "bundle-visitor" => self.execute_bundle_visitor_surface(&request),
            "logical-record-map-raw" => self.execute_logical_record_raw_surface(&request),
            "tree-file"
            | "tree-schema-decoder"
            | "metadata-decoder"
            | "bundle-memory-verifier"
            | "bundle-stream-verifier" => self.execute_codec_surface(&request, authority.as_ref()),
            "metadata-encoder"
            | "tree-ordered"
            | "tree-sorted"
            | "content-manifest"
            | "bundle-ordered"
            | "bundle-memory-encoder" => self.execute_emitter_surface(&request, authority.as_ref()),
            _ => self.execute_repository_mode_surface(&request, scenario, authority),
        }
    }

    fn execute_bundle_visitor_surface(&self, request: &Value) -> Result<u8> {
        if request.get("registry").and_then(Value::as_str) != Some("absent")
            || request.get("semanticProfiles").and_then(Value::as_bool) != Some(false)
            || request
                .as_object()
                .is_some_and(|object| object.contains_key("mode"))
        {
            return Err(configured_preflight_error());
        }
        let mut visitor = NoopBundleVisitor;
        visit_logical_bundle(
            Cursor::new(self.result_bytes(value_string(request, "source")?)?),
            &mut visitor,
            BundleLimits::HARD,
        )?;
        Ok(2)
    }

    fn execute_logical_record_raw_surface(&self, request: &Value) -> Result<u8> {
        if request.get("registry").and_then(Value::as_str) != Some("absent")
            || request.get("semanticProfiles").and_then(Value::as_bool) != Some(false)
            || request.get("requestedLayer").and_then(Value::as_u64) != Some(2)
            || request
                .as_object()
                .is_some_and(|object| object.contains_key("mode"))
        {
            return Err(configured_preflight_error());
        }
        validate_logical_record(
            &self.result_bytes(value_string(request, "source")?)?,
            Limits::METADATA,
        )?;
        Ok(2)
    }

    fn execute_codec_surface(&self, request: &Value, authority: Option<&Registry>) -> Result<u8> {
        let layer_two = request.get("registry").and_then(Value::as_str) == Some("absent")
            && request.get("semanticProfiles").and_then(Value::as_bool) == Some(false)
            && !request
                .as_object()
                .is_some_and(|object| object.contains_key("semanticCallback"))
            && !request
                .as_object()
                .is_some_and(|object| object.contains_key("operation"));
        let semantic = request.get("registry").and_then(Value::as_str) == Some("bundled")
            && request.get("semanticProfiles").and_then(Value::as_bool) != Some(false);
        let surface = value_string(request, "surface")?;
        if layer_two {
            let source = self.result_bytes(value_string(request, "source")?)?;
            return match surface {
                "metadata-decoder" | "tree-schema-decoder" => {
                    let object = scan_metadata(&source, Limits::METADATA)?;
                    validate_metadata_schema(&object)?;
                    Ok(2)
                }
                "bundle-memory-verifier" | "bundle-stream-verifier" => {
                    let scratch = TempDirectory::new("mode-bundle-layer2")?;
                    let summary = verify_logical_bundle_stream(
                        Cursor::new(source),
                        LogicalBundleVerifyOptions::layer2(&scratch.path),
                    )?;
                    Ok(summary.highest_layer)
                }
                _ => Err(configured_preflight_error()),
            };
        }
        if request.get("semanticProfiles").and_then(Value::as_bool) == Some(false) {
            return Err(configured_preflight_error());
        }
        if surface == "metadata-decoder" {
            let registry = authority.ok_or_else(configured_preflight_error)?;
            let operation = codec_operation(request)?;
            let source = if semantic {
                self.result_bytes(value_string(request, "source")?)?
            } else {
                Vec::new()
            };
            let summary = decode_metadata(
                Cursor::new(source),
                MetadataDecodeOptions::new(registry, operation),
            )?;
            return Ok(summary.highest_layer);
        }
        if !semantic {
            if request.get("registry").and_then(Value::as_str) != Some("bundled") {
                if let Some(registry) = authority {
                    let operation = codec_operation(request)?;
                    match surface {
                        "tree-file" => {
                            let mut file_ids = BTreeSet::new();
                            verify_tree_stream(
                                Cursor::new(Vec::<u8>::new()),
                                ObjectRef {
                                    kind: ObjectKind::Tree,
                                    digest: [0; 32],
                                },
                                ObjectRef {
                                    kind: ObjectKind::RepositoryDescriptor,
                                    digest: [0; 32],
                                },
                                registry,
                                operation,
                                &mut file_ids,
                                TreeStreamLimits::default(),
                            )?;
                            return Ok(3);
                        }
                        "bundle-memory-verifier" | "bundle-stream-verifier" => {
                            let summary = verify_logical_bundle_stream(
                                Cursor::new(Vec::<u8>::new()),
                                LogicalBundleVerifyOptions::semantic(
                                    Path::new(""),
                                    registry,
                                    operation,
                                ),
                            )?;
                            return Ok(summary.highest_layer);
                        }
                        _ => {}
                    }
                }
            }
            return Err(configured_preflight_error());
        }
        let registry = authority.ok_or_else(configured_preflight_error)?;
        let operation = codec_operation(request)?;
        let source = self.result_bytes(value_string(request, "source")?)?;
        match surface {
            "tree-schema-decoder" => Err(configured_preflight_error()),
            "tree-file" => {
                let descriptor =
                    ObjectRef::from_str(value_string(request, "repositoryDescriptor")?)?;
                let expected = ObjectRef {
                    kind: ObjectKind::Tree,
                    digest: object_id(ObjectKind::Tree, &source)?,
                };
                let mut file_ids = BTreeSet::new();
                verify_tree_stream(
                    Cursor::new(source),
                    expected,
                    descriptor,
                    registry,
                    operation,
                    &mut file_ids,
                    TreeStreamLimits::default(),
                )?;
                Ok(3)
            }
            "bundle-memory-verifier" | "bundle-stream-verifier" => {
                let scratch = TempDirectory::new("mode-bundle-semantic")?;
                let summary = verify_logical_bundle_stream(
                    Cursor::new(source),
                    LogicalBundleVerifyOptions::semantic(&scratch.path, registry, operation),
                )?;
                Ok(summary.highest_layer)
            }
            _ => Err(configured_preflight_error()),
        }
    }

    fn execute_emitter_surface(&self, request: &Value, authority: Option<&Registry>) -> Result<u8> {
        let surface = value_string(request, "surface")?;
        let Some(registry) = authority else {
            return Err(configured_preflight_error());
        };
        let operation = codec_operation(request)?;
        let configured = request.get("registry").and_then(Value::as_str) == Some("bundled")
            && matches!(
                operation,
                Operation::ConformanceWrite | Operation::ProductionWrite
            );
        if !configured {
            return self.execute_emitter_preflight(surface, registry, operation);
        }
        let source = self.result_bytes(value_string(request, "source")?)?;
        match surface {
            "metadata-encoder" => {
                let value = decode_canonical(&source, Limits::METADATA)?;
                let summary = encode_metadata(
                    &value,
                    Vec::new(),
                    MetadataEncodeOptions::new(registry, operation),
                )?;
                Ok(summary.highest_layer)
            }
            "tree-ordered" | "tree-sorted" => {
                self.execute_tree_emitter(surface, &source, registry, operation)
            }
            "content-manifest" => self.execute_manifest_emitter(&source, registry, operation),
            "bundle-ordered" | "bundle-memory-encoder" => {
                self.execute_bundle_emitter(&source, registry, operation)
            }
            _ => Err(configured_preflight_error()),
        }
    }

    fn execute_emitter_preflight(
        &self,
        surface: &str,
        registry: &Registry,
        operation: Operation,
    ) -> Result<u8> {
        match surface {
            "metadata-encoder" => {
                let summary = encode_metadata(
                    &Cbor::UInt(0),
                    Vec::new(),
                    MetadataEncodeOptions::new(registry, operation),
                )?;
                Ok(summary.highest_layer)
            }
            "tree-ordered" => {
                let mut file_ids = BTreeSet::new();
                encode_ordered_tree_with_features(
                    Vec::new(),
                    ObjectRef {
                        kind: ObjectKind::RepositoryDescriptor,
                        digest: [0; 32],
                    },
                    &[],
                    0,
                    Vec::<TreeStreamEntry>::new(),
                    registry,
                    operation,
                    &mut file_ids,
                    TreeStreamLimits::default(),
                )?;
                Ok(3)
            }
            "tree-sorted" => {
                let mut metrics = TreeScratchMetrics::default();
                encode_tree_with_scratch_and_features(
                    Vec::new(),
                    ObjectRef {
                        kind: ObjectKind::RepositoryDescriptor,
                        digest: [0; 32],
                    },
                    &[],
                    0,
                    Vec::<TreeStreamEntry>::new(),
                    registry,
                    operation,
                    Path::new(""),
                    TreeStreamLimits::default(),
                    &mut metrics,
                )?;
                Ok(3)
            }
            "content-manifest" => {
                let profile = ProfileRef::from_str("chunking.test/external-boundaries@1")?;
                let mut source =
                    |_index: u64,
                     _part: &ManifestStreamPart,
                     _consume: &mut dyn FnMut(&[u8]) -> Result<()>| Ok(());
                encode_and_verify_content_manifest_stream(
                    Vec::new(),
                    0,
                    Vec::<ManifestStreamPart>::new,
                    &profile,
                    0,
                    ogvcs_object_model::sha256(&[]),
                    &mut source,
                    registry,
                    operation,
                    ManifestStreamLimits::default(),
                )?;
                Ok(3)
            }
            "bundle-ordered" | "bundle-memory-encoder" => {
                let plan = LogicalBundleWritePlan {
                    object_count: 0,
                    logical_record_count: 0,
                    root_count: 0,
                    budget: LogicalBundleBudget {
                        sequence_bytes: 0,
                        largest_item_bytes: 0,
                        traversal_edges: 0,
                        index_entries: 0,
                    },
                };
                LogicalBundleWriter::new(
                    Vec::new(),
                    plan,
                    LogicalBundleWriteOptions::new(registry, operation),
                )?;
                Ok(3)
            }
            _ => Err(configured_preflight_error()),
        }
    }

    fn execute_tree_emitter(
        &self,
        surface: &str,
        source: &[u8],
        registry: &Registry,
        operation: Operation,
    ) -> Result<u8> {
        let value = decode_canonical(source, Limits::METADATA)?;
        let descriptor = ObjectRef::from_cbor(cbor_field(&value, 16)?)?;
        let features = cbor_array(cbor_field(&value, 2)?)?
            .iter()
            .map(|value| {
                u32::try_from(cbor_uint(value)?)
                    .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
            })
            .collect::<Result<Vec<_>>>()?;
        let entries = cbor_array(cbor_field(&value, 17)?)?
            .iter()
            .map(tree_stream_entry_cbor)
            .collect::<Result<Vec<_>>>()?;
        let declared =
            u64::try_from(entries.len()).map_err(|_| Error::new(ErrorCode::LimitCount))?;
        match surface {
            "tree-ordered" => {
                let mut file_ids = BTreeSet::new();
                encode_ordered_tree_with_features(
                    Vec::new(),
                    descriptor,
                    &features,
                    declared,
                    entries,
                    registry,
                    operation,
                    &mut file_ids,
                    TreeStreamLimits::default(),
                )?;
            }
            "tree-sorted" => {
                let scratch = TempDirectory::new("mode-tree-emitter")?;
                let mut metrics = TreeScratchMetrics::default();
                encode_tree_with_scratch_and_features(
                    Vec::new(),
                    descriptor,
                    &features,
                    declared,
                    entries,
                    registry,
                    operation,
                    &scratch.path,
                    TreeStreamLimits::default(),
                    &mut metrics,
                )?;
            }
            _ => return Err(configured_preflight_error()),
        }
        Ok(3)
    }

    fn execute_manifest_emitter(
        &self,
        source: &[u8],
        registry: &Registry,
        operation: Operation,
    ) -> Result<u8> {
        let value = decode_canonical(source, Limits::METADATA)?;
        let profile = ProfileRef::from_cbor(cbor_field(&value, 18)?)?;
        let parts = cbor_array(cbor_field(&value, 19)?)?
            .iter()
            .map(|part| {
                Ok(ManifestStreamPart {
                    chunk: ObjectRef::from_cbor(cbor_field(part, 0)?)?,
                    length: cbor_uint(cbor_field(part, 1)?)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if !parts.is_empty() {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let digest = TypedDigest::from_cbor(cbor_field(&value, 17)?)?;
        let mut chunk_source =
            |_index: u64,
             _part: &ManifestStreamPart,
             _consume: &mut dyn FnMut(&[u8]) -> Result<()>| Ok(());
        encode_and_verify_content_manifest_stream(
            Vec::new(),
            u64::try_from(parts.len()).map_err(|_| Error::new(ErrorCode::LimitCount))?,
            || parts.clone(),
            &profile,
            cbor_uint(cbor_field(&value, 16)?)?,
            *digest.digest(),
            &mut chunk_source,
            registry,
            operation,
            ManifestStreamLimits::default(),
        )?;
        Ok(3)
    }

    fn execute_bundle_emitter(
        &self,
        source: &[u8],
        registry: &Registry,
        operation: Operation,
    ) -> Result<u8> {
        let items = decode_bundle_items(source)?;
        let header = items
            .first()
            .ok_or_else(|| Error::new(ErrorCode::BundleSequenceInvalid))?;
        let budget = cbor_field(header, 6)?;
        let plan = LogicalBundleWritePlan {
            object_count: cbor_uint(cbor_field(header, 3)?)?,
            logical_record_count: cbor_uint(cbor_field(header, 4)?)?,
            root_count: cbor_uint(cbor_field(header, 5)?)?,
            budget: LogicalBundleBudget {
                sequence_bytes: cbor_uint(cbor_field(budget, 0)?)?,
                largest_item_bytes: cbor_uint(cbor_field(budget, 1)?)?,
                traversal_edges: cbor_uint(cbor_field(budget, 2)?)?,
                index_entries: cbor_uint(cbor_field(budget, 3)?)?,
            },
        };
        let mut writer = LogicalBundleWriter::new(
            Vec::new(),
            plan,
            LogicalBundleWriteOptions::new(registry, operation),
        )?;
        for item in items.iter().skip(1).take(items.len().saturating_sub(2)) {
            match cbor_uint(cbor_field(item, 1)?)? {
                2 => {
                    let reference = ObjectRef::from_cbor(cbor_field(item, 3)?)?;
                    writer.write_object(reference, cbor_bytes(cbor_field(item, 4)?)?)?;
                }
                3 => {
                    writer.write_logical_record(cbor_field(item, 4)?)?;
                }
                4 => {
                    let role = ProfileRef::from_cbor(cbor_field(item, 5)?)?;
                    match cbor_uint(cbor_field(item, 3)?)? {
                        1 => writer.write_object_root(
                            ObjectRef::from_cbor(cbor_field(item, 4)?)?,
                            &role,
                        )?,
                        2 => writer.write_logical_record_root(
                            TypedDigest::from_cbor(cbor_field(item, 4)?)?,
                            &role,
                        )?,
                        _ => return Err(Error::new(ErrorCode::BundleRootInvalid)),
                    }
                }
                _ => return Err(Error::new(ErrorCode::BundleSequenceInvalid)),
            }
        }
        writer.finish()?;
        Ok(3)
    }

    fn execute_repository_mode_surface(
        &self,
        request: &Value,
        scenario: &Value,
        authority: Option<Registry>,
    ) -> Result<u8> {
        let surface = value_string(request, "surface")?;
        if surface == "repository-lookup-layer2" {
            if request.get("registry").and_then(Value::as_str) != Some("absent")
                || request.get("semanticProfiles").and_then(Value::as_bool) != Some(false)
                || request
                    .as_object()
                    .is_some_and(|object| object.contains_key("mode"))
            {
                return Err(configured_preflight_error());
            }
            let mut limits = RepositoryLimits::default();
            if let Some(value) = request.pointer("/limits/maxTimeMs").and_then(Value::as_u64) {
                limits.max_time = Some(Duration::from_millis(value));
            }
            RepositoryObjectLookup::new_layer2([], limits)?;
            return Ok(2);
        }
        let mode = repository_validation_mode(request)?;
        let case_mode = if surface == "tree-expand" {
            path_case_mode_value(
                request
                    .get("caseMode")
                    .ok_or_else(configured_preflight_error)?,
            )?
        } else {
            path_case_mode(scenario)?
        };
        if request.get("semanticProfiles").and_then(Value::as_bool) == Some(false) {
            return self.execute_repository_layer2_rejection(surface, request, scenario, case_mode);
        }
        if request.get("registry").and_then(Value::as_str) != Some("bundled")
            || request.get("semanticProfiles").and_then(Value::as_bool) != Some(true)
        {
            if let Some(registry) = authority {
                // Exercise the public complete-authority gate without touching
                // scenario object bytes.
                RepositoryObjectLookup::new([], registry, mode, RepositoryLimits::default())?;
            }
            return Err(configured_preflight_error());
        }
        let registry = authority.ok_or_else(configured_preflight_error)?;
        if mode == ValidationMode::Read {
            RepositoryObjectLookup::new(
                Vec::<(ObjectRef, Vec<u8>)>::new(),
                registry,
                mode,
                RepositoryLimits::default(),
            )?;
            return Ok(3);
        }
        if surface == "repository-lookup-validate-all" {
            let order = json_array_result(request, "lookupOrder")?;
            let sources = json_array_result(request, "sources")?;
            if order.len() != sources.len() {
                return Err(configured_preflight_error());
            }
            let entries = order
                .iter()
                .zip(sources)
                .map(|(reference, source)| {
                    Ok((
                        object_ref_json(reference)?,
                        self.result_bytes(source.as_str().ok_or_else(configured_preflight_error)?)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let lookup =
                RepositoryObjectLookup::new(entries, registry, mode, RepositoryLimits::default())?;
            lookup.validate_all()?;
            return Ok(3);
        }
        let lookup = self.lookup_with_registry(
            scenario,
            registry.clone(),
            mode,
            RepositoryLimits::default(),
        )?;
        let descriptor = ObjectRef::from_str(value_string(request, "repositoryDescriptor")?)?;
        match surface {
            "tree-expand" => {
                expand_tree(
                    ObjectRef::from_str(value_string(request, "tree")?)?,
                    &lookup,
                    descriptor,
                    false,
                    case_mode,
                )?;
            }
            "manifest-verify" => {
                verify_manifest(
                    ObjectRef::from_str(value_string(request, "manifest")?)?,
                    &lookup,
                )?;
            }
            "repository-candidate" => {
                let lifetime_context = field_value(request, "lifetimeContext")?;
                let lifetime = parse_lifetime_records_from(lifetime_context, "lifetimeRecords")?;
                let working =
                    parse_lifetime_records_from(lifetime_context, "workingLifetimeAdditions")?;
                let mappings = parse_import_mappings_from(lifetime_context)?;
                let mut context = RepositoryContext::new(
                    &lookup,
                    descriptor,
                    ObjectRef::from_str(value_string(request, "designatedRoot")?)?,
                    case_mode,
                );
                context.lifetime_records = &lifetime;
                context.working_lifetime_additions = &working;
                context.import_mappings = &mappings;
                validate_repository_candidate(
                    ObjectRef::from_str(value_string(request, "candidateSnapshot")?)?,
                    &context,
                )?;
            }
            "import-request" => {
                let import_context = field_value(request, "importContext")?;
                let lifetime = parse_lifetime_records_from(import_context, "lifetimeRecords")?;
                let working =
                    parse_lifetime_records_from(import_context, "workingLifetimeAdditions")?;
                let mappings = parse_import_mappings_from(import_context)?;
                let mut context =
                    RepositoryContext::new(&lookup, descriptor, descriptor, case_mode);
                context.lifetime_records = &lifetime;
                context.working_lifetime_additions = &working;
                context.import_mappings = &mappings;
                validate_import_request(
                    &context,
                    &parse_import_request(field_value(request, "importRequest")?)?,
                )?;
            }
            "asset-groups" => {
                let (groups, file_ids) = group_inputs_fixture(request)?;
                validate_asset_groups_with_limits(
                    &groups,
                    &file_ids,
                    &[],
                    &[],
                    &registry,
                    mode,
                    RepositoryLimits::default(),
                )?;
            }
            _ => return Err(configured_preflight_error()),
        }
        Ok(3)
    }

    fn execute_repository_layer2_rejection(
        &self,
        surface: &str,
        request: &Value,
        _scenario: &Value,
        case_mode: PathCaseMode,
    ) -> Result<u8> {
        let descriptor = ObjectRef::from_str(value_string(request, "repositoryDescriptor")?)?;
        if surface == "asset-groups" {
            let (groups, file_ids) = group_inputs_fixture(request)?;
            let incomplete = Registry::load(Vec::<RegistryEntry>::new(), Vec::<u32>::new())?;
            validate_asset_groups_with_limits(
                &groups,
                &file_ids,
                &[],
                &[],
                &incomplete,
                ValidationMode::Conformance,
                RepositoryLimits::default(),
            )?;
            return Ok(3);
        }
        let lookup = RepositoryObjectLookup::new_layer2([], RepositoryLimits::default())?;
        match surface {
            "tree-expand" => {
                expand_tree(
                    ObjectRef::from_str(value_string(request, "tree")?)?,
                    &lookup,
                    descriptor,
                    false,
                    case_mode,
                )?;
            }
            "manifest-verify" => {
                verify_manifest(
                    ObjectRef::from_str(value_string(request, "manifest")?)?,
                    &lookup,
                )?;
            }
            "repository-candidate" => {
                let context = RepositoryContext::new(
                    &lookup,
                    descriptor,
                    ObjectRef::from_str(value_string(request, "designatedRoot")?)?,
                    case_mode,
                );
                validate_repository_candidate(
                    ObjectRef::from_str(value_string(request, "candidateSnapshot")?)?,
                    &context,
                )?;
            }
            "import-request" => {
                let context = RepositoryContext::new(&lookup, descriptor, descriptor, case_mode);
                validate_import_request(
                    &context,
                    &parse_import_request(field_value(request, "importRequest")?)?,
                )?;
            }
            _ => return Err(configured_preflight_error()),
        }
        Ok(3)
    }

    fn lookup_with_registry(
        &self,
        scenario: &Value,
        registry: Registry,
        mode: ValidationMode,
        limits: RepositoryLimits,
    ) -> Result<RepositoryObjectLookup> {
        let entries = self.lookup_entries(scenario)?;
        RepositoryObjectLookup::new(entries, registry, mode, limits)
    }

    fn lookup_entries(&self, scenario: &Value) -> Result<Vec<(ObjectRef, Vec<u8>)>> {
        context_array(scenario, "objectLookup")?
            .iter()
            .map(|entry| {
                Ok((
                    object_ref_json(field_value(entry, "ref")?)?,
                    self.result_bytes(value_string(field_value(entry, "artifact")?, "path")?)?,
                ))
            })
            .collect()
    }

    fn lookup(&self, scenario: &Value, limits: RepositoryLimits) -> Result<RepositoryObjectLookup> {
        let entries = self.lookup_entries(scenario)?;
        RepositoryObjectLookup::new(
            entries,
            self.registry.clone(),
            ValidationMode::Conformance,
            limits,
        )
    }

    fn execute_resource_actual(&self, row: &Value, scenario: &Value) -> Result<Value> {
        let request = self.operation_request(scenario)?;
        let expected_evidence = field_value(field_value(row, "expected")?, "evidence")?;
        if request.get("evidenceRequired") != Some(expected_evidence) {
            return Err(configured_preflight_error());
        }
        let operation = value_string(row, "operation")?;
        let (failure, route_evidence, component_fit) = if operation == "validate-tree-groups-memory"
        {
            let (failure, evidence) = self.execute_tree_groups_memory(scenario, &request)?;
            (failure, evidence, true)
        } else if operation == "validate-resource-reservation" {
            let (failure, evidence) = self.execute_resource_reservation(scenario, &request)?;
            (failure, evidence, false)
        } else {
            return Err(configured_preflight_error());
        };
        let evidence = if component_fit {
            json!({
                "eachComponentAloneFit": true,
                "noPartialState": true,
                "routeEvidence": route_evidence
            })
        } else {
            json!({
                "noPartialState": true,
                "routeEvidence": route_evidence
            })
        };
        if &evidence != expected_evidence || !failure.is_registered_site() {
            return Err(configured_preflight_error());
        }
        Ok(json!({
            "code": failure.code.as_str(),
            "evidence": evidence,
            "layer": failure.layer,
            "result": "reject",
            "stage": failure.stage.as_str()
        }))
    }

    fn execute_resource_reservation(
        &self,
        scenario: &Value,
        request: &Value,
    ) -> Result<(Error, Vec<Value>)> {
        if value_string(request, "api")? != "validate-resource-reservation"
            || request.get("assertNoPartialState").and_then(Value::as_bool) != Some(true)
            || request.get("routes").and_then(Value::as_array).is_none()
        {
            return Err(configured_preflight_error());
        }
        let entries = self.lookup_entries(scenario)?;
        match value_string(request, "cluster")? {
            "replay-base" => {
                let descriptor = reference_of_kind(scenario, ObjectKind::RepositoryDescriptor)?;
                let tree =
                    ObjectRef::from_str(value_string(field_value(request, "baseState")?, "tree")?)?;
                let change_set = ObjectRef::from_str(value_string(request, "changeSet")?)?;
                let base_lookup = self.lookup_with_registry(
                    scenario,
                    self.registry.clone(),
                    ValidationMode::Conformance,
                    RepositoryLimits {
                        max_memory_bytes: 67_108_864,
                        ..RepositoryLimits::default()
                    },
                )?;
                let expanded = expand_tree(
                    tree,
                    &base_lookup,
                    descriptor,
                    false,
                    path_case_mode(scenario)?,
                )?;
                let base = RepositoryState {
                    entries: expanded.entries,
                    groups: BTreeMap::new(),
                };
                let before = base.clone();
                let run = |ceiling: usize| -> Result<()> {
                    let lookup = RepositoryObjectLookup::new(
                        entries.clone(),
                        self.registry.clone(),
                        ValidationMode::Conformance,
                        RepositoryLimits {
                            max_memory_bytes: ceiling,
                            ..RepositoryLimits::default()
                        },
                    )?;
                    let context = RepositoryContext::new(
                        &lookup,
                        descriptor,
                        descriptor,
                        path_case_mode(scenario)?,
                    );
                    replay_change_set(change_set, &base, &context, None)?;
                    Ok(())
                };
                let minimum = minimum_successful_ceiling(&run)?;
                let lookup = RepositoryObjectLookup::new(
                    entries.clone(),
                    self.registry.clone(),
                    ValidationMode::Conformance,
                    RepositoryLimits {
                        max_memory_bytes: minimum.saturating_sub(1),
                        ..RepositoryLimits::default()
                    },
                )?;
                let context = RepositoryContext::new(
                    &lookup,
                    descriptor,
                    descriptor,
                    path_case_mode(scenario)?,
                );
                let failure = replay_change_set(change_set, &base, &context, None).unwrap_err();
                if base != before {
                    return Err(Error::new(ErrorCode::LimitMemory));
                }
                let recovery_base = RepositoryState::default();
                let recovery_before = recovery_base.clone();
                replay_change_set(change_set, &recovery_base, &context, None)?;
                if base != before || recovery_base != recovery_before {
                    return Err(Error::new(ErrorCode::LimitMemory));
                }
                Ok((
                    failure,
                    vec![resource_route_evidence(
                        "replay-change-set",
                        "same-authority-instance",
                    )],
                ))
            }
            "fileid-lifetime-import-indexes" => {
                let descriptor = reference_of_kind(scenario, ObjectKind::RepositoryDescriptor)?;
                let change_set = reference_of_kind(scenario, ObjectKind::ChangeSet)?;
                let tree = reference_of_kind(scenario, ObjectKind::Tree)?;
                let expansion_lookup = self.lookup_with_registry(
                    scenario,
                    self.registry.clone(),
                    ValidationMode::Conformance,
                    RepositoryLimits {
                        max_memory_bytes: 67_108_864,
                        ..RepositoryLimits::default()
                    },
                )?;
                let working_entries = expand_tree(
                    tree,
                    &expansion_lookup,
                    descriptor,
                    false,
                    path_case_mode(scenario)?,
                )?
                .entries;
                let before = working_entries.clone();
                let run = |ceiling: usize| -> Result<()> {
                    let lookup = RepositoryObjectLookup::new(
                        Vec::<(ObjectRef, Vec<u8>)>::new(),
                        self.registry.clone(),
                        ValidationMode::Conformance,
                        RepositoryLimits {
                            max_memory_bytes: ceiling,
                            ..RepositoryLimits::default()
                        },
                    )?;
                    let context = RepositoryContext::new(
                        &lookup,
                        descriptor,
                        descriptor,
                        path_case_mode(scenario)?,
                    );
                    validate_lifetime_and_imports(&context, change_set, &[], Some(&working_entries))
                };
                let minimum = minimum_successful_ceiling(&run)?;
                let lookup = RepositoryObjectLookup::new(
                    Vec::<(ObjectRef, Vec<u8>)>::new(),
                    self.registry.clone(),
                    ValidationMode::Conformance,
                    RepositoryLimits {
                        max_memory_bytes: minimum.saturating_sub(1),
                        ..RepositoryLimits::default()
                    },
                )?;
                let context = RepositoryContext::new(
                    &lookup,
                    descriptor,
                    descriptor,
                    path_case_mode(scenario)?,
                );
                let failure = validate_lifetime_and_imports(
                    &context,
                    change_set,
                    &[],
                    Some(&working_entries),
                )
                .unwrap_err();
                validate_lifetime_and_imports(&context, change_set, &[], None)?;
                if working_entries != before {
                    return Err(Error::new(ErrorCode::LimitMemory));
                }
                Ok((
                    failure,
                    vec![resource_route_evidence(
                        "validate-lifetime-and-imports",
                        "same-authority-instance",
                    )],
                ))
            }
            "fileid-import-many-mappings-deadline" => {
                let descriptor = reference_of_kind(scenario, ObjectKind::RepositoryDescriptor)?;
                let change_set = reference_of_kind(scenario, ObjectKind::ChangeSet)?;
                let working = (1u8..=64)
                    .map(|index| {
                        Ok(LifetimeRecord {
                            file_id: FileId::new([index; 16])?,
                            origin: LifetimeOrigin::NativeCreate,
                            first_change_set: change_set,
                            first_operation: 0,
                            import_mapping_key: None,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let import_request = ImportRequest {
                    importer_profile: ProfileRef::from_str("importer.test/fixture-adapter@1")?,
                    source_namespace_digest: [0x71; 32],
                    source_identity_digest: [0x72; 32],
                    requested_file_id: FileId::new([0xff; 16])?,
                };
                let run = |maximum: Option<Duration>| -> Result<()> {
                    let lookup = RepositoryObjectLookup::new(
                        entries.clone(),
                        self.registry.clone(),
                        ValidationMode::Conformance,
                        RepositoryLimits {
                            max_time: maximum,
                            ..RepositoryLimits::default()
                        },
                    )?;
                    let mut context = RepositoryContext::new(
                        &lookup,
                        descriptor,
                        descriptor,
                        path_case_mode(scenario)?,
                    );
                    context.working_lifetime_additions = &working;
                    validate_import_request(&context, &import_request)?;
                    Ok(())
                };
                let before = working.clone();
                let failure = run(Some(Duration::ZERO)).unwrap_err();
                if working != before {
                    return Err(Error::new(ErrorCode::LimitTime));
                }
                run(Some(Duration::from_secs(600)))?;
                if working != before {
                    return Err(Error::new(ErrorCode::LimitTime));
                }
                Ok((
                    failure,
                    vec![resource_route_evidence(
                        "validate-import-request",
                        "fresh-operation-after-deadline",
                    )],
                ))
            }
            "graph-workspace-indexes" => {
                let graph_scenario =
                    self.result_json("scenarios/cases/tree-groups-combined-memory.json")?;
                let graph_entries = self.lookup_entries(&graph_scenario)?;
                let descriptor =
                    object_ref_json(context_value(&graph_scenario, "repositoryDescriptor")?)?;
                let snapshot =
                    object_ref_json(context_value(&graph_scenario, "candidateSnapshot")?)?;
                let designated_root =
                    object_ref_json(context_value(&graph_scenario, "designatedRoot")?)?;
                let run = |ceiling: usize| -> Result<()> {
                    let lookup = RepositoryObjectLookup::new(
                        graph_entries.clone(),
                        self.registry.clone(),
                        ValidationMode::Conformance,
                        RepositoryLimits {
                            max_memory_bytes: ceiling,
                            ..RepositoryLimits::default()
                        },
                    )?;
                    let context = RepositoryContext::new(
                        &lookup,
                        descriptor,
                        designated_root,
                        path_case_mode(&graph_scenario)?,
                    );
                    validate_snapshot_graph(snapshot, &context)?;
                    Ok(())
                };
                let minimum = minimum_successful_ceiling(&run)?;
                let lookup = RepositoryObjectLookup::new(
                    graph_entries,
                    self.registry.clone(),
                    ValidationMode::Conformance,
                    RepositoryLimits {
                        max_memory_bytes: minimum.saturating_sub(1),
                        ..RepositoryLimits::default()
                    },
                )?;
                let context = RepositoryContext::new(
                    &lookup,
                    descriptor,
                    designated_root,
                    path_case_mode(&graph_scenario)?,
                );
                let failure = validate_snapshot_graph(snapshot, &context).unwrap_err();
                validate_snapshot_graph(designated_root, &context)?;
                Ok((
                    failure,
                    vec![resource_route_evidence(
                        "validate-snapshot-graph",
                        "same-authority-instance",
                    )],
                ))
            }
            "conflict-group-indexes" => {
                let conflict_scenario =
                    self.result_json("scenarios/cases/conflict-choice-base.json")?;
                let conflict_entries = self.lookup_entries(&conflict_scenario)?;
                let conflict_reference = ObjectRef::from_str(
                    "ogvcs:v1:conflict-set:sha256:562aa353fa3bfcf681e7e4a218f66c9f3c1157c490508cb81f4320f271be25cf",
                )?;
                let descriptor =
                    object_ref_json(context_value(&conflict_scenario, "repositoryDescriptor")?)?;
                let run_conflict = |ceiling: usize| -> Result<()> {
                    let lookup = RepositoryObjectLookup::new(
                        conflict_entries.clone(),
                        self.registry.clone(),
                        ValidationMode::Conformance,
                        RepositoryLimits {
                            max_memory_bytes: ceiling,
                            ..RepositoryLimits::default()
                        },
                    )?;
                    validate_conflict_set(Some(conflict_reference), &lookup, descriptor, false)?;
                    Ok(())
                };
                let conflict_minimum = minimum_successful_ceiling(&run_conflict)?;
                let conflict_lookup = RepositoryObjectLookup::new(
                    conflict_entries,
                    self.registry.clone(),
                    ValidationMode::Conformance,
                    RepositoryLimits {
                        max_memory_bytes: conflict_minimum.saturating_sub(1),
                        ..RepositoryLimits::default()
                    },
                )?;
                let conflict_failure = validate_conflict_set(
                    Some(conflict_reference),
                    &conflict_lookup,
                    descriptor,
                    false,
                )
                .unwrap_err();
                validate_conflict_set(None, &conflict_lookup, descriptor, false)?;

                let (groups, file_ids) = asset_groups_from_payload(
                    &self.result_bytes("objects/05-asset-group-set.cbor")?,
                )?;
                let before = groups.clone();
                let run = |ceiling: usize| {
                    validate_asset_groups_with_limits(
                        &groups,
                        &file_ids,
                        &[],
                        &[],
                        &self.registry,
                        ValidationMode::Conformance,
                        RepositoryLimits {
                            max_memory_bytes: ceiling,
                            ..RepositoryLimits::default()
                        },
                    )
                    .map(|_| ())
                };
                let minimum = minimum_successful_ceiling(&run)?;
                let group_failure = run(minimum.saturating_sub(1)).unwrap_err();
                if groups != before {
                    return Err(Error::new(ErrorCode::LimitMemory));
                }
                run(minimum)?;
                if groups != before {
                    return Err(Error::new(ErrorCode::LimitMemory));
                }
                if group_failure.code != conflict_failure.code {
                    return Err(configured_preflight_error());
                }
                Ok((
                    conflict_failure,
                    vec![
                        resource_route_evidence("validate-conflict-set", "same-authority-instance"),
                        resource_route_evidence("validate-asset-groups", "stateless-reinvoke"),
                    ],
                ))
            }
            "many-invalid-error-selection" => {
                let run = |ceiling: usize| -> Result<()> {
                    let lookup = RepositoryObjectLookup::new(
                        entries.clone(),
                        self.registry.clone(),
                        ValidationMode::Conformance,
                        RepositoryLimits {
                            max_memory_bytes: ceiling,
                            ..RepositoryLimits::default()
                        },
                    )?;
                    lookup.validate_all()
                };
                let minimum = minimum_successful_ceiling(&run)?;
                let failure = run(minimum.saturating_sub(1)).unwrap_err();
                run(minimum)?;
                let original = self.result_bytes("objects/03-tree.cbor")?;
                let scanned = scan_metadata(&original, Limits::METADATA)?;
                let mut malformed_value = scanned.value().clone();
                let Cbor::Map(fields) = &mut malformed_value else {
                    return Err(configured_preflight_error());
                };
                for field in 100u64..164 {
                    fields.push((Cbor::UInt(field), Cbor::UInt(field)));
                }
                let malformed_bytes = encode_canonical(&malformed_value)?;
                let malformed = scan_metadata(&malformed_bytes, Limits::METADATA)?;
                let schema_failure =
                    validate_metadata_schema_with_limits(&malformed, 511).unwrap_err();
                let recovery = validate_metadata_schema_with_limits(&malformed, 512).unwrap_err();
                if recovery.code != ErrorCode::SchemaFieldUnknown
                    || recovery.layer != 2
                    || recovery.stage != ValidationStage::KnownSchema
                    || encode_canonical(malformed.value())? != malformed_bytes
                    || schema_failure.code != failure.code
                {
                    return Err(configured_preflight_error());
                }
                Ok((
                    failure,
                    vec![
                        resource_route_evidence(
                            "repository-object-lookup-validate-all",
                            "stateless-reinvoke",
                        ),
                        resource_route_evidence("validate-known-schema", "stateless-reinvoke"),
                    ],
                ))
            }
            "lookup-edge-counter-rollback" | "lookup-scratch-counter-rollback" => {
                if request
                    .get("assertCounterBaselineAfterFailure")
                    .and_then(Value::as_bool)
                    != Some(true)
                    || request
                        .get("assertCounterBaselineAfterRecovery")
                        .and_then(Value::as_bool)
                        != Some(true)
                {
                    return Err(configured_preflight_error());
                }
                let cluster = value_string(request, "cluster")?;
                let configured = field_value(request, "configuredLimit")?;
                let mut limits = RepositoryLimits::default();
                let (field, value) = (
                    value_string(configured, "field")?,
                    usize::try_from(value_u64(configured, "value")?)
                        .map_err(|_| configured_preflight_error())?,
                );
                let (route, expected) = if cluster == "lookup-edge-counter-rollback" {
                    if field != "maxEdges" || value != 1 {
                        return Err(configured_preflight_error());
                    }
                    limits.max_edges = value;
                    ("expand-tree-edge-budget", ErrorCode::LimitCount)
                } else {
                    if field != "maxScratchBytes" || value != 64 {
                        return Err(configured_preflight_error());
                    }
                    limits.max_scratch_bytes = value;
                    ("expand-tree-scratch-budget", ErrorCode::LimitScratch)
                };
                let lookup = RepositoryObjectLookup::new(
                    entries,
                    self.registry.clone(),
                    ValidationMode::Conformance,
                    limits,
                )?;
                let descriptor = reference_of_kind(scenario, ObjectKind::RepositoryDescriptor)?;
                let baseline = lookup.resource_summary();
                let failure = expand_tree(
                    ObjectRef::from_str(value_string(request, "failureTree")?)?,
                    &lookup,
                    descriptor,
                    false,
                    path_case_mode(scenario)?,
                )
                .unwrap_err();
                if failure.code != expected || lookup.resource_summary() != baseline {
                    return Err(configured_preflight_error());
                }
                let recovery = field_value(request, "recovery")?;
                match value_string(recovery, "api")? {
                    "verify-manifest" => {
                        verify_manifest(
                            ObjectRef::from_str(value_string(recovery, "reference")?)?,
                            &lookup,
                        )?;
                    }
                    "expand-tree" => {
                        expand_tree(
                            ObjectRef::from_str(value_string(recovery, "recoveryTree")?)?,
                            &lookup,
                            descriptor,
                            false,
                            path_case_mode(scenario)?,
                        )?;
                    }
                    _ => return Err(configured_preflight_error()),
                }
                if lookup.resource_summary() != baseline {
                    return Err(configured_preflight_error());
                }
                Ok((
                    failure,
                    vec![resource_route_evidence_with_counter(
                        route,
                        "same-authority-instance",
                    )],
                ))
            }
            "tree-stream-transaction-composite-memory" => {
                if request
                    .pointer("/memoryCeiling/derivation")
                    .and_then(Value::as_str)
                    != Some("one-byte-below-reader-current-entry-and-fileid-index-composite-v1")
                    || request
                        .pointer("/memoryCeiling/indexCapacity")
                        .and_then(Value::as_str)
                        != Some("remaining-composite-budget-not-full-operation-ceiling")
                    || request
                        .pointer("/transaction/targetBytesUnchanged")
                        .and_then(Value::as_bool)
                        != Some(true)
                    || request
                        .pointer("/transaction/scratchIndexReusableAfterAbortDrop")
                        .and_then(Value::as_bool)
                        != Some(true)
                {
                    return Err(configured_preflight_error());
                }
                let failure_bytes =
                    self.result_bytes(value_string(field_value(request, "failure")?, "source")?)?;
                let recovery_bytes =
                    self.result_bytes(value_string(field_value(request, "recovery")?, "source")?)?;
                let descriptor = reference_of_kind(scenario, ObjectKind::RepositoryDescriptor)?;
                let expected = |bytes: &[u8]| -> Result<ObjectRef> {
                    Ok(ObjectRef {
                        kind: ObjectKind::Tree,
                        digest: object_id(ObjectKind::Tree, bytes)?,
                    })
                };
                let run = |ceiling: usize| -> Result<()> {
                    let scratch = TempDirectory::new("tree-index-probe")?;
                    let mut index = CompositeTreeFileIdIndex::new(&scratch.path)?;
                    verify_tree_stream(
                        Cursor::new(&recovery_bytes),
                        expected(&recovery_bytes)?,
                        descriptor,
                        &self.registry,
                        Operation::ConformanceWrite,
                        &mut index,
                        TreeStreamLimits {
                            max_memory_bytes: ceiling,
                            ..TreeStreamLimits::default()
                        },
                    )?;
                    Ok(())
                };
                let minimum = minimum_successful_ceiling(&run)?;
                let scratch = TempDirectory::new("tree-index-reuse")?;
                let mut index = CompositeTreeFileIdIndex::new(&scratch.path)?;
                let before = index.scratch_metrics();
                let failure = verify_tree_stream(
                    Cursor::new(&failure_bytes),
                    expected(&failure_bytes)?,
                    descriptor,
                    &self.registry,
                    Operation::ConformanceWrite,
                    &mut index,
                    TreeStreamLimits {
                        max_memory_bytes: minimum,
                        ..TreeStreamLimits::default()
                    },
                )
                .unwrap_err();
                if failure.code != ErrorCode::LimitMemory || index.retained_len() != 0 {
                    return Err(configured_preflight_error());
                }
                let recovered = verify_tree_stream(
                    Cursor::new(&recovery_bytes),
                    expected(&recovery_bytes)?,
                    descriptor,
                    &self.registry,
                    Operation::ConformanceWrite,
                    &mut index,
                    TreeStreamLimits {
                        max_memory_bytes: minimum,
                        ..TreeStreamLimits::default()
                    },
                )?;
                let after = index.scratch_metrics();
                if recovered.entries != 1
                    || index.retained_len() != 1
                    || after.files_created < before.files_created
                {
                    return Err(configured_preflight_error());
                }
                Ok((
                    failure,
                    vec![json!({
                        "compositeMemoryBounded": true,
                        "indexInstanceReused": true,
                        "noPartialState": true,
                        "recoveryKind": "same-authority-instance",
                        "route": "verify-tree-file-stream",
                        "scratchIndexReusableAfterAbort": true,
                        "succeeded": true,
                        "targetUnchanged": true
                    })],
                ))
            }
            _ => Err(configured_preflight_error()),
        }
    }

    fn execute_tree_groups_memory(
        &self,
        scenario: &Value,
        request: &Value,
    ) -> Result<(Error, Vec<Value>)> {
        if value_string(request, "api")? != "validate-tree-groups-memory"
            || request.pointer("/memoryCeiling/derivation").and_then(Value::as_str)
                != Some("one-byte-below-simultaneous-retained-tree-group-membership-and-collision-index")
            || request.pointer("/memoryCeiling/requireEachComponentAloneToFit").and_then(Value::as_bool)
                != Some(true)
        {
            return Err(configured_preflight_error());
        }
        let entries = self.lookup_entries(scenario)?;
        let before = entries.clone();
        let candidate = object_ref_json(context_value(scenario, "candidateSnapshot")?)?;
        let descriptor = object_ref_json(context_value(scenario, "repositoryDescriptor")?)?;
        let lifetime = parse_lifetime_records(scenario, "lifetimeRecords")?;
        let working = parse_lifetime_records(scenario, "workingLifetimeAdditions")?;
        let mappings = parse_import_mappings(scenario)?;
        let run_composite = |ceiling: usize| -> Result<()> {
            let lookup = RepositoryObjectLookup::new(
                entries.clone(),
                self.registry.clone(),
                ValidationMode::Conformance,
                RepositoryLimits {
                    max_memory_bytes: ceiling,
                    ..RepositoryLimits::default()
                },
            )?;
            let mut context = RepositoryContext::new(
                &lookup,
                descriptor,
                object_ref_json(context_value(scenario, "designatedRoot")?)?,
                path_case_mode(scenario)?,
            );
            context.lifetime_records = &lifetime;
            context.working_lifetime_additions = &working;
            context.import_mappings = &mappings;
            validate_repository_candidate(candidate, &context)?;
            Ok(())
        };
        let minimum = minimum_successful_ceiling(&run_composite)?;
        let reduced = minimum.saturating_sub(1);

        let lookup = RepositoryObjectLookup::new(
            entries.clone(),
            self.registry.clone(),
            ValidationMode::Conformance,
            RepositoryLimits {
                max_memory_bytes: reduced,
                ..RepositoryLimits::default()
            },
        )?;
        let snapshot = lookup.resolve_expected(candidate, ObjectKind::Snapshot)?;
        let tree = ObjectRef::from_cbor(cbor_field(
            snapshot
                .value
                .as_deref()
                .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?,
            18,
        )?)?;
        expand_tree(tree, &lookup, descriptor, false, path_case_mode(scenario)?)?;
        drop(lookup);

        let lookup = RepositoryObjectLookup::new(
            entries.clone(),
            self.registry.clone(),
            ValidationMode::Conformance,
            RepositoryLimits {
                max_memory_bytes: reduced,
                ..RepositoryLimits::default()
            },
        )?;
        let snapshot = lookup.resolve_expected(candidate, ObjectKind::Snapshot)?;
        let group_set = ObjectRef::from_cbor(cbor_field(
            snapshot
                .value
                .as_deref()
                .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?,
            20,
        )?)?;
        let resolved = lookup.resolve_expected(group_set, ObjectKind::AssetGroupSet)?;
        let (groups, file_ids) = asset_groups_from_value(
            resolved
                .value
                .as_deref()
                .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?,
        )?;
        validate_asset_groups_with_limits(
            &groups,
            &file_ids,
            &[],
            &[],
            &self.registry,
            ValidationMode::Conformance,
            RepositoryLimits {
                max_memory_bytes: reduced,
                ..RepositoryLimits::default()
            },
        )?;
        drop(lookup);

        let lookup = RepositoryObjectLookup::new(
            entries.clone(),
            self.registry.clone(),
            ValidationMode::Conformance,
            RepositoryLimits {
                max_memory_bytes: minimum,
                ..RepositoryLimits::default()
            },
        )?;
        let mut context = RepositoryContext::new(
            &lookup,
            descriptor,
            object_ref_json(context_value(scenario, "designatedRoot")?)?,
            path_case_mode(scenario)?,
        );
        context.lifetime_records = &lifetime;
        context.working_lifetime_additions = &working;
        context.import_mappings = &mappings;
        let baseline = lookup.resource_summary();
        let pressure = lookup.reserve_working_memory(1)?;
        let failure = validate_repository_candidate(candidate, &context).unwrap_err();
        drop(pressure);
        if failure.code != ErrorCode::LimitMemory
            || entries != before
            || lookup.resource_summary() != baseline
        {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        validate_repository_candidate(candidate, &context)?;
        if entries != before || lookup.resource_summary() != baseline {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        Ok((
            failure,
            vec![resource_route_evidence(
                "validate-tree-groups-memory",
                "same-authority-instance",
            )],
        ))
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
                    let mut bytes = serde_json::to_vec_pretty(document)
                        .map_err(|_| Error::new(ErrorCode::RegistryInvalid))?;
                    bytes.push(b'\n');
                    Ok((*name, bytes))
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
                LogicalBundleVerifyOptions::semantic(
                    &scratch.path,
                    &self.registry,
                    Operation::ConformanceWrite,
                ),
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
                        LogicalBundleVerifyOptions::semantic(
                            &scratch.path,
                            &self.registry,
                            Operation::ConformanceWrite,
                        ),
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

// The resource scenario needs one public index instance whose scratch state and
// caller target are both transactional under the verifier's remaining memory
// admission. The scratch side is deliberately kept to one FileID so the full
// tree reaches a later retained-target admission failure; the one-entry retry
// then proves that both halves were aborted and reopened on the same instance.
const COMPOSITE_PROBE_SCRATCH_MEMORY_BYTES: usize = std::mem::size_of::<[u8; 16]>();

struct CompositeTreeFileIdIndex {
    retained: BTreeSet<[u8; 16]>,
    scratch: TreeFileIdScratchIndex,
}

impl CompositeTreeFileIdIndex {
    fn new(scratch_directory: &Path) -> Result<Self> {
        Ok(Self {
            retained: BTreeSet::new(),
            scratch: TreeFileIdScratchIndex::new(
                scratch_directory,
                COMPOSITE_PROBE_SCRATCH_MEMORY_BYTES,
                8 * 1024 * 1024,
                None,
            )?,
        })
    }

    fn retained_len(&self) -> usize {
        self.retained.len()
    }

    fn scratch_metrics(&self) -> TreeScratchMetrics {
        self.scratch.scratch_metrics()
    }
}

impl TreeFileIdIndex for CompositeTreeFileIdIndex {
    fn begin(
        &mut self,
        maximum_items: u64,
        max_memory_bytes: usize,
    ) -> Result<Box<dyn TreeFileIdTransaction + '_>> {
        let retained_memory = max_memory_bytes
            .checked_sub(COMPOSITE_PROBE_SCRATCH_MEMORY_BYTES)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        let scratch = self
            .scratch
            .begin(maximum_items, COMPOSITE_PROBE_SCRATCH_MEMORY_BYTES)?;
        let retained = self.retained.begin(maximum_items, retained_memory)?;
        Ok(Box::new(CompositeTreeFileIdTransaction {
            scratch: Some(scratch),
            retained: Some(retained),
        }))
    }
}

struct CompositeTreeFileIdTransaction<'a> {
    scratch: Option<Box<dyn TreeFileIdTransaction + 'a>>,
    retained: Option<Box<dyn TreeFileIdTransaction + 'a>>,
}

impl TreeFileIdTransaction for CompositeTreeFileIdTransaction<'_> {
    fn insert(&mut self, file_id: [u8; 16]) -> Result<()> {
        self.scratch
            .as_deref_mut()
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?
            .insert(file_id)?;
        self.retained
            .as_deref_mut()
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?
            .insert(file_id)
    }

    fn finish(&mut self) -> Result<()> {
        self.scratch
            .as_deref_mut()
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?
            .finish()?;
        self.retained
            .as_deref_mut()
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?
            .finish()
    }

    fn commit(mut self: Box<Self>) -> Result<()> {
        if let Some(transaction) = self.scratch.take() {
            transaction.commit()?;
        }
        if let Some(transaction) = self.retained.take() {
            transaction.commit()?;
        }
        Ok(())
    }

    fn abort(mut self: Box<Self>) {
        if let Some(transaction) = self.scratch.take() {
            transaction.abort();
        }
        if let Some(transaction) = self.retained.take() {
            transaction.abort();
        }
    }
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

struct NoopBundleVisitor;

impl BundleVisitor for NoopBundleVisitor {}

#[derive(Default)]
struct BundleBoundaryVisitor {
    items: Vec<BundleItemInfo>,
}

impl BundleVisitor for BundleBoundaryVisitor {
    fn item_end(&mut self, info: BundleItemInfo) -> Result<()> {
        self.items.push(info);
        Ok(())
    }
}

fn decode_bundle_items(source: &[u8]) -> Result<Vec<Cbor>> {
    let mut visitor = BundleBoundaryVisitor::default();
    visit_logical_bundle(Cursor::new(source), &mut visitor, BundleLimits::HARD)?;
    visitor
        .items
        .into_iter()
        .map(|item| {
            let end = item
                .offset
                .checked_add(item.bytes)
                .ok_or_else(|| Error::new(ErrorCode::BundleBudgetExceeded))?;
            let bytes = source
                .get(item.offset..end)
                .ok_or_else(|| Error::new(ErrorCode::CborTruncated))?;
            decode_canonical(bytes, Limits::BUNDLE_ITEM)
        })
        .collect()
}

struct RecipePathProfileValidator {
    profile: ProfileRef,
    case_mode: PathCaseMode,
    invocations: Vec<(Vec<String>, PathProfileDecision)>,
    next: Cell<usize>,
}

impl RecipePathProfileValidator {
    fn from_request(request: &Value) -> Result<Self> {
        let adapter = field_value(request, "adapter")?;
        let requested_case_mode = path_case_mode_value(field_value(request, "caseMode")?)?;
        let case_mode = adapter
            .get("caseMode")
            .map(path_case_mode_value)
            .transpose()?
            .unwrap_or(match requested_case_mode {
                PathCaseMode::CaseSensitive => PathCaseMode::CaseFolded,
                PathCaseMode::CaseFolded => PathCaseMode::CaseSensitive,
            });
        let decision = path_profile_decision(field_value(adapter, "decision")?);
        let segments = json_array_result(request, "segments")?
            .iter()
            .map(|value| value_string_value(value).map(str::to_owned))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            profile: ProfileRef::from_str(value_string(adapter, "profile")?)?,
            case_mode,
            invocations: vec![(segments, decision)],
            next: Cell::new(0),
        })
    }

    fn from_scenario(scenario: &Value) -> Result<Option<Self>> {
        let Some(adapter) = scenario
            .get("context")
            .and_then(|context| context.get("pathProfileValidator"))
        else {
            return Ok(None);
        };
        let invocations = json_array_result(adapter, "invocations")?
            .iter()
            .map(|invocation| {
                let segments = json_array_result(invocation, "segments")?
                    .iter()
                    .map(|value| value_string_value(value).map(str::to_owned))
                    .collect::<Result<Vec<_>>>()?;
                Ok((
                    segments,
                    path_profile_decision(field_value(invocation, "decision")?),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(Self {
            profile: ProfileRef::from_str(value_string(adapter, "profile")?)?,
            case_mode: path_case_mode_value(field_value(adapter, "caseMode")?)?,
            invocations,
            next: Cell::new(0),
        }))
    }

    fn assert_complete(&self) -> Result<()> {
        if self.next.get() == self.invocations.len() {
            Ok(())
        } else {
            Err(configured_preflight_error())
        }
    }
}

impl PathProfileValidator for RecipePathProfileValidator {
    fn profile(&self) -> &ProfileRef {
        &self.profile
    }

    fn case_mode(&self) -> PathCaseMode {
        self.case_mode
    }

    fn validate(&self, segments: &[String]) -> PathProfileDecision {
        let index = self.next.get();
        self.next.set(index.saturating_add(1));
        self.invocations
            .get(index)
            .filter(|(expected, _)| expected == segments)
            .map_or_else(PathProfileDecision::rejected, |(_, decision)| {
                decision.clone()
            })
    }
}

fn path_profile_decision(value: &Value) -> PathProfileDecision {
    if value.get("accepted").and_then(Value::as_bool) == Some(true) {
        match (
            value.get("repositoryKey").and_then(Value::as_str),
            value.get("platformKey").and_then(Value::as_str),
        ) {
            (Some(repository_key), Some(platform_key)) => {
                PathProfileDecision::accepted(repository_key.to_owned(), platform_key.to_owned())
            }
            _ => PathProfileDecision::rejected(),
        }
    } else {
        PathProfileDecision::rejected()
    }
}

fn configured_preflight_error() -> Error {
    Error::new(ErrorCode::SchemaFieldInvalid)
        .with_layer(1)
        .with_stage(ValidationStage::ConfiguredResourcePreflight)
}

fn resource_route_evidence(route: &str, recovery_kind: &str) -> Value {
    json!({
        "noPartialState": true,
        "recoveryKind": recovery_kind,
        "route": route,
        "succeeded": true
    })
}

fn resource_route_evidence_with_counter(route: &str, recovery_kind: &str) -> Value {
    json!({
        "counterBaselineRestored": true,
        "noPartialState": true,
        "recoveryKind": recovery_kind,
        "route": route,
        "succeeded": true
    })
}

fn operation_input(scenario: &Value) -> Result<&Value> {
    scenario
        .get("inputs")
        .and_then(Value::as_array)
        .and_then(|inputs| {
            inputs.iter().find(|input| {
                input
                    .get("path")
                    .and_then(Value::as_str)
                    .is_some_and(|path| path.starts_with("scenarios/operations/"))
            })
        })
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn decimal_u64(value: &str) -> Result<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    value
        .parse::<u64>()
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn codec_operation(request: &Value) -> Result<Operation> {
    match request.get("operation").and_then(Value::as_str) {
        Some("read") => Ok(Operation::Read),
        Some("conformance") => Ok(Operation::ConformanceWrite),
        Some("production-write") => Ok(Operation::ProductionWrite),
        _ => Err(configured_preflight_error()),
    }
}

fn write_operation(request: &Value) -> Result<Operation> {
    match codec_operation(request)? {
        Operation::ConformanceWrite => Ok(Operation::ConformanceWrite),
        Operation::ProductionWrite => Ok(Operation::ProductionWrite),
        Operation::Read => Err(configured_preflight_error()),
    }
}

fn repository_validation_mode(request: &Value) -> Result<ValidationMode> {
    match request.get("mode").and_then(Value::as_str) {
        Some("read") => Ok(ValidationMode::Read),
        Some("conformance") => Ok(ValidationMode::Conformance),
        Some("production") => Ok(ValidationMode::Production),
        _ => Err(configured_preflight_error()),
    }
}

fn path_case_mode_value(value: &Value) -> Result<PathCaseMode> {
    match value.as_str() {
        Some("case-sensitive") => Ok(PathCaseMode::CaseSensitive),
        Some("case-folded") => Ok(PathCaseMode::CaseFolded),
        _ => Err(configured_preflight_error()),
    }
}

fn tree_stream_entry(value: &Value) -> Result<TreeStreamEntry> {
    Ok(TreeStreamEntry {
        basename: value_string(value, "name")?.to_owned(),
        entry_kind: u8::try_from(value_u64(value, "kind")?)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        file_id: hex_array(value_string(value, "fileId")?)?,
        portable_mode: u8::try_from(value_u64(value, "mode")?)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        target: ObjectRef::from_str(value_string(value, "target")?)?,
        logical_size: decimal_u64(value_string(value, "logicalSize")?)?,
        content_policy: ProfileRef::from_str(value_string(value, "contentPolicy")?)?,
    })
}

fn tree_stream_entry_cbor(value: &Cbor) -> Result<TreeStreamEntry> {
    Ok(TreeStreamEntry {
        basename: cbor_text(cbor_field(value, 0)?)?.to_owned(),
        entry_kind: u8::try_from(cbor_uint(cbor_field(value, 1)?)?)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        file_id: cbor_fixed_bytes(cbor_field(value, 2)?)?,
        portable_mode: u8::try_from(cbor_uint(cbor_field(value, 3)?)?)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        target: ObjectRef::from_cbor(cbor_field(value, 4)?)?,
        logical_size: cbor_uint(cbor_field(value, 5)?)?,
        content_policy: ProfileRef::from_cbor(cbor_field(value, 6)?)?,
    })
}

fn parse_lifetime_records_from(value: &Value, key: &str) -> Result<Vec<LifetimeRecord>> {
    json_array_result(value, key)?
        .iter()
        .map(|record| {
            Ok(LifetimeRecord {
                file_id: file_id_json(field_value(record, "fileId")?)?,
                origin: match value_string(record, "origin")? {
                    "native-create" => LifetimeOrigin::NativeCreate,
                    "native-copy" => LifetimeOrigin::NativeCopy,
                    "import" => LifetimeOrigin::Import,
                    _ => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
                },
                first_change_set: object_ref_json(field_value(record, "firstChangeSet")?)?,
                first_operation: value_u64(record, "firstOperation")?,
                import_mapping_key: record
                    .get("importMappingKey")
                    .map(|value| value_string_value(value).and_then(hex_array))
                    .transpose()?,
            })
        })
        .collect()
}

fn parse_import_mappings_from(value: &Value) -> Result<Vec<ImportMapping>> {
    json_array_result(value, "importMappings")?
        .iter()
        .map(|mapping| {
            Ok(ImportMapping {
                descriptor: object_ref_json(field_value(mapping, "descriptor")?)?,
                importer_profile: ProfileRef::from_str(value_string(mapping, "importerProfile")?)?,
                source_namespace_digest: hex_array(value_string(
                    mapping,
                    "sourceNamespaceDigest",
                )?)?,
                source_identity_digest: hex_array(value_string(mapping, "sourceIdentityDigest")?)?,
                file_id: file_id_json(field_value(mapping, "fileId")?)?,
                state: match value_string(mapping, "state")? {
                    "reserved" => ImportState::Reserved,
                    "materialized" => ImportState::Materialized,
                    "published" => ImportState::Published,
                    _ => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
                },
                declared_mapping_key: hex_array(value_string(mapping, "mappingKey")?)?,
            })
        })
        .collect()
}

type AssetGroupFixture = (
    BTreeMap<[u8; 16], AssetGroup>,
    BTreeMap<FileId, Vec<String>>,
);

fn group_fixture(value: &Value) -> Result<AssetGroupFixture> {
    let id: [u8; 16] = hex_array(value_string(value, "groupId")?)?;
    let file_ids = json_array_result(value, "fileIds")?
        .iter()
        .map(file_id_json)
        .collect::<Result<Vec<_>>>()?;
    let primary = *file_ids
        .first()
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
    let role = ProfileRef::from_str(value_string(value, "roleProfile")?)?;
    let members = file_ids
        .iter()
        .copied()
        .map(|file_id| {
            Cbor::Map(vec![
                (Cbor::UInt(0), file_id.to_cbor()),
                (Cbor::UInt(1), role.to_cbor()),
            ])
        })
        .collect();
    let external_profile = ProfileRef::from_str(value_string(value, "externalKeyProfile")?)?;
    let raw = Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::Bytes(id.to_vec())),
        (
            Cbor::UInt(1),
            ProfileRef::from_str(value_string(value, "groupProfile")?)?.to_cbor(),
        ),
        (Cbor::UInt(2), primary.to_cbor()),
        (Cbor::UInt(3), Cbor::Array(members)),
        (
            Cbor::UInt(4),
            Cbor::Array(vec![Cbor::Map(vec![
                (Cbor::UInt(0), external_profile.to_cbor()),
                (
                    Cbor::UInt(1),
                    Cbor::Bytes(hex_vec(value_string(value, "externalKeyValueHex")?)?),
                ),
            ])]),
        ),
    ]);
    let group = AssetGroup::from_cbor(&raw)?;
    let groups = BTreeMap::from([(id, group)]);
    let paths = file_ids
        .into_iter()
        .map(|file_id| (file_id, vec!["fixture".to_owned()]))
        .collect();
    Ok((groups, paths))
}

fn group_inputs_fixture(request: &Value) -> Result<AssetGroupFixture> {
    let fixtures = if let Some(values) = request.get("groupInputs").and_then(Value::as_array) {
        values.as_slice()
    } else {
        std::slice::from_ref(field_value(request, "groupInput")?)
    };
    let mut groups = BTreeMap::new();
    let mut file_ids = BTreeMap::new();
    for fixture in fixtures {
        let (next_groups, next_file_ids) = group_fixture(fixture)?;
        for (id, group) in next_groups {
            if groups.insert(id, group).is_some() {
                return Err(Error::new(ErrorCode::SchemaFieldInvalid));
            }
        }
        for (file_id, path) in next_file_ids {
            file_ids.entry(file_id).or_insert(path);
        }
    }
    Ok((groups, file_ids))
}

fn registry_from_documents(documents: &BTreeMap<&str, Value>) -> Result<Registry> {
    let encoded = documents
        .iter()
        .map(|(name, document)| {
            let mut bytes = serde_json::to_vec_pretty(document)
                .map_err(|_| Error::new(ErrorCode::RegistryInvalid))?;
            bytes.push(b'\n');
            Ok((*name, bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    let borrowed = encoded
        .iter()
        .map(|(name, bytes)| (*name, bytes.as_slice()))
        .collect::<Vec<_>>();
    Registry::from_json_files(&borrowed)
}

fn append_snapshot_entries(
    document: &mut Value,
    source: Option<&Value>,
    add_owner: bool,
) -> Result<()> {
    let entries = document
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?;
    for source in source.and_then(Value::as_array).into_iter().flatten() {
        let mut entry = source.clone();
        if add_owner {
            entry
                .as_object_mut()
                .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?
                .entry("owner")
                .or_insert_with(|| Value::String("OGVCS-002".to_owned()));
        }
        entries.push(entry);
    }
    entries.sort_by(|left, right| {
        let left_key = (
            left.get("namespace").and_then(Value::as_str).unwrap_or(""),
            left.get("id").and_then(Value::as_str).unwrap_or(""),
            left.get("major").and_then(Value::as_u64).unwrap_or(0),
        );
        let right_key = (
            right.get("namespace").and_then(Value::as_str).unwrap_or(""),
            right.get("id").and_then(Value::as_str).unwrap_or(""),
            right.get("major").and_then(Value::as_u64).unwrap_or(0),
        );
        left_key.cmp(&right_key)
    });
    Ok(())
}

fn append_feature_entries(document: &mut Value, source: Option<&Value>) -> Result<()> {
    let additions = source
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if additions.is_empty() {
        return Ok(());
    }
    let entries = document
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?;
    entries.extend(additions);
    entries.sort_by_key(|entry| {
        entry
            .get("code")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX)
    });
    let highest = entries
        .iter()
        .filter_map(|entry| entry.get("code").and_then(Value::as_u64))
        .max()
        .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?;
    document["unassigned"] = if highest < u64::from(u32::MAX) {
        json!([{"from": highest + 1, "to": u32::MAX}])
    } else {
        json!([])
    };
    Ok(())
}

fn minimum_successful_ceiling<F>(callback: &F) -> Result<usize>
where
    F: Fn(usize) -> Result<()>,
{
    let mut low = 0usize;
    let mut high = 67_108_864usize;
    callback(high)?;
    while low < high {
        let middle = low + (high - low) / 2;
        match callback(middle) {
            Ok(()) => high = middle,
            Err(error) if error.code == ErrorCode::LimitMemory => low = middle + 1,
            Err(error) => return Err(error),
        }
    }
    Ok(low)
}

fn reference_of_kind(scenario: &Value, kind: ObjectKind) -> Result<ObjectRef> {
    context_array(scenario, "objectLookup")?
        .iter()
        .filter_map(|entry| entry.get("ref"))
        .map(object_ref_json)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .find(|reference| reference.kind == kind)
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn cbor_field(value: &Cbor, key: u64) -> Result<&Cbor> {
    let Cbor::Map(fields) = value else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    };
    fields
        .iter()
        .find_map(|(candidate, value)| match candidate {
            Cbor::UInt(candidate) if *candidate == key => Some(value),
            _ => None,
        })
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn cbor_optional_field(value: &Cbor, key: u64) -> Option<&Cbor> {
    let Cbor::Map(fields) = value else {
        return None;
    };
    fields
        .iter()
        .find_map(|(candidate, value)| match candidate {
            Cbor::UInt(candidate) if *candidate == key => Some(value),
            _ => None,
        })
}

fn cbor_uint(value: &Cbor) -> Result<u64> {
    match value {
        Cbor::UInt(value) => Ok(*value),
        _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    }
}

fn cbor_text(value: &Cbor) -> Result<&str> {
    match value {
        Cbor::Text(value) => Ok(value),
        _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    }
}

fn cbor_bytes(value: &Cbor) -> Result<&[u8]> {
    match value {
        Cbor::Bytes(value) => Ok(value),
        _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    }
}

fn cbor_fixed_bytes<const N: usize>(value: &Cbor) -> Result<[u8; N]> {
    cbor_bytes(value)?
        .try_into()
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn cbor_array(value: &Cbor) -> Result<&[Cbor]> {
    match value {
        Cbor::Array(value) => Ok(value),
        _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    }
}

fn asset_groups_from_payload(payload: &[u8]) -> Result<AssetGroupFixture> {
    let object = scan_metadata(payload, Limits::METADATA)?;
    if validate_metadata_schema(&object)? != ObjectKind::AssetGroupSet {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    asset_groups_from_value(object.value())
}

fn asset_groups_from_value(value: &Cbor) -> Result<AssetGroupFixture> {
    let Cbor::Array(values) = cbor_field(value, 17)? else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    };
    let mut groups = BTreeMap::new();
    let mut file_ids = BTreeMap::new();
    for value in values {
        let group = AssetGroup::from_cbor(value)?;
        for (file_id, _) in &group.members {
            file_ids
                .entry(*file_id)
                .or_insert_with(|| vec!["fixture".to_owned()]);
        }
        if groups.insert(group.id, group).is_some() {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
    }
    Ok((groups, file_ids))
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
    let mut context = RepositoryContext::new(
        lookup,
        descriptor,
        designated_root,
        path_case_mode(scenario)?,
    );
    context.lifetime_records = lifetime;
    context.working_lifetime_additions = working;
    context.import_mappings = mappings;
    context.verify_content = true;
    Ok(context)
}

fn scenario_validation_mode(scenario: &Value) -> Result<ValidationMode> {
    match context_value(scenario, "mode")?.as_str() {
        Some("conformance") => Ok(ValidationMode::Conformance),
        Some("production") => Ok(ValidationMode::Production),
        _ => Err(configured_preflight_error()),
    }
}

fn path_case_mode(scenario: &Value) -> Result<PathCaseMode> {
    match context_value(scenario, "caseMode")?.as_str() {
        Some("case-sensitive") => Ok(PathCaseMode::CaseSensitive),
        Some("case-folded") => Ok(PathCaseMode::CaseFolded),
        _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)
            .with_layer(1)
            .with_stage(ValidationStage::ConfiguredResourcePreflight)),
    }
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
                descriptor: object_ref_json(field_value(value, "descriptor")?)?,
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
                declared_mapping_key: hex_array(value_string(value, "mappingKey")?)?,
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
        "read-or-production-write" => {
            vec![Operation::Read, Operation::ProductionWrite]
        }
        "read" => vec![Operation::Read],
        "production-write" => vec![Operation::ProductionWrite],
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
        "accept" => {
            let mut outcome = json!({
                "highestLayer": value.get("highestLayer").and_then(Value::as_u64)
                    .ok_or_else(|| "accepted outcome has no highestLayer".to_owned())?,
                "result": "accept"
            });
            if let Some(evidence) = value.get("evidence") {
                outcome["evidence"] = evidence.clone();
            }
            Ok(outcome)
        }
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
            let mut outcome = json!({
                "code": code_name,
                "layer": layer,
                "result": "reject",
                "stage": stage_name
            });
            if let Some(evidence) = value.get("evidence") {
                outcome["evidence"] = evidence.clone();
            }
            Ok(outcome)
        }
        other => Err(format!("unsupported expected result {other}")),
    }
}

fn diagnostic_outcome(scenario_id: &str, error: Error) -> std::result::Result<Value, String> {
    if !error.is_registered_site() {
        return Err(format!(
            "{scenario_id}: unregistered diagnostic site {}@{}:{}",
            error.code.as_str(),
            error.layer,
            error.stage.as_str()
        ));
    }
    Ok(json!({
        "code": error.code.as_str(),
        "layer": error.layer,
        "result": "reject",
        "stage": error.stage.as_str()
    }))
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

fn hex_vec(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |byte| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
            };
            Ok(nibble(pair[0])? << 4 | nibble(pair[1])?)
        })
        .collect()
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
