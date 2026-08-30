use std::{
    collections::BTreeMap,
    fs::{create_dir, read_dir, remove_dir},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use ogvcs_chunking_manifest::{
    chunk_bytes, compare_manifest, reconstruct_manifest, verify_manifest, ChunkError, ChunkPart,
    ChunkSource, Chunker, KnownChunkIndex, LedgerOptions, ManifestPart,
    TransactionalPublication, VerifyOptions, PROFILE,
};
use ogvcs_object_model::{
    encode_canonical, object_id, sha256, Cbor, ObjectKind, ObjectRef, ProfileRef,
};
use serde_json::Value;

const GOLDEN: &str = include_str!("../../../../spec/chunking-manifest/v1/vectors/golden.json");
const MALFORMED: &str = include_str!("../../../../spec/chunking-manifest/v1/vectors/malformed.json");
const ERRORS: &str = include_str!("../../../../spec/chunking-manifest/v1/registries/errors.json");

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn source(recipe: &Value) -> Vec<u8> {
    match recipe["kind"].as_str().unwrap() {
        "literal" => decode_hex(recipe["hex"].as_str().unwrap()),
        "repeat" => vec![recipe["byte"].as_u64().unwrap() as u8; recipe["length"].as_u64().unwrap() as usize],
        "sha256-counter" => {
            let length = recipe["length"].as_u64().unwrap() as usize;
            let seed = recipe["seed"].as_str().unwrap().as_bytes();
            let mut output = Vec::with_capacity(length);
            let mut counter = 0u64;
            while output.len() < length {
                let mut preimage = b"OpenGameVCS chunk vector block v1\0".to_vec();
                preimage.extend_from_slice(seed);
                preimage.push(0);
                preimage.extend_from_slice(&counter.to_be_bytes());
                let digest = sha256(&preimage);
                let take = (length - output.len()).min(32);
                output.extend_from_slice(&digest[..take]);
                counter += 1;
            }
            output
        }
        "insert" => {
            let base = source(&recipe["base"]);
            let offset = recipe["offset"].as_u64().unwrap() as usize;
            let inserted = decode_hex(recipe["hex"].as_str().unwrap());
            [&base[..offset], &inserted, &base[offset..]].concat()
        }
        kind => panic!("unknown recipe {kind}"),
    }
}

#[derive(Default)]
struct MapSource(BTreeMap<String, Vec<u8>>);

impl ChunkSource for MapSource {
    fn stream_chunk(
        &mut self,
        part: &ManifestPart,
        _occurrence: usize,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), ChunkError>,
    ) -> Result<(), ChunkError> {
        let bytes = self
            .0
            .get(&part.reference.to_string())
            .ok_or(ChunkError::SourceMissing)?;
        for fragment in bytes.chunks(4093) {
            consume(fragment)?;
        }
        Ok(())
    }
}

fn generated(bytes: &[u8]) -> (ogvcs_chunking_manifest::ChunkResult, MapSource) {
    let mut delivered = Vec::new();
    let result = chunk_bytes(bytes, |chunk, _part, _index| {
        delivered.push(chunk.to_vec());
        Ok(())
    })
    .unwrap();
    let chunks = result
        .parts
        .iter()
        .zip(delivered)
        .map(|(part, bytes)| (part.object_id.clone(), bytes))
        .collect();
    (result, MapSource(chunks))
}

fn manifest(logical: u64, whole: [u8; 32], parts: &[(ObjectRef, u64)]) -> Vec<u8> {
    let profile = ProfileRef::new("chunking.opengamevcs", "gear-fastcdc-1m", 1).unwrap();
    encode_canonical(&Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(2)),
        (Cbor::UInt(2), Cbor::Array(Vec::new())),
        (Cbor::UInt(16), Cbor::UInt(logical)),
        (Cbor::UInt(17), Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::Bytes(whole.to_vec())),
        ])),
        (Cbor::UInt(18), profile.to_cbor()),
        (Cbor::UInt(19), Cbor::Array(parts.iter().map(|(reference, length)| Cbor::Map(vec![
            (Cbor::UInt(0), reference.to_cbor()),
            (Cbor::UInt(1), Cbor::UInt(*length)),
        ])).collect())),
    ])).unwrap()
}

fn vector(case_id: &str) -> Value {
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    golden["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["caseId"] == case_id)
        .unwrap()
        .clone()
}

#[test]
fn generated_error_registry_matches_every_rust_error_code() {
    let registry: Value = serde_json::from_str(ERRORS).unwrap();
    let expected: Vec<&str> = registry["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    let actual: Vec<&str> = ChunkError::ALL.iter().map(|error| error.code()).collect();
    assert_eq!(actual, expected);
}

#[test]
fn every_golden_manifest_verifies_and_reconstructs_transactionally() {
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    for item in golden["cases"].as_array().unwrap() {
        let bytes = source(&item["recipe"]);
        let (result, mut chunks) = generated(&bytes);
        let summary = verify_manifest(&result.manifest.bytes, &mut chunks, &VerifyOptions::default()).unwrap();
        assert_eq!(summary.logical_bytes, bytes.len() as u64);

        let (_, mut chunks) = generated(&bytes);
        let mut publication = Publication::default();
        let reconstructed = reconstruct_manifest(
            &result.manifest.bytes,
            &mut chunks,
            &mut publication,
            &VerifyOptions::default(),
        ).unwrap();
        assert_eq!(reconstructed.logical_bytes, bytes.len() as u64);
        assert_eq!(publication.staged, bytes);
        assert_eq!((publication.commits, publication.aborts), (1, 0));
    }
}

#[derive(Default)]
struct Publication {
    staged: Vec<u8>,
    commits: usize,
    aborts: usize,
}

impl TransactionalPublication for Publication {
    fn write(&mut self, bytes: &[u8], _occurrence: usize) -> Result<(), ChunkError> {
        self.staged.extend_from_slice(bytes);
        Ok(())
    }
    fn commit(&mut self) -> Result<(), ChunkError> {
        self.commits += 1;
        Ok(())
    }
    fn abort(&mut self, _cause: ChunkError) -> Result<(), ChunkError> {
        self.aborts += 1;
        self.staged.clear();
        Ok(())
    }
}

struct Known(BTreeMap<String, u64>);

impl KnownChunkIndex for Known {
    fn known_length(&mut self, reference: &ObjectRef) -> Result<Option<u64>, ChunkError> {
        Ok(self.0.get(&reference.to_string()).copied())
    }
}

#[test]
fn repeated_reference_accounting_and_conflicts_are_exact() {
    let bytes = source(&vector("zero-five-mib")["recipe"]);
    let (result, mut chunks) = generated(&bytes);
    let summary = verify_manifest(&result.manifest.bytes, &mut chunks, &VerifyOptions::default()).unwrap();
    assert!(summary.repeated_bytes > 0);
    assert_eq!(summary.provider_reads, result.parts.len());
    let first = &result.parts[0];
    let mut known = Known(BTreeMap::from([(first.object_id.clone(), first.length)]));
    let compared = compare_manifest(&result.manifest.bytes, &mut known, &VerifyOptions::default()).unwrap();
    assert_eq!(compared.reused_bytes, first.length);
    assert_eq!(compared.unique_bytes, compared.reused_bytes + compared.newly_required_bytes);
    let exhausted_options = VerifyOptions {
        max_index_memory_bytes: 0,
        ..VerifyOptions::default()
    };
    assert_eq!(
        compare_manifest(&result.manifest.bytes, &mut Known(BTreeMap::new()), &exhausted_options).unwrap_err(),
        ChunkError::ResourceExhausted
    );

    let reference = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: object_id(ObjectKind::Chunk, &[1]).unwrap(),
    };
    let conflict = manifest(3, sha256(&[1, 1, 1]), &[(reference, 1), (reference, 2)]);
    let mut none = Known(BTreeMap::new());
    assert_eq!(
        compare_manifest(&conflict, &mut none, &VerifyOptions::default()).unwrap_err(),
        ChunkError::MetadataConflict
    );
}

#[test]
fn corrupt_reconstruction_aborts_without_commit() {
    let bytes = source(&vector("counter-a-six-mib")["recipe"]);
    let (result, mut chunks) = generated(&bytes);
    chunks.0.get_mut(&result.parts[0].object_id).unwrap()[0] ^= 1;
    let mut publication = Publication::default();
    assert_eq!(
        reconstruct_manifest(
            &result.manifest.bytes,
            &mut chunks,
            &mut publication,
            &VerifyOptions::default(),
        ).unwrap_err(),
        ChunkError::DigestMismatch
    );
    assert_eq!((publication.commits, publication.aborts), (0, 1));
    assert!(publication.staged.is_empty());
}

fn scratch_directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "ogvcs-chunk-rust-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    create_dir(&path).unwrap();
    path
}

#[test]
fn ledger_spill_and_exhaustion_clean_private_scratch() {
    let directory = scratch_directory();
    let bytes = source(&vector("counter-a-six-mib")["recipe"]);
    let mut delivered = Vec::<(ChunkPart, Vec<u8>)>::new();
    let mut chunker = Chunker::new_bounded(
        bytes.len() as u64,
        PROFILE,
        LedgerOptions {
            max_memory_bytes: 0,
            max_scratch_bytes: 1024 * 1024,
            scratch_directory: directory.clone(),
        },
        |chunk, part, _index| {
            delivered.push((part.clone(), chunk.to_vec()));
            Ok(())
        },
    ).unwrap();
    chunker.update(&bytes).unwrap();
    let result = chunker.finish().unwrap();
    assert!(result.ledger.spilled);
    assert_eq!(read_dir(&directory).unwrap().count(), 0);

    let mut exhausted = Chunker::new_bounded(
        2_097_152,
        PROFILE,
        LedgerOptions {
            max_memory_bytes: 0,
            max_scratch_bytes: 0,
            scratch_directory: directory.clone(),
        },
        |_chunk, _part, _index| Ok(()),
    ).unwrap();
    let exhausted_fragment = vec![0; 2_097_152];
    assert_eq!(exhausted.update(&exhausted_fragment).unwrap_err(), ChunkError::ScratchExhausted);
    assert_eq!(read_dir(&directory).unwrap().count(), 0);
    remove_dir(directory).unwrap();
}

#[test]
fn every_malformed_vector_is_dispatched_and_executed() {
    let malformed: Value = serde_json::from_str(MALFORMED).unwrap();
    let fixture_bytes = source(&vector("counter-a-six-mib")["recipe"]);
    let (fixture, fixture_source) = generated(&fixture_bytes);
    let mut executed = Vec::new();
    for case in malformed["cases"].as_array().unwrap() {
        let case_id = case["caseId"].as_str().unwrap();
        let expected = case["expectedError"].as_str().unwrap();
        let parameters = &case["parameters"];
        let error = match case_id {
            "declared-negative" => parameters["declaredLength"]
                .as_u64()
                .map(|_| ChunkError::SessionFailed)
                .unwrap_or(ChunkError::DeclaredLengthInvalid),
            "declared-over-limit" => Chunker::new(
                parameters["declaredLength"].as_u64().unwrap(), PROFILE,
                |_chunk, _part, _index| Ok(())
            ).err().unwrap(),
            "source-short" => {
                let mut chunker = Chunker::new(4, PROFILE, |_chunk, _part, _index| Ok(())).unwrap();
                chunker.update(&decode_hex(parameters["sourceHex"].as_str().unwrap())).unwrap();
                chunker.finish().unwrap_err()
            }
            "source-long" => {
                let mut chunker = Chunker::new(2, PROFILE, |_chunk, _part, _index| Ok(())).unwrap();
                chunker.update(&decode_hex(parameters["sourceHex"].as_str().unwrap())).unwrap_err()
            }
            "unknown-profile" | "wrong-profile-major" => Chunker::new(
                0, parameters["profile"].as_str().unwrap(), |_chunk, _part, _index| Ok(())
            ).err().unwrap(),
            "boundary-shift" => {
                let mut boundaries = fixture.boundaries.clone();
                boundaries[0] += 1;
                let mut offset = 0usize;
                let mut parts = Vec::new();
                let mut chunks = BTreeMap::new();
                for boundary in boundaries {
                    let bytes = &fixture_bytes[offset..boundary as usize];
                    let reference = ObjectRef {
                        kind: ObjectKind::Chunk,
                        digest: object_id(ObjectKind::Chunk, bytes).unwrap(),
                    };
                    chunks.insert(reference.to_string(), bytes.to_vec());
                    parts.push((reference, bytes.len() as u64));
                    offset = boundary as usize;
                }
                let manifest = manifest(fixture_bytes.len() as u64, sha256(&fixture_bytes), &parts);
                verify_manifest(&manifest, &mut MapSource(chunks), &VerifyOptions::default()).unwrap_err()
            }
            "chunk-bit-flip" => {
                let mut chunks = MapSource(fixture_source.0.clone());
                chunks.0.get_mut(&fixture.parts[0].object_id).unwrap()[0] ^= 1;
                verify_manifest(&fixture.manifest.bytes, &mut chunks, &VerifyOptions::default()).unwrap_err()
            }
            "manifest-bit-flip" => {
                let mut bytes = fixture.manifest.bytes.clone();
                bytes[0] ^= 1;
                let mut chunks = MapSource(fixture_source.0.clone());
                verify_manifest(&bytes, &mut chunks, &VerifyOptions::default()).unwrap_err()
            }
            "fragment-over-limit" => {
                let mut chunker = Chunker::new(67_108_865, PROFILE, |_chunk, _part, _index| Ok(())).unwrap();
                let fragment = vec![0; 67_108_865];
                chunker.update(&fragment).unwrap_err()
            }
            "resource-below-scalar-minimum" => Chunker::new_with_resources(
                6_291_456, PROFILE, 1, 0,
                parameters["maxWorkingMemoryBytes"].as_u64().unwrap(),
                |_chunk, _part, _index| Ok(())
            ).err().unwrap(),
            other => panic!("unhandled malformed vector {other}"),
        };
        assert_eq!(error.code(), expected, "{case_id}");
        executed.push(case_id);
    }
    assert_eq!(executed.len(), malformed["cases"].as_array().unwrap().len());
}
