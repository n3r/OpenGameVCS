use std::{collections::BTreeMap, env, fs, path::Path};

use ogvcs_chunking_manifest::{
    chunk_bytes, chunk_cache_key, gear_table_sha256, verify_manifest, ChunkError, ChunkSource,
    Chunker, ManifestPart, OperationControl, VerifyOptions, CACHE_KEY_DOMAIN, CACHE_KEY_VERSION,
    CHUNK_COUNT_MAXIMUM, LOGICAL_MAXIMUM, MAXIMUM, MINIMUM, PROFILE, SCALAR_WORKING_MINIMUM,
    SMALL_MAXIMUM, TARGET, WORKING_MAXIMUM,
};
use ogvcs_object_model::{sha256, ObjectKind, ObjectRef};
use serde_json::{json, Value};

const GOLDEN: &str = include_str!("../../../../spec/chunking-manifest/v1/vectors/golden.json");

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn source(recipe: &Value) -> Vec<u8> {
    match recipe["kind"].as_str().unwrap() {
        "literal" => decode_hex(recipe["hex"].as_str().unwrap()),
        "repeat" => vec![
            recipe["byte"].as_u64().unwrap() as u8;
            recipe["length"].as_u64().unwrap() as usize
        ],
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

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            use std::fmt::Write;
            write!(&mut text, "{byte:02x}").expect("string write");
            text
        })
}

struct Source(BTreeMap<String, Vec<u8>>);

impl ChunkSource for Source {
    fn stream_chunk(
        &mut self,
        part: &ManifestPart,
        _occurrence: usize,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), ChunkError>,
    ) -> Result<(), ChunkError> {
        consume(
            self.0
                .get(&part.reference.to_string())
                .ok_or(ChunkError::SourceMissing)?,
        )
    }
}

fn main() {
    let output = env::args()
        .nth(1)
        .expect("usage: bounded_report <output.json>");
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    let mut cases = Vec::new();
    for vector in golden["cases"].as_array().unwrap() {
        let bytes = source(&vector["recipe"]);
        let mut delivered = Vec::new();
        let generated = chunk_bytes(&bytes, |chunk, _part, _index| {
            delivered.push(chunk.to_vec());
            Ok(())
        })
        .unwrap();
        let chunks = generated
            .parts
            .iter()
            .zip(delivered)
            .map(|(part, bytes)| (part.object_id.clone(), bytes))
            .collect();
        let verified = verify_manifest(
            &generated.manifest.bytes,
            &mut Source(chunks),
            &VerifyOptions::default(),
        )
        .unwrap();
        let chunk_report = generated
            .parts
            .iter()
            .map(|part| {
                let reference = ObjectRef {
                    kind: ObjectKind::Chunk,
                    digest: part.digest,
                };
                json!({
                    "cacheKey": chunk_cache_key(&reference).unwrap(),
                    "length": part.length,
                    "objectId": part.object_id,
                })
            })
            .collect::<Vec<_>>();
        cases.push(json!({
            "boundaries": generated.boundaries,
            "caseId": vector["caseId"],
            "class": generated.class,
            "chunks": chunk_report,
            "logicalLength": generated.logical_length,
            "manifestHex": hex(&generated.manifest.bytes),
            "manifestObjectId": generated.manifest.object_id,
            "partCount": verified.part_count,
            "providerReads": verified.provider_reads,
            "repeatedBytes": verified.repeated_bytes.to_string(),
            "uniqueBytes": verified.unique_bytes.to_string(),
            "wholeFileSha256": hex(&generated.whole_file_digest),
        }));
    }
    let below_scalar = Chunker::new_with_resources(
        0,
        PROFILE,
        1,
        0,
        SCALAR_WORKING_MINIMUM - 1,
        |_chunk, _part, _index| Ok(()),
    )
    .err()
    .unwrap()
    .code();
    let cancellation = OperationControl::default();
    cancellation.cancel();
    let cancelled =
        Chunker::new_controlled(0, PROFILE, cancellation, |_chunk, _part, _index| Ok(()))
            .err()
            .unwrap()
            .code();
    let unsupported = Chunker::new_with_resources(
        0,
        PROFILE,
        2,
        0,
        SCALAR_WORKING_MINIMUM,
        |_chunk, _part, _index| Ok(()),
    )
    .err()
    .unwrap()
    .code();
    let report = json!({
        "cacheKey": {
            "domain": std::str::from_utf8(CACHE_KEY_DOMAIN).unwrap(),
            "version": CACHE_KEY_VERSION,
        },
        "cases": cases,
        "errorCodes": ChunkError::ALL.iter().map(|error| error.code()).collect::<Vec<_>>(),
        "limits": {
            "chunkCountMaximum": CHUNK_COUNT_MAXIMUM,
            "logicalMaximum": LOGICAL_MAXIMUM,
            "maximum": MAXIMUM,
            "minimum": MINIMUM,
            "scalarWorkingMinimum": SCALAR_WORKING_MINIMUM,
            "smallMaximum": SMALL_MAXIMUM,
            "target": TARGET,
            "workingMaximum": WORKING_MAXIMUM,
        },
        "profile": PROFILE,
        "resourceOutcomes": {
            "belowScalarMinimum": below_scalar,
            "cancellation": cancelled,
            "unsupportedParallelism": unsupported,
        },
        "schemaVersion": "ogvcs.chunking/bounded-conformance-report/v1",
        "tableSha256": hex(&gear_table_sha256()),
    });
    if let Some(parent) = Path::new(&output).parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(
        output,
        format!("{}\n", serde_json::to_string_pretty(&report).unwrap()),
    )
    .unwrap();
}
