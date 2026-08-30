use std::{collections::BTreeMap, env, fs, path::Path};

use ogvcs_chunking_manifest::{
    chunk_bytes, verify_manifest, ChunkError, ChunkSource, ManifestPart, VerifyOptions,
};
use ogvcs_object_model::sha256;
use serde_json::{json, Value};

const GOLDEN: &str = include_str!("../../../../spec/chunking-manifest/v1/vectors/golden.json");

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2)
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
            let mut output = Vec::with_capacity(length); let mut counter = 0u64;
            while output.len() < length {
                let mut preimage = b"OpenGameVCS chunk vector block v1\0".to_vec();
                preimage.extend_from_slice(seed); preimage.push(0); preimage.extend_from_slice(&counter.to_be_bytes());
                let digest = sha256(&preimage); let take = (length - output.len()).min(32);
                output.extend_from_slice(&digest[..take]); counter += 1;
            }
            output
        }
        "insert" => {
            let base = source(&recipe["base"]); let offset = recipe["offset"].as_u64().unwrap() as usize;
            let inserted = decode_hex(recipe["hex"].as_str().unwrap());
            [&base[..offset], &inserted, &base[offset..]].concat()
        }
        kind => panic!("unknown recipe {kind}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Source(BTreeMap<String, Vec<u8>>);

impl ChunkSource for Source {
    fn stream_chunk(
        &mut self,
        part: &ManifestPart,
        _occurrence: usize,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), ChunkError>,
    ) -> Result<(), ChunkError> {
        consume(self.0.get(&part.reference.to_string()).ok_or(ChunkError::SourceMissing)?)
    }
}

fn main() {
    let output = env::args().nth(1).expect("usage: bounded_report <output.json>");
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    let mut cases = Vec::new();
    for vector in golden["cases"].as_array().unwrap() {
        let bytes = source(&vector["recipe"]);
        let mut delivered = Vec::new();
        let generated = chunk_bytes(&bytes, |chunk, _part, _index| {
            delivered.push(chunk.to_vec()); Ok(())
        }).unwrap();
        let chunks = generated.parts.iter().zip(delivered)
            .map(|(part, bytes)| (part.object_id.clone(), bytes)).collect();
        let verified = verify_manifest(&generated.manifest.bytes, &mut Source(chunks), &VerifyOptions::default()).unwrap();
        cases.push(json!({
            "boundaries": generated.boundaries,
            "caseId": vector["caseId"],
            "class": generated.class,
            "logicalLength": generated.logical_length,
            "manifestObjectId": generated.manifest.object_id,
            "partCount": verified.part_count,
            "repeatedBytes": verified.repeated_bytes.to_string(),
            "uniqueBytes": verified.unique_bytes.to_string(),
            "wholeFileSha256": hex(&generated.whole_file_digest),
        }));
    }
    let report = json!({
        "cases": cases,
        "profile": golden["profile"],
        "schemaVersion": "ogvcs.chunking/bounded-conformance-report/v1",
    });
    if let Some(parent) = Path::new(&output).parent() { fs::create_dir_all(parent).unwrap(); }
    fs::write(output, format!("{}\n", serde_json::to_string_pretty(&report).unwrap())).unwrap();
}
