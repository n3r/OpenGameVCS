use ogvcs_chunking_manifest::{chunk_bytes, gear_table_sha256, ChunkError, Chunker, PROFILE};
use ogvcs_object_model::{object_id, sha256, ObjectKind};
use serde_json::Value;

const GOLDEN: &str = include_str!("../../../../spec/chunking-manifest/v1/vectors/golden.json");
const FRAGMENTATION: &str = include_str!("../../../../spec/chunking-manifest/v1/vectors/fragmentation.json");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
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

fn assert_result(vector: &Value, bytes: &[u8], pattern: Option<&[usize]>) {
    let result = if let Some(pattern) = pattern {
        let mut chunker = Chunker::new(bytes.len() as u64, PROFILE, |_bytes, _part, _index| Ok(())).unwrap();
        let mut offset = 0; let mut cursor = 0;
        while offset < bytes.len() {
            let take = pattern[cursor % pattern.len()].min(bytes.len() - offset);
            chunker.update(&bytes[offset..offset + take]).unwrap(); offset += take; cursor += 1;
        }
        chunker.finish().unwrap()
    } else {
        chunk_bytes(bytes, |_bytes, _part, _index| Ok(())).unwrap()
    };
    let expected = &vector["expected"];
    let boundaries: Vec<u64> = expected["boundaries"].as_array().unwrap().iter().map(|item| item.as_u64().unwrap()).collect();
    assert_eq!(result.boundaries, boundaries, "{}", vector["caseId"]);
    assert_eq!(result.class, expected["class"].as_str().unwrap());
    assert_eq!(result.logical_length, expected["logicalLength"].as_u64().unwrap());
    assert_eq!(hex(&result.whole_file_digest), expected["wholeFileSha256"].as_str().unwrap());
    assert_eq!(hex(&result.manifest.bytes), expected["manifestHex"].as_str().unwrap());
    assert_eq!(result.manifest.object_id, expected["manifestObjectId"].as_str().unwrap());
    for (actual, wanted) in result.parts.iter().zip(expected["chunks"].as_array().unwrap()) {
        assert_eq!(actual.length, wanted["length"].as_u64().unwrap());
        assert_eq!(actual.object_id, wanted["objectId"].as_str().unwrap());
    }
    let expected_digest: [u8; 32] = decode_hex(result.manifest.object_id.rsplit(':').next().unwrap()).try_into().unwrap();
    assert_eq!(object_id(ObjectKind::ContentManifest, &result.manifest.bytes).unwrap(), expected_digest);
}

#[test]
fn public_object_model_codec_matches_every_independent_golden_manifest() {
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    assert_eq!(hex(&gear_table_sha256()), golden["tableSha256"].as_str().unwrap());
    for vector in golden["cases"].as_array().unwrap() {
        let bytes = source(&vector["recipe"]);
        assert_result(vector, &bytes, None);
    }
}

#[test]
fn update_fragmentation_does_not_change_boundaries_or_manifest() {
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    let fragmentation: Value = serde_json::from_str(FRAGMENTATION).unwrap();
    for fixture in fragmentation["cases"].as_array().unwrap() {
        let id = fixture["caseId"].as_str().unwrap();
        let vector = golden["cases"].as_array().unwrap().iter().find(|item| item["caseId"] == id).unwrap();
        let bytes = source(&vector["recipe"]);
        for pattern in fixture["fragmentPatterns"].as_array().unwrap() {
            let sizes: Vec<usize> = pattern.as_array().unwrap().iter().map(|item| item.as_u64().unwrap() as usize).collect();
            assert_result(vector, &bytes, Some(&sizes));
        }
    }
}

#[test]
fn source_and_sink_failures_are_terminal() {
    assert!(matches!(Chunker::new(0, "chunking.opengamevcs/unknown@1", |_bytes, _part, _index| Ok(())), Err(ChunkError::ProfileUnsupported)));
    assert!(matches!(Chunker::new_with_resources(0, PROFILE, 1, 0, 2_097_151, |_bytes, _part, _index| Ok(())), Err(ChunkError::ResourceExhausted)));
    assert!(matches!(Chunker::new_with_resources(0, PROFILE, 2, 0, 4_259_840, |_bytes, _part, _index| Ok(())), Err(ChunkError::ResourceUnsupported)));
    let mut oversized = Chunker::new(67_108_865, PROFILE, |_bytes, _part, _index| Ok(())).unwrap();
    let oversized_fragment = vec![0; 67_108_865];
    assert_eq!(oversized.update(&oversized_fragment).unwrap_err(), ChunkError::FragmentInvalid);
    assert_eq!(oversized.update(&[]).unwrap_err(), ChunkError::SessionFailed);
    let mut short = Chunker::new(2, PROFILE, |_bytes, _part, _index| Ok(())).unwrap();
    short.update(&[1]).unwrap(); assert_eq!(short.finish().unwrap_err(), ChunkError::SourceTooShort);

    let mut deliveries = 0;
    let mut failed = Chunker::new(2_097_152, PROFILE, |_bytes, _part, _index| { deliveries += 1; Err(ChunkError::SinkFailed) }).unwrap();
    let failed_fragment = vec![0; 2_097_152];
    assert_eq!(failed.update(&failed_fragment).unwrap_err(), ChunkError::SinkFailed);
    assert_eq!(failed.update(&[]).unwrap_err(), ChunkError::SessionFailed);
    drop(failed);
    assert_eq!(deliveries, 1);
}
