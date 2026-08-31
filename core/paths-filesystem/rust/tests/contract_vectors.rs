use ogvcs_path_contract::{
    case_fold, find_path_collisions, path_collision_keys, PathCandidate, PathError, PathErrorDetail,
};
use serde_json::{json, Value};

fn error_value(error: &PathError) -> Value {
    let mut value = json!({ "accepted": false, "error": error.code().as_str() });
    let detail = match error.detail() {
        None => return value,
        Some(PathErrorDetail::Segment(segment)) => json!({ "segment": segment }),
        Some(PathErrorDetail::Resource(resource)) => json!({ "resource": resource }),
        Some(PathErrorDetail::ResourceSegment { resource, segment }) => {
            json!({ "resource": resource, "segment": segment })
        }
        Some(PathErrorDetail::RuleSegment { rule, segment }) => {
            json!({ "rule": rule, "segment": segment })
        }
        Some(PathErrorDetail::Item(item)) => json!({ "item": item }),
        Some(PathErrorDetail::Collision {
            class,
            first,
            second,
        }) => json!({ "class": class, "first": first, "second": second }),
    };
    value
        .as_object_mut()
        .expect("outcome is an object")
        .insert("detail".to_owned(), detail);
    value
}

#[test]
fn every_unicode_16_fold_vector_matches_the_javascript_authority() {
    let document: Value = serde_json::from_str(include_str!("fold-cases.json")).unwrap();
    for case in document["cases"].as_array().unwrap() {
        assert_eq!(
            case_fold(case["input"].as_str().unwrap()),
            case["expected"].as_str().unwrap(),
            "fold vector {}",
            case["id"]
        );
    }
    assert_eq!(case_fold("Straße"), "strasse");
    assert_eq!(case_fold("Σσς"), "σσσ");
    assert_eq!(case_fold("İ"), "i\u{307}");
    assert_eq!(case_fold("ꭰᎠ"), "ᎠᎠ");
}

#[test]
fn every_path_vector_matches_the_javascript_authority() {
    let document: Value = serde_json::from_str(include_str!("path-cases.json")).unwrap();
    for case in document["cases"].as_array().unwrap() {
        let actual = match path_collision_keys(
            case["input"].as_str().unwrap(),
            case["profile"].as_str().unwrap(),
            case["caseMode"].as_str().unwrap(),
        ) {
            Ok(keys) => {
                let measures = keys.path().measures();
                json!({
                    "accepted": true,
                    "canonical": keys.path().canonical(),
                    "segments": keys.path().segments(),
                    "measures": {
                        "depth": measures.depth,
                        "joinedUtf8Bytes": measures.joined_utf8_bytes,
                        "joinedUtf16Units": measures.joined_utf16_units,
                    },
                    "repositoryKey": keys.repository_key().as_str(),
                    "platformKey": keys.platform_key(),
                })
            }
            Err(error) => error_value(&error),
        };
        assert_eq!(actual, case["expected"], "path vector {}", case["id"]);
    }
}

#[test]
fn every_collision_vector_matches_the_javascript_authority() {
    let document: Value = serde_json::from_str(include_str!("collision-cases.json")).unwrap();
    for case in document["cases"].as_array().unwrap() {
        let ids: Vec<_> = (0..case["paths"].as_array().unwrap().len())
            .map(|index| index.to_string())
            .collect();
        let candidates: Vec<_> = case["paths"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, path)| PathCandidate {
                id: &ids[index],
                path: path.as_str().unwrap(),
            })
            .collect();
        let actual = match find_path_collisions(
            &candidates,
            case["profile"].as_str().unwrap(),
            case["caseMode"].as_str().unwrap(),
            100_000,
        ) {
            Ok(items) => json!({
                "accepted": true,
                "items": items.into_iter().map(|item| json!({
                    "id": item.id,
                    "path": item.path,
                    "repositoryKey": item.repository_key,
                    "platformKey": item.platform_key,
                })).collect::<Vec<_>>(),
            }),
            Err(error) => error_value(&error),
        };
        assert_eq!(actual, case["expected"], "collision vector {}", case["id"]);
    }
}
