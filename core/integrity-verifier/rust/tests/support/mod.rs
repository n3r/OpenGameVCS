#![allow(dead_code)]

use std::{collections::BTreeMap, fmt::Write as _, fs, path::PathBuf};

use ogvcs_chunking_manifest::chunk_bytes;
use ogvcs_integrity_verifier::{
    resume_verification, start_verification, Generation, ImmutableObjectSource, ObjectRead,
    ObjectReadOutcome, VerificationControl, VerificationLimits, VerificationPage,
    VerificationReport, VerificationStatus,
};
use ogvcs_object_model::{
    decode_canonical, encode_canonical, opaque_object_digest, Cbor, Limits, ObjectKind, ObjectRef,
};

pub const GENERATION: Generation = [0x47; 32];
pub const OTHER_GENERATION: Generation = [0x48; 32];
pub const BACKEND: [u8; 32] = [0x42; 32];
pub const CONTENT: &[u8] = b"OpenGameVCS integrity verifier golden content\n";

#[derive(Clone, Debug)]
pub enum Behavior {
    Found {
        bytes: Vec<u8>,
        declared_bytes: u64,
    },
    FoundWithCapacity {
        bytes: Vec<u8>,
        declared_bytes: u64,
        capacity: usize,
    },
    Missing,
    SourceAmbiguous,
    BackendAmbiguous,
    Failure,
}

#[derive(Clone, Debug)]
pub struct FixtureSource {
    pub generation: Generation,
    pub read_generation: Generation,
    pub generation_failure: bool,
    pub objects: BTreeMap<ObjectRef, Behavior>,
}

impl ImmutableObjectSource for FixtureSource {
    type Error = ();

    fn generation(&mut self) -> Result<Generation, Self::Error> {
        if self.generation_failure {
            Err(())
        } else {
            Ok(self.generation)
        }
    }

    fn read_object(
        &mut self,
        reference: &ObjectRef,
        maximum_bytes: u64,
    ) -> Result<ObjectRead, Self::Error> {
        let outcome = match self.objects.get(reference) {
            Some(Behavior::Found {
                bytes,
                declared_bytes,
            }) if bytes.len() as u64 > maximum_bytes => ObjectReadOutcome::ByteLimit {
                declared_bytes: *declared_bytes,
            },
            Some(Behavior::FoundWithCapacity {
                bytes,
                declared_bytes,
                ..
            }) if bytes.len() as u64 > maximum_bytes => ObjectReadOutcome::ByteLimit {
                declared_bytes: *declared_bytes,
            },
            Some(Behavior::Found {
                bytes,
                declared_bytes,
            }) => ObjectReadOutcome::Found {
                backend: BACKEND,
                declared_bytes: *declared_bytes,
                bytes: bytes.clone(),
            },
            Some(Behavior::FoundWithCapacity {
                bytes,
                declared_bytes,
                capacity,
            }) => {
                let mut returned = Vec::with_capacity(*capacity);
                returned.extend_from_slice(bytes);
                ObjectReadOutcome::Found {
                    backend: BACKEND,
                    declared_bytes: *declared_bytes,
                    bytes: returned,
                }
            }
            Some(Behavior::Missing) | None => ObjectReadOutcome::Missing,
            Some(Behavior::SourceAmbiguous) => ObjectReadOutcome::SourceAmbiguous,
            Some(Behavior::BackendAmbiguous) => ObjectReadOutcome::BackendAmbiguous,
            Some(Behavior::Failure) => return Err(()),
        };
        Ok(ObjectRead {
            generation: self.read_generation,
            outcome,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Graph {
    pub root: ObjectRef,
    pub snapshot: ObjectRef,
    pub tree: ObjectRef,
    pub child_tree: ObjectRef,
    pub manifest: ObjectRef,
    pub chunks: Vec<ObjectRef>,
    pub source: FixtureSource,
}

impl Graph {
    pub fn golden() -> Self {
        Self::with_content(CONTENT)
    }

    pub fn with_content(content: &[u8]) -> Self {
        let fixture_tree = read_cbor("objects/03-tree.cbor");

        let mut child_value = decode_canonical(&fixture_tree, Limits::METADATA).unwrap();
        *field_mut(&mut child_value, 17) = Cbor::Array(Vec::new());
        let child_bytes = encode_canonical(&child_value).unwrap();
        let child_tree = reference(ObjectKind::Tree, &child_bytes);

        let mut chunks = BTreeMap::<ObjectRef, Vec<u8>>::new();
        let chunked = chunk_bytes(content, |bytes, _part, _ordinal| {
            let reference = reference(ObjectKind::Chunk, bytes);
            chunks.insert(reference, bytes.to_vec());
            Ok(())
        })
        .unwrap();
        let manifest_bytes = chunked.manifest.bytes;
        let manifest = reference(ObjectKind::ContentManifest, &manifest_bytes);

        let mut tree_value = decode_canonical(&fixture_tree, Limits::METADATA).unwrap();
        let entries = array_mut(field_mut(&mut tree_value, 17));
        for entry in entries {
            let kind = as_u64(field(entry, 1));
            if kind == 1 {
                *field_mut(entry, 4) = child_tree.to_cbor();
                *field_mut(entry, 5) = Cbor::UInt(0);
            } else {
                *field_mut(entry, 4) = manifest.to_cbor();
                *field_mut(entry, 5) = Cbor::UInt(content.len() as u64);
            }
        }
        let tree_bytes = encode_canonical(&tree_value).unwrap();
        let tree = reference(ObjectKind::Tree, &tree_bytes);

        let fixture_snapshot = read_cbor("objects/07-snapshot.cbor");
        let mut snapshot_value = decode_canonical(&fixture_snapshot, Limits::METADATA).unwrap();
        *field_mut(&mut snapshot_value, 18) = tree.to_cbor();
        let snapshot_bytes = encode_canonical(&snapshot_value).unwrap();
        let snapshot = reference(ObjectKind::Snapshot, &snapshot_bytes);

        let mut objects = BTreeMap::new();
        insert(&mut objects, snapshot, snapshot_bytes);
        insert(&mut objects, tree, tree_bytes);
        insert(&mut objects, child_tree, child_bytes);
        insert(&mut objects, manifest, manifest_bytes);
        let chunk_references = chunks.keys().copied().collect::<Vec<_>>();
        for (reference, bytes) in chunks {
            insert(&mut objects, reference, bytes);
        }

        Self {
            root: snapshot,
            snapshot,
            tree,
            child_tree,
            manifest,
            chunks: chunk_references,
            source: FixtureSource {
                generation: GENERATION,
                read_generation: GENERATION,
                generation_failure: false,
                objects,
            },
        }
    }

    pub fn bytes(&self, reference: ObjectRef) -> Vec<u8> {
        match self.source.objects.get(&reference).unwrap() {
            Behavior::Found { bytes, .. } | Behavior::FoundWithCapacity { bytes, .. } => {
                bytes.clone()
            }
            _ => panic!("object is not present"),
        }
    }

    pub fn set_behavior(&mut self, reference: ObjectRef, behavior: Behavior) {
        self.source.objects.insert(reference, behavior);
    }

    pub fn replace_snapshot(&mut self, value: Cbor) {
        let bytes = encode_canonical(&value).unwrap();
        let reference = reference(ObjectKind::Snapshot, &bytes);
        self.source.objects.remove(&self.snapshot);
        insert(&mut self.source.objects, reference, bytes);
        self.snapshot = reference;
        self.root = reference;
    }

    pub fn replace_tree(&mut self, value: Cbor) {
        let bytes = encode_canonical(&value).unwrap();
        let reference = reference(ObjectKind::Tree, &bytes);
        self.source.objects.remove(&self.tree);
        insert(&mut self.source.objects, reference, bytes);
        self.tree = reference;
        let mut snapshot = decode_canonical(&self.bytes(self.snapshot), Limits::METADATA).unwrap();
        *field_mut(&mut snapshot, 18) = reference.to_cbor();
        self.replace_snapshot(snapshot);
    }

    pub fn replace_manifest(&mut self, value: Cbor) {
        let bytes = encode_canonical(&value).unwrap();
        let reference = reference(ObjectKind::ContentManifest, &bytes);
        self.source.objects.remove(&self.manifest);
        insert(&mut self.source.objects, reference, bytes);
        self.manifest = reference;
        let mut tree = decode_canonical(&self.bytes(self.tree), Limits::METADATA).unwrap();
        for entry in array_mut(field_mut(&mut tree, 17)) {
            if as_u64(field(entry, 1)) != 1 {
                *field_mut(entry, 4) = reference.to_cbor();
            }
        }
        self.replace_tree(tree);
    }
}

pub fn complete(graph: &mut Graph) -> VerificationReport {
    complete_with_limits(graph, VerificationLimits::default())
}

pub fn complete_with_limits(graph: &mut Graph, limits: VerificationLimits) -> VerificationReport {
    let mut page = start_verification(
        graph.root,
        &mut graph.source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    while page.status == VerificationStatus::PageBoundary {
        page = resume_verification(
            page.cursor,
            &mut graph.source,
            &limits,
            &VerificationControl::default(),
        )
        .unwrap();
    }
    assert_eq!(page.status, VerificationStatus::Complete);
    page.report.unwrap()
}

pub fn start(graph: &mut Graph, limits: &VerificationLimits) -> VerificationPage {
    start_verification(
        graph.root,
        &mut graph.source,
        limits,
        &VerificationControl::default(),
    )
    .unwrap()
}

pub fn read_value(graph: &Graph, reference: ObjectRef) -> Cbor {
    decode_canonical(&graph.bytes(reference), Limits::METADATA).unwrap()
}

pub fn field(value: &Cbor, key: u64) -> &Cbor {
    let Cbor::Map(entries) = value else {
        panic!("expected map")
    };
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate == &Cbor::UInt(key)).then_some(value))
        .unwrap()
}

pub fn field_mut(value: &mut Cbor, key: u64) -> &mut Cbor {
    let Cbor::Map(entries) = value else {
        panic!("expected map")
    };
    entries
        .iter_mut()
        .find_map(|(candidate, value)| (candidate == &Cbor::UInt(key)).then_some(value))
        .unwrap()
}

pub fn remove_field(value: &mut Cbor, key: u64) {
    let Cbor::Map(entries) = value else {
        panic!("expected map")
    };
    entries.retain(|(candidate, _)| candidate != &Cbor::UInt(key));
}

pub fn array_mut(value: &mut Cbor) -> &mut Vec<Cbor> {
    let Cbor::Array(values) = value else {
        panic!("expected array")
    };
    values
}

pub fn as_u64(value: &Cbor) -> u64 {
    let Cbor::UInt(value) = value else {
        panic!("expected uint")
    };
    *value
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut encoded, byte| {
            write!(&mut encoded, "{byte:02x}").expect("writing to String");
            encoded
        },
    )
}

fn insert(objects: &mut BTreeMap<ObjectRef, Behavior>, reference: ObjectRef, bytes: Vec<u8>) {
    objects.insert(
        reference,
        Behavior::Found {
            declared_bytes: bytes.len() as u64,
            bytes,
        },
    );
}

fn reference(kind: ObjectKind, bytes: &[u8]) -> ObjectRef {
    ObjectRef {
        kind,
        digest: opaque_object_digest(kind.code(), bytes).unwrap(),
    }
}

fn read_cbor(relative: &str) -> Vec<u8> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::read(
        root.join("../../../spec/repository-format/v1/vectors")
            .join(relative),
    )
    .unwrap()
}
