#![allow(dead_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use ogvcs_history_diff_kernel::{Generation, ImmutableObjectSource, ObjectRead, ObjectReadOutcome};
use ogvcs_object_model::{
    encode_canonical, object_id, Cbor, FileId, ObjectKind, ObjectRef, ProfileRef, TypedDigest,
};

pub const GENERATION: Generation = [0x71; 32];

pub fn file_id(value: u128) -> FileId {
    FileId::new(value.to_be_bytes()).unwrap()
}

pub fn reference(kind: ObjectKind, value: u8) -> ObjectRef {
    ObjectRef {
        kind,
        digest: [value; 32],
    }
}

fn profile(value: &str) -> Cbor {
    ProfileRef::from_str(value).unwrap().to_cbor()
}

fn common(kind: ObjectKind) -> Vec<(Cbor, Cbor)> {
    vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(u64::from(kind.code()))),
        (Cbor::UInt(2), Cbor::Array(vec![])),
    ]
}

#[derive(Clone, Debug)]
pub struct EntrySpec {
    pub name: String,
    pub entry_kind: u8,
    pub file_id: FileId,
    pub mode: u8,
    pub target: ObjectRef,
    pub logical_bytes: u64,
    pub content_policy: &'static str,
}

impl EntrySpec {
    pub fn directory(name: &str, file_id: FileId, target: ObjectRef) -> Self {
        Self {
            name: name.to_owned(),
            entry_kind: 1,
            file_id,
            mode: 1,
            target,
            logical_bytes: 0,
            content_policy: "content-policy.test/opaque@1",
        }
    }

    pub fn file(name: &str, file_id: FileId, target: ObjectRef, logical_bytes: u64) -> Self {
        Self {
            name: name.to_owned(),
            entry_kind: 2,
            file_id,
            mode: 2,
            target,
            logical_bytes,
            content_policy: "content-policy.test/opaque@1",
        }
    }

    pub fn typed(
        name: &str,
        file_id: FileId,
        target: ObjectRef,
        logical_bytes: u64,
        entry_kind: u8,
    ) -> Self {
        Self {
            name: name.to_owned(),
            entry_kind,
            file_id,
            mode: entry_kind,
            target,
            logical_bytes,
            content_policy: "content-policy.test/opaque@1",
        }
    }

    pub fn with_policy(mut self, value: &'static str) -> Self {
        self.content_policy = value;
        self
    }
}

#[derive(Clone, Debug)]
pub struct Store {
    pub objects: BTreeMap<ObjectRef, Vec<u8>>,
    pub descriptor: ObjectRef,
}

impl Store {
    pub fn new() -> Self {
        Self::with_repository_tag(0x44)
    }

    pub fn with_repository_tag(repository_tag: u8) -> Self {
        Self::with_repository_profiles(
            repository_tag,
            &[
                "content-policy.test/alternate@1",
                "content-policy.test/opaque@1",
            ],
            &["chunking.test/external-boundaries@1"],
        )
    }

    pub fn with_repository_profiles(
        repository_tag: u8,
        content_profiles: &[&str],
        chunk_profiles: &[&str],
    ) -> Self {
        let mut content_profiles = content_profiles
            .iter()
            .map(|value| profile(value))
            .collect::<Vec<_>>();
        content_profiles.sort_by_key(|value| encode_canonical(value).unwrap());
        let mut chunk_profiles = chunk_profiles
            .iter()
            .map(|value| profile(value))
            .collect::<Vec<_>>();
        chunk_profiles.sort_by_key(|value| encode_canonical(value).unwrap());
        let mut store = Self {
            objects: BTreeMap::new(),
            descriptor: reference(ObjectKind::RepositoryDescriptor, 0),
        };
        let mut fields = common(ObjectKind::RepositoryDescriptor);
        fields.extend([
            (Cbor::UInt(16), Cbor::Bytes(vec![repository_tag; 16])),
            (Cbor::UInt(17), profile("path.opengamevcs/portable@1")),
            (Cbor::UInt(18), Cbor::Array(content_profiles)),
            (Cbor::UInt(19), Cbor::Array(vec![])),
        ]);
        if !chunk_profiles.is_empty() {
            fields.push((Cbor::UInt(20), Cbor::Array(chunk_profiles)));
        }
        store.descriptor = store.put(ObjectKind::RepositoryDescriptor, Cbor::Map(fields));
        store
    }

    pub fn put(&mut self, kind: ObjectKind, value: Cbor) -> ObjectRef {
        let payload = encode_canonical(&value).unwrap();
        let reference = ObjectRef {
            kind,
            digest: object_id(kind, &payload).unwrap(),
        };
        self.objects
            .insert(reference, payload.into_boxed_slice().into_vec());
        reference
    }

    pub fn manifest(&mut self, tag: u8, logical_bytes: u64) -> ObjectRef {
        let mut fields = common(ObjectKind::ContentManifest);
        let parts = if logical_bytes == 0 {
            vec![]
        } else {
            vec![Cbor::Map(vec![
                (
                    Cbor::UInt(0),
                    reference(ObjectKind::Chunk, tag.wrapping_add(1)).to_cbor(),
                ),
                (Cbor::UInt(1), Cbor::UInt(logical_bytes)),
            ])]
        };
        fields.extend([
            (Cbor::UInt(16), Cbor::UInt(logical_bytes)),
            (Cbor::UInt(17), TypedDigest::sha256([tag; 32]).to_cbor()),
            (
                Cbor::UInt(18),
                profile("chunking.test/external-boundaries@1"),
            ),
            (Cbor::UInt(19), Cbor::Array(parts)),
        ]);
        self.put(ObjectKind::ContentManifest, Cbor::Map(fields))
    }

    pub fn tree(&mut self, mut entries: Vec<EntrySpec>) -> ObjectRef {
        entries.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        let entries = entries
            .into_iter()
            .map(|entry| {
                Cbor::Map(vec![
                    (Cbor::UInt(0), Cbor::Text(entry.name)),
                    (Cbor::UInt(1), Cbor::UInt(u64::from(entry.entry_kind))),
                    (Cbor::UInt(2), entry.file_id.to_cbor()),
                    (Cbor::UInt(3), Cbor::UInt(u64::from(entry.mode))),
                    (Cbor::UInt(4), entry.target.to_cbor()),
                    (Cbor::UInt(5), Cbor::UInt(entry.logical_bytes)),
                    (Cbor::UInt(6), profile(entry.content_policy)),
                ])
            })
            .collect();
        let mut fields = common(ObjectKind::Tree);
        fields.extend([
            (Cbor::UInt(16), self.descriptor.to_cbor()),
            (Cbor::UInt(17), Cbor::Array(entries)),
        ]);
        self.put(ObjectKind::Tree, Cbor::Map(fields))
    }

    pub fn snapshot(
        &mut self,
        tag: u8,
        parents: Vec<ObjectRef>,
        root_tree: ObjectRef,
    ) -> ObjectRef {
        let identity = Cbor::Map(vec![
            (Cbor::UInt(0), profile("identity.test/opaque@1")),
            (Cbor::UInt(1), Cbor::Bytes(vec![tag.max(1)])),
        ]);
        let policy = Cbor::Map(vec![
            (Cbor::UInt(0), profile("policy.test/allow@1")),
            (Cbor::UInt(1), Cbor::UInt(u64::from(tag))),
            (Cbor::UInt(2), Cbor::UInt(1)),
            (
                Cbor::UInt(3),
                TypedDigest::sha256([tag.wrapping_add(1); 32]).to_cbor(),
            ),
        ]);
        let mut fields = common(ObjectKind::Snapshot);
        fields.extend([
            (Cbor::UInt(16), self.descriptor.to_cbor()),
            (
                Cbor::UInt(17),
                Cbor::Array(parents.into_iter().map(ObjectRef::to_cbor).collect()),
            ),
            (Cbor::UInt(18), root_tree.to_cbor()),
            (
                Cbor::UInt(19),
                reference(ObjectKind::ChangeSet, tag.wrapping_add(11)).to_cbor(),
            ),
            (Cbor::UInt(21), identity.clone()),
            (Cbor::UInt(22), identity),
            (Cbor::UInt(23), Cbor::UInt(u64::from(tag))),
            (Cbor::UInt(24), Cbor::UInt(u64::from(tag))),
            (Cbor::UInt(25), Cbor::Text(format!("snapshot-{tag}"))),
            (Cbor::UInt(26), policy),
        ]);
        self.put(ObjectKind::Snapshot, Cbor::Map(fields))
    }

    pub fn source(&self) -> MemorySource {
        MemorySource::new(self.objects.clone())
    }
}

#[derive(Clone, Debug)]
pub struct MemorySource {
    pub objects: BTreeMap<ObjectRef, Vec<u8>>,
    pub generation: Generation,
    pub object_generation: Option<Generation>,
    pub generation_calls: usize,
    pub reads: usize,
    pub ambiguous: BTreeSet<ObjectRef>,
    pub byte_limited: BTreeSet<ObjectRef>,
    pub flip_generation_on_call: Option<usize>,
    pub spare_capacity: BTreeSet<ObjectRef>,
    pub fail_generation: bool,
}

impl MemorySource {
    pub fn new(objects: BTreeMap<ObjectRef, Vec<u8>>) -> Self {
        Self {
            objects,
            generation: GENERATION,
            object_generation: None,
            generation_calls: 0,
            reads: 0,
            ambiguous: BTreeSet::new(),
            byte_limited: BTreeSet::new(),
            flip_generation_on_call: None,
            spare_capacity: BTreeSet::new(),
            fail_generation: false,
        }
    }
}

impl ImmutableObjectSource for MemorySource {
    type Error = ();

    fn generation(&mut self) -> Result<Generation, Self::Error> {
        self.generation_calls += 1;
        if self.fail_generation {
            return Err(());
        }
        if self
            .flip_generation_on_call
            .is_some_and(|call| self.generation_calls >= call)
        {
            Ok([0x72; 32])
        } else {
            Ok(self.generation)
        }
    }

    fn read_object(
        &mut self,
        reference: &ObjectRef,
        maximum_bytes: u64,
    ) -> Result<ObjectRead, Self::Error> {
        self.reads += 1;
        let outcome = if self.ambiguous.contains(reference) {
            ObjectReadOutcome::Ambiguous
        } else if self.byte_limited.contains(reference) {
            ObjectReadOutcome::ByteLimit {
                declared_bytes: maximum_bytes.saturating_add(1),
            }
        } else if let Some(value) = self.objects.get(reference) {
            let mut bytes = value.clone().into_boxed_slice().into_vec();
            if self.spare_capacity.contains(reference) {
                bytes.reserve(
                    usize::try_from(maximum_bytes)
                        .unwrap_or(usize::MAX)
                        .min(1024),
                );
            }
            ObjectReadOutcome::Found(bytes)
        } else {
            ObjectReadOutcome::Missing
        };
        Ok(ObjectRead {
            generation: self.object_generation.unwrap_or(self.generation),
            outcome,
        })
    }
}
