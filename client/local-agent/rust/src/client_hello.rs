use std::cell::Cell;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;

use crate::commitment::{CommitmentBuilder, Digest32};
use crate::model::{
    check_cancel, public_protocol_manifest_commitment, validate_raw_frame, CancellationPoint,
    CancellationProbe, Capability, Error, ErrorCode, NegotiationOffer, ProtocolVersion, RawFrame,
    Result, CAPABILITY_ITEMS_MAXIMUM, VERSION_ITEMS_MAXIMUM,
};

/// Private candidate schema identifier for the sole decoded frame in this tranche.
///
/// This is not a published protocol assignment or a compatibility promise.
pub const CLIENT_HELLO_SCHEMA_V1: &str = "ogvcs.local-agent/client-hello/v1";
pub const CLIENT_HELLO_BYTES_MAXIMUM: usize = 16_384;

const CLIENT_HELLO_FIELDS: &[&str] = &[
    "schemaVersion",
    "publicProtocolManifestSha256",
    "versions",
    "requiredCapabilities",
    "optionalCapabilities",
    "clientChallengeHex",
];
const VERSION_FIELDS: &[&str] = &["major", "minor"];

#[derive(Clone, Eq, PartialEq)]
pub struct DecodedClientHello {
    offer: NegotiationOffer,
    client_challenge: [u8; 32],
    raw_frame_commitment: Digest32,
    semantic_commitment: Digest32,
}

impl fmt::Debug for DecodedClientHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedClientHello")
            .field("offer", &self.offer)
            .field("client_challenge", &"<redacted>")
            .field("raw_frame_commitment", &self.raw_frame_commitment)
            .field("semantic_commitment", &self.semantic_commitment)
            .finish()
    }
}

impl DecodedClientHello {
    pub const fn offer(&self) -> &NegotiationOffer {
        &self.offer
    }

    pub const fn raw_frame_commitment(&self) -> Digest32 {
        self.raw_frame_commitment
    }

    pub const fn semantic_commitment(&self) -> Digest32 {
        self.semantic_commitment
    }

    pub(crate) const fn client_challenge(&self) -> [u8; 32] {
        self.client_challenge
    }
}

#[derive(Default)]
struct DecodeContext {
    code: Cell<Option<ErrorCode>>,
}

impl DecodeContext {
    fn fail<E: de::Error>(&self, code: ErrorCode) -> E {
        self.code.set(Some(code));
        E::custom("bounded client hello rejected")
    }

    fn error(&self) -> Error {
        Error::new(self.code.get().unwrap_or(ErrorCode::FrameInvalid))
    }
}

#[derive(Clone, Copy)]
enum ClientHelloField {
    SchemaVersion,
    PublicProtocolManifest,
    Versions,
    RequiredCapabilities,
    OptionalCapabilities,
    ClientChallenge,
}

impl<'de> Deserialize<'de> for ClientHelloField {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldVisitor;

        impl Visitor<'_> for FieldVisitor {
            type Value = ClientHelloField;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a closed client hello field")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "schemaVersion" => Ok(ClientHelloField::SchemaVersion),
                    "publicProtocolManifestSha256" => Ok(ClientHelloField::PublicProtocolManifest),
                    "versions" => Ok(ClientHelloField::Versions),
                    "requiredCapabilities" => Ok(ClientHelloField::RequiredCapabilities),
                    "optionalCapabilities" => Ok(ClientHelloField::OptionalCapabilities),
                    "clientChallengeHex" => Ok(ClientHelloField::ClientChallenge),
                    _ => Err(E::unknown_field(value, CLIENT_HELLO_FIELDS)),
                }
            }
        }

        deserializer.deserialize_identifier(FieldVisitor)
    }
}

#[derive(Clone, Copy)]
enum VersionField {
    Major,
    Minor,
}

impl<'de> Deserialize<'de> for VersionField {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldVisitor;

        impl Visitor<'_> for FieldVisitor {
            type Value = VersionField;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a closed protocol-version field")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "major" => Ok(VersionField::Major),
                    "minor" => Ok(VersionField::Minor),
                    _ => Err(E::unknown_field(value, VERSION_FIELDS)),
                }
            }
        }

        deserializer.deserialize_identifier(FieldVisitor)
    }
}

struct BoundedStringSeed {
    maximum_bytes: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedStringSeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor {
            maximum_bytes: usize,
        }

        impl Visitor<'_> for StringVisitor {
            type Value = String;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded UTF-8 string")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > self.maximum_bytes {
                    return Err(E::custom("bounded string rejected"));
                }
                Ok(value.to_owned())
            }

            fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > self.maximum_bytes {
                    return Err(E::custom("bounded string rejected"));
                }
                Ok(value)
            }
        }

        deserializer.deserialize_string(StringVisitor {
            maximum_bytes: self.maximum_bytes,
        })
    }
}

struct DigestSeed;

impl<'de> DeserializeSeed<'de> for DigestSeed {
    type Value = Digest32;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DigestVisitor;

        impl Visitor<'_> for DigestVisitor {
            type Value = Digest32;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly 64 lowercase hexadecimal characters")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Digest32::from_lower_hex(value)
                    .ok_or_else(|| E::custom("lowercase digest rejected"))
            }
        }

        deserializer.deserialize_str(DigestVisitor)
    }
}

struct VersionSeed;

impl<'de> DeserializeSeed<'de> for VersionSeed {
    type Value = ProtocolVersion;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VersionVisitor;

        impl<'de> Visitor<'de> for VersionVisitor {
            type Value = ProtocolVersion;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a closed major/minor protocol version")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut major = None;
                let mut minor = None;
                while let Some(field) = map.next_key::<VersionField>()? {
                    match field {
                        VersionField::Major => {
                            if major.is_some() {
                                return Err(de::Error::duplicate_field("major"));
                            }
                            major = Some(map.next_value::<u16>()?);
                        }
                        VersionField::Minor => {
                            if minor.is_some() {
                                return Err(de::Error::duplicate_field("minor"));
                            }
                            minor = Some(map.next_value::<u16>()?);
                        }
                    }
                }
                Ok(ProtocolVersion::new(
                    major.ok_or_else(|| de::Error::missing_field("major"))?,
                    minor.ok_or_else(|| de::Error::missing_field("minor"))?,
                ))
            }
        }

        deserializer.deserialize_map(VersionVisitor)
    }
}

struct VersionsSeed<'a> {
    context: &'a DecodeContext,
}

impl<'de> DeserializeSeed<'de> for VersionsSeed<'_> {
    type Value = Vec<ProtocolVersion>;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VersionsVisitor<'a> {
            context: &'a DecodeContext,
        }

        impl<'de> Visitor<'de> for VersionsVisitor<'_> {
            type Value = Vec<ProtocolVersion>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded protocol-version array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|size| size > VERSION_ITEMS_MAXIMUM)
                {
                    return Err(self.context.fail(ErrorCode::ItemLimit));
                }
                let mut versions = Vec::with_capacity(
                    sequence.size_hint().unwrap_or(0).min(VERSION_ITEMS_MAXIMUM),
                );
                while let Some(version) = sequence.next_element_seed(VersionSeed)? {
                    if versions.len() == VERSION_ITEMS_MAXIMUM {
                        return Err(self.context.fail(ErrorCode::ItemLimit));
                    }
                    versions.push(version);
                }
                Ok(versions)
            }
        }

        deserializer.deserialize_seq(VersionsVisitor {
            context: self.context,
        })
    }
}

struct CapabilitySeed<'a> {
    context: &'a DecodeContext,
}

impl<'de> DeserializeSeed<'de> for CapabilitySeed<'_> {
    type Value = Capability;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CapabilityVisitor<'a> {
            context: &'a DecodeContext,
        }

        impl Visitor<'_> for CapabilityVisitor<'_> {
            type Value = Capability;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a closed local-agent capability name")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "read-status" => Ok(Capability::ReadStatus),
                    "sync-materialize" => Ok(Capability::SyncMaterialize),
                    "start-edit-lock-fact" => Ok(Capability::StartEditLockFact),
                    "checkpoint-handoff" => Ok(Capability::CheckpointHandoff),
                    "revert-handoff" => Ok(Capability::RevertHandoff),
                    "job-progress" => Ok(Capability::JobProgress),
                    "workspace-events" => Ok(Capability::WorkspaceEvents),
                    "trusted-client-handoff" => Ok(Capability::TrustedClientHandoff),
                    _ => Err(self.context.fail(ErrorCode::FrameInvalid)),
                }
            }
        }

        deserializer.deserialize_str(CapabilityVisitor {
            context: self.context,
        })
    }
}

struct CapabilitiesSeed<'a> {
    context: &'a DecodeContext,
}

impl<'de> DeserializeSeed<'de> for CapabilitiesSeed<'_> {
    type Value = Vec<Capability>;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CapabilitiesVisitor<'a> {
            context: &'a DecodeContext,
        }

        impl<'de> Visitor<'de> for CapabilitiesVisitor<'_> {
            type Value = Vec<Capability>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded local-agent capability array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|size| size > CAPABILITY_ITEMS_MAXIMUM)
                {
                    return Err(self.context.fail(ErrorCode::ItemLimit));
                }
                let mut capabilities = Vec::with_capacity(
                    sequence
                        .size_hint()
                        .unwrap_or(0)
                        .min(CAPABILITY_ITEMS_MAXIMUM),
                );
                while let Some(capability) = sequence.next_element_seed(CapabilitySeed {
                    context: self.context,
                })? {
                    if capabilities.len() == CAPABILITY_ITEMS_MAXIMUM {
                        return Err(self.context.fail(ErrorCode::ItemLimit));
                    }
                    capabilities.push(capability);
                }
                Ok(capabilities)
            }
        }

        deserializer.deserialize_seq(CapabilitiesVisitor {
            context: self.context,
        })
    }
}

struct ParsedClientHello {
    schema_version: String,
    public_protocol_manifest: Digest32,
    versions: Vec<ProtocolVersion>,
    required_capabilities: Vec<Capability>,
    optional_capabilities: Vec<Capability>,
    client_challenge: [u8; 32],
}

struct ClientHelloSeed<'a> {
    context: &'a DecodeContext,
}

impl<'de> DeserializeSeed<'de> for ClientHelloSeed<'_> {
    type Value = ParsedClientHello;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ClientHelloVisitor<'a> {
            context: &'a DecodeContext,
        }

        impl<'de> Visitor<'de> for ClientHelloVisitor<'_> {
            type Value = ParsedClientHello;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("the closed private client hello object")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut schema_version = None;
                let mut public_protocol_manifest = None;
                let mut versions = None;
                let mut required_capabilities = None;
                let mut optional_capabilities = None;
                let mut client_challenge = None;

                while let Some(field) = map.next_key::<ClientHelloField>()? {
                    match field {
                        ClientHelloField::SchemaVersion => {
                            if schema_version.is_some() {
                                return Err(de::Error::duplicate_field("schemaVersion"));
                            }
                            schema_version =
                                Some(map.next_value_seed(BoundedStringSeed { maximum_bytes: 64 })?);
                        }
                        ClientHelloField::PublicProtocolManifest => {
                            if public_protocol_manifest.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "publicProtocolManifestSha256",
                                ));
                            }
                            public_protocol_manifest = Some(map.next_value_seed(DigestSeed)?);
                        }
                        ClientHelloField::Versions => {
                            if versions.is_some() {
                                return Err(de::Error::duplicate_field("versions"));
                            }
                            versions = Some(map.next_value_seed(VersionsSeed {
                                context: self.context,
                            })?);
                        }
                        ClientHelloField::RequiredCapabilities => {
                            if required_capabilities.is_some() {
                                return Err(de::Error::duplicate_field("requiredCapabilities"));
                            }
                            required_capabilities =
                                Some(map.next_value_seed(CapabilitiesSeed {
                                    context: self.context,
                                })?);
                        }
                        ClientHelloField::OptionalCapabilities => {
                            if optional_capabilities.is_some() {
                                return Err(de::Error::duplicate_field("optionalCapabilities"));
                            }
                            optional_capabilities =
                                Some(map.next_value_seed(CapabilitiesSeed {
                                    context: self.context,
                                })?);
                        }
                        ClientHelloField::ClientChallenge => {
                            if client_challenge.is_some() {
                                return Err(de::Error::duplicate_field("clientChallengeHex"));
                            }
                            client_challenge = Some(*map.next_value_seed(DigestSeed)?.as_bytes());
                        }
                    }
                }

                Ok(ParsedClientHello {
                    schema_version: schema_version
                        .ok_or_else(|| de::Error::missing_field("schemaVersion"))?,
                    public_protocol_manifest: public_protocol_manifest
                        .ok_or_else(|| de::Error::missing_field("publicProtocolManifestSha256"))?,
                    versions: versions.ok_or_else(|| de::Error::missing_field("versions"))?,
                    required_capabilities: required_capabilities
                        .ok_or_else(|| de::Error::missing_field("requiredCapabilities"))?,
                    optional_capabilities: optional_capabilities
                        .ok_or_else(|| de::Error::missing_field("optionalCapabilities"))?,
                    client_challenge: client_challenge
                        .ok_or_else(|| de::Error::missing_field("clientChallengeHex"))?,
                })
            }
        }

        deserializer.deserialize_map(ClientHelloVisitor {
            context: self.context,
        })
    }
}

pub(crate) fn preflight_client_hello(raw: &RawFrame<'_>) -> Result<Digest32> {
    if raw.len() > CLIENT_HELLO_BYTES_MAXIMUM {
        return Err(Error::new(ErrorCode::InputTooLarge));
    }
    validate_raw_frame(raw)
}

pub(crate) fn decode_client_hello_after_preflight(
    raw: &RawFrame<'_>,
    raw_frame_commitment: Digest32,
) -> Result<DecodedClientHello> {
    let context = DecodeContext::default();
    let mut deserializer = serde_json::Deserializer::from_slice(raw.bytes());
    let parsed = ClientHelloSeed { context: &context }
        .deserialize(&mut deserializer)
        .and_then(|value| {
            deserializer.end()?;
            Ok(value)
        })
        .map_err(|_| context.error())?;

    if parsed.schema_version != CLIENT_HELLO_SCHEMA_V1 {
        return Err(Error::new(ErrorCode::UnsupportedVersion));
    }
    if parsed.public_protocol_manifest != public_protocol_manifest_commitment()? {
        return Err(Error::new(ErrorCode::BaselineMismatch));
    }
    if parsed.client_challenge == [0; 32] {
        return Err(Error::new(ErrorCode::InvalidFact));
    }
    let offer = NegotiationOffer {
        versions: parsed.versions,
        required_capabilities: parsed.required_capabilities,
        optional_capabilities: parsed.optional_capabilities,
        public_protocol_manifest: parsed.public_protocol_manifest,
    };
    let semantic_offer_commitment = offer.commitment()?;
    let mut builder = CommitmentBuilder::new("client-hello-semantic-v1");
    builder.bytes(CLIENT_HELLO_SCHEMA_V1.as_bytes());
    builder.digest(semantic_offer_commitment);
    builder.bytes(&parsed.client_challenge);
    let semantic_commitment = builder.finish();

    Ok(DecodedClientHello {
        offer,
        client_challenge: parsed.client_challenge,
        raw_frame_commitment,
        semantic_commitment,
    })
}

pub fn decode_client_hello(
    raw: &RawFrame<'_>,
    cancellation: &dyn CancellationProbe,
) -> Result<DecodedClientHello> {
    let raw_frame_commitment = preflight_client_hello(raw)?;
    check_cancel(cancellation, CancellationPoint::Preflight)?;
    let decoded = decode_client_hello_after_preflight(raw, raw_frame_commitment)?;
    check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
    Ok(decoded)
}
