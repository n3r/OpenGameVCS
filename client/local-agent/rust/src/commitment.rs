use ogvcs_object_model::Sha256Writer;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest32([u8; 32]);

impl std::fmt::Debug for Digest32 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Digest32(<redacted>)")
    }
}

impl Digest32 {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_lower_hex(text: &str) -> Option<Self> {
        if text.len() != 64 {
            return None;
        }
        let bytes = text.as_bytes();
        let mut out = [0u8; 32];
        let mut index = 0usize;
        while index < out.len() {
            let high = lower_hex_nibble(bytes[index * 2])?;
            let low = lower_hex_nibble(bytes[index * 2 + 1])?;
            out[index] = (high << 4) | low;
            index += 1;
        }
        Some(Self(out))
    }

    pub fn to_lower_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        out
    }

    pub const fn is_zero(self) -> bool {
        self.0[0] == 0
            && self.0[1] == 0
            && self.0[2] == 0
            && self.0[3] == 0
            && self.0[4] == 0
            && self.0[5] == 0
            && self.0[6] == 0
            && self.0[7] == 0
            && self.0[8] == 0
            && self.0[9] == 0
            && self.0[10] == 0
            && self.0[11] == 0
            && self.0[12] == 0
            && self.0[13] == 0
            && self.0[14] == 0
            && self.0[15] == 0
            && self.0[16] == 0
            && self.0[17] == 0
            && self.0[18] == 0
            && self.0[19] == 0
            && self.0[20] == 0
            && self.0[21] == 0
            && self.0[22] == 0
            && self.0[23] == 0
            && self.0[24] == 0
            && self.0[25] == 0
            && self.0[26] == 0
            && self.0[27] == 0
            && self.0[28] == 0
            && self.0[29] == 0
            && self.0[30] == 0
            && self.0[31] == 0
    }
}

fn lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

pub(crate) struct CommitmentBuilder {
    hash: Sha256Writer,
}

impl CommitmentBuilder {
    pub(crate) fn new(domain: &str) -> Self {
        let mut hash = Sha256Writer::new();
        hash.update(b"OpenGameVCS local agent commitment\0");
        hash.update(&1u16.to_be_bytes());
        hash.update(&(domain.len() as u64).to_be_bytes());
        hash.update(domain.as_bytes());
        Self { hash }
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.hash.update(&[value]);
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.hash.update(&value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.hash.update(&value.to_be_bytes());
    }

    pub(crate) fn usize(&mut self, value: usize) {
        self.u64(value as u64);
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.hash.update(value);
    }

    pub(crate) fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    pub(crate) fn digest(&mut self, value: Digest32) {
        self.hash.update(value.as_bytes());
    }

    pub(crate) fn finish(self) -> Digest32 {
        Digest32::from_bytes(self.hash.finish())
    }
}
