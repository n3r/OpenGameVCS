use sha2::{Digest as _, Sha256};

pub(crate) type Digest = [u8; 32];

pub(crate) struct DigestBuilder(Sha256);

impl DigestBuilder {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut inner = Sha256::new();
        inner.update((domain.len() as u64).to_be_bytes());
        inner.update(domain);
        Self(inner)
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.0.update([value]);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.0.update(value.to_be_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.0.update(value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    pub(crate) fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.0.update(value);
    }

    pub(crate) fn fixed(&mut self, value: &[u8]) {
        self.0.update(value);
    }

    pub(crate) fn optional_fixed(&mut self, value: Option<&[u8]>) {
        self.boolean(value.is_some());
        if let Some(value) = value {
            self.fixed(value);
        }
    }

    pub(crate) fn finish(self) -> Digest {
        self.0.finalize().into()
    }
}

pub(crate) fn digest16(domain: &[u8], fields: &[&[u8]]) -> [u8; 16] {
    let mut digest = DigestBuilder::new(domain);
    for field in fields {
        digest.bytes(field);
    }
    let full = digest.finish();
    let mut result = [0_u8; 16];
    result.copy_from_slice(&full[..16]);
    result
}
