use sha2::{Digest, Sha256};

use crate::{Commitment, IdentityBinding, ReportDigest, Version, WorkspaceBinding};

const REPORT_DOMAIN: &[u8] = b"OpenGameVCS R1 CLI evidence report\0v1\0";

pub(crate) struct Transcript {
    hash: Sha256,
}

impl Transcript {
    pub(crate) fn new() -> Self {
        let mut hash = Sha256::new();
        hash.update(REPORT_DOMAIN);
        Self { hash }
    }

    pub(crate) fn section(&mut self, tag: u8) {
        self.hash.update([0xf0, tag]);
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.hash.update([0x01, value]);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.hash.update([0x02]);
        self.hash.update(value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.hash.update([0x03]);
        self.hash.update(value.to_be_bytes());
    }

    pub(crate) fn commitment(&mut self, value: Commitment) {
        self.hash.update([0x20, 0x00, 0x00, 0x00, 0x20]);
        self.hash.update(value.0);
    }

    pub(crate) fn workspace(&mut self, value: WorkspaceBinding) {
        self.hash.update([0x21, 0x00, 0x00, 0x00, 0x20]);
        self.hash.update(value.0);
    }

    pub(crate) fn identity(&mut self, value: IdentityBinding) {
        self.hash.update([0x22, 0x00, 0x00, 0x00, 0x20]);
        self.hash.update(value.0);
    }

    pub(crate) fn version(&mut self, value: Version) {
        self.hash.update([0x30]);
        self.hash.update(value.major.to_be_bytes());
        self.hash.update(value.minor.to_be_bytes());
        self.hash.update(value.patch.to_be_bytes());
        self.hash.update(value.prerelease.to_be_bytes());
    }

    pub(crate) fn snapshot(&mut self, kind: u8, kind_code: u16, digest: [u8; 32]) {
        self.hash.update([0x40, kind]);
        self.hash.update(kind_code.to_be_bytes());
        self.hash.update([0x00, 0x00, 0x00, 0x20]);
        self.hash.update(digest);
    }

    pub(crate) fn finish(self) -> ReportDigest {
        ReportDigest(self.hash.finalize().into())
    }
}
