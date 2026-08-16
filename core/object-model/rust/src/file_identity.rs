use std::{fs::File, io, path::Path};

#[cfg(windows)]
#[derive(Default)]
struct IdentityHashInput(Vec<u8>);

#[cfg(windows)]
impl std::hash::Hasher for IdentityHashInput {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    hash: [u8; 32],
}

impl FileIdentity {
    pub(crate) fn from_file(file: &File) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata()?;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(windows)]
        {
            use std::hash::Hash;
            let handle = same_file::Handle::from_file(file.try_clone()?)?;
            let mut input = IdentityHashInput::default();
            handle.hash(&mut input);
            Ok(Self {
                hash: crate::hash::sha256(&input.0),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = file;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "file identity is unavailable on this platform",
            ))
        }
    }

    pub(crate) fn matches_path(
        self,
        path: &Path,
        metadata: &std::fs::Metadata,
    ) -> io::Result<bool> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let _ = path;
            Ok(metadata.dev() == self.device && metadata.ino() == self.inode)
        }
        #[cfg(windows)]
        {
            let _ = metadata;
            Ok(Self::from_file(&File::open(path)?)? == self)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (path, metadata);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "file identity is unavailable on this platform",
            ))
        }
    }
}
