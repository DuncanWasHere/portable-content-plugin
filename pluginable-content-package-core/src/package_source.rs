use std::{fs::File, io, path::Path, sync::Arc};

/// Immutable random-access source containing a package.
/// Implementations must allow concurrent reads from different offsets.
pub trait PackageSource: Send + Sync {
    fn byte_count(&self) -> u64;

    fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<()>;
}

pub struct FilePackageSource {
    file: File,
    byte_count: u64,
}

impl FilePackageSource {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path)?;
        let byte_count = file.metadata()?.len();

        Ok(Self { file, byte_count })
    }
}

impl PackageSource for FilePackageSource {
    fn byte_count(&self) -> u64 {
        self.byte_count
    }

    fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<()> {
        read_exact_at(&self.file, offset, destination)
    }
}

/// In-memory immutable source, useful for whole-file save loading and tests.
#[derive(Clone, Debug)]
pub struct MemoryPackageSource {
    bytes: Arc<[u8]>,
}

impl MemoryPackageSource {
    pub fn new(bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }
}

impl PackageSource for MemoryPackageSource {
    fn byte_count(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Package offset does not fit in usize.",
            )
        })?;
        let end = start.checked_add(destination.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Package memory read range overflowed.",
            )
        })?;
        let source = self.bytes.get(start..end).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Package memory source ended during a positional read.",
            )
        })?;
        destination.copy_from_slice(source);
        Ok(())
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, offset: u64, destination: &mut [u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;

    file.read_exact_at(destination, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut offset: u64, mut destination: &mut [u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;

    while !destination.is_empty() {
        let read_byte_count = file.seek_read(destination, offset)?;

        if read_byte_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "The package ended before the requested positional read completed.",
            ));
        }

        offset = offset.checked_add(read_byte_count as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The package read offset overflowed the 64-bit file offset.",
            )
        })?;

        destination = &mut destination[read_byte_count..];
    }

    Ok(())
}

#[cfg(not(any(unix, windows)))]
compile_error!("FilePackageSource currently supports Unix and Windows targets only.");
