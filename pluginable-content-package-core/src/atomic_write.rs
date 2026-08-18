use crate::{Package, PackageIndexError, PackageOpenError};
use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Writes an updated package and validates it before replacing the original file.
pub fn write_package_atomically(
    path: impl AsRef<Path>,
    bytes: &[u8],
) -> Result<(), AtomicWriteError> {
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| AtomicWriteError::InvalidDestination(path.to_path_buf()))?;
    let (mut file, temporary_path) = loop {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary_path = parent.join(format!(
            ".{}.{}.{}.pending",
            file_name.to_string_lossy(),
            std::process::id(),
            sequence
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(file) => break (file, temporary_path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    };

    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);

        let package = Package::open(&temporary_path).map_err(AtomicWriteError::InvalidPackage)?;
        package
            .build_index()
            .map_err(AtomicWriteError::InvalidStructure)?;
        fs::rename(&temporary_path, path)?;
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

#[derive(Debug)]
pub enum AtomicWriteError {
    InvalidDestination(PathBuf),
    Io(io::Error),
    InvalidPackage(PackageOpenError),
    InvalidStructure(PackageIndexError),
}

impl fmt::Display for AtomicWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDestination(path) => {
                write!(f, "Invalid package destination: {}", path.display())
            }
            Self::Io(error) => write!(f, "Could not atomically write package: {error}"),
            Self::InvalidPackage(error) => {
                write!(f, "Refusing to install invalid package: {error}")
            }
            Self::InvalidStructure(error) => {
                write!(
                    f,
                    "Refusing to install structurally invalid package: {error}"
                )
            }
        }
    }
}

impl std::error::Error for AtomicWriteError {}

impl From<io::Error> for AtomicWriteError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
