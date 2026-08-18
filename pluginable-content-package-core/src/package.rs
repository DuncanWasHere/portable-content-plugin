use std::{collections::HashMap, fmt, path::Path, sync::Arc};

use crate::{
    FilePackageSource, GroupType, PackageHeader, PackageHeaderError, PackageIndex,
    PackageIndexError, PackageReadError, PackageReader, PackageSource, PackageWriteError,
    RecordHeader, RecordView, SceneOffset, SceneOffsetTable, Signature,
};

pub const PACKAGE_HEADER_SIGNATURE: Signature = Signature::from_bytes(*b"PKHD");

/// An opened immutable package source with only PKHD decoded.
pub struct Package {
    source: Arc<dyn PackageSource>,
    header_record: RecordView,
    header: PackageHeader,
    content_offset: u64,
}

pub fn scene_offset_tables_from_index(
    index: &PackageIndex,
) -> Result<Vec<SceneOffsetTable>, PackageHeaderError> {
    let mut table_indices = HashMap::<Option<crate::RecordId>, usize>::new();
    let mut tables = Vec::<(Option<crate::RecordId>, Vec<SceneOffset>)>::new();
    for group in index
        .groups()
        .iter()
        .filter(|group| group.header().group_type() == GroupType::SceneTemporaryChildren)
    {
        let scene_id = group.header().label().record_id();
        let scene = index
            .record(scene_id)
            .ok_or(PackageHeaderError::SceneRecordMissingForOffset(scene_id))?;
        let path = index
            .record_path(scene_id)
            .ok_or(PackageHeaderError::SceneRecordMissingForOffset(scene_id))?;
        let world_id = path
            .iter()
            .find(|header| header.group_type() == GroupType::WorldChildren)
            .map(|header| header.label().record_id());
        let table_index = *table_indices.entry(world_id).or_insert_with(|| {
            tables.push((world_id, Vec::new()));
            tables.len() - 1
        });
        let end_offset = index
            .groups()
            .iter()
            .filter(|container| {
                container.header().group_type() == GroupType::SceneChildren
                    && container.header().label().record_id() == scene_id
                    && container.header_offset() <= group.header_offset()
                    && container.end_offset() >= group.end_offset()
            })
            .min_by_key(|container| container.end_offset() - container.header_offset())
            .map_or(group.end_offset(), |container| container.end_offset());
        tables[table_index].1.push(SceneOffset::new(
            scene_id,
            scene.header_offset(),
            end_offset,
        )?);
    }
    tables
        .into_iter()
        .map(|(world_id, offsets)| SceneOffsetTable::new(world_id, offsets))
        .collect()
}

/// Replaces PKHD and fixes the scene offsets.
pub fn rewrite_package_header_bytes(
    mut bytes: Vec<u8>,
    package: &Package,
    header: &PackageHeader,
) -> Result<Vec<u8>, PackageRewriteError> {
    let old_len =
        RecordHeader::BYTE_COUNT + package.header_record().header().payload_byte_count() as usize;
    if bytes.len() < old_len {
        return Err(PackageRewriteError::SourceTooShort {
            required: old_len,
            actual: bytes.len(),
        });
    }

    let mut adjusted = header.clone();
    let provisional = adjusted.encode(package.header_record().header().last_change_set())?;
    let new_len =
        i64::try_from(provisional.len()).map_err(|_| PackageRewriteError::HeaderTooLarge)?;
    let old_len_signed = i64::try_from(old_len).map_err(|_| PackageRewriteError::HeaderTooLarge)?;
    let delta = new_len - old_len_signed;
    if delta != 0 && !adjusted.scene_offset_tables().is_empty() {
        adjusted.shift_scene_offsets(delta)?;
    }

    let encoded = adjusted.encode(package.header_record().header().last_change_set())?;
    bytes.splice(..old_len, encoded);
    Ok(bytes)
}

#[derive(Debug)]
pub enum PackageRewriteError {
    Header(PackageHeaderError),
    Write(PackageWriteError),
    HeaderTooLarge,
    SourceTooShort { required: usize, actual: usize },
}

impl fmt::Display for PackageRewriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(error) => write!(f, "Could not encode package header: {error}"),
            Self::Write(error) => write!(f, "Could not encode package header: {error}"),
            Self::HeaderTooLarge => f.write_str("Package header is too large."),
            Self::SourceTooShort { required, actual } => write!(
                f,
                "Package source has {actual} bytes, but its header occupies {required} bytes."
            ),
        }
    }
}

impl std::error::Error for PackageRewriteError {}

impl From<PackageHeaderError> for PackageRewriteError {
    fn from(value: PackageHeaderError) -> Self {
        Self::Header(value)
    }
}

impl From<PackageWriteError> for PackageRewriteError {
    fn from(value: PackageWriteError) -> Self {
        Self::Write(value)
    }
}

impl Package {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PackageOpenError> {
        Self::from_source(Arc::new(FilePackageSource::open(path)?))
    }

    pub fn from_source(source: Arc<dyn PackageSource>) -> Result<Self, PackageOpenError> {
        let mut reader = PackageReader::new(source.clone());
        let header_record = reader
            .next_record()?
            .ok_or(PackageOpenError::EmptyPackage)?;
        let actual = header_record.header().signature();
        if actual != PACKAGE_HEADER_SIGNATURE {
            return Err(PackageOpenError::MissingPackageHeader { actual });
        }
        if header_record.header().record_id().raw() != 0 {
            return Err(PackageOpenError::InvalidPackageHeaderId(
                header_record.header().record_id(),
            ));
        }
        let header = PackageHeader::decode(header_record.read()?)?;
        let content_offset = reader.position();
        for offset in header
            .scene_offset_tables()
            .iter()
            .flat_map(SceneOffsetTable::offsets)
        {
            if offset.start_offset() < content_offset || offset.end_offset() > source.byte_count() {
                return Err(PackageOpenError::SceneOffsetOutOfBounds {
                    start_offset: offset.start_offset(),
                    end_offset: offset.end_offset(),
                    content_offset,
                    byte_count: source.byte_count(),
                });
            }
        }
        Ok(Self {
            source,
            header_record,
            header,
            content_offset,
        })
    }

    pub fn byte_count(&self) -> u64 {
        self.source.byte_count()
    }
    pub fn header_record(&self) -> &RecordView {
        &self.header_record
    }
    pub fn header(&self) -> &PackageHeader {
        &self.header
    }
    /// Creates a reader over all entries, including the package header.
    pub fn reader(&self) -> PackageReader {
        PackageReader::new(self.source.clone())
    }
    /// Creates a reader positioned after the package header.
    pub fn content_reader(&self) -> PackageReader {
        PackageReader::with_range(
            self.source.clone(),
            self.content_offset,
            self.source.byte_count(),
        )
        .expect("package content range was validated while opening")
    }
    /// Performs a complete package scan and builds a record index for editors.
    pub fn build_index(&self) -> Result<PackageIndex, PackageIndexError> {
        PackageIndex::build(
            self.content_reader(),
            self.header.record_count(),
            self.header.owned_record_count(),
            self.header.dependencies().len() as u8,
        )
    }
    pub fn reader_with_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<PackageReader, PackageReadError> {
        PackageReader::with_range(self.source.clone(), start, end)
    }
}

#[derive(Debug)]
pub enum PackageOpenError {
    InputOutput(std::io::Error),
    Read(PackageReadError),
    Metadata(PackageHeaderError),
    EmptyPackage,
    MissingPackageHeader {
        actual: Signature,
    },
    InvalidPackageHeaderId(crate::RecordId),
    SceneOffsetOutOfBounds {
        start_offset: u64,
        end_offset: u64,
        content_offset: u64,
        byte_count: u64,
    },
}

impl fmt::Display for PackageOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputOutput(error) => write!(f, "Could not open package: {error}"),
            Self::Read(error) => write!(f, "Could not read package: {error}"),
            Self::Metadata(error) => write!(f, "Invalid package metadata: {error}"),
            Self::EmptyPackage => write!(
                f,
                "A package must begin with a PKHD record, but the source is empty."
            ),
            Self::MissingPackageHeader { actual } => write!(
                f,
                "A package must begin with PKHD, but begins with {actual}."
            ),
            Self::InvalidPackageHeaderId(id) => {
                write!(f, "PKHD must use record ID 00000000, but uses {id}.")
            }
            Self::SceneOffsetOutOfBounds {
                start_offset,
                end_offset,
                content_offset,
                byte_count,
            } => write!(
                f,
                "Scene offset range {start_offset}..{end_offset} lies outside package content \
                 {content_offset}..{byte_count}."
            ),
        }
    }
}

impl std::error::Error for PackageOpenError {}
impl From<std::io::Error> for PackageOpenError {
    fn from(value: std::io::Error) -> Self {
        Self::InputOutput(value)
    }
}
impl From<PackageReadError> for PackageOpenError {
    fn from(value: PackageReadError) -> Self {
        Self::Read(value)
    }
}
impl From<PackageHeaderError> for PackageOpenError {
    fn from(value: PackageHeaderError) -> Self {
        Self::Metadata(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ChangeSetId, MemoryPackageSource, PackageId, RecordFlags, RecordHeader, RecordId,
        RecordWriter,
    };
    use std::{io, sync::Mutex};

    struct ObservedSource {
        bytes: Arc<[u8]>,
        reads: Mutex<Vec<std::ops::Range<u64>>>,
    }

    impl PackageSource for ObservedSource {
        fn byte_count(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<()> {
            let end = offset + destination.len() as u64;
            self.reads.lock().unwrap().push(offset..end);
            destination.copy_from_slice(&self.bytes[offset as usize..end as usize]);
            Ok(())
        }
    }

    #[test]
    fn requires_pkhd_as_first_record() {
        let header = RecordHeader::new(
            Signature::from_bytes(*b"NOPE"),
            0,
            RecordFlags::default(),
            RecordId::from_raw(0),
            1.0,
            ChangeSetId::from_bytes([0; 32]),
        )
        .unwrap();
        let source = Arc::new(MemoryPackageSource::new(header.to_bytes().to_vec()));
        assert!(matches!(
            Package::from_source(source),
            Err(PackageOpenError::MissingPackageHeader { .. })
        ));
    }

    #[test]
    fn reads_independent_record_and_subrecord_views() {
        let bytes = PackageHeader::new(PackageId::from_bytes([1; 16]))
            .unwrap()
            .encode(ChangeSetId::from_bytes([0; 32]))
            .unwrap();

        let package = Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap();
        let mut first = package.header_record().read().unwrap();
        let mut second = package.header_record().read().unwrap();

        let first_header = first.next_subrecord().unwrap().unwrap();
        assert_eq!(first_header.signature(), Signature::from_bytes(*b"FMTV"));
        assert_eq!(
            first.current_subrecord_payload().unwrap(),
            &PackageHeader::CURRENT_FORMAT_VERSION.to_le_bytes()
        );
        assert_eq!(second.next_subrecord().unwrap(), Some(first_header));
    }

    #[test]
    fn opening_reads_only_the_package_header_until_indexing_is_requested() {
        let mut header = PackageHeader::new(PackageId::from_bytes([9; 16])).unwrap();
        header.set_record_count(1);
        header.set_owned_record_count(1);
        let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
        let content_offset = bytes.len() as u64;
        let record = RecordWriter::new(
            Signature::from_bytes(*b"TEST"),
            RecordFlags::default(),
            RecordId::from_raw(0x800),
            1.0,
            ChangeSetId::from_bytes([0; 32]),
        )
        .finish()
        .unwrap();
        bytes.extend(record);
        let source = Arc::new(ObservedSource {
            bytes: bytes.into(),
            reads: Mutex::new(Vec::new()),
        });

        let package = Package::from_source(source.clone()).unwrap();
        assert!(
            source
                .reads
                .lock()
                .unwrap()
                .iter()
                .all(|range| range.end <= content_offset)
        );

        assert_eq!(package.build_index().unwrap().record_count(), 1);
        assert!(
            source
                .reads
                .lock()
                .unwrap()
                .iter()
                .any(|range| range.start >= content_offset)
        );
    }

    #[test]
    fn package_metadata_round_trips_schema_namespace_and_mutable_dependencies() {
        let mut header = PackageHeader::new(PackageId::from_bytes([1; 16])).unwrap();
        header.set_schema_namespace("utconmaz.game-content.draft");
        header.set_package_version(crate::PackageVersion::parse("1.2.0-beta.2").unwrap());
        let dependency_package_id = PackageId::from_bytes([2; 16]);
        header
            .add_dependency(
                crate::PackageDependency::new(dependency_package_id, "base.pcp")
                    .unwrap()
                    .with_version_requirement(
                        crate::PackageVersionRequirement::parse(">=1.0.0, <2.0.0").unwrap(),
                    ),
            )
            .unwrap();
        assert!(header.remove_dependency(dependency_package_id));
        header
            .add_dependency(
                crate::PackageDependency::new(dependency_package_id, "base.pcp")
                    .unwrap()
                    .with_version_requirement(
                        crate::PackageVersionRequirement::parse(">=1.0.0, <2.0.0").unwrap(),
                    ),
            )
            .unwrap();
        header
            .add_incompatibility(
                crate::PackageIncompatibility::new(
                    PackageId::from_bytes([3; 16]),
                    "old-overhaul.pcp",
                )
                .unwrap()
                .with_version_requirement(
                    crate::PackageVersionRequirement::parse("<3.0.0").unwrap(),
                ),
            )
            .unwrap();
        let bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
        let package = Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap();
        assert_eq!(
            package.header().schema_namespace(),
            "utconmaz.game-content.draft"
        );
        assert_eq!(package.header().dependencies()[0].name(), "base.pcp");
        assert_eq!(
            package.header().package_version().to_string(),
            "1.2.0-beta.2"
        );
        assert_eq!(
            package.header().dependencies()[0]
                .version_requirement()
                .unwrap()
                .to_string(),
            ">=1.0.0, <2.0.0"
        );
        assert_eq!(
            package.header().incompatibilities()[0].name(),
            "old-overhaul.pcp"
        );
    }
}
