use std::{collections::HashMap, fmt};

use crate::{
    GroupHeader, GroupView, PACKAGE_HEADER_SIGNATURE, PackageEntry, PackageReadError,
    PackageReader, RecordId, RecordView, Signature,
};

/// Index of a package's content records, for editors that need random access.
pub struct PackageIndex {
    records: Vec<RecordView>,
    records_by_id: HashMap<RecordId, usize>,
    records_by_signature: HashMap<Signature, Vec<usize>>,
    record_path_indices: Vec<usize>,
    paths: Vec<Box<[GroupHeader]>>,
    groups: Vec<GroupView>,
}

impl PackageIndex {
    pub fn build(
        mut content_reader: PackageReader,
        expected_record_count: u32,
        expected_owned_record_count: u32,
        owner_package_index: u8,
    ) -> Result<Self, PackageIndexError> {
        let expected_capacity = expected_record_count as usize;
        let mut result = Self {
            records: Vec::with_capacity(expected_capacity),
            records_by_id: HashMap::with_capacity(expected_capacity),
            records_by_signature: HashMap::new(),
            record_path_indices: Vec::with_capacity(expected_capacity),
            paths: vec![Box::default()],
            groups: Vec::new(),
        };
        result.scan(&mut content_reader, &mut Vec::new(), 0)?;
        let actual = u32::try_from(result.records.len())
            .map_err(|_| PackageIndexError::RecordCountExceedsFormat(result.records.len()))?;
        if actual != expected_record_count {
            return Err(PackageIndexError::RecordCountMismatch {
                expected: expected_record_count,
                actual,
            });
        }
        let owned = result
            .records
            .iter()
            .filter(|record| record.header().record_id().package_index() == owner_package_index)
            .count();
        let owned =
            u32::try_from(owned).map_err(|_| PackageIndexError::RecordCountExceedsFormat(owned))?;
        if owned != expected_owned_record_count {
            return Err(PackageIndexError::OwnedRecordCountMismatch {
                expected: expected_owned_record_count,
                actual: owned,
            });
        }
        Ok(result)
    }

    fn scan(
        &mut self,
        reader: &mut PackageReader,
        path: &mut Vec<GroupHeader>,
        path_index: usize,
    ) -> Result<(), PackageIndexError> {
        while let Some(entry) = reader.next_entry()? {
            match entry {
                PackageEntry::Record(record) => {
                    let header = record.header();
                    if header.signature() == PACKAGE_HEADER_SIGNATURE {
                        return Err(PackageIndexError::UnexpectedPackageHeader(
                            header.record_id(),
                        ));
                    }
                    let id = header.record_id();
                    let record_index = self.records.len();
                    if self.records_by_id.insert(id, record_index).is_some() {
                        return Err(PackageIndexError::DuplicateRecordId(id));
                    }
                    self.records_by_signature
                        .entry(header.signature())
                        .or_default()
                        .push(record_index);
                    self.records.push(record);
                    self.record_path_indices.push(path_index);
                }
                PackageEntry::Group(group) => {
                    let mut children = group.children()?;
                    path.push(group.header());
                    let child_path_index = self.paths.len();
                    self.paths.push(path.clone().into_boxed_slice());
                    self.groups.push(group);
                    self.scan(&mut children, path, child_path_index)?;
                    path.pop();
                }
            }
        }
        Ok(())
    }

    pub fn record(&self, id: RecordId) -> Option<&RecordView> {
        self.records_by_id
            .get(&id)
            .map(|index| &self.records[*index])
    }

    pub fn records_by_signature(
        &self,
        signature: Signature,
    ) -> impl ExactSizeIterator<Item = &RecordView> {
        self.records_by_signature
            .get(&signature)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .map(|index| &self.records[*index])
    }

    pub fn records(&self) -> impl ExactSizeIterator<Item = &RecordView> {
        self.records.iter()
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn record_at(&self, index: usize) -> Option<&RecordView> {
        self.records.get(index)
    }

    pub fn record_path(&self, id: RecordId) -> Option<&[GroupHeader]> {
        let record_index = *self.records_by_id.get(&id)?;
        self.paths
            .get(self.record_path_indices[record_index])
            .map(Box::as_ref)
    }

    pub fn groups(&self) -> &[GroupView] {
        &self.groups
    }
}

#[derive(Debug)]
pub enum PackageIndexError {
    Read(PackageReadError),
    DuplicateRecordId(RecordId),
    UnexpectedPackageHeader(RecordId),
    RecordCountExceedsFormat(usize),
    RecordCountMismatch { expected: u32, actual: u32 },
    OwnedRecordCountMismatch { expected: u32, actual: u32 },
}

impl fmt::Display for PackageIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "Could not index package: {error}"),
            Self::DuplicateRecordId(id) => {
                write!(
                    formatter,
                    "Record ID {id} appears more than once in one package."
                )
            }
            Self::UnexpectedPackageHeader(id) => write!(
                formatter,
                "Package header record {id} appears after the beginning of the package."
            ),
            Self::RecordCountExceedsFormat(count) => write!(
                formatter,
                "Package contains {count} records, exceeding its 32-bit record-count field."
            ),
            Self::RecordCountMismatch { expected, actual } => write!(
                formatter,
                "PKHD declares {expected} records, but indexing found {actual}."
            ),
            Self::OwnedRecordCountMismatch { expected, actual } => write!(
                formatter,
                "PKHD declares {expected} package-owned records, but indexing found {actual}."
            ),
        }
    }
}

impl std::error::Error for PackageIndexError {}

impl From<PackageReadError> for PackageIndexError {
    fn from(value: PackageReadError) -> Self {
        Self::Read(value)
    }
}
