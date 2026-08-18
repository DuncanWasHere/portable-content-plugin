use std::{fmt, io, sync::Arc};

use crate::{
    GROUP_SIGNATURE, GroupHeader, GroupHeaderError, GroupView, PackageSource, RecordHeader,
    RecordHeaderError, RecordView, Signature,
};

pub enum PackageEntry {
    Record(RecordView),
    Group(GroupView),
}

/// Independent cursor over a shared immutable package source or range.
pub struct PackageReader {
    source: Arc<dyn PackageSource>,
    position: u64,
    end_offset: u64,
}

impl PackageReader {
    pub fn new(source: Arc<dyn PackageSource>) -> Self {
        let end_offset = source.byte_count();
        Self {
            source,
            position: 0,
            end_offset,
        }
    }

    pub fn with_range(
        source: Arc<dyn PackageSource>,
        start_offset: u64,
        end_offset: u64,
    ) -> Result<Self, PackageReadError> {
        let source_byte_count = source.byte_count();
        if start_offset > end_offset || end_offset > source_byte_count {
            return Err(PackageReadError::InvalidReaderRange {
                start_offset,
                end_offset,
                source_byte_count,
            });
        }
        Ok(Self {
            source,
            position: start_offset,
            end_offset,
        })
    }

    pub const fn position(&self) -> u64 {
        self.position
    }
    pub const fn end_offset(&self) -> u64 {
        self.end_offset
    }
    pub const fn is_end(&self) -> bool {
        self.position == self.end_offset
    }

    pub fn next_entry(&mut self) -> Result<Option<PackageEntry>, PackageReadError> {
        if self.is_end() {
            return Ok(None);
        }
        let offset = self.position;
        let available = self.end_offset - offset;
        if available < Signature::BYTE_COUNT as u64 {
            return Err(PackageReadError::IncompleteEntrySignature {
                offset,
                available_byte_count: available,
            });
        }
        let read_byte_count = available.min(RecordHeader::BYTE_COUNT as u64) as usize;
        let mut bytes = [0; RecordHeader::BYTE_COUNT];
        self.source
            .read_exact_at(offset, &mut bytes[..read_byte_count])?;
        let signature = Signature::from_bytes(
            bytes[..Signature::BYTE_COUNT]
                .try_into()
                .expect("checked signature length"),
        );
        if signature == GROUP_SIGNATURE {
            if read_byte_count < GroupHeader::BYTE_COUNT {
                return Err(PackageReadError::IncompleteGroupHeader {
                    offset,
                    available_byte_count: available,
                });
            }
            let header = GroupHeader::from_bytes(
                bytes[..GroupHeader::BYTE_COUNT]
                    .try_into()
                    .expect("checked group header length"),
            )?;
            Ok(Some(PackageEntry::Group(
                self.finish_group(offset, header)?,
            )))
        } else {
            if read_byte_count < RecordHeader::BYTE_COUNT {
                return Err(PackageReadError::IncompleteRecordHeader {
                    offset,
                    available_byte_count: available,
                });
            }
            let header = RecordHeader::from_bytes(bytes)?;
            Ok(Some(PackageEntry::Record(
                self.finish_record(offset, header)?,
            )))
        }
    }

    pub fn next_record(&mut self) -> Result<Option<RecordView>, PackageReadError> {
        match self.next_entry()? {
            Some(PackageEntry::Record(record)) => Ok(Some(record)),
            Some(PackageEntry::Group(group)) => Err(PackageReadError::ExpectedRecord {
                offset: group.header_offset(),
            }),
            None => Ok(None),
        }
    }

    fn finish_record(
        &mut self,
        offset: u64,
        header: RecordHeader,
    ) -> Result<RecordView, PackageReadError> {
        let payload_offset = offset + RecordHeader::BYTE_COUNT as u64;
        let end_offset = payload_offset
            .checked_add(header.payload_byte_count() as u64)
            .ok_or(PackageReadError::EntryRangeOverflow { offset })?;
        if end_offset > self.end_offset {
            return Err(PackageReadError::EntryExceedsRange {
                offset,
                entry_end_offset: end_offset,
                reader_end_offset: self.end_offset,
            });
        }
        self.position = end_offset;
        Ok(RecordView::new(
            self.source.clone(),
            offset,
            payload_offset,
            header,
        ))
    }

    fn finish_group(
        &mut self,
        offset: u64,
        header: GroupHeader,
    ) -> Result<GroupView, PackageReadError> {
        let end_offset = offset
            .checked_add(header.group_byte_count() as u64)
            .ok_or(PackageReadError::EntryRangeOverflow { offset })?;
        if end_offset > self.end_offset {
            return Err(PackageReadError::EntryExceedsRange {
                offset,
                entry_end_offset: end_offset,
                reader_end_offset: self.end_offset,
            });
        }
        let payload_offset = offset + GroupHeader::BYTE_COUNT as u64;
        self.position = end_offset;
        Ok(GroupView::new(
            self.source.clone(),
            offset,
            payload_offset,
            end_offset,
            header,
        ))
    }
}

#[derive(Debug)]
pub enum PackageReadError {
    InputOutput(io::Error),
    InvalidHeader(RecordHeaderError),
    InvalidGroupHeader(GroupHeaderError),
    InvalidReaderRange {
        start_offset: u64,
        end_offset: u64,
        source_byte_count: u64,
    },
    IncompleteEntrySignature {
        offset: u64,
        available_byte_count: u64,
    },
    IncompleteRecordHeader {
        offset: u64,
        available_byte_count: u64,
    },
    IncompleteGroupHeader {
        offset: u64,
        available_byte_count: u64,
    },
    EntryRangeOverflow {
        offset: u64,
    },
    EntryExceedsRange {
        offset: u64,
        entry_end_offset: u64,
        reader_end_offset: u64,
    },
    ExpectedRecord {
        offset: u64,
    },
}

impl fmt::Display for PackageReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputOutput(error) => write!(f, "Package I/O error: {error}"),
            Self::InvalidHeader(error) => write!(f, "Invalid record header: {error}"),
            Self::InvalidGroupHeader(error) => write!(f, "Invalid group header: {error}"),
            Self::InvalidReaderRange {
                start_offset,
                end_offset,
                source_byte_count,
            } => write!(
                f,
                "Reader range {start_offset}..{end_offset} is invalid for a {source_byte_count}-byte source."
            ),
            Self::IncompleteEntrySignature {
                offset,
                available_byte_count,
            } => write!(
                f,
                "Only {available_byte_count} bytes remain at offset {offset}; an entry signature requires 4 bytes."
            ),
            Self::IncompleteRecordHeader {
                offset,
                available_byte_count,
            } => write!(
                f,
                "Only {available_byte_count} bytes remain at offset {offset}; a record header requires {} bytes.",
                RecordHeader::BYTE_COUNT
            ),
            Self::IncompleteGroupHeader {
                offset,
                available_byte_count,
            } => write!(
                f,
                "Only {available_byte_count} bytes remain at offset {offset}; a group header requires {} bytes.",
                GroupHeader::BYTE_COUNT
            ),
            Self::EntryRangeOverflow { offset } => {
                write!(f, "Entry at offset {offset} has an overflowing byte range.")
            }
            Self::EntryExceedsRange {
                offset,
                entry_end_offset,
                reader_end_offset,
            } => write!(
                f,
                "Entry at offset {offset} ends at {entry_end_offset}, beyond reader boundary {reader_end_offset}."
            ),
            Self::ExpectedRecord { offset } => write!(
                f,
                "Expected a record at offset {offset}, but found a group."
            ),
        }
    }
}

impl std::error::Error for PackageReadError {}
impl From<io::Error> for PackageReadError {
    fn from(value: io::Error) -> Self {
        Self::InputOutput(value)
    }
}
impl From<RecordHeaderError> for PackageReadError {
    fn from(value: RecordHeaderError) -> Self {
        Self::InvalidHeader(value)
    }
}
impl From<GroupHeaderError> for PackageReadError {
    fn from(value: GroupHeaderError) -> Self {
        Self::InvalidGroupHeader(value)
    }
}
