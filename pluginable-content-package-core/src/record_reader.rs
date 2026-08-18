use crate::{RecordHeader, Signature, SubrecordHeader};
use std::fmt;

pub struct RecordReader {
    header: RecordHeader,
    payload: Vec<u8>,
    position: usize,
    current: Option<(SubrecordHeader, std::ops::Range<usize>)>,
}
impl RecordReader {
    pub(crate) fn new(header: RecordHeader, payload: Vec<u8>) -> Self {
        Self {
            header,
            payload,
            position: 0,
            current: None,
        }
    }
    pub const fn header(&self) -> RecordHeader {
        self.header
    }
    pub fn next_subrecord(&mut self) -> Result<Option<SubrecordHeader>, RecordReadError> {
        self.current = None;
        if self.position == self.payload.len() {
            return Ok(None);
        }
        let remaining = self.payload.len() - self.position;
        if remaining < SubrecordHeader::BYTE_COUNT {
            return Err(RecordReadError::IncompleteSubrecordHeader {
                remaining_byte_count: remaining,
            });
        }
        let header_end = self.position + SubrecordHeader::BYTE_COUNT;
        let header = SubrecordHeader::from_bytes(
            self.payload[self.position..header_end]
                .try_into()
                .expect("checked length"),
        );
        let signature = header.signature();
        let size = header.payload_byte_count();
        let payload_start = header_end;
        let payload_end = payload_start
            .checked_add(size as usize)
            .ok_or(RecordReadError::SubrecordRangeOverflow { signature })?;
        if payload_end > self.payload.len() {
            return Err(RecordReadError::SubrecordExceedsRecord {
                signature,
                payload_byte_count: size,
                remaining_byte_count: self.payload.len() - payload_start,
            });
        }
        self.position = payload_end;
        self.current = Some((header, payload_start..payload_end));
        Ok(Some(header))
    }
    pub fn current_subrecord_payload(&self) -> Result<&[u8], RecordReadError> {
        let range = self
            .current
            .as_ref()
            .map(|value| value.1.clone())
            .ok_or(RecordReadError::NoCurrentSubrecord)?;
        Ok(&self.payload[range])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordReadError {
    NoCurrentSubrecord,
    IncompleteSubrecordHeader {
        remaining_byte_count: usize,
    },
    SubrecordRangeOverflow {
        signature: Signature,
    },
    SubrecordExceedsRecord {
        signature: Signature,
        payload_byte_count: u32,
        remaining_byte_count: usize,
    },
}
impl fmt::Display for RecordReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCurrentSubrecord => write!(f, "No subrecord is currently selected."),
            Self::IncompleteSubrecordHeader {
                remaining_byte_count,
            } => write!(
                f,
                "Only {remaining_byte_count} bytes remain for a standard subrecord header."
            ),
            Self::SubrecordRangeOverflow { signature } => {
                write!(f, "Subrecord {signature} has an overflowing byte range.")
            }
            Self::SubrecordExceedsRecord {
                signature,
                payload_byte_count,
                remaining_byte_count,
            } => write!(
                f,
                "Subrecord {signature} declares {payload_byte_count} bytes, but only {remaining_byte_count} remain."
            ),
        }
    }
}
impl std::error::Error for RecordReadError {}
