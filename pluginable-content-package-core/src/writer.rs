use std::fmt;

use crate::{
    ChangeSetId, GROUP_SIGNATURE, GroupHeader, GroupLabel, GroupType, RecordFlags, RecordHeader,
    RecordId, Signature, SubrecordHeader,
};

pub struct RecordWriter {
    signature: Signature,
    flags: RecordFlags,
    record_id: RecordId,
    version: f32,
    last_change_set: ChangeSetId,
    payload: Vec<u8>,
}

impl RecordWriter {
    pub fn new(
        signature: Signature,
        flags: RecordFlags,
        record_id: RecordId,
        version: f32,
        last_change_set: ChangeSetId,
    ) -> Self {
        Self {
            signature,
            flags,
            record_id,
            version,
            last_change_set,
            payload: Vec::new(),
        }
    }
    pub fn write_subrecord(
        &mut self,
        signature: Signature,
        payload: &[u8],
    ) -> Result<(), PackageWriteError> {
        let payload_byte_count =
            u32::try_from(payload.len()).map_err(|_| PackageWriteError::SubrecordTooLarge {
                signature,
                byte_count: payload.len(),
            })?;
        self.payload
            .extend_from_slice(&SubrecordHeader::new(signature, payload_byte_count).to_bytes());
        self.payload.extend_from_slice(payload);
        Ok(())
    }
    pub fn write_u32(&mut self, signature: Signature, value: u32) -> Result<(), PackageWriteError> {
        self.write_subrecord(signature, &value.to_le_bytes())
    }
    pub fn write_f32(&mut self, signature: Signature, value: f32) -> Result<(), PackageWriteError> {
        self.write_subrecord(signature, &value.to_le_bytes())
    }
    pub fn finish(self) -> Result<Vec<u8>, PackageWriteError> {
        if self.signature == GROUP_SIGNATURE {
            return Err(PackageWriteError::ReservedRecordSignature);
        }
        let payload_byte_count =
            u32::try_from(self.payload.len()).map_err(|_| PackageWriteError::RecordTooLarge {
                signature: self.signature,
                byte_count: self.payload.len(),
            })?;
        let header = RecordHeader::new(
            self.signature,
            payload_byte_count,
            self.flags,
            self.record_id,
            self.version,
            self.last_change_set,
        )?;
        let mut bytes = Vec::with_capacity(RecordHeader::BYTE_COUNT + self.payload.len());
        bytes.extend_from_slice(&header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }
}

pub struct GroupWriter {
    label: GroupLabel,
    group_type: GroupType,
    payload: Vec<u8>,
}

impl GroupWriter {
    pub fn new(label: GroupLabel, group_type: GroupType) -> Self {
        Self {
            label,
            group_type,
            payload: Vec::new(),
        }
    }
    pub fn push_entry(&mut self, serialized_entry: &[u8]) {
        self.payload.extend_from_slice(serialized_entry);
    }
    pub fn finish(self) -> Result<Vec<u8>, PackageWriteError> {
        let total = GroupHeader::BYTE_COUNT
            .checked_add(self.payload.len())
            .ok_or(PackageWriteError::GroupTooLarge)?;
        let total = u32::try_from(total).map_err(|_| PackageWriteError::GroupTooLarge)?;
        let header = GroupHeader::new(total, self.label, self.group_type)
            .map_err(PackageWriteError::InvalidGroupHeader)?;
        let mut bytes = Vec::with_capacity(total as usize);
        bytes.extend_from_slice(&header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }
}

#[derive(Debug)]
pub enum PackageWriteError {
    InvalidPackageHeader(Box<crate::PackageHeaderError>),
    InvalidRecordHeader(crate::RecordHeaderError),
    InvalidGroupHeader(crate::GroupHeaderError),
    SubrecordTooLarge {
        signature: Signature,
        byte_count: usize,
    },
    RecordTooLarge {
        signature: Signature,
        byte_count: usize,
    },
    GroupTooLarge,
    ReservedRecordSignature,
}

impl fmt::Display for PackageWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPackageHeader(error) => write!(f, "Invalid package header: {error}"),
            Self::InvalidRecordHeader(error) => write!(f, "Invalid record header: {error}"),
            Self::InvalidGroupHeader(error) => write!(f, "Invalid group header: {error}"),
            Self::SubrecordTooLarge {
                signature,
                byte_count,
            } => write!(
                f,
                "Subrecord {signature} contains {byte_count} bytes, exceeding u32 capacity."
            ),
            Self::RecordTooLarge {
                signature,
                byte_count,
            } => write!(
                f,
                "Record {signature} contains {byte_count} bytes, exceeding u32 capacity."
            ),
            Self::GroupTooLarge => write!(f, "Group size exceeds u32 capacity."),
            Self::ReservedRecordSignature => {
                write!(f, "GRUP is reserved for group chunks.")
            }
        }
    }
}
impl std::error::Error for PackageWriteError {}
impl From<crate::RecordHeaderError> for PackageWriteError {
    fn from(value: crate::RecordHeaderError) -> Self {
        Self::InvalidRecordHeader(value)
    }
}
