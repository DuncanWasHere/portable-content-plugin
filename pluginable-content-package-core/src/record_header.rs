use std::fmt;

use crate::{ChangeSetId, RecordFlags, RecordId, Signature};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RecordHeader {
    signature: Signature,
    payload_byte_count: u32,
    flags: RecordFlags,
    record_id: RecordId,
    version: f32,
    last_change_set: ChangeSetId,
}

impl RecordHeader {
    pub const BYTE_COUNT: usize = 52;

    pub fn new(
        signature: Signature,
        payload_byte_count: u32,
        flags: RecordFlags,
        record_id: RecordId,
        version: f32,
        last_change_set: ChangeSetId,
    ) -> Result<Self, RecordHeaderError> {
        if !version.is_finite() || version < 0.0 {
            return Err(RecordHeaderError::InvalidVersion { version });
        }

        Ok(Self {
            signature,
            payload_byte_count,
            flags,
            record_id,
            version,
            last_change_set,
        })
    }

    pub fn from_bytes(bytes: [u8; Self::BYTE_COUNT]) -> Result<Self, RecordHeaderError> {
        let mut hash = [0; ChangeSetId::BYTE_COUNT];
        hash.copy_from_slice(&bytes[20..52]);
        Self::new(
            Signature::from_bytes(bytes[0..4].try_into().expect("fixed-size slice")),
            u32::from_le_bytes(bytes[4..8].try_into().expect("fixed-size slice")),
            RecordFlags::from_bits(u32::from_le_bytes(
                bytes[8..12].try_into().expect("fixed-size slice"),
            )),
            RecordId::from_raw(u32::from_le_bytes(
                bytes[12..16].try_into().expect("fixed-size slice"),
            )),
            f32::from_le_bytes(bytes[16..20].try_into().expect("fixed-size slice")),
            ChangeSetId::from_bytes(hash),
        )
    }

    pub fn to_bytes(self) -> [u8; Self::BYTE_COUNT] {
        let mut bytes = [0; Self::BYTE_COUNT];
        bytes[0..4].copy_from_slice(&self.signature.bytes());
        bytes[4..8].copy_from_slice(&self.payload_byte_count.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.flags.bits().to_le_bytes());
        bytes[12..16].copy_from_slice(&self.record_id.raw().to_le_bytes());
        bytes[16..20].copy_from_slice(&self.version.to_le_bytes());
        bytes[20..52].copy_from_slice(&self.last_change_set.bytes());
        bytes
    }

    pub const fn signature(&self) -> Signature {
        self.signature
    }

    pub const fn payload_byte_count(&self) -> u32 {
        self.payload_byte_count
    }

    pub const fn flags(&self) -> RecordFlags {
        self.flags
    }

    pub const fn record_id(&self) -> RecordId {
        self.record_id
    }

    pub const fn version(&self) -> f32 {
        self.version
    }

    pub const fn last_change_set(&self) -> ChangeSetId {
        self.last_change_set
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RecordHeaderError {
    InvalidVersion { version: f32 },
}

impl fmt::Display for RecordHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { version } => write!(
                formatter,
                "Record version {version} is invalid; versions must be finite and non-negative."
            ),
        }
    }
}

impl std::error::Error for RecordHeaderError {}
