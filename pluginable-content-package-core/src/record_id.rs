use std::fmt;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordId(u32);

impl RecordId {
    pub const MAXIMUM_LOCAL_IDENTIFIER: u32 = 0x00FF_FFFF;

    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    pub fn new(package_index: u8, local_identifier: u32) -> Result<Self, RecordIdError> {
        if local_identifier > Self::MAXIMUM_LOCAL_IDENTIFIER {
            return Err(RecordIdError::LocalIdentifierOutOfRange { local_identifier });
        }

        Ok(Self(((package_index as u32) << 24) | local_identifier))
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Within a serialized package this is relative to the dependency list.
    pub const fn package_index(self) -> u8 {
        (self.0 >> 24) as u8
    }

    pub const fn local_identifier(self) -> u32 {
        self.0 & Self::MAXIMUM_LOCAL_IDENTIFIER
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:08X}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordIdError {
    LocalIdentifierOutOfRange { local_identifier: u32 },
}

impl fmt::Display for RecordIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalIdentifierOutOfRange { local_identifier } => {
                write!(
                    formatter,
                    "Record local identifier 0x{local_identifier:X} exceeds the maximum value 0x{:06X}.",
                    RecordId::MAXIMUM_LOCAL_IDENTIFIER
                )
            }
        }
    }
}

impl std::error::Error for RecordIdError {}
