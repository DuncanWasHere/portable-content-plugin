use std::fmt;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Signature([u8; 4]);

impl Signature {
    pub const BYTE_COUNT: usize = 4;

    pub const fn from_bytes(bytes: [u8; Self::BYTE_COUNT]) -> Self {
        Self(bytes)
    }

    pub fn from_ascii(value: &str) -> Result<Self, SignatureError> {
        let bytes = value.as_bytes();

        if bytes.len() != Self::BYTE_COUNT {
            return Err(SignatureError::InvalidLength {
                actual_byte_count: bytes.len(),
            });
        }

        if !bytes.is_ascii() {
            return Err(SignatureError::NonAscii);
        }

        Ok(Self([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub const fn bytes(self) -> [u8; Self::BYTE_COUNT] {
        self.0
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            if byte.is_ascii_graphic() || byte == b' ' {
                write!(formatter, "{}", byte as char)?;
            } else {
                write!(formatter, "\\x{byte:02X}")?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    InvalidLength { actual_byte_count: usize },
    NonAscii,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual_byte_count } => {
                write!(
                    formatter,
                    "A signature must contain exactly 4 bytes, but {actual_byte_count} bytes were provided."
                )
            }
            Self::NonAscii => {
                write!(formatter, "A signature must contain only ASCII characters.")
            }
        }
    }
}

impl std::error::Error for SignatureError {}
