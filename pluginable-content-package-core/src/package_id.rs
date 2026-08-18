use std::fmt;

/// Stable UUID for packages.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageId([u8; 16]);

impl PackageId {
    pub const BYTE_COUNT: usize = 16;
    pub const fn from_bytes(bytes: [u8; Self::BYTE_COUNT]) -> Self {
        Self(bytes)
    }
    pub const fn bytes(self) -> [u8; Self::BYTE_COUNT] {
        self.0
    }
    pub fn is_nil(self) -> bool {
        self.0 == [0; Self::BYTE_COUNT]
    }
}

impl fmt::Display for PackageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}
