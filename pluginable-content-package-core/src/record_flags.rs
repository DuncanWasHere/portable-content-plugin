#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RecordFlags(u32);

impl RecordFlags {
    /// Marks an override record as deleted. Original record will be removed from file if merged.
    pub const DELETED: Self = Self(1 << 0);

    /// Requests placement beneath a scene's persistent-children group.
    pub const PERSISTENT: Self = Self(1 << 1);

    /// Bits reserved for the format spec.
    /// Remaining bits are schema-defined and ignored by the library.
    pub const CORE_MASK: Self = Self(Self::DELETED.0 | Self::PERSISTENT.0);

    pub const fn application_bits(self) -> u32 {
        self.0 & !Self::CORE_MASK.0
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, value: Self) -> bool {
        self.0 & value.0 == value.0
    }
}
