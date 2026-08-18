use std::fmt;

use crate::{RecordId, Signature};

pub const GROUP_SIGNATURE: Signature = Signature::from_bytes(*b"GRUP");

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GroupLabel([u8; 4]);

impl GroupLabel {
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
    pub const fn from_signature(value: Signature) -> Self {
        Self(value.bytes())
    }
    pub const fn from_record_id(value: RecordId) -> Self {
        Self(value.raw().to_le_bytes())
    }
    pub const fn from_i32(value: i32) -> Self {
        Self(value.to_le_bytes())
    }
    pub const fn from_grid(y: i16, x: i16) -> Self {
        let y = y.to_le_bytes();
        let x = x.to_le_bytes();
        Self([y[0], y[1], x[0], x[1]])
    }
    pub const fn bytes(self) -> [u8; 4] {
        self.0
    }
    pub const fn signature(self) -> Signature {
        Signature::from_bytes(self.0)
    }
    pub const fn record_id(self) -> RecordId {
        RecordId::from_raw(u32::from_le_bytes(self.0))
    }
    pub const fn i32(self) -> i32 {
        i32::from_le_bytes(self.0)
    }
    pub const fn grid(self) -> (i16, i16) {
        (
            i16::from_le_bytes([self.0[0], self.0[1]]),
            i16::from_le_bytes([self.0[2], self.0[3]]),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GroupType {
    TopLevel,
    WorldChildren,
    InteriorSceneBlock,
    InteriorSceneSubBlock,
    ExteriorSceneBlock,
    ExteriorSceneSubBlock,
    SceneChildren,
    ConversationChildren,
    ScenePersistentChildren,
    SceneTemporaryChildren,
    SceneDistantChildren,
    Unknown(i32),
}

impl GroupType {
    pub const fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::TopLevel,
            1 => Self::WorldChildren,
            2 => Self::InteriorSceneBlock,
            3 => Self::InteriorSceneSubBlock,
            4 => Self::ExteriorSceneBlock,
            5 => Self::ExteriorSceneSubBlock,
            6 => Self::SceneChildren,
            7 => Self::ConversationChildren,
            8 => Self::ScenePersistentChildren,
            9 => Self::SceneTemporaryChildren,
            10 => Self::SceneDistantChildren,
            value => Self::Unknown(value),
        }
    }
    pub const fn raw(self) -> i32 {
        match self {
            Self::TopLevel => 0,
            Self::WorldChildren => 1,
            Self::InteriorSceneBlock => 2,
            Self::InteriorSceneSubBlock => 3,
            Self::ExteriorSceneBlock => 4,
            Self::ExteriorSceneSubBlock => 5,
            Self::SceneChildren => 6,
            Self::ConversationChildren => 7,
            Self::ScenePersistentChildren => 8,
            Self::SceneTemporaryChildren => 9,
            Self::SceneDistantChildren => 10,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupHeader {
    group_byte_count: u32,
    label: GroupLabel,
    group_type: GroupType,
}

impl GroupHeader {
    pub const BYTE_COUNT: usize = 16;
    pub const fn new(
        group_byte_count: u32,
        label: GroupLabel,
        group_type: GroupType,
    ) -> Result<Self, GroupHeaderError> {
        if group_byte_count < Self::BYTE_COUNT as u32 {
            return Err(GroupHeaderError::InvalidSize(group_byte_count));
        }
        Ok(Self {
            group_byte_count,
            label,
            group_type,
        })
    }
    pub fn from_bytes(bytes: [u8; Self::BYTE_COUNT]) -> Result<Self, GroupHeaderError> {
        let signature = Signature::from_bytes(bytes[0..4].try_into().expect("fixed-size slice"));
        if signature != GROUP_SIGNATURE {
            return Err(GroupHeaderError::InvalidSignature(signature));
        }
        Self::new(
            u32::from_le_bytes(bytes[4..8].try_into().expect("fixed-size slice")),
            GroupLabel::from_bytes(bytes[8..12].try_into().expect("fixed-size slice")),
            GroupType::from_raw(i32::from_le_bytes(
                bytes[12..16].try_into().expect("fixed-size slice"),
            )),
        )
    }
    pub fn to_bytes(self) -> [u8; Self::BYTE_COUNT] {
        let mut bytes = [0; Self::BYTE_COUNT];
        bytes[0..4].copy_from_slice(&GROUP_SIGNATURE.bytes());
        bytes[4..8].copy_from_slice(&self.group_byte_count.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.label.bytes());
        bytes[12..16].copy_from_slice(&self.group_type.raw().to_le_bytes());
        bytes
    }
    pub const fn group_byte_count(self) -> u32 {
        self.group_byte_count
    }
    pub const fn payload_byte_count(self) -> u32 {
        self.group_byte_count - Self::BYTE_COUNT as u32
    }
    pub const fn label(self) -> GroupLabel {
        self.label
    }
    pub const fn group_type(self) -> GroupType {
        self.group_type
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupHeaderError {
    InvalidSignature(Signature),
    InvalidSize(u32),
}

impl fmt::Display for GroupHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature(signature) => {
                write!(formatter, "Expected GRUP header, but found {signature}.")
            }
            Self::InvalidSize(size) => write!(
                formatter,
                "Group size {size} is smaller than its {}-byte header.",
                GroupHeader::BYTE_COUNT
            ),
        }
    }
}

impl std::error::Error for GroupHeaderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_groups_begin_with_an_explicit_grup_signature_and_have_no_padding() {
        let header = GroupHeader::new(
            GroupHeader::BYTE_COUNT as u32,
            GroupLabel::from_signature(Signature::from_bytes(*b"ITEM")),
            GroupType::TopLevel,
        )
        .unwrap();

        assert_eq!(GroupHeader::BYTE_COUNT, 16);
        assert_eq!(
            header.to_bytes(),
            [
                b'G', b'R', b'U', b'P', 16, 0, 0, 0, b'I', b'T', b'E', b'M', 0, 0, 0, 0,
            ]
        );
        assert_eq!(GroupHeader::from_bytes(header.to_bytes()).unwrap(), header);
    }

    #[test]
    fn a_non_group_signature_is_rejected() {
        let mut bytes = [0; GroupHeader::BYTE_COUNT];
        bytes[0..4].copy_from_slice(b"ITEM");
        bytes[4..8].copy_from_slice(&(GroupHeader::BYTE_COUNT as u32).to_le_bytes());
        assert!(matches!(
            GroupHeader::from_bytes(bytes),
            Err(GroupHeaderError::InvalidSignature(signature))
                if signature == Signature::from_bytes(*b"ITEM")
        ));
    }
}
