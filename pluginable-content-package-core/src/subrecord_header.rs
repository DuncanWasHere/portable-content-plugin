use crate::Signature;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubrecordHeader {
    signature: Signature,
    payload_byte_count: u32,
}

impl SubrecordHeader {
    pub const BYTE_COUNT: usize = 8;
    pub const fn new(signature: Signature, payload_byte_count: u32) -> Self {
        Self {
            signature,
            payload_byte_count,
        }
    }
    pub fn from_bytes(bytes: [u8; Self::BYTE_COUNT]) -> Self {
        Self::new(
            Signature::from_bytes(bytes[0..4].try_into().expect("fixed-size slice")),
            u32::from_le_bytes(bytes[4..8].try_into().expect("fixed-size slice")),
        )
    }
    pub fn to_bytes(self) -> [u8; Self::BYTE_COUNT] {
        let mut bytes = [0; Self::BYTE_COUNT];
        bytes[0..4].copy_from_slice(&self.signature.bytes());
        bytes[4..8].copy_from_slice(&self.payload_byte_count.to_le_bytes());
        bytes
    }
    pub const fn signature(&self) -> Signature {
        self.signature
    }
    pub const fn payload_byte_count(&self) -> u32 {
        self.payload_byte_count
    }
}
