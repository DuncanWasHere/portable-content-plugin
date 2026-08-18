use crate::{GroupHeader, PackageReadError, PackageReader, PackageSource};
use std::sync::Arc;

#[derive(Clone)]
pub struct GroupView {
    source: Arc<dyn PackageSource>,
    header_offset: u64,
    payload_offset: u64,
    end_offset: u64,
    header: GroupHeader,
}

impl GroupView {
    pub(crate) fn new(
        source: Arc<dyn PackageSource>,
        header_offset: u64,
        payload_offset: u64,
        end_offset: u64,
        header: GroupHeader,
    ) -> Self {
        Self {
            source,
            header_offset,
            payload_offset,
            end_offset,
            header,
        }
    }
    pub const fn header(&self) -> GroupHeader {
        self.header
    }
    pub const fn header_offset(&self) -> u64 {
        self.header_offset
    }
    pub const fn payload_offset(&self) -> u64 {
        self.payload_offset
    }
    pub const fn end_offset(&self) -> u64 {
        self.end_offset
    }
    pub fn children(&self) -> Result<PackageReader, PackageReadError> {
        PackageReader::with_range(self.source.clone(), self.payload_offset, self.end_offset)
    }
}
