use std::{io, sync::Arc};

use crate::{PackageSource, RecordHeader, RecordReader};

/// Cheap, cloneable description of a record in a package source.
#[derive(Clone)]
pub struct RecordView {
    source: Arc<dyn PackageSource>,
    header_offset: u64,
    payload_offset: u64,
    header: RecordHeader,
}

impl RecordView {
    pub(crate) fn new(
        source: Arc<dyn PackageSource>,
        header_offset: u64,
        payload_offset: u64,
        header: RecordHeader,
    ) -> Self {
        Self {
            source,
            header_offset,
            payload_offset,
            header,
        }
    }

    pub const fn header(&self) -> RecordHeader {
        self.header
    }
    pub const fn header_offset(&self) -> u64 {
        self.header_offset
    }
    pub const fn payload_offset(&self) -> u64 {
        self.payload_offset
    }

    pub fn read(&self) -> io::Result<RecordReader> {
        let size = usize::try_from(self.header.payload_byte_count())
            .expect("u32 always fits supported usize");
        let mut payload = vec![0; size];
        self.source
            .read_exact_at(self.payload_offset, &mut payload)?;
        Ok(RecordReader::new(self.header, payload))
    }
}
