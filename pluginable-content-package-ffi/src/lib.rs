use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    ffi::{CStr, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    ptr,
    sync::Arc,
};

use pluginable_content_package_core::{
    ChangeSetId, LoadOrder, LoadOrderRecordIndex, MemoryPackageSource, Package, PackageDependency,
    PackageEntry, PackageHeader, PackageId, PackageIncompatibility, PackageIndex, PackageLoadClass,
    PackageReader, PackageVersion, PackageVersionRequirement, RecordFlags, RecordHeader, RecordId,
    RecordReader, RecordWriter, RuntimeRecordId, Signature, SubrecordHeader,
    rewrite_package_header_bytes, scene_offset_tables_from_index, write_package_atomically,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcpResult {
    Success = 0,
    InvalidArgument = 1,
    InputOutputError = 2,
    InvalidPackage = 3,
    EndOfRecords = 4,
    EndOfSubrecords = 5,
    BufferTooSmall = 6,
    IndexUnavailable = 7,
    NotEditable = 8,
    Panic = 255,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcpPackageEntryKind {
    Record = 0,
    Group = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PcpRecordHeader {
    pub signature: [u8; 4],
    pub payload_byte_count: u32,
    pub flags: u32,
    pub record_id: u32,
    pub version: f32,
    pub last_change_set: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PcpSubrecordHeader {
    pub signature: [u8; 4],
    pub payload_byte_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PcpIndexedRecord {
    pub header_offset: u64,
    pub header: PcpRecordHeader,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PcpRecordOrigin {
    pub package_index: usize,
    pub record: PcpIndexedRecord,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PcpIndexedGroup {
    pub header_offset: u64,
    pub payload_offset: u64,
    pub end_offset: u64,
    pub group_byte_count: u32,
    pub label: [u8; 4],
    pub group_type: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PcpSceneOffset {
    pub world_record_id: u32,
    pub scene_record_id: u32,
    pub start_offset: u64,
    pub end_offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PcpPackageMetadata {
    pub format_version: u32,
    pub package_id: [u8; 16],
    pub load_class: u8,
    pub has_package_version: u8,
    pub reserved: [u8; 2],
    pub next_local_identifier: u32,
    pub record_count: u32,
    pub owned_record_count: u32,
    pub dependency_count: usize,
    pub incompatibility_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PcpPackageRelationship {
    pub package_id: [u8; 16],
    pub has_version_requirement: u8,
    pub reserved: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PcpPackageRelationshipInput {
    pub package_id: [u8; 16],
    pub name: *const c_char,
    pub version_requirement: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PcpRecordMutation {
    pub kind: i32, // 0 = replacement, 1 = insertion, 2 = deletion
    pub record_signature: u32,
    pub record_id: u32,
    pub reserved: u32,
    pub target_group_offset: u64,
    pub payload: *const u8,
    pub payload_byte_count: usize,
}

pub struct PcpPackageHandle {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    package: Package,
    index: Option<PackageIndex>,
    dirty: bool,
}
pub struct PcpRecordReaderHandle {
    reader: RecordReader,
}
pub struct PcpPackageCursorHandle {
    readers: Vec<PackageReader>,
    pending_group: Option<pluginable_content_package_core::GroupView>,
}
pub struct PcpLoadOrderHandle {
    load_order: LoadOrder,
    record_index: Option<LoadOrderRecordIndex>,
    runtime_ids: Vec<RuntimeRecordId>,
}

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_error(message: impl Into<String>) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = message.into());
}

fn boundary(operation: impl FnOnce() -> PcpResult) -> PcpResult {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => {
            set_error("A Rust panic was caught at the PCP ABI boundary.");
            PcpResult::Panic
        }
    }
}

impl From<RecordHeader> for PcpRecordHeader {
    fn from(value: RecordHeader) -> Self {
        Self {
            signature: value.signature().bytes(),
            payload_byte_count: value.payload_byte_count(),
            flags: value.flags().bits(),
            record_id: value.record_id().raw(),
            version: value.version(),
            last_change_set: value.last_change_set().bytes(),
        }
    }
}

impl From<SubrecordHeader> for PcpSubrecordHeader {
    fn from(value: SubrecordHeader) -> Self {
        Self {
            signature: value.signature().bytes(),
            payload_byte_count: value.payload_byte_count(),
        }
    }
}

fn indexed_record(value: &pluginable_content_package_core::RecordView) -> PcpIndexedRecord {
    PcpIndexedRecord {
        header_offset: value.header_offset(),
        header: value.header().into(),
    }
}

fn indexed_group(value: &pluginable_content_package_core::GroupView) -> PcpIndexedGroup {
    let header = value.header();
    PcpIndexedGroup {
        header_offset: value.header_offset(),
        payload_offset: value.payload_offset(),
        end_offset: value.end_offset(),
        group_byte_count: header.group_byte_count(),
        label: header.label().bytes(),
        group_type: header.group_type().raw(),
    }
}

fn copy_text(
    value: &str,
    destination: *mut u8,
    destination_byte_count: usize,
    required_byte_count: *mut usize,
) -> PcpResult {
    if required_byte_count.is_null() || (destination.is_null() && destination_byte_count != 0) {
        return PcpResult::InvalidArgument;
    }
    let required = value.len();
    unsafe { required_byte_count.write(required) };
    if destination_byte_count < required {
        return PcpResult::BufferTooSmall;
    }
    if required != 0 {
        unsafe { ptr::copy_nonoverlapping(value.as_ptr(), destination, required) };
    }
    PcpResult::Success
}

unsafe fn required_utf8<'a>(value: *const c_char, label: &str) -> Result<&'a str, String> {
    if value.is_null() {
        return Err(format!("{label} is required."));
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map_err(|error| format!("{label} is not valid UTF-8: {error}"))
}

unsafe fn optional_utf8<'a>(value: *const c_char, label: &str) -> Result<Option<&'a str>, String> {
    if value.is_null() {
        Ok(None)
    } else {
        unsafe { required_utf8(value, label) }.map(Some)
    }
}

fn signature(value: u32) -> Signature {
    Signature::from_bytes(value.to_le_bytes())
}

fn reopen(handle: &mut PcpPackageHandle, bytes: Vec<u8>) -> Result<(), String> {
    let package = Package::from_source(Arc::new(MemoryPackageSource::new(bytes.clone())))
        .map_err(|error| error.to_string())?;
    let index = package.build_index().map_err(|error| error.to_string())?;
    handle.bytes = Some(bytes);
    handle.package = package;
    handle.index = Some(index);
    handle.dirty = true;
    Ok(())
}

fn package_index(handle: &PcpPackageHandle) -> Result<&PackageIndex, String> {
    handle
        .index
        .as_ref()
        .ok_or_else(|| "The package has not been indexed.".into())
}

fn package_bytes(handle: &PcpPackageHandle) -> Result<&[u8], String> {
    handle
        .bytes
        .as_deref()
        .ok_or_else(|| "The package was not opened for editing.".into())
}

mod cursor;
mod editing;
mod editing_engine;
mod error_api;
mod load_order;
mod metadata;
mod package;
mod record_reader;
mod streaming;

pub use cursor::*;
pub use editing::*;
pub(crate) use editing_engine::*;
pub use error_api::*;
pub use load_order::*;
pub use metadata::*;
pub use package::*;
pub use record_reader::*;
pub use streaming::*;

#[cfg(test)]
mod tests;
