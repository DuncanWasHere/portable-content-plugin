use super::*;

#[unsafe(no_mangle)]
/// Reads and buffers the record beginning exactly at `offset`.
///
/// # Safety
/// `handle` must be live. Both output pointers must be valid and writable;
/// ownership of the returned reader handle transfers to the caller.
pub unsafe extern "C" fn pcp_package_read_record_at(
    handle: *const PcpPackageHandle,
    offset: u64,
    output_reader: *mut *mut PcpRecordReaderHandle,
    output_header: *mut PcpRecordHeader,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output_reader.is_null() || output_header.is_null() {
            return PcpResult::InvalidArgument;
        }
        // SAFETY: handle is valid by API contract.
        let package = unsafe { &(*handle).package };
        let mut cursor = match package.reader_with_range(offset, package.byte_count()) {
            Ok(value) => value,
            Err(error) => {
                set_error(error.to_string());
                return PcpResult::InvalidArgument;
            }
        };
        let view = match cursor.next_record() {
            Ok(Some(value)) => value,
            Ok(None) => return PcpResult::EndOfRecords,
            Err(error) => {
                set_error(error.to_string());
                return PcpResult::InvalidPackage;
            }
        };
        let header = view.header();
        let reader = match view.read() {
            Ok(value) => value,
            Err(error) => {
                set_error(error.to_string());
                return PcpResult::InputOutputError;
            }
        };
        // SAFETY: output pointers are writable by API contract.
        unsafe {
            output_header.write(header.into());
            output_reader.write(Box::into_raw(Box::new(PcpRecordReaderHandle { reader })));
        }
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Releases a record-reader handle.
///
/// # Safety
/// `handle` must be null or a live reader returned by
/// `pcp_package_read_record_at`, and may be destroyed exactly once.
pub unsafe extern "C" fn pcp_record_reader_destroy(handle: *mut PcpRecordReaderHandle) {
    if !handle.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: handle ownership is transferred exactly once.
            unsafe {
                drop(Box::from_raw(handle));
            }
        }));
    }
}

#[unsafe(no_mangle)]
/// Advances to the next subrecord.
///
/// # Safety
/// `handle` must be a live, exclusively accessed reader and `output` must be
/// valid writable storage.
pub unsafe extern "C" fn pcp_record_reader_next_subrecord(
    handle: *mut PcpRecordReaderHandle,
    output: *mut PcpSubrecordHeader,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        // SAFETY: pointers are valid and exclusively borrowed by API contract.
        match unsafe { (*handle).reader.next_subrecord() } {
            Ok(Some(header)) => {
                unsafe {
                    output.write(header.into());
                }
                PcpResult::Success
            }
            Ok(None) => PcpResult::EndOfSubrecords,
            Err(error) => {
                set_error(error.to_string());
                PcpResult::InvalidPackage
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Copies the selected subrecord payload into caller-owned storage.
///
/// # Safety
/// `handle` and `required_byte_count` must be valid. If `destination` is
/// non-null, it must reference at least `destination_byte_count` writable
/// bytes and must not overlap the reader's internal storage.
pub unsafe extern "C" fn pcp_record_reader_copy_current_subrecord_payload(
    handle: *const PcpRecordReaderHandle,
    destination: *mut u8,
    destination_byte_count: usize,
    required_byte_count: *mut usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || required_byte_count.is_null() {
            return PcpResult::InvalidArgument;
        }
        // SAFETY: handle is valid by API contract.
        let payload = match unsafe { (*handle).reader.current_subrecord_payload() } {
            Ok(value) => value,
            Err(error) => {
                set_error(error.to_string());
                return PcpResult::InvalidArgument;
            }
        };
        unsafe {
            required_byte_count.write(payload.len());
        }
        if destination_byte_count < payload.len() {
            return PcpResult::BufferTooSmall;
        }
        if !payload.is_empty() {
            if destination.is_null() {
                return PcpResult::InvalidArgument;
            }
            // SAFETY: destination has at least payload.len() writable bytes by API contract.
            unsafe {
                ptr::copy_nonoverlapping(payload.as_ptr(), destination, payload.len());
            }
        }
        PcpResult::Success
    })
}
