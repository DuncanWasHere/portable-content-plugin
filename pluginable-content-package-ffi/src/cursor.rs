use super::*;

#[unsafe(no_mangle)]
/// Creates a depth-controlled cursor over package content.
///
/// The cursor begins after PKHD. Groups are skipped unless the caller invokes
/// [`pcp_package_cursor_enter_group`] immediately after receiving them.
///
/// # Safety
/// Both pointers must be valid for the documented access.
pub unsafe extern "C" fn pcp_package_cursor_create(
    handle: *const PcpPackageHandle,
    output: *mut *mut PcpPackageCursorHandle,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let reader = unsafe { &(*handle).package }.content_reader();
        unsafe {
            output.write(Box::into_raw(Box::new(PcpPackageCursorHandle {
                readers: vec![reader],
                pending_group: None,
            })))
        };
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Returns the next record or group header in the currently entered ranges.
///
/// # Safety
/// The cursor and all output pointers must be valid.
pub unsafe extern "C" fn pcp_package_cursor_next(
    handle: *mut PcpPackageCursorHandle,
    output_kind: *mut PcpPackageEntryKind,
    output_record: *mut PcpIndexedRecord,
    output_group: *mut PcpIndexedGroup,
) -> PcpResult {
    boundary(|| {
        if handle.is_null()
            || output_kind.is_null()
            || output_record.is_null()
            || output_group.is_null()
        {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &mut *handle };
        handle.pending_group = None;
        loop {
            let Some(reader) = handle.readers.last_mut() else {
                return PcpResult::EndOfRecords;
            };
            match reader.next_entry() {
                Ok(Some(PackageEntry::Record(record))) => {
                    unsafe {
                        output_kind.write(PcpPackageEntryKind::Record);
                        output_record.write(indexed_record(&record));
                        output_group.write(PcpIndexedGroup::default());
                    }
                    return PcpResult::Success;
                }
                Ok(Some(PackageEntry::Group(group))) => {
                    unsafe {
                        output_kind.write(PcpPackageEntryKind::Group);
                        output_record.write(PcpIndexedRecord::default());
                        output_group.write(indexed_group(&group));
                    }
                    handle.pending_group = Some(group);
                    return PcpResult::Success;
                }
                Ok(None) => {
                    handle.readers.pop();
                }
                Err(error) => {
                    set_error(error.to_string());
                    return PcpResult::InvalidPackage;
                }
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Enters the group returned by the preceding cursor step.
///
/// # Safety
/// `handle` must be a live, uniquely accessed package cursor.
pub unsafe extern "C" fn pcp_package_cursor_enter_group(
    handle: *mut PcpPackageCursorHandle,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &mut *handle };
        let Some(group) = handle.pending_group.take() else {
            set_error("The cursor has no pending group to enter.");
            return PcpResult::InvalidArgument;
        };
        match group.children() {
            Ok(reader) => {
                handle.readers.push(reader);
                PcpResult::Success
            }
            Err(error) => {
                set_error(error.to_string());
                PcpResult::InvalidPackage
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Releases a package cursor.
///
/// # Safety
/// The handle must be null or a live uniquely owned cursor handle.
pub unsafe extern "C" fn pcp_package_cursor_destroy(handle: *mut PcpPackageCursorHandle) {
    if !handle.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe { drop(Box::from_raw(handle)) }));
    }
}
