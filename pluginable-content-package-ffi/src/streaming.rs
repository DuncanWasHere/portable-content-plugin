use super::*;

#[unsafe(no_mangle)]
/// Returns the number of record IDs in the package header's streaming-override list.
///
/// # Safety
/// `handle` must be live and `output` must be writable.
pub unsafe extern "C" fn pcp_package_streaming_override_count(
    handle: *const PcpPackageHandle,
    output: *mut usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let count = unsafe { (*handle).package.header().streaming_overrides().len() };
        unsafe { output.write(count) };
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Returns one serialized record ID from the streaming-override list.
///
/// # Safety
/// `handle` must be live and `output` must be writable.
pub unsafe extern "C" fn pcp_package_streaming_override_at(
    handle: *const PcpPackageHandle,
    index: usize,
    output: *mut u32,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let Some(id) = (unsafe { (*handle).package.header().streaming_overrides().get(index) })
        else {
            return PcpResult::EndOfRecords;
        };
        unsafe { output.write(id.raw()) };
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Replaces the package header's streaming-override list.
///
/// # Safety
/// `handle` must be live. When `count` is nonzero, `record_ids` must point to
/// `count` readable `u32` values.
pub unsafe extern "C" fn pcp_package_replace_streaming_overrides(
    handle: *mut PcpPackageHandle,
    record_ids: *const u32,
    count: usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || (record_ids.is_null() && count != 0) {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &mut *handle };
        let ids = if count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(record_ids, count) }
        };
        let mut header = handle.package.header().clone();
        header.replace_streaming_overrides(ids.iter().copied().map(RecordId::from_raw).collect());
        let result = package_bytes(handle)
            .map(ToOwned::to_owned)
            .and_then(|bytes| rewrite_package_header(bytes, &handle.package, &header))
            .and_then(|bytes| reopen(handle, bytes));
        match result {
            Ok(()) => PcpResult::Success,
            Err(error) => {
                set_error(error);
                PcpResult::InvalidPackage
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Returns the total number of serialized temporary-scene offsets in PKHD.
///
/// # Safety
/// `handle` must be live and `output` writable.
pub unsafe extern "C" fn pcp_package_scene_offset_count(
    handle: *const PcpPackageHandle,
    output: *mut usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let count = unsafe { (*handle).package.header() }
            .scene_offset_tables()
            .iter()
            .map(|table| table.offsets().len())
            .sum();
        unsafe { output.write(count) };
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Returns one serialized temporary-scene offset, flattened across world tables.
///
/// # Safety
/// `handle` must be live and `output` writable.
pub unsafe extern "C" fn pcp_package_scene_offset_at(
    handle: *const PcpPackageHandle,
    index: usize,
    output: *mut PcpSceneOffset,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let Some((table, offset)) = (unsafe { (*handle).package.header() })
            .scene_offset_tables()
            .iter()
            .flat_map(|table| table.offsets().iter().map(move |offset| (table, offset)))
            .nth(index)
        else {
            return PcpResult::EndOfRecords;
        };
        unsafe {
            output.write(PcpSceneOffset {
                world_record_id: table.world_id().map_or(0, RecordId::raw),
                scene_record_id: offset.scene_id().raw(),
                start_offset: offset.start_offset(),
                end_offset: offset.end_offset(),
            })
        };
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Rebuilds serialized per-world temporary-scene offsets from the index.
///
/// # Safety
/// `handle` must be a live, uniquely accessed editable package handle.
pub unsafe extern "C" fn pcp_package_rebuild_scene_offsets(
    handle: *mut PcpPackageHandle,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &mut *handle };
        if handle.bytes.is_none() {
            return PcpResult::NotEditable;
        }
        match rebuild_scene_offsets(handle) {
            Ok(()) => PcpResult::Success,
            Err(error) => {
                set_error(error);
                PcpResult::InvalidPackage
            }
        }
    })
}
