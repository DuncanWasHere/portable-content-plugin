use super::*;

#[unsafe(no_mangle)]
/// Builds load order by opening the file paths in order.
///
/// # Safety
/// `paths` must point to `path_count` valid NUL-terminated UTF-8 strings and
/// `output` must be writable. The returned handle transfers to the caller.
pub unsafe extern "C" fn pcp_load_order_open(
    paths: *const *const c_char,
    path_count: usize,
    output: *mut *mut PcpLoadOrderHandle,
) -> PcpResult {
    boundary(|| unsafe { open_load_order(paths, path_count, output, false) })
}

#[unsafe(no_mangle)]
/// Opens a load order using editor compatibility policy.
///
/// # Safety
/// Paths and output must satisfy the same contract as `pcp_load_order_open`.
pub unsafe extern "C" fn pcp_load_order_open_for_editor(
    paths: *const *const c_char,
    path_count: usize,
    output: *mut *mut PcpLoadOrderHandle,
) -> PcpResult {
    boundary(|| unsafe { open_load_order(paths, path_count, output, true) })
}

unsafe fn open_load_order(
    paths: *const *const c_char,
    path_count: usize,
    output: *mut *mut PcpLoadOrderHandle,
    allow_incompatible: bool,
) -> PcpResult {
    if paths.is_null() || output.is_null() || path_count == 0 {
        return PcpResult::InvalidArgument;
    }
    let mut packages = Vec::with_capacity(path_count);
    for index in 0..path_count {
        let path_pointer = unsafe { paths.add(index).read() };
        if path_pointer.is_null() {
            return PcpResult::InvalidArgument;
        }
        let path = match unsafe { CStr::from_ptr(path_pointer) }.to_str() {
            Ok(value) => value,
            Err(error) => {
                set_error(error.to_string());
                return PcpResult::InvalidArgument;
            }
        };
        match Package::open(path) {
            Ok(package) => packages.push(Arc::new(package)),
            Err(error) => {
                set_error(format!(
                    "Could not open load-order package {index}: {error}"
                ));
                return PcpResult::InvalidPackage;
            }
        }
    }
    let built = if allow_incompatible {
        LoadOrder::build_for_editor(packages)
    } else {
        LoadOrder::build(packages)
    };
    match built {
        Ok(load_order) => {
            let record_index = if allow_incompatible {
                match load_order.build_record_index() {
                    Ok(index) => Some(index),
                    Err(error) => {
                        set_error(error.to_string());
                        return PcpResult::InvalidPackage;
                    }
                }
            } else {
                None
            };
            let mut runtime_ids: Vec<_> = record_index
                .as_ref()
                .into_iter()
                .flat_map(LoadOrderRecordIndex::records)
                .map(|chain| chain.runtime_id())
                .collect();
            runtime_ids.sort_unstable();
            unsafe {
                output.write(Box::into_raw(Box::new(PcpLoadOrderHandle {
                    load_order,
                    record_index,
                    runtime_ids,
                })))
            };
            PcpResult::Success
        }
        Err(error) => {
            set_error(error.to_string());
            PcpResult::InvalidPackage
        }
    }
}

#[unsafe(no_mangle)]
/// Builds the complete override-chain index for a load order.
///
/// # Safety
/// `handle` must be a live, uniquely accessed load-order handle.
pub unsafe extern "C" fn pcp_load_order_build_record_index(
    handle: *mut PcpLoadOrderHandle,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &mut *handle };
        if handle.record_index.is_none() {
            match handle.load_order.build_record_index() {
                Ok(index) => handle.record_index = Some(index),
                Err(error) => {
                    set_error(error.to_string());
                    return PcpResult::InvalidPackage;
                }
            }
        }
        handle.runtime_ids = handle
            .record_index
            .as_ref()
            .expect("record index was just initialized")
            .records()
            .map(|chain| chain.runtime_id())
            .collect();
        handle.runtime_ids.sort_unstable();
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Returns the number of winning runtime records.
///
/// # Safety
/// `handle` must be live and `output` writable.
pub unsafe extern "C" fn pcp_load_order_record_count(
    handle: *const PcpLoadOrderHandle,
    output: *mut usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &*handle };
        if handle.record_index.is_none() {
            return PcpResult::IndexUnavailable;
        }
        unsafe { output.write(handle.runtime_ids.len()) };
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Returns a sorted winning record and its runtime ID.
///
/// # Safety
/// The handle and both output pointers must be valid.
pub unsafe extern "C" fn pcp_load_order_winning_record_at(
    handle: *const PcpLoadOrderHandle,
    index: usize,
    output_runtime_record_id: *mut u32,
    output_origin: *mut PcpRecordOrigin,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output_runtime_record_id.is_null() || output_origin.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &*handle };
        let Some(runtime_id) = handle.runtime_ids.get(index).copied() else {
            return PcpResult::EndOfRecords;
        };
        let origin = handle
            .record_index
            .as_ref()
            .ok_or(PcpResult::IndexUnavailable)
            .and_then(|index| {
                index
                    .winning_record(runtime_id)
                    .ok_or(PcpResult::EndOfRecords)
            });
        let origin = match origin {
            Ok(origin) => origin,
            Err(result) => return result,
        };
        unsafe {
            output_runtime_record_id.write(runtime_id.raw());
            output_origin.write(PcpRecordOrigin {
                package_index: origin.package_index(),
                record: indexed_record(origin.record()),
            });
        }
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Resolves one package-relative serialized record ID.
///
/// # Safety
/// The handle must be live and the output pointer writable.
pub unsafe extern "C" fn pcp_load_order_resolve_record_id(
    handle: *const PcpLoadOrderHandle,
    package_index: usize,
    serialized_record_id: u32,
    output_runtime_record_id: *mut u32,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output_runtime_record_id.is_null() {
            return PcpResult::InvalidArgument;
        }
        match unsafe { &(*handle).load_order }
            .resolve_record_id(package_index, RecordId::from_raw(serialized_record_id))
        {
            Ok(value) => {
                unsafe { output_runtime_record_id.write(value.raw()) };
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
/// Releases a load-order handle.
///
/// # Safety
/// The handle must be null or a live uniquely-owned ABI handle.
pub unsafe extern "C" fn pcp_load_order_destroy(handle: *mut PcpLoadOrderHandle) {
    if !handle.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe { drop(Box::from_raw(handle)) }));
    }
}

#[unsafe(no_mangle)]
/// Returns the number of origins participating in a runtime record's override chain.
///
/// # Safety
/// Both pointers must be valid for the documented access.
pub unsafe extern "C" fn pcp_load_order_override_count(
    handle: *const PcpLoadOrderHandle,
    runtime_record_id: u32,
    output: *mut usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &*handle };
        let Some(record_index) = handle.record_index.as_ref() else {
            return PcpResult::IndexUnavailable;
        };
        let count = record_index
            .override_chain(RuntimeRecordId::from_raw(runtime_record_id))
            .map_or(0, |chain| chain.origins().len());
        unsafe { output.write(count) };
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Returns one source-ordered origin from a runtime record's override chain.
///
/// # Safety
/// Both pointers must be valid for the documented access.
pub unsafe extern "C" fn pcp_load_order_override_origin(
    handle: *const PcpLoadOrderHandle,
    runtime_record_id: u32,
    origin_index: usize,
    output: *mut PcpRecordOrigin,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &*handle };
        let Some(record_index) = handle.record_index.as_ref() else {
            return PcpResult::IndexUnavailable;
        };
        let Some(origin) = record_index
            .override_chain(RuntimeRecordId::from_raw(runtime_record_id))
            .and_then(|chain| chain.origins().get(origin_index))
        else {
            return PcpResult::EndOfRecords;
        };
        unsafe {
            output.write(PcpRecordOrigin {
                package_index: origin.package_index(),
                record: indexed_record(origin.record()),
            })
        };
        PcpResult::Success
    })
}
