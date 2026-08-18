use super::*;

#[unsafe(no_mangle)]
/// Replaces subrecord payload in an editable package handle.
///
/// # Safety
/// `handle` must be live. A non-null `payload` must reference
/// `payload_byte_count` readable bytes for the duration of the call.
pub unsafe extern "C" fn pcp_package_replace_subrecord(
    handle: *mut PcpPackageHandle,
    record_id: u32,
    field_signature: u32,
    occurrence: usize,
    payload: *const u8,
    payload_byte_count: usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || (payload.is_null() && payload_byte_count != 0) {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &mut *handle };
        let payload = if payload_byte_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(payload, payload_byte_count) }
        };
        let result = (|| {
            let id = RecordId::from_raw(record_id);
            let record = package_index(handle)?
                .record(id)
                .cloned()
                .ok_or("Record does not exist.")?;
            let payload_start = record.payload_offset() as usize;
            let payload_end = payload_start + record.header().payload_byte_count() as usize;
            let current = &package_bytes(handle)?[payload_start..payload_end];
            let range = subrecord_ranges(current)?
                .into_iter()
                .filter(|(candidate, _)| *candidate == signature(field_signature))
                .nth(occurrence)
                .map(|(_, range)| range)
                .ok_or("Subrecord occurrence does not exist.")?;
            let mut updated_payload = current.to_vec();
            updated_payload.splice(range, frame_subrecord(signature(field_signature), payload)?);
            let header = RecordHeader::new(
                record.header().signature(),
                u32::try_from(updated_payload.len()).map_err(|_| "Record payload is too large.")?,
                record.header().flags(),
                id,
                record.header().version(),
                record.header().last_change_set(),
            )
            .map_err(|error| error.to_string())?;
            let mut replacement = header.to_bytes().to_vec();
            replacement.extend(updated_payload);
            replace_record(
                package_bytes(handle)?,
                package_index(handle)?,
                id,
                Some(&replacement),
            )
        })();
        match result.and_then(|bytes| reopen(handle, bytes)) {
            Ok(()) => PcpResult::Success,
            Err(error) => {
                set_error(error);
                PcpResult::InvalidPackage
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Replaces the entire payload (all subrecords) of an existing record.
///
/// # Safety
/// `handle` must be live and editable. A non-null `payload` must reference
/// `payload_byte_count` readable bytes for the duration of the call.
pub unsafe extern "C" fn pcp_package_replace_record_payload(
    handle: *mut PcpPackageHandle,
    record_id: u32,
    payload: *const u8,
    payload_byte_count: usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || (payload.is_null() && payload_byte_count != 0) {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &mut *handle };
        let payload = if payload_byte_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(payload, payload_byte_count) }
        };
        let result = (|| {
            subrecord_ranges(payload)?;
            let id = RecordId::from_raw(record_id);
            let record = package_index(handle)?
                .record(id)
                .cloned()
                .ok_or("Record does not exist.")?;
            let header = RecordHeader::new(
                record.header().signature(),
                u32::try_from(payload.len()).map_err(|_| "Record payload is too large.")?,
                record.header().flags(),
                id,
                record.header().version(),
                record.header().last_change_set(),
            )
            .map_err(|error| error.to_string())?;
            let mut replacement = header.to_bytes().to_vec();
            replacement.extend_from_slice(payload);
            replace_record(
                package_bytes(handle)?,
                package_index(handle)?,
                id,
                Some(&replacement),
            )
        })();
        match result.and_then(|bytes| reopen(handle, bytes)) {
            Ok(()) => PcpResult::Success,
            Err(error) => {
                set_error(error);
                PcpResult::InvalidPackage
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Inserts a record at the end of a group, or at package root for `u64::MAX`.
///
/// # Safety
/// `handle` must be live and editable, `output_record_id` writable, and a
/// non-null `payload` must reference `payload_byte_count` readable bytes.
pub unsafe extern "C" fn pcp_package_insert_record(
    handle: *mut PcpPackageHandle,
    target_group_offset: u64,
    record_signature: u32,
    payload: *const u8,
    payload_byte_count: usize,
    output_record_id: *mut u32,
) -> PcpResult {
    boundary(|| {
        if handle.is_null()
            || output_record_id.is_null()
            || (payload.is_null() && payload_byte_count != 0)
        {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &mut *handle };
        let payload = if payload_byte_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(payload, payload_byte_count) }
        };
        match insert_record(handle, target_group_offset, record_signature, payload, None) {
            Ok(id) => {
                unsafe { output_record_id.write(id.raw()) };
                PcpResult::Success
            }
            Err(error) => {
                set_error(error);
                PcpResult::InvalidPackage
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Inserts a record using an explicit ID, for overrides and undo.
///
/// # Safety
/// `handle` must be live and editable. A non-null `payload` must reference
/// `payload_byte_count` readable bytes for the duration of the call.
pub unsafe extern "C" fn pcp_package_insert_record_with_id(
    handle: *mut PcpPackageHandle,
    target_group_offset: u64,
    record_signature: u32,
    record_id: u32,
    payload: *const u8,
    payload_byte_count: usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || (payload.is_null() && payload_byte_count != 0) {
            return PcpResult::InvalidArgument;
        }
        let payload = if payload_byte_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(payload, payload_byte_count) }
        };
        match insert_record(
            unsafe { &mut *handle },
            target_group_offset,
            record_signature,
            payload,
            Some(RecordId::from_raw(record_id)),
        ) {
            Ok(_) => PcpResult::Success,
            Err(error) => {
                set_error(error);
                PcpResult::InvalidPackage
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Applies record replacements, insertions, and deletions as one package rewrite.
///
/// # Safety
/// `handle` must be a live editable handle. `mutations` must reference
/// `mutation_count` readable entries, and every non-empty payload must remain
/// readable for the duration of this call.
pub unsafe extern "C" fn pcp_package_apply_record_batch(
    handle: *mut PcpPackageHandle,
    mutations: *const PcpRecordMutation,
    mutation_count: usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || (mutations.is_null() && mutation_count != 0) {
            return PcpResult::InvalidArgument;
        }
        let mutations = if mutation_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(mutations, mutation_count) }
        };
        match apply_record_batch(unsafe { &mut *handle }, mutations) {
            Ok(()) => PcpResult::Success,
            Err(error) => {
                set_error(error);
                PcpResult::InvalidPackage
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Removes a record from an editable package handle (can't be the package header).
///
/// # Safety
/// `handle` must be a live, uniquely accessed editable package handle.
pub unsafe extern "C" fn pcp_package_remove_record(
    handle: *mut PcpPackageHandle,
    record_id: u32,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || record_id == 0 {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &mut *handle };
        let result = (|| {
            let id = RecordId::from_raw(record_id);
            let bytes = replace_record(package_bytes(handle)?, package_index(handle)?, id, None)?;
            let mut package_header = handle.package.header().clone();
            package_header.set_record_count(package_header.record_count().saturating_sub(1));
            let owned_index = handle.package.header().dependencies().len() as u8;
            if id.package_index() == owned_index {
                package_header
                    .set_owned_record_count(package_header.owned_record_count().saturating_sub(1));
            }
            let bytes = rewrite_package_header(bytes, &handle.package, &package_header)?;
            reopen(handle, bytes)
        })();
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
/// Reports whether the in-memory package differs from its last save.
///
/// # Safety
/// `handle` must be live and `output` must be writable.
pub unsafe extern "C" fn pcp_package_is_dirty(
    handle: *const PcpPackageHandle,
    output: *mut u8,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        unsafe { output.write(u8::from((*handle).dirty)) };
        PcpResult::Success
    })
}

fn save_handle(handle: &mut PcpPackageHandle, path: PathBuf) -> PcpResult {
    if let Err(error) = rebuild_scene_offsets(handle) {
        set_error(error);
        return PcpResult::InvalidPackage;
    }
    let bytes = match package_bytes(handle) {
        Ok(bytes) => bytes,
        Err(error) => {
            set_error(error);
            return PcpResult::NotEditable;
        }
    };
    match write_package_atomically(&path, bytes) {
        Ok(()) => {
            handle.path = path;
            handle.dirty = false;
            PcpResult::Success
        }
        Err(error) => {
            set_error(error.to_string());
            PcpResult::InputOutputError
        }
    }
}

#[unsafe(no_mangle)]
/// Atomically saves the package to its current path.
///
/// # Safety
/// `handle` must be a live, uniquely accessed package handle.
pub unsafe extern "C" fn pcp_package_save(handle: *mut PcpPackageHandle) -> PcpResult {
    boundary(|| {
        if handle.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &mut *handle };
        save_handle(handle, handle.path.clone())
    })
}

#[unsafe(no_mangle)]
/// Atomically saves the package to a new path and adopts that path.
///
/// # Safety
/// `handle` must be live and `path` must be a valid NUL-terminated UTF-8 string.
pub unsafe extern "C" fn pcp_package_save_as(
    handle: *mut PcpPackageHandle,
    path: *const c_char,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || path.is_null() {
            return PcpResult::InvalidArgument;
        }
        let path = match unsafe { CStr::from_ptr(path) }.to_str() {
            Ok(path) => PathBuf::from(path),
            Err(error) => {
                set_error(error.to_string());
                return PcpResult::InvalidArgument;
            }
        };
        save_handle(unsafe { &mut *handle }, path)
    })
}
