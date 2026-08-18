use super::*;

#[unsafe(no_mangle)]
/// Creates a new package file and returns it as an editable handle.
///
/// # Safety
/// Pointer arguments must be valid for the documented reads/writes.
pub unsafe extern "C" fn pcp_package_create(
    path: *const c_char,
    package_id: *const u8,
    schema_namespace: *const c_char,
    package_version: *const c_char,
    output: *mut *mut PcpPackageHandle,
) -> PcpResult {
    boundary(|| {
        if package_id.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let result = (|| {
            let path = unsafe { required_utf8(path, "Package path") }?;
            let schema = unsafe { required_utf8(schema_namespace, "Schema namespace") }?;
            let version = unsafe { required_utf8(package_version, "Package version") }?;
            let mut package_id_bytes = [0; 16];
            unsafe { ptr::copy_nonoverlapping(package_id, package_id_bytes.as_mut_ptr(), 16) };
            let mut header = PackageHeader::new(PackageId::from_bytes(package_id_bytes))
                .map_err(|error| error.to_string())?;
            header.set_schema_namespace(schema);
            header.set_package_version(
                PackageVersion::parse(version).map_err(|error| error.to_string())?,
            );
            let bytes = header
                .encode(ChangeSetId::from_bytes([0; 32]))
                .map_err(|error| error.to_string())?;
            let package = Package::from_source(Arc::new(MemoryPackageSource::new(bytes.clone())))
                .map_err(|error| error.to_string())?;
            let index = package.build_index().map_err(|error| error.to_string())?;
            write_package_atomically(path, &bytes).map_err(|error| error.to_string())?;
            Ok::<_, String>((PathBuf::from(path), bytes, package, index))
        })();
        match result {
            Ok((path, bytes, package, index)) => {
                unsafe {
                    output.write(Box::into_raw(Box::new(PcpPackageHandle {
                        path,
                        bytes: Some(bytes),
                        package,
                        index: Some(index),
                        dirty: false,
                    })))
                };
                PcpResult::Success
            }
            Err(error) => {
                set_error(error);
                PcpResult::InvalidArgument
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Opens a package and transfers ownership of a new handle to `output`.
///
/// # Safety
/// `path` must point to a valid NUL-terminated string and `output` must point
/// to writable storage for one handle pointer.
pub unsafe extern "C" fn pcp_package_open(
    path: *const c_char,
    output: *mut *mut PcpPackageHandle,
) -> PcpResult {
    boundary(|| unsafe { open_package(path, output, false) })
}

#[unsafe(no_mangle)]
/// Opens a package into an indexed, mutable in-memory image for editors.
///
/// # Safety
/// Pointer arguments follow the same contract as [`pcp_package_open`].
pub unsafe extern "C" fn pcp_package_open_for_editing(
    path: *const c_char,
    output: *mut *mut PcpPackageHandle,
) -> PcpResult {
    boundary(|| unsafe { open_package(path, output, true) })
}

unsafe fn open_package(
    path: *const c_char,
    output: *mut *mut PcpPackageHandle,
    for_editing: bool,
) -> PcpResult {
    if path.is_null() || output.is_null() {
        return PcpResult::InvalidArgument;
    }
    let path = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(value) => value,
        Err(error) => {
            set_error(error.to_string());
            return PcpResult::InvalidArgument;
        }
    };
    let opened = if for_editing {
        std::fs::read(path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                let package =
                    Package::from_source(Arc::new(MemoryPackageSource::new(bytes.clone())))
                        .map_err(|error| error.to_string())?;
                let index = package.build_index().map_err(|error| error.to_string())?;
                Ok((package, Some(bytes), Some(index)))
            })
    } else {
        Package::open(path)
            .map(|package| (package, None, None))
            .map_err(|error| error.to_string())
    };
    match opened {
        Ok((package, bytes, index)) => {
            unsafe {
                output.write(Box::into_raw(Box::new(PcpPackageHandle {
                    path: PathBuf::from(path),
                    bytes,
                    package,
                    index,
                    dirty: false,
                })));
            }
            PcpResult::Success
        }
        Err(error) => {
            set_error(error);
            PcpResult::InvalidPackage
        }
    }
}

#[unsafe(no_mangle)]
/// Builds the index for a package handle.
///
/// # Safety
/// `handle` must be a live, uniquely accessed package handle.
pub unsafe extern "C" fn pcp_package_build_index(handle: *mut PcpPackageHandle) -> PcpResult {
    boundary(|| {
        if handle.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &mut *handle };
        if handle.index.is_none() {
            match handle.package.build_index() {
                Ok(index) => handle.index = Some(index),
                Err(error) => {
                    set_error(error.to_string());
                    return PcpResult::InvalidPackage;
                }
            }
        }
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Releases a package handle.
///
/// # Safety
/// `handle` must be null or a live handle returned by `pcp_package_open`. A
/// non-null handle may be destroyed exactly once.
pub unsafe extern "C" fn pcp_package_destroy(handle: *mut PcpPackageHandle) {
    if !handle.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: handle was returned by Box::into_raw and ownership is transferred exactly once.
            unsafe {
                drop(Box::from_raw(handle));
            }
        }));
    }
}

#[unsafe(no_mangle)]
/// Returns the source size of an opened package.
///
/// # Safety
/// `handle` must be a live package handle and `output` must be writable.
pub unsafe extern "C" fn pcp_package_byte_count(
    handle: *const PcpPackageHandle,
    output: *mut u64,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        // SAFETY: non-null pointers are valid for reads/writes by API contract.
        unsafe {
            output.write((*handle).package.byte_count());
        }
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Returns the number of indexed records, including the package header record.
///
/// # Safety
/// Both pointers must be valid for the documented access.
pub unsafe extern "C" fn pcp_package_record_count(
    handle: *const PcpPackageHandle,
    output: *mut usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &*handle };
        let Ok(index) = package_index(handle) else {
            return PcpResult::IndexUnavailable;
        };
        unsafe { output.write(index.record_count()) };
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Returns source-ordered indexed record metadata without reading its payload.
///
/// # Safety
/// Both pointers must be valid for the documented access.
pub unsafe extern "C" fn pcp_package_indexed_record(
    handle: *const PcpPackageHandle,
    index: usize,
    output: *mut PcpIndexedRecord,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &*handle };
        let Ok(package_index) = package_index(handle) else {
            return PcpResult::IndexUnavailable;
        };
        let Some(record) = package_index.record_at(index) else {
            return PcpResult::EndOfRecords;
        };
        unsafe { output.write(indexed_record(record)) };
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Returns the indexed group count.
///
/// # Safety
/// `handle` must be live and `output` must be writable.
pub unsafe extern "C" fn pcp_package_group_count(
    handle: *const PcpPackageHandle,
    output: *mut usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &*handle };
        let Ok(index) = package_index(handle) else {
            return PcpResult::IndexUnavailable;
        };
        unsafe { output.write(index.groups().len()) };
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Copies one indexed group descriptor.
///
/// # Safety
/// `handle` must be live and `output` must be writable.
pub unsafe extern "C" fn pcp_package_indexed_group(
    handle: *const PcpPackageHandle,
    index: usize,
    output: *mut PcpIndexedGroup,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let handle = unsafe { &*handle };
        let Ok(package_index) = package_index(handle) else {
            return PcpResult::IndexUnavailable;
        };
        let Some(group) = package_index.groups().get(index) else {
            return PcpResult::EndOfRecords;
        };
        unsafe { output.write(indexed_group(group)) };
        PcpResult::Success
    })
}
