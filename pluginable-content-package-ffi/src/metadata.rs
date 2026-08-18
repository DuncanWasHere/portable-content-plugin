use super::*;

#[unsafe(no_mangle)]
/// Returns fixed-size package metadata and relationship counts.
///
/// # Safety
/// `handle` must be live and `output` writable.
pub unsafe extern "C" fn pcp_package_metadata(
    handle: *const PcpPackageHandle,
    output: *mut PcpPackageMetadata,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let header = unsafe { (*handle).package.header() };
        let metadata = PcpPackageMetadata {
            format_version: header.format_version(),
            package_id: header.package_id().bytes(),
            load_class: match header.load_class() {
                PackageLoadClass::Full => 0,
                PackageLoadClass::Compact => 1,
                PackageLoadClass::Overlay => 2,
            },
            has_package_version: 1,
            reserved: [0; 2],
            next_local_identifier: header.next_local_identifier(),
            record_count: header.record_count(),
            owned_record_count: header.owned_record_count(),
            dependency_count: header.dependencies().len(),
            incompatibility_count: header.incompatibilities().len(),
        };
        unsafe { output.write(metadata) };
        PcpResult::Success
    })
}

#[unsafe(no_mangle)]
/// Copies the package version without a null terminator.
///
/// # Safety
/// Pointer arguments must satisfy the buffer contract documented in the C header.
pub unsafe extern "C" fn pcp_package_copy_version(
    handle: *const PcpPackageHandle,
    destination: *mut u8,
    destination_byte_count: usize,
    required_byte_count: *mut usize,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() {
            return PcpResult::InvalidArgument;
        }
        let value = unsafe { (*handle).package.header() }
            .package_version()
            .to_string();
        copy_text(
            &value,
            destination,
            destination_byte_count,
            required_byte_count,
        )
    })
}

macro_rules! package_text_function {
    ($name:ident, $accessor:ident) => {
        #[unsafe(no_mangle)]
        /// Copies a UTF-8 package header string without a null terminator.
        ///
        /// # Safety
        /// The handle and buffer pointers must satisfy the public C ABI contract.
        pub unsafe extern "C" fn $name(
            handle: *const PcpPackageHandle,
            destination: *mut u8,
            destination_byte_count: usize,
            required_byte_count: *mut usize,
        ) -> PcpResult {
            boundary(|| {
                if handle.is_null() {
                    return PcpResult::InvalidArgument;
                }
                copy_text(
                    unsafe { (*handle).package.header() }.$accessor(),
                    destination,
                    destination_byte_count,
                    required_byte_count,
                )
            })
        }
    };
}

package_text_function!(pcp_package_copy_author, author);
package_text_function!(pcp_package_copy_description, description);
package_text_function!(pcp_package_copy_schema_namespace, schema_namespace);

#[unsafe(no_mangle)]
/// Rewrites mutable package-header metadata without changing the package ID or records.
///
/// # Safety
/// `handle` must be live and all strings must be valid null-terminated UTF-8.
pub unsafe extern "C" fn pcp_package_set_metadata(
    handle: *mut PcpPackageHandle,
    package_version: *const c_char,
    author: *const c_char,
    description: *const c_char,
    schema_namespace: *const c_char,
    load_class: u8,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() {
            return PcpResult::InvalidArgument;
        }
        let result = (|| {
            let version = unsafe { required_utf8(package_version, "Package version") }?;
            let author = unsafe { required_utf8(author, "Author") }?;
            let description = unsafe { required_utf8(description, "Description") }?;
            let schema = unsafe { required_utf8(schema_namespace, "Schema namespace") }?;
            let class = match load_class {
                0 => PackageLoadClass::Full,
                1 => PackageLoadClass::Compact,
                2 => PackageLoadClass::Overlay,
                _ => return Err(format!("Unknown package load class {load_class}.")),
            };
            let handle = unsafe { &mut *handle };
            let mut header = handle.package.header().clone();
            header.set_package_version(
                PackageVersion::parse(version).map_err(|error| error.to_string())?,
            );
            header.set_author(author);
            header.set_description(description);
            header.set_schema_namespace(schema);
            header.set_load_class(class);
            let bytes =
                rewrite_package_header(package_bytes(handle)?.to_vec(), &handle.package, &header)?;
            reopen(handle, bytes)
        })();
        match result {
            Ok(()) => PcpResult::Success,
            Err(error) => {
                set_error(error);
                PcpResult::InvalidArgument
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Adds one dependency to the end of the package header.
///
/// Existing record IDs must be remapped by the caller before loading or saving records
/// after the relationship count changes.
///
/// # Safety
/// The handle must be live and all pointer arguments valid for the call.
pub unsafe extern "C" fn pcp_package_add_dependency(
    handle: *mut PcpPackageHandle,
    package_id: *const u8,
    name: *const c_char,
    version_requirement: *const c_char,
) -> PcpResult {
    unsafe { mutate_relationship(handle, package_id, name, version_requirement, false) }
}

#[unsafe(no_mangle)]
/// Adds an incompatibility relationship.
///
/// # Safety
/// The handle must be live and all pointer arguments valid for the call.
pub unsafe extern "C" fn pcp_package_add_incompatibility(
    handle: *mut PcpPackageHandle,
    package_id: *const u8,
    name: *const c_char,
    version_requirement: *const c_char,
) -> PcpResult {
    unsafe { mutate_relationship(handle, package_id, name, version_requirement, true) }
}

unsafe fn mutate_relationship(
    handle: *mut PcpPackageHandle,
    package_id: *const u8,
    name: *const c_char,
    version_requirement: *const c_char,
    incompatibility: bool,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || package_id.is_null() {
            return PcpResult::InvalidArgument;
        }
        let result = (|| {
            let name = unsafe { required_utf8(name, "Relationship name") }?;
            let requirement = unsafe { optional_utf8(version_requirement, "Version requirement") }?
                .filter(|value| !value.is_empty())
                .map(PackageVersionRequirement::parse)
                .transpose()
                .map_err(|error| error.to_string())?;
            let mut package_id_bytes = [0; 16];
            unsafe { ptr::copy_nonoverlapping(package_id, package_id_bytes.as_mut_ptr(), 16) };
            let package_id = PackageId::from_bytes(package_id_bytes);
            let handle = unsafe { &mut *handle };
            let mut header = handle.package.header().clone();
            if incompatibility {
                let mut value = PackageIncompatibility::new(package_id, name)
                    .map_err(|error| error.to_string())?;
                value.set_version_requirement(requirement);
                header
                    .add_incompatibility(value)
                    .map_err(|error| error.to_string())?;
            } else {
                let mut value =
                    PackageDependency::new(package_id, name).map_err(|error| error.to_string())?;
                value.set_version_requirement(requirement);
                header
                    .add_dependency(value)
                    .map_err(|error| error.to_string())?;
            }
            let bytes =
                rewrite_package_header(package_bytes(handle)?.to_vec(), &handle.package, &header)?;
            reopen(handle, bytes)
        })();
        match result {
            Ok(()) => PcpResult::Success,
            Err(error) => {
                set_error(error);
                PcpResult::InvalidArgument
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Removes a dependency relationship.
///
/// # Safety
/// The handle and 16-byte package-ID pointer must be valid.
pub unsafe extern "C" fn pcp_package_remove_dependency(
    handle: *mut PcpPackageHandle,
    package_id: *const u8,
) -> PcpResult {
    unsafe { remove_relationship(handle, package_id, false) }
}

#[unsafe(no_mangle)]
/// Removes an incompatibility relationship.
///
/// # Safety
/// The handle and 16-byte package-ID pointer must be valid.
pub unsafe extern "C" fn pcp_package_remove_incompatibility(
    handle: *mut PcpPackageHandle,
    package_id: *const u8,
) -> PcpResult {
    unsafe { remove_relationship(handle, package_id, true) }
}

unsafe fn remove_relationship(
    handle: *mut PcpPackageHandle,
    package_id: *const u8,
    incompatibility: bool,
) -> PcpResult {
    boundary(|| {
        if handle.is_null() || package_id.is_null() {
            return PcpResult::InvalidArgument;
        }
        let mut package_id_bytes = [0; 16];
        unsafe { ptr::copy_nonoverlapping(package_id, package_id_bytes.as_mut_ptr(), 16) };
        let handle = unsafe { &mut *handle };
        let mut header = handle.package.header().clone();
        let removed = if incompatibility {
            header.remove_incompatibility(PackageId::from_bytes(package_id_bytes))
        } else {
            header.remove_dependency(PackageId::from_bytes(package_id_bytes))
        };
        if !removed {
            set_error("Relationship was not present.");
            return PcpResult::InvalidArgument;
        }
        match package_bytes(handle)
            .map(ToOwned::to_owned)
            .and_then(|bytes| rewrite_package_header(bytes, &handle.package, &header))
            .and_then(|bytes| reopen(handle, bytes))
        {
            Ok(()) => PcpResult::Success,
            Err(error) => {
                set_error(error);
                PcpResult::InvalidPackage
            }
        }
    })
}

#[unsafe(no_mangle)]
/// Evaluates a version requirement.
///
/// # Safety
/// Both strings must be valid null-terminated UTF-8 and `output` writable.
pub unsafe extern "C" fn pcp_version_requirement_matches(
    version_requirement: *const c_char,
    package_version: *const c_char,
    output: *mut u8,
) -> PcpResult {
    boundary(|| {
        if output.is_null() {
            return PcpResult::InvalidArgument;
        }
        let result = (|| {
            let requirement = PackageVersionRequirement::parse(unsafe {
                required_utf8(version_requirement, "Version requirement")?
            })
            .map_err(|error| error.to_string())?;
            let version = PackageVersion::parse(unsafe {
                required_utf8(package_version, "Package version")?
            })
            .map_err(|error| error.to_string())?;
            Ok::<_, String>(requirement.matches(&version))
        })();
        match result {
            Ok(matches) => {
                unsafe { output.write(u8::from(matches)) };
                PcpResult::Success
            }
            Err(error) => {
                set_error(error);
                PcpResult::InvalidArgument
            }
        }
    })
}

fn relationship_header(
    package_id: PackageId,
    has_version_requirement: bool,
) -> PcpPackageRelationship {
    PcpPackageRelationship {
        package_id: package_id.bytes(),
        has_version_requirement: u8::from(has_version_requirement),
        reserved: [0; 7],
    }
}

macro_rules! relationship_functions {
    ($get:ident, $copy_name:ident, $copy_version:ident, $accessor:ident) => {
        #[unsafe(no_mangle)]
        /// Returns fixed relationship metadata by source order.
        ///
        /// # Safety
        /// `handle` must be live and `output` writable.
        pub unsafe extern "C" fn $get(
            handle: *const PcpPackageHandle,
            index: usize,
            output: *mut PcpPackageRelationship,
        ) -> PcpResult {
            boundary(|| {
                if handle.is_null() || output.is_null() {
                    return PcpResult::InvalidArgument;
                }
                let relationships = unsafe { (*handle).package.header() }.$accessor();
                let Some(value) = relationships.get(index) else {
                    return PcpResult::EndOfRecords;
                };
                unsafe {
                    output.write(relationship_header(
                        value.package_id(),
                        value.version_requirement().is_some(),
                    ))
                };
                PcpResult::Success
            })
        }

        #[unsafe(no_mangle)]
        /// Copies a relationship display name without a trailing null terminator.
        ///
        /// # Safety
        /// Pointer arguments must satisfy the documented buffer contract.
        pub unsafe extern "C" fn $copy_name(
            handle: *const PcpPackageHandle,
            index: usize,
            destination: *mut u8,
            destination_byte_count: usize,
            required_byte_count: *mut usize,
        ) -> PcpResult {
            boundary(|| {
                if handle.is_null() {
                    return PcpResult::InvalidArgument;
                }
                let relationships = unsafe { (*handle).package.header() }.$accessor();
                let Some(value) = relationships.get(index) else {
                    return PcpResult::EndOfRecords;
                };
                copy_text(
                    value.name(),
                    destination,
                    destination_byte_count,
                    required_byte_count,
                )
            })
        }

        #[unsafe(no_mangle)]
        /// Copies a relationship version requirement without a trailing null terminator.
        ///
        /// # Safety
        /// Pointer arguments must satisfy the documented buffer contract.
        pub unsafe extern "C" fn $copy_version(
            handle: *const PcpPackageHandle,
            index: usize,
            destination: *mut u8,
            destination_byte_count: usize,
            required_byte_count: *mut usize,
        ) -> PcpResult {
            boundary(|| {
                if handle.is_null() {
                    return PcpResult::InvalidArgument;
                }
                let relationships = unsafe { (*handle).package.header() }.$accessor();
                let Some(value) = relationships.get(index) else {
                    return PcpResult::EndOfRecords;
                };
                let requirement = value
                    .version_requirement()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                copy_text(
                    &requirement,
                    destination,
                    destination_byte_count,
                    required_byte_count,
                )
            })
        }
    };
}

relationship_functions!(
    pcp_package_dependency,
    pcp_package_copy_dependency_name,
    pcp_package_copy_dependency_version_requirement,
    dependencies
);
relationship_functions!(
    pcp_package_incompatibility,
    pcp_package_copy_incompatibility_name,
    pcp_package_copy_incompatibility_version_requirement,
    incompatibilities
);
