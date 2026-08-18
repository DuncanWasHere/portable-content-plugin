use super::*;
use pluginable_content_package_core::{
    ChangeSetId, GroupLabel, GroupType, GroupWriter, PackageDependency, PackageHeader, PackageId,
    PackageVersionRequirement, RecordFlags, RecordId, RecordWriter, Signature,
};
use std::ffi::CString;

#[test]
fn ffi_header_layouts_match_the_c_header() {
    println!("[abi-layout] validating Rust repr(C) layouts against the public C header");
    assert_eq!(std::mem::size_of::<PcpRecordHeader>(), 52);
    assert_eq!(std::mem::align_of::<PcpRecordHeader>(), 4);
    assert_eq!(std::mem::size_of::<PcpSubrecordHeader>(), 8);
    assert_eq!(std::mem::align_of::<PcpSubrecordHeader>(), 4);
    assert_eq!(std::mem::size_of::<PcpIndexedRecord>(), 64);
    assert_eq!(std::mem::align_of::<PcpIndexedRecord>(), 8);
    assert_eq!(std::mem::size_of::<PcpRecordOrigin>(), 72);
    assert_eq!(std::mem::align_of::<PcpRecordOrigin>(), 8);
    assert_eq!(std::mem::size_of::<PcpIndexedGroup>(), 40);
    assert_eq!(std::mem::align_of::<PcpIndexedGroup>(), 8);
    assert_eq!(std::mem::size_of::<PcpSceneOffset>(), 24);
    assert_eq!(std::mem::align_of::<PcpSceneOffset>(), 8);
    assert_eq!(std::mem::size_of::<PcpPackageMetadata>(), 56);
    assert_eq!(std::mem::align_of::<PcpPackageMetadata>(), 8);
    assert_eq!(std::mem::size_of::<PcpPackageRelationship>(), 24);
    assert_eq!(std::mem::align_of::<PcpPackageRelationship>(), 1);
    assert_eq!(std::mem::size_of::<PcpPackageRelationshipInput>(), 32);
    assert_eq!(std::mem::align_of::<PcpPackageRelationshipInput>(), 8);
    assert_eq!(std::mem::size_of::<PcpRecordMutation>(), 40);
    assert_eq!(std::mem::align_of::<PcpRecordMutation>(), 8);
}

#[test]
fn abi_creates_packages_and_evaluates_semantic_version_requirements() {
    let path = std::env::temp_dir().join(format!("pcp-abi-create-{}.pcp", std::process::id()));
    let path_text = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let schema = CString::new("test.schema").unwrap();
    let version = CString::new("2.0.0-rc.1").unwrap();
    let mut handle = ptr::null_mut();
    assert_eq!(
        unsafe {
            pcp_package_create(
                path_text.as_ptr(),
                [7u8; 16].as_ptr(),
                schema.as_ptr(),
                version.as_ptr(),
                &mut handle,
            )
        },
        PcpResult::Success
    );
    let mut metadata = PcpPackageMetadata::default();
    assert_eq!(
        unsafe { pcp_package_metadata(handle, &mut metadata) },
        PcpResult::Success
    );
    assert_eq!(metadata.package_id, [7; 16]);
    let requirement = CString::new(">=2.0.0-rc.1, <2.0.0").unwrap();
    let mut matches = 0;
    assert_eq!(
        unsafe {
            pcp_version_requirement_matches(requirement.as_ptr(), version.as_ptr(), &mut matches)
        },
        PcpResult::Success
    );
    assert_eq!(matches, 1);
    unsafe { pcp_package_destroy(handle) };
    let _ = std::fs::remove_file(path);
}

#[test]
fn exported_abi_opens_reads_copies_and_destroys_handles() {
    let mut package_header = PackageHeader::new(PackageId::from_bytes([5; 16])).unwrap();
    package_header
        .add_dependency(
            PackageDependency::new(PackageId::from_bytes([4; 16]), "base.pcp")
                .unwrap()
                .with_version_requirement(
                    PackageVersionRequirement::parse(">=1.0.0, <2.0.0").unwrap(),
                ),
        )
        .unwrap();
    let bytes = package_header
        .encode(ChangeSetId::from_bytes([0; 32]))
        .unwrap();
    let path = std::env::temp_dir().join(format!("pcp-abi-{}.pcp", std::process::id()));
    std::fs::write(&path, &bytes).unwrap();
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();

    let mut package = ptr::null_mut();
    println!("[abi] pcp_package_open -> opaque package handle");
    assert_eq!(
        unsafe { pcp_package_open(path.as_ptr(), &mut package) },
        PcpResult::Success
    );
    assert!(!package.is_null());

    let mut byte_count = 0;
    assert_eq!(
        unsafe { pcp_package_byte_count(package, &mut byte_count) },
        PcpResult::Success
    );
    println!("[abi] source reports {byte_count} bytes");
    assert_eq!(byte_count, bytes.len() as u64);

    let mut metadata = PcpPackageMetadata::default();
    assert_eq!(
        unsafe { pcp_package_metadata(package, &mut metadata) },
        PcpResult::Success
    );
    assert_eq!(
        metadata.format_version,
        PackageHeader::CURRENT_FORMAT_VERSION
    );
    assert_eq!(metadata.package_id, [5; 16]);
    assert_eq!(metadata.dependency_count, 1);
    assert_eq!(metadata.has_package_version, 1);
    let mut relationship = PcpPackageRelationship::default();
    assert_eq!(
        unsafe { pcp_package_dependency(package, 0, &mut relationship) },
        PcpResult::Success
    );
    assert_eq!(relationship.package_id, [4; 16]);
    assert_eq!(relationship.has_version_requirement, 1);
    let mut required = 0;
    assert_eq!(
        unsafe { pcp_package_copy_dependency_name(package, 0, ptr::null_mut(), 0, &mut required) },
        PcpResult::BufferTooSmall
    );
    let mut dependency_name = vec![0; required];
    assert_eq!(
        unsafe {
            pcp_package_copy_dependency_name(
                package,
                0,
                dependency_name.as_mut_ptr(),
                dependency_name.len(),
                &mut required,
            )
        },
        PcpResult::Success
    );
    assert_eq!(dependency_name, b"base.pcp");

    let mut reader = ptr::null_mut();
    let mut header = PcpRecordHeader::default();
    assert_eq!(
        unsafe { pcp_package_read_record_at(package, 0, &mut reader, &mut header) },
        PcpResult::Success
    );
    println!(
        "[abi] record {:?}, id {:08X}",
        header.signature, header.record_id
    );
    assert_eq!(header.signature, *b"PKHD");

    let mut subrecord = PcpSubrecordHeader::default();
    assert_eq!(
        unsafe { pcp_record_reader_next_subrecord(reader, &mut subrecord) },
        PcpResult::Success
    );
    assert_eq!(subrecord.signature, *b"FMTV");
    let mut required = 0;
    assert_eq!(
        unsafe {
            pcp_record_reader_copy_current_subrecord_payload(
                reader,
                ptr::null_mut(),
                0,
                &mut required,
            )
        },
        PcpResult::BufferTooSmall
    );
    let mut payload = vec![0; required];
    assert_eq!(
        unsafe {
            pcp_record_reader_copy_current_subrecord_payload(
                reader,
                payload.as_mut_ptr(),
                payload.len(),
                &mut required,
            )
        },
        PcpResult::Success
    );
    println!("[abi] copied subrecord payload {payload:?}");
    assert_eq!(payload, PackageHeader::CURRENT_FORMAT_VERSION.to_le_bytes());
    let mut remaining_subrecords = 0;
    loop {
        match unsafe { pcp_record_reader_next_subrecord(reader, &mut subrecord) } {
            PcpResult::Success => remaining_subrecords += 1,
            PcpResult::EndOfSubrecords => break,
            result => panic!("unexpected ABI traversal result: {result:?}"),
        }
    }
    println!("[abi] traversed {remaining_subrecords} additional metadata subrecords");

    unsafe {
        pcp_record_reader_destroy(reader);
        pcp_package_destroy(package);
    }
    std::fs::remove_file(path.to_str().unwrap()).unwrap();
    println!("[abi] destroyed both opaque handles without crossing ownership boundaries");
}

#[test]
fn lightweight_abi_requires_explicit_indexing_and_cursor_skips_unentered_groups() {
    let mut header = PackageHeader::new(PackageId::from_bytes([6; 16])).unwrap();
    header.set_record_count(2);
    header.set_owned_record_count(2);
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
    let record = |signature: &str, local_id: u32| {
        RecordWriter::new(
            Signature::from_ascii(signature).unwrap(),
            RecordFlags::from_bits(0),
            RecordId::new(0, local_id).unwrap(),
            1.0,
            ChangeSetId::from_bytes([0; 32]),
        )
        .finish()
        .unwrap()
    };
    let mut skipped = GroupWriter::new(
        GroupLabel::from_signature(Signature::from_bytes(*b"SKIP")),
        GroupType::TopLevel,
    );
    skipped.push_entry(&record("HIDE", 1));
    let mut entered = GroupWriter::new(
        GroupLabel::from_record_id(RecordId::from_raw(2)),
        GroupType::SceneTemporaryChildren,
    );
    entered.push_entry(&record("SEEN", 2));
    bytes.extend_from_slice(&skipped.finish().unwrap());
    bytes.extend_from_slice(&entered.finish().unwrap());

    let path = std::env::temp_dir().join(format!("pcp-abi-cursor-{}.pcp", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let path_c = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let mut package = ptr::null_mut();
    assert_eq!(
        unsafe { pcp_package_open(path_c.as_ptr(), &mut package) },
        PcpResult::Success
    );
    let mut count = 0;
    assert_eq!(
        unsafe { pcp_package_record_count(package, &mut count) },
        PcpResult::IndexUnavailable
    );

    let mut cursor = ptr::null_mut();
    assert_eq!(
        unsafe { pcp_package_cursor_create(package, &mut cursor) },
        PcpResult::Success
    );
    let mut kind = PcpPackageEntryKind::Record;
    let mut indexed_record = PcpIndexedRecord::default();
    let mut indexed_group = PcpIndexedGroup::default();
    assert_eq!(
        unsafe {
            pcp_package_cursor_next(cursor, &mut kind, &mut indexed_record, &mut indexed_group)
        },
        PcpResult::Success
    );
    assert_eq!(kind, PcpPackageEntryKind::Group);
    assert_eq!(indexed_group.label, *b"SKIP");

    assert_eq!(
        unsafe {
            pcp_package_cursor_next(cursor, &mut kind, &mut indexed_record, &mut indexed_group)
        },
        PcpResult::Success
    );
    assert_eq!(kind, PcpPackageEntryKind::Group);
    assert_eq!(indexed_group.label, 2u32.to_le_bytes());
    assert_eq!(
        unsafe { pcp_package_cursor_enter_group(cursor) },
        PcpResult::Success
    );
    assert_eq!(
        unsafe {
            pcp_package_cursor_next(cursor, &mut kind, &mut indexed_record, &mut indexed_group)
        },
        PcpResult::Success
    );
    assert_eq!(kind, PcpPackageEntryKind::Record);
    assert_eq!(indexed_record.header.signature, *b"SEEN");
    assert_eq!(
        unsafe {
            pcp_package_cursor_next(cursor, &mut kind, &mut indexed_record, &mut indexed_group)
        },
        PcpResult::EndOfRecords
    );

    assert_eq!(
        unsafe { pcp_package_build_index(package) },
        PcpResult::Success
    );
    assert_eq!(
        unsafe { pcp_package_record_count(package, &mut count) },
        PcpResult::Success
    );
    assert_eq!(count, 2);
    unsafe {
        pcp_package_cursor_destroy(cursor);
        pcp_package_destroy(package);
    }

    let mut editable = ptr::null_mut();
    assert_eq!(
        unsafe { pcp_package_open_for_editing(path_c.as_ptr(), &mut editable) },
        PcpResult::Success
    );
    assert_eq!(
        unsafe { pcp_package_rebuild_scene_offsets(editable) },
        PcpResult::Success
    );
    let mut range_count = 0;
    assert_eq!(
        unsafe { pcp_package_scene_offset_count(editable, &mut range_count) },
        PcpResult::Success
    );
    assert_eq!(range_count, 1);
    let mut range = PcpSceneOffset::default();
    assert_eq!(
        unsafe { pcp_package_scene_offset_at(editable, 0, &mut range) },
        PcpResult::Success
    );
    assert_eq!(range.scene_record_id, 2);
    assert_eq!(range.world_record_id, 0);
    assert!(range.start_offset < range.end_offset);
    assert_eq!(unsafe { pcp_package_save(editable) }, PcpResult::Success);
    unsafe { pcp_package_destroy(editable) };

    let reopened = Package::open(&path).unwrap();
    assert_eq!(reopened.header().scene_offset_tables().len(), 1);
    assert_eq!(
        reopened.header().scene_offset_tables()[0].offsets()[0]
            .scene_id()
            .raw(),
        2
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn mutable_abi_inserts_updates_saves_and_removes_records() {
    let bytes = PackageHeader::new(PackageId::from_bytes([9; 16]))
        .unwrap()
        .encode(ChangeSetId::from_bytes([0; 32]))
        .unwrap();
    let source = std::env::temp_dir().join(format!("pcp-abi-edit-{}.pcp", std::process::id()));
    let saved = std::env::temp_dir().join(format!("pcp-abi-save-{}.pcp", std::process::id()));
    std::fs::write(&source, bytes).unwrap();
    let source_c = CString::new(source.as_os_str().as_encoded_bytes()).unwrap();
    let saved_c = CString::new(saved.as_os_str().as_encoded_bytes()).unwrap();
    let mut package = ptr::null_mut();
    assert_eq!(
        unsafe { pcp_package_open_for_editing(source_c.as_ptr(), &mut package) },
        PcpResult::Success
    );

    let mut payload = Vec::new();
    payload.extend_from_slice(b"POSX");
    payload.extend_from_slice(&4u32.to_le_bytes());
    payload.extend_from_slice(&1.0f32.to_le_bytes());
    let mut id = 0;
    assert_eq!(
        unsafe {
            pcp_package_insert_record(
                package,
                u64::MAX,
                u32::from_le_bytes(*b"ENTY"),
                payload.as_ptr(),
                payload.len(),
                &mut id,
            )
        },
        PcpResult::Success
    );
    assert_eq!(id & 0x00FF_FFFF, PackageHeader::FIRST_USER_LOCAL_IDENTIFIER);
    assert_eq!(
        unsafe {
            pcp_package_replace_subrecord(
                package,
                id,
                u32::from_le_bytes(*b"POSX"),
                0,
                2.5f32.to_le_bytes().as_ptr(),
                4,
            )
        },
        PcpResult::Success
    );
    let mut replacement_payload = Vec::new();
    replacement_payload.extend_from_slice(b"POSX");
    replacement_payload.extend_from_slice(&4u32.to_le_bytes());
    replacement_payload.extend_from_slice(&3.5f32.to_le_bytes());
    replacement_payload.extend_from_slice(b"EDID");
    replacement_payload.extend_from_slice(&6u32.to_le_bytes());
    replacement_payload.extend_from_slice(b"Placed");
    assert_eq!(
        unsafe {
            pcp_package_replace_record_payload(
                package,
                id,
                replacement_payload.as_ptr(),
                replacement_payload.len(),
            )
        },
        PcpResult::Success
    );
    let mut dirty = 0;
    assert_eq!(
        unsafe { pcp_package_is_dirty(package, &mut dirty) },
        PcpResult::Success
    );
    assert_eq!(dirty, 1);
    assert_eq!(
        unsafe { pcp_package_save_as(package, saved_c.as_ptr()) },
        PcpResult::Success
    );
    assert_eq!(
        Package::open(&saved)
            .unwrap()
            .build_index()
            .unwrap()
            .record_count(),
        1
    );
    assert_eq!(
        unsafe { pcp_package_remove_record(package, id) },
        PcpResult::Success
    );
    let mut count = 0;
    assert_eq!(
        unsafe { pcp_package_record_count(package, &mut count) },
        PcpResult::Success
    );
    assert_eq!(count, 0);
    unsafe { pcp_package_destroy(package) };
    std::fs::remove_file(source).unwrap();
    std::fs::remove_file(saved).unwrap();
}

#[test]
fn mutable_abi_applies_record_changes_in_one_batch() {
    let field_payload = |value: u32| {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"VALU");
        payload.extend_from_slice(&4u32.to_le_bytes());
        payload.extend_from_slice(&value.to_le_bytes());
        payload
    };
    let record = |id: u32, value: u32| {
        let mut writer = RecordWriter::new(
            Signature::from_bytes(*b"ITEM"),
            RecordFlags::default(),
            RecordId::from_raw(id),
            1.0,
            ChangeSetId::from_bytes([0; 32]),
        );
        writer
            .write_subrecord(Signature::from_bytes(*b"VALU"), &value.to_le_bytes())
            .unwrap();
        writer.finish().unwrap()
    };

    let mut header = PackageHeader::new(PackageId::from_bytes([11; 16])).unwrap();
    header.set_record_count(2);
    header.set_owned_record_count(2);
    header.set_next_local_identifier(0x802).unwrap();
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
    let mut group = GroupWriter::new(
        GroupLabel::from_signature(Signature::from_bytes(*b"ITEM")),
        GroupType::TopLevel,
    );
    group.push_entry(&record(0x800, 1));
    group.push_entry(&record(0x801, 2));
    bytes.extend_from_slice(&group.finish().unwrap());

    let path = std::env::temp_dir().join(format!("pcp-abi-batch-{}.pcp", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let path_c = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let mut package = ptr::null_mut();
    assert_eq!(
        unsafe { pcp_package_open_for_editing(path_c.as_ptr(), &mut package) },
        PcpResult::Success
    );

    let original_group = unsafe { (*package).index.as_ref().unwrap().groups()[0].header_offset() };
    let replacement = field_payload(10);
    let inserted = field_payload(30);
    let mutations = [
        PcpRecordMutation {
            kind: 0,
            record_signature: u32::from_le_bytes(*b"ITEM"),
            record_id: 0x800,
            reserved: 0,
            target_group_offset: u64::MAX,
            payload: replacement.as_ptr(),
            payload_byte_count: replacement.len(),
        },
        PcpRecordMutation {
            kind: 2,
            record_signature: 0,
            record_id: 0x801,
            reserved: 0,
            target_group_offset: u64::MAX,
            payload: ptr::null(),
            payload_byte_count: 0,
        },
        PcpRecordMutation {
            kind: 1,
            record_signature: u32::from_le_bytes(*b"ITEM"),
            record_id: 0x802,
            reserved: 0,
            target_group_offset: original_group,
            payload: inserted.as_ptr(),
            payload_byte_count: inserted.len(),
        },
    ];
    assert_eq!(
        unsafe { pcp_package_apply_record_batch(package, mutations.as_ptr(), mutations.len()) },
        PcpResult::Success
    );
    let index = unsafe { (*package).index.as_ref().unwrap() };
    assert!(index.record(RecordId::from_raw(0x800)).is_some());
    assert!(index.record(RecordId::from_raw(0x801)).is_none());
    assert!(index.record(RecordId::from_raw(0x802)).is_some());
    assert_eq!(index.record_count(), 2);
    assert_eq!(
        unsafe { (*package).package.header().owned_record_count() },
        2
    );
    assert_eq!(
        unsafe { (*package).package.header().next_local_identifier() },
        0x803
    );
    assert_eq!(unsafe { pcp_package_save(package) }, PcpResult::Success);
    unsafe { pcp_package_destroy(package) };

    let reopened = Package::open(&path).unwrap();
    let reopened_index = reopened.build_index().unwrap();
    assert_eq!(reopened_index.record_count(), 2);
    let value = |id| {
        let view = reopened_index.record(RecordId::from_raw(id)).unwrap();
        let mut reader = view.read().unwrap();
        reader.next_subrecord().unwrap().unwrap();
        u32::from_le_bytes(
            reader
                .current_subrecord_payload()
                .unwrap()
                .try_into()
                .unwrap(),
        )
    };
    assert_eq!(value(0x800), 10);
    assert_eq!(value(0x802), 30);
    std::fs::remove_file(path).unwrap();
}
