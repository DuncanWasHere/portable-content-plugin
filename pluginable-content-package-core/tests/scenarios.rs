use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    thread,
};

use pluginable_content_package_core::{
    ChangeSetId, ChangeSetStore, CollectionLimits, GroupLabel, GroupType, GroupWriter,
    ListAppendMode, LoadOrder, MemoryPackageSource, MergeOptions, MergeRequest, MergeSelection,
    OverrideMergeMode, Package, PackageDependency, PackageEntry, PackageHeader, PackageId,
    PackageIncompatibility, PackageIssueCode, PackageLoadClass, PackageReader, PackageVersion,
    PackageVersionRequirement, RecordFlags, RecordId, RecordIdMapper, RecordReader, RecordWriter,
    ReferenceRewriter, RuntimeRecordId, RuntimeSlot, Signature, SubrecordMergeRule,
    SubrecordMergeStrategy, ValidationReport, ValidationSeverity, append_encoded_list,
    compose_override_chain, compose_record_override, decode_list, decode_map, decode_set,
    encode_list, encode_map, encode_set, inspect_package_availability, merge_packages,
    merge_packages_with_options, repair_load_order, write_package_atomically,
};

const ITEM: Signature = Signature::from_bytes(*b"ITEM");
const EDID: Signature = Signature::from_bytes(*b"EDID");
const VALU: Signature = Signature::from_bytes(*b"VALU");
const WGHT: Signature = Signature::from_bytes(*b"WGHT");
const BASE: Signature = Signature::from_bytes(*b"BASE");
const QSTS: Signature = Signature::from_bytes(*b"QSTS");
const TAGS: Signature = Signature::from_bytes(*b"TAGS");

#[derive(Debug, PartialEq)]
struct ExampleItem {
    id: RecordId,
    editor_id: String,
    value: u32,
    weight: f32,
    base: Option<RecordId>,
}

impl ExampleItem {
    fn encode(&self) -> Vec<u8> {
        let mut writer = RecordWriter::new(
            ITEM,
            RecordFlags::default(),
            self.id,
            1.0,
            ChangeSetId::from_bytes([0; 32]),
        );
        writer
            .write_subrecord(EDID, self.editor_id.as_bytes())
            .unwrap();
        writer.write_u32(VALU, self.value).unwrap();
        writer.write_f32(WGHT, self.weight).unwrap();
        if let Some(base) = self.base {
            writer.write_u32(BASE, base.raw()).unwrap();
        }
        writer.finish().unwrap()
    }

    fn decode(mut reader: RecordReader) -> Self {
        let id = reader.header().record_id();
        let mut result = Self {
            id,
            editor_id: String::new(),
            value: 0,
            weight: 0.0,
            base: None,
        };
        while let Some(header) = reader.next_subrecord().unwrap() {
            let payload = reader.current_subrecord_payload().unwrap();
            match header.signature() {
                EDID => result.editor_id = String::from_utf8(payload.to_vec()).unwrap(),
                VALU => result.value = u32::from_le_bytes(payload.try_into().unwrap()),
                WGHT => result.weight = f32::from_le_bytes(payload.try_into().unwrap()),
                BASE => {
                    result.base = Some(RecordId::from_raw(u32::from_le_bytes(
                        payload.try_into().unwrap(),
                    )))
                }
                _ => {}
            }
        }
        result
    }
}

fn build_package(items: &[ExampleItem]) -> Vec<u8> {
    build_package_as(items, 1, None)
}

fn build_package_as(
    items: &[ExampleItem],
    package_id_byte: u8,
    dependency: Option<(u8, &str)>,
) -> Vec<u8> {
    let mut header = PackageHeader::new(PackageId::from_bytes([package_id_byte; 16])).unwrap();
    if let Some((dependency_byte, name)) = dependency {
        header
            .add_dependency(
                PackageDependency::new(PackageId::from_bytes([dependency_byte; 16]), name).unwrap(),
            )
            .unwrap();
    }
    header.set_record_count(items.len() as u32);
    let owned_index = header.dependencies().len() as u8;
    header.set_owned_record_count(
        items
            .iter()
            .filter(|item| item.id.package_index() == owned_index)
            .count() as u32,
    );
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();

    let mut group = GroupWriter::new(GroupLabel::from_signature(ITEM), GroupType::TopLevel);
    for item in items {
        group.push_entry(&item.encode());
    }
    bytes.extend_from_slice(&group.finish().unwrap());
    bytes
}

fn read_items(package: &Package) -> Vec<ExampleItem> {
    let mut root = package.reader();
    assert!(matches!(
        root.next_entry().unwrap(),
        Some(PackageEntry::Record(_))
    ));
    let group = match root.next_entry().unwrap() {
        Some(PackageEntry::Group(group)) => group,
        _ => panic!("expected ITEM group"),
    };
    assert_eq!(group.header().group_type(), GroupType::TopLevel);
    assert_eq!(group.header().label().signature(), ITEM);
    let mut children = group.children().unwrap();
    let mut items = Vec::new();
    while let Some(entry) = children.next_entry().unwrap() {
        match entry {
            PackageEntry::Record(record) => items.push(ExampleItem::decode(record.read().unwrap())),
            PackageEntry::Group(_) => panic!("unexpected nested group"),
        }
    }
    items
}

fn metadata_package(package_id: u8, version: &str, dependencies: &[(u8, &str)]) -> Arc<Package> {
    let mut header = PackageHeader::new(PackageId::from_bytes([package_id; 16])).unwrap();
    header.set_package_version(PackageVersion::parse(version).unwrap());
    for (dependency, requirement) in dependencies {
        header
            .add_dependency(
                PackageDependency::new(
                    PackageId::from_bytes([*dependency; 16]),
                    format!("{dependency}.pcp"),
                )
                .unwrap()
                .with_version_requirement(PackageVersionRequirement::parse(requirement).unwrap()),
            )
            .unwrap();
    }
    let bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
    Arc::new(Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap())
}

#[test]
fn package_versions_constraints_incompatibilities_and_order_repair_are_deterministic() {
    let base = metadata_package(41, "1.5.0", &[]);
    let middle = metadata_package(42, "2.0.0-rc.1", &[(41, ">=1.0.0, <2.0.0")]);
    let mut leaf_header = PackageHeader::new(PackageId::from_bytes([43; 16])).unwrap();
    leaf_header
        .add_dependency(
            PackageDependency::new(PackageId::from_bytes([42; 16]), "42.pcp")
                .unwrap()
                .with_version_requirement(
                    PackageVersionRequirement::parse(">=2.0.0-rc.1").unwrap(),
                ),
        )
        .unwrap();
    leaf_header
        .add_incompatibility(
            PackageIncompatibility::new(PackageId::from_bytes([41; 16]), "41.pcp")
                .unwrap()
                .with_version_requirement(PackageVersionRequirement::parse("<1.4.0").unwrap()),
        )
        .unwrap();
    let leaf = Arc::new(
        Package::from_source(Arc::new(MemoryPackageSource::new(
            leaf_header
                .encode(ChangeSetId::from_bytes([0; 32]))
                .unwrap(),
        )))
        .unwrap(),
    );
    let mut packages = vec![leaf.clone(), middle.clone(), base.clone()];
    let report = repair_load_order(&mut packages).unwrap();
    assert!(!report.moves.is_empty());
    assert_eq!(
        packages[0].header().package_id(),
        base.header().package_id()
    );
    assert_eq!(
        packages[1].header().package_id(),
        middle.header().package_id()
    );
    assert_eq!(
        packages[2].header().package_id(),
        leaf.header().package_id()
    );
    LoadOrder::build(packages).unwrap();

    let unavailable = metadata_package(44, "1.0.0", &[(99, ">=1.0.0")]);
    let dependent = metadata_package(45, "1.0.0", &[(44, "*")]);
    let issues = inspect_package_availability(&[unavailable.clone(), dependent.clone()]);
    assert!(
        issues[&unavailable.header().package_id()]
            .iter()
            .any(|issue| issue.code == PackageIssueCode::MissingDependency)
    );
    assert!(
        issues[&dependent.header().package_id()]
            .iter()
            .any(|issue| issue.code == PackageIssueCode::DependencyUnavailable)
    );
}

#[test]
fn game_specific_schema_round_trips_through_generic_core() {
    println!("[schema] defining two game-specific ITEM records outside pcp-core");
    let expected = vec![
        ExampleItem {
            id: RecordId::from_raw(0x0000_0800),
            editor_id: "IronSword".into(),
            value: 25,
            weight: 9.5,
            base: None,
        },
        ExampleItem {
            id: RecordId::from_raw(0x0000_0801),
            editor_id: "FineSword".into(),
            value: 60,
            weight: 8.0,
            base: Some(RecordId::from_raw(0x0000_0800)),
        },
    ];
    let package =
        Package::from_source(Arc::new(MemoryPackageSource::new(build_package(&expected)))).unwrap();
    println!(
        "[schema] serialized package size: {} bytes",
        package.byte_count()
    );
    let decoded = read_items(&package);
    println!("[schema] decoded records: {decoded:#?}");
    assert_eq!(decoded, expected);
}

#[test]
fn shared_source_supports_independent_parallel_readers() {
    let expected_count = 128;
    let items: Vec<_> = (0..expected_count)
        .map(|index| ExampleItem {
            id: RecordId::from_raw(0x800 + index),
            editor_id: format!("Item{index}"),
            value: index,
            weight: index as f32 / 2.0,
            base: None,
        })
        .collect();
    let package = Arc::new(
        Package::from_source(Arc::new(MemoryPackageSource::new(build_package(&items)))).unwrap(),
    );
    println!(
        "[threads] sharing one {}-byte source across 8 workers",
        package.byte_count()
    );
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let package = package.clone();
            thread::spawn(move || {
                let count = read_items(&package).len();
                println!(
                    "[threads] {:?} decoded {count} records",
                    thread::current().id()
                );
                count
            })
        })
        .collect();
    for worker in workers {
        assert_eq!(worker.join().unwrap(), expected_count as usize);
    }
}

#[test]
fn multiple_package_files_can_be_read_independently_from_async_code() {
    let unique = format!(
        "pcp-scenarios-{}-{}",
        std::process::id(),
        thread::current().name().unwrap_or("test")
    );
    let directory = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&directory).unwrap();
    let first_path = directory.join("first.pcp");
    let second_path = directory.join("second.pcp");
    let make_item = |id, name: &str| ExampleItem {
        id: RecordId::from_raw(id),
        editor_id: name.into(),
        value: id,
        weight: 1.0,
        base: None,
    };
    std::fs::write(&first_path, build_package(&[make_item(0x800, "First")])).unwrap();
    std::fs::write(
        &second_path,
        build_package(&[make_item(0x800, "Second"), make_item(0x801, "Third")]),
    )
    .unwrap();
    println!(
        "[async] created {} and {}",
        first_path.display(),
        second_path.display()
    );

    async fn load_count(path: std::path::PathBuf) -> usize {
        let package = Package::open(path).unwrap();
        read_items(&package).len()
    }
    assert_eq!(block_on(load_count(first_path)), 1);
    assert_eq!(block_on(load_count(second_path)), 2);
    println!("[async] executor-neutral caller decoded 1 and 2 records");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn nested_groups_enforce_independent_child_ranges() {
    let item = ExampleItem {
        id: RecordId::from_raw(0x800),
        editor_id: "Nested".into(),
        value: 7,
        weight: 2.5,
        base: None,
    };
    let mut inner = GroupWriter::new(GroupLabel::from_i32(3), GroupType::InteriorSceneSubBlock);
    inner.push_entry(&item.encode());
    let inner = inner.finish().unwrap();
    let mut outer = GroupWriter::new(GroupLabel::from_i32(1), GroupType::InteriorSceneBlock);
    outer.push_entry(&inner);
    let mut nested_header = PackageHeader::new(PackageId::from_bytes([3; 16])).unwrap();
    nested_header.set_record_count(1);
    nested_header.set_owned_record_count(1);
    let mut bytes = nested_header
        .encode(ChangeSetId::from_bytes([0; 32]))
        .unwrap();
    bytes.extend_from_slice(&outer.finish().unwrap());
    let package = Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap();

    let mut root = package.reader();
    root.next_entry().unwrap();
    let outer = match root.next_entry().unwrap().unwrap() {
        PackageEntry::Group(value) => value,
        _ => panic!("expected outer group"),
    };
    println!(
        "[groups] outer child range {}..{}",
        outer.payload_offset(),
        outer.end_offset()
    );
    let mut outer_children = outer.children().unwrap();
    let inner = match outer_children.next_entry().unwrap().unwrap() {
        PackageEntry::Group(value) => value,
        _ => panic!("expected inner group"),
    };
    println!(
        "[groups] inner child range {}..{} is bounded by outer end {}",
        inner.payload_offset(),
        inner.end_offset(),
        outer.end_offset()
    );
    let mut inner_children = inner.children().unwrap();
    let record = match inner_children.next_entry().unwrap().unwrap() {
        PackageEntry::Record(value) => value,
        _ => panic!("expected nested record"),
    };
    assert_eq!(ExampleItem::decode(record.read().unwrap()), item);
    assert!(inner_children.next_entry().unwrap().is_none());
    assert!(outer_children.next_entry().unwrap().is_none());
}

#[test]
fn malformed_group_cannot_escape_its_source_boundary() {
    let mut bytes = PackageHeader::new(PackageId::from_bytes([4; 16]))
        .unwrap()
        .encode(ChangeSetId::from_bytes([0; 32]))
        .unwrap();
    let group_offset = bytes.len();
    let mut group = GroupWriter::new(GroupLabel::from_signature(ITEM), GroupType::TopLevel)
        .finish()
        .unwrap();
    group[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes.extend_from_slice(&group);
    let source = Arc::new(MemoryPackageSource::new(bytes));
    let mut reader = PackageReader::new(source);
    reader.next_entry().unwrap();
    let error = match reader.next_entry() {
        Err(error) => error,
        Ok(_) => panic!("corrupt group was accepted"),
    };
    println!("[validation] rejected group at offset {group_offset}: {error}");
    assert!(error.to_string().contains("beyond reader boundary"));
}

#[test]
fn load_order_caller_can_construct_a_last_wins_override_view() {
    let original = ExampleItem {
        id: RecordId::from_raw(0x800),
        editor_id: "Original".into(),
        value: 10,
        weight: 1.0,
        base: None,
    };
    let override_record = ExampleItem {
        id: original.id,
        editor_id: "Overridden".into(),
        value: 99,
        weight: 1.0,
        base: None,
    };
    let first = Arc::new(
        Package::from_source(Arc::new(MemoryPackageSource::new(build_package_as(
            &[original],
            1,
            None,
        ))))
        .unwrap(),
    );
    let second = Arc::new(
        Package::from_source(Arc::new(MemoryPackageSource::new(build_package_as(
            &[override_record],
            2,
            Some((1, "origin.pcp")),
        ))))
        .unwrap(),
    );
    let first_index = first.build_index().unwrap();
    let second_index = second.build_index().unwrap();
    let load_order = LoadOrder::build(vec![first, second]).unwrap();
    let record_index = load_order.build_record_index().unwrap();
    let cached_record_index = load_order
        .build_record_index_from(&[&first_index, &second_index])
        .unwrap();
    assert_eq!(
        cached_record_index
            .override_chain(RuntimeRecordId::from_raw(0x800))
            .unwrap()
            .origins()
            .len(),
        2
    );
    let chain = record_index
        .override_chain(RuntimeRecordId::from_raw(0x800))
        .unwrap();
    println!(
        "[overrides] core constructed a {}-record override chain",
        chain.origins().len()
    );
    assert_eq!(chain.origins().len(), 2);
    let winner = ExampleItem::decode(chain.winner().record().read().unwrap());
    println!("[overrides] final winner: {winner:#?}");
    assert_eq!(winner.editor_id, "Overridden");
    assert_eq!(winner.value, 99);
    let report = ValidationReport::for_load_order(&record_index);
    assert!(report.issues().iter().any(|issue| {
        issue.code == "PCP-OVERRIDE-CHAIN" && issue.severity == ValidationSeverity::Information
    }));
}

#[test]
fn compact_packages_receive_shared_namespace_slots() {
    let item = ExampleItem {
        id: RecordId::from_raw(0x800),
        editor_id: "CompactItem".into(),
        value: 1,
        weight: 1.0,
        base: None,
    };
    let mut header = PackageHeader::new(PackageId::from_bytes([12; 16])).unwrap();
    header.set_load_class(PackageLoadClass::Compact);
    header.set_record_count(1);
    header.set_owned_record_count(1);
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
    let mut group = GroupWriter::new(GroupLabel::from_signature(ITEM), GroupType::TopLevel);
    group.push_entry(&item.encode());
    bytes.extend_from_slice(&group.finish().unwrap());
    let package =
        Arc::new(Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap());
    let package_id = package.header().package_id();
    let load_order = LoadOrder::build(vec![package]).unwrap();
    let record_index = load_order.build_record_index().unwrap();
    assert_eq!(load_order.slot(package_id), Some(RuntimeSlot::Compact(0)));
    let runtime_id = RuntimeRecordId::from_raw(0xFE00_0800);
    assert!(record_index.winning_record(runtime_id).is_some());
    println!("[load-order] compact slot 0 maps serialized 00000800 to {runtime_id}");
}

#[test]
fn compact_and_overlay_load_classes_enforce_owned_record_rules() {
    let mut compact = PackageHeader::new(PackageId::from_bytes([90; 16])).unwrap();
    compact.set_load_class(PackageLoadClass::Compact);
    assert_eq!(compact.next_local_identifier(), 1);
    compact.set_owned_record_count(4096);
    compact.validate_load_class().unwrap();
    compact.set_owned_record_count(4097);
    assert!(compact.validate_load_class().is_err());

    let mut overlay = PackageHeader::new(PackageId::from_bytes([91; 16])).unwrap();
    overlay.set_load_class(PackageLoadClass::Overlay);
    overlay.validate_load_class().unwrap();
    overlay.set_owned_record_count(1);
    assert!(overlay.validate_load_class().is_err());
}

#[test]
fn overlays_override_dependencies_without_consuming_a_slot() {
    let base = Arc::new(
        Package::from_source(Arc::new(MemoryPackageSource::new(build_package_as(
            &[ExampleItem {
                id: RecordId::from_raw(0x800),
                editor_id: "Base".into(),
                value: 1,
                weight: 1.0,
                base: None,
            }],
            92,
            None,
        ))))
        .unwrap(),
    );
    let mut header = PackageHeader::new(PackageId::from_bytes([93; 16])).unwrap();
    header
        .add_dependency(PackageDependency::new(base.header().package_id(), "base.pcp").unwrap())
        .unwrap();
    header.set_load_class(PackageLoadClass::Overlay);
    header.set_record_count(1);
    header.set_owned_record_count(0);
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
    bytes.extend_from_slice(
        &ExampleItem {
            id: RecordId::from_raw(0x800),
            editor_id: "Overlay".into(),
            value: 2,
            weight: 1.0,
            base: None,
        }
        .encode(),
    );
    let overlay =
        Arc::new(Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap());
    let overlay_id = overlay.header().package_id();
    let order = LoadOrder::build(vec![base, overlay]).unwrap();
    assert_eq!(order.slot(overlay_id), None);
    let records = order.build_record_index().unwrap();
    assert_eq!(
        records
            .override_chain(RuntimeRecordId::from_raw(0x800))
            .unwrap()
            .origins()
            .len(),
        2
    );
}

#[test]
fn large_subrecords_use_the_same_u32_header_as_small_subrecords() {
    let large = vec![0xA5; 100_000];
    let mut item = RecordWriter::new(
        ITEM,
        RecordFlags::default(),
        RecordId::from_raw(0x800),
        1.0,
        ChangeSetId::from_bytes([0; 32]),
    );
    item.write_subrecord(Signature::from_bytes(*b"BLOB"), &large)
        .unwrap();
    let mut header = PackageHeader::new(PackageId::from_bytes([13; 16])).unwrap();
    header.set_record_count(1);
    header.set_owned_record_count(1);
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
    let mut group = GroupWriter::new(GroupLabel::from_signature(ITEM), GroupType::TopLevel);
    group.push_entry(&item.finish().unwrap());
    bytes.extend_from_slice(&group.finish().unwrap());
    let package = Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap();
    let index = package.build_index().unwrap();
    let mut reader = index
        .record(RecordId::from_raw(0x800))
        .unwrap()
        .read()
        .unwrap();
    let logical = reader.next_subrecord().unwrap().unwrap();
    println!(
        "[subrecord-u32] decoded one {}-byte {} subrecord",
        logical.payload_byte_count(),
        logical.signature()
    );
    assert_eq!(logical.payload_byte_count(), 100_000);
    assert_eq!(reader.current_subrecord_payload().unwrap(), large);
}

#[test]
fn portable_collection_codecs_round_trip_lists_sets_and_maps() {
    let limits = CollectionLimits::default();
    let list = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
    let bytes = encode_list(&list, |value| value.as_bytes().to_vec(), limits).unwrap();
    let decoded = decode_list(
        &bytes,
        |value| String::from_utf8(value.to_vec()).map_err(|error| error.to_string()),
        limits,
    )
    .unwrap();
    assert_eq!(decoded, list);

    let first = encode_list(&[1u32, 2], |value| value.to_le_bytes().to_vec(), limits).unwrap();
    let second = encode_list(&[2u32, 3], |value| value.to_le_bytes().to_vec(), limits).unwrap();
    let all = append_encoded_list(&first, &second, ListAppendMode::All, limits).unwrap();
    let unique = append_encoded_list(&first, &second, ListAppendMode::Unique, limits).unwrap();
    let decode_u32_list = |bytes: &[u8]| {
        decode_list(
            bytes,
            |value| {
                Ok(u32::from_le_bytes(
                    value.try_into().map_err(|_| "u32 size".to_string())?,
                ))
            },
            limits,
        )
        .unwrap()
    };
    assert_eq!(decode_u32_list(&all), vec![1, 2, 2, 3]);
    assert_eq!(decode_u32_list(&unique), vec![1, 2, 3]);

    let set = HashSet::from([7u32, 3, 11]);
    let bytes = encode_set(&set, |value| value.to_le_bytes().to_vec(), limits).unwrap();
    let decoded = decode_set(
        &bytes,
        |value| {
            Ok(u32::from_le_bytes(
                value.try_into().map_err(|_| "u32 size".to_string())?,
            ))
        },
        limits,
    )
    .unwrap();
    assert_eq!(decoded, set);

    let map = HashMap::from([("health".to_string(), 100i32), ("energy".to_string(), 75)]);
    let bytes = encode_map(
        &map,
        |key| key.as_bytes().to_vec(),
        |value| value.to_le_bytes().to_vec(),
        limits,
    )
    .unwrap();
    let decoded = decode_map(
        &bytes,
        |value| String::from_utf8(value.to_vec()).map_err(|error| error.to_string()),
        |value| {
            Ok(i32::from_le_bytes(
                value.try_into().map_err(|_| "i32 size".to_string())?,
            ))
        },
        limits,
    )
    .unwrap();
    println!("[collections] decoded list={list:?}, set={set:?}, map={map:?}");
    assert_eq!(decoded, map);
}

#[test]
fn atomic_package_writes_validate_before_replacing_the_destination() {
    let directory = std::env::temp_dir().join(format!(
        "pcp-atomic-{}-{}",
        std::process::id(),
        thread::current().name().unwrap_or("test")
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("content.pcp");
    let first = build_package(&[ExampleItem {
        id: RecordId::from_raw(0x800),
        editor_id: "First".into(),
        value: 1,
        weight: 1.0,
        base: None,
    }]);
    let second = build_package(&[ExampleItem {
        id: RecordId::from_raw(0x800),
        editor_id: "Second".into(),
        value: 2,
        weight: 1.0,
        base: None,
    }]);

    write_package_atomically(&path, &first).unwrap();
    assert_eq!(
        read_items(&Package::open(&path).unwrap())[0].editor_id,
        "First"
    );
    write_package_atomically(&path, &second).unwrap();
    assert_eq!(
        read_items(&Package::open(&path).unwrap())[0].editor_id,
        "Second"
    );

    let invalid = b"not a package";
    assert!(write_package_atomically(&path, invalid).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), second);
    println!("[atomic-write] validated replacement and preserved the old package after rejection");
    std::fs::remove_dir_all(directory).unwrap();
}

struct ExampleSchema;
impl ReferenceRewriter for ExampleSchema {
    fn rewrite_subrecord(
        &self,
        _record_signature: Signature,
        subrecord_signature: Signature,
        payload: &mut Vec<u8>,
        ids: &RecordIdMapper,
    ) -> Result<(), String> {
        if subrecord_signature == BASE {
            let raw = u32::from_le_bytes(payload.as_slice().try_into().map_err(|_| "BASE size")?);
            *payload = ids
                .map(RecordId::from_raw(raw))
                .map_err(|error| error.to_string())?
                .raw()
                .to_le_bytes()
                .to_vec();
        }
        Ok(())
    }
}

#[test]
fn merge_injects_ids_rewrites_schema_references_and_persists_history() {
    let destination_item = ExampleItem {
        id: RecordId::from_raw(0x800),
        editor_id: "Original".into(),
        value: 10,
        weight: 1.0,
        base: None,
    };
    let mut destination_header = PackageHeader::new(PackageId::from_bytes([21; 16])).unwrap();
    destination_header.set_record_count(1);
    destination_header.set_owned_record_count(1);
    destination_header.set_next_local_identifier(0x801).unwrap();
    let mut destination_bytes = destination_header
        .encode(ChangeSetId::from_bytes([0; 32]))
        .unwrap();
    destination_bytes.extend_from_slice(&destination_item.encode());
    let destination =
        Package::from_source(Arc::new(MemoryPackageSource::new(destination_bytes))).unwrap();

    let override_item = ExampleItem {
        id: RecordId::from_raw(0x0000_0800),
        editor_id: "Overridden".into(),
        value: 20,
        weight: 1.0,
        base: Some(RecordId::from_raw(0x0100_0800)),
    };
    let new_item = ExampleItem {
        id: RecordId::from_raw(0x0100_0800),
        editor_id: "Injected".into(),
        value: 30,
        weight: 1.0,
        base: None,
    };
    let mut source_header = PackageHeader::new(PackageId::from_bytes([22; 16])).unwrap();
    source_header
        .add_dependency(
            PackageDependency::new(destination.header().package_id(), "main.pcp").unwrap(),
        )
        .unwrap();
    source_header.set_record_count(2);
    source_header.set_owned_record_count(1);
    source_header.set_next_local_identifier(0x801).unwrap();
    let mut source_bytes = source_header
        .encode(ChangeSetId::from_bytes([0; 32]))
        .unwrap();
    source_bytes.extend_from_slice(&override_item.encode());
    source_bytes.extend_from_slice(&new_item.encode());
    let source = Package::from_source(Arc::new(MemoryPackageSource::new(source_bytes))).unwrap();

    let merged = merge_packages(
        MergeRequest {
            destination: &destination,
            source: &source,
            author: "developer",
            message: "merge item feature",
            timestamp_seconds: 1_700_000_000,
            parents: vec![],
        },
        &ExampleSchema,
    )
    .unwrap();
    assert_eq!(
        merged.injected_ids[&RecordId::from_raw(0x0100_0800)],
        RecordId::from_raw(0x801)
    );
    let package =
        Package::from_source(Arc::new(MemoryPackageSource::new(merged.package_bytes))).unwrap();
    let index = package.build_index().unwrap();
    let mut items: Vec<_> = index
        .records_by_signature(ITEM)
        .map(|record| ExampleItem::decode(record.read().unwrap()))
        .collect();
    items.sort_by_key(|item| item.id);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].editor_id, "Overridden");
    assert_eq!(items[0].base, Some(RecordId::from_raw(0x801)));
    assert_eq!(items[1].editor_id, "Injected");
    assert_eq!(package.header().next_local_identifier(), 0x802);

    let change_set_id = merged.change_set.id();
    let mut history = ChangeSetStore::default();
    history.insert(merged.change_set).unwrap();
    let encoded = history.to_bytes().unwrap();
    let decoded = ChangeSetStore::from_bytes(&encoded).unwrap();
    assert!(decoded.get(change_set_id).is_some());
    let mut damaged = encoded;
    *damaged.last_mut().unwrap() ^= 1;
    assert!(ChangeSetStore::from_bytes(&damaged).is_err());
    println!(
        "[merge] injected 01000800 -> 00000801, rewrote BASE, and verified history {change_set_id}"
    );
}

#[test]
fn merge_can_select_one_record_or_ignore_all_overrides() {
    let item = |id, name: &str, value| ExampleItem {
        id: RecordId::from_raw(id),
        editor_id: name.into(),
        value,
        weight: 1.0,
        base: None,
    };
    let mut destination_header = PackageHeader::new(PackageId::from_bytes([71; 16])).unwrap();
    destination_header.set_record_count(2);
    destination_header.set_owned_record_count(2);
    destination_header.set_next_local_identifier(0x802).unwrap();
    let mut destination_bytes = destination_header
        .encode(ChangeSetId::from_bytes([0; 32]))
        .unwrap();
    destination_bytes.extend_from_slice(&item(0x800, "A", 1).encode());
    destination_bytes.extend_from_slice(&item(0x801, "B", 2).encode());
    let destination =
        Package::from_source(Arc::new(MemoryPackageSource::new(destination_bytes))).unwrap();

    let mut source_header = PackageHeader::new(PackageId::from_bytes([72; 16])).unwrap();
    source_header
        .add_dependency(
            PackageDependency::new(destination.header().package_id(), "main.pcp").unwrap(),
        )
        .unwrap();
    source_header.set_record_count(3);
    source_header.set_owned_record_count(1);
    source_header.set_next_local_identifier(0x801).unwrap();
    let mut source_bytes = source_header
        .encode(ChangeSetId::from_bytes([0; 32]))
        .unwrap();
    source_bytes.extend_from_slice(&item(0x800, "A override", 100).encode());
    source_bytes.extend_from_slice(&item(0x801, "B override", 200).encode());
    source_bytes.extend_from_slice(&item(0x0100_0800, "New", 3).encode());
    let source = Package::from_source(Arc::new(MemoryPackageSource::new(source_bytes))).unwrap();

    let request = |message| MergeRequest {
        destination: &destination,
        source: &source,
        author: "developer",
        message,
        timestamp_seconds: 1_700_000_200,
        parents: vec![],
    };
    let selected = merge_packages_with_options(
        request("merge B only"),
        &ExampleSchema,
        &MergeOptions {
            selection: MergeSelection::Record(RecordId::from_raw(0x801)),
            ..MergeOptions::default()
        },
    )
    .unwrap();
    let selected =
        Package::from_source(Arc::new(MemoryPackageSource::new(selected.package_bytes))).unwrap();
    let selected_index = selected.build_index().unwrap();
    assert_eq!(
        ExampleItem::decode(
            selected_index
                .record(RecordId::from_raw(0x800))
                .unwrap()
                .read()
                .unwrap()
        )
        .value,
        1
    );
    assert_eq!(
        ExampleItem::decode(
            selected_index
                .record(RecordId::from_raw(0x801))
                .unwrap()
                .read()
                .unwrap()
        )
        .value,
        200
    );

    let additions_only = merge_packages_with_options(
        request("merge additions only"),
        &ExampleSchema,
        &MergeOptions {
            include_overrides: false,
            ..MergeOptions::default()
        },
    )
    .unwrap();
    let additions_only = Package::from_source(Arc::new(MemoryPackageSource::new(
        additions_only.package_bytes,
    )))
    .unwrap();
    let additions_only_index = additions_only.build_index().unwrap();
    assert_eq!(
        ExampleItem::decode(
            additions_only_index
                .record(RecordId::from_raw(0x800))
                .unwrap()
                .read()
                .unwrap()
        )
        .value,
        1
    );
    assert_eq!(
        ExampleItem::decode(
            additions_only_index
                .record(RecordId::from_raw(0x802))
                .unwrap()
                .read()
                .unwrap()
        )
        .editor_id,
        "New"
    );
    println!(
        "[merge-selection] merged one override, then additions-only without applying overrides"
    );
}

fn field_merge_record(id: u32, name: &str, value: u32, quests: &[u32], tags: &[&str]) -> Vec<u8> {
    let mut writer = RecordWriter::new(
        ITEM,
        RecordFlags::default(),
        RecordId::from_raw(id),
        1.0,
        ChangeSetId::from_bytes([0; 32]),
    );
    writer.write_subrecord(EDID, name.as_bytes()).unwrap();
    writer.write_u32(VALU, value).unwrap();
    let quests = encode_list(
        quests,
        |quest| quest.to_le_bytes().to_vec(),
        CollectionLimits::default(),
    )
    .unwrap();
    writer.write_subrecord(QSTS, &quests).unwrap();
    for tag in tags {
        writer.write_subrecord(TAGS, tag.as_bytes()).unwrap();
    }
    writer.finish().unwrap()
}

fn read_field_merge_record(mut reader: RecordReader) -> (String, u32, Vec<u32>, Vec<String>) {
    let mut name = String::new();
    let mut value = 0;
    let mut quests = Vec::new();
    let mut tags = Vec::new();
    while let Some(header) = reader.next_subrecord().unwrap() {
        let payload = reader.current_subrecord_payload().unwrap();
        match header.signature() {
            EDID => name = String::from_utf8(payload.to_vec()).unwrap(),
            VALU => value = u32::from_le_bytes(payload.try_into().unwrap()),
            QSTS => {
                quests = decode_list(
                    payload,
                    |item| {
                        Ok(u32::from_le_bytes(
                            item.try_into().map_err(|_| "quest size".to_string())?,
                        ))
                    },
                    CollectionLimits::default(),
                )
                .unwrap()
            }
            TAGS => tags.push(String::from_utf8(payload.to_vec()).unwrap()),
            _ => {}
        }
    }
    (name, value, quests, tags)
}

#[test]
fn selected_subrecords_and_list_append_work_offline_and_at_runtime() {
    let mut destination_header = PackageHeader::new(PackageId::from_bytes([81; 16])).unwrap();
    destination_header.set_record_count(1);
    destination_header.set_owned_record_count(1);
    destination_header.set_next_local_identifier(0x801).unwrap();
    let mut destination_bytes = destination_header
        .encode(ChangeSetId::from_bytes([0; 32]))
        .unwrap();
    destination_bytes.extend_from_slice(&field_merge_record(
        0x800,
        "Original",
        1,
        &[10, 20],
        &["shared"],
    ));
    let destination =
        Package::from_source(Arc::new(MemoryPackageSource::new(destination_bytes))).unwrap();

    let mut source_header = PackageHeader::new(PackageId::from_bytes([82; 16])).unwrap();
    source_header
        .add_dependency(
            PackageDependency::new(destination.header().package_id(), "dialogue.pcp").unwrap(),
        )
        .unwrap();
    source_header.set_record_count(1);
    source_header.set_owned_record_count(0);
    let mut source_bytes = source_header
        .encode(ChangeSetId::from_bytes([0; 32]))
        .unwrap();
    source_bytes.extend_from_slice(&field_merge_record(
        0x800,
        "Ignored name",
        9,
        &[10, 20, 30],
        &["shared", "added"],
    ));
    let source = Package::from_source(Arc::new(MemoryPackageSource::new(source_bytes))).unwrap();

    let rules = vec![
        SubrecordMergeRule {
            signature: EDID,
            strategy: SubrecordMergeStrategy::KeepDestination,
        },
        SubrecordMergeRule {
            signature: VALU,
            strategy: SubrecordMergeStrategy::Replace,
        },
        SubrecordMergeRule {
            signature: QSTS,
            strategy: SubrecordMergeStrategy::AppendEncodedList {
                mode: ListAppendMode::NewIndices,
                limits: CollectionLimits::default(),
            },
        },
        SubrecordMergeRule {
            signature: TAGS,
            strategy: SubrecordMergeStrategy::AppendOccurrences { deduplicate: true },
        },
    ];
    let destination_index = destination.build_index().unwrap();
    let source_index = source.build_index().unwrap();

    let runtime_bytes = compose_record_override(
        destination_index.record(RecordId::from_raw(0x800)).unwrap(),
        source_index.record(RecordId::from_raw(0x800)).unwrap(),
        &rules,
    )
    .unwrap();
    let chain_bytes = compose_override_chain(
        &[
            destination_index.record(RecordId::from_raw(0x800)).unwrap(),
            source_index.record(RecordId::from_raw(0x800)).unwrap(),
        ],
        &rules,
    )
    .unwrap();
    assert_eq!(runtime_bytes, chain_bytes);
    let mut runtime_header = destination.header().clone();
    runtime_header.set_record_count(1);
    runtime_header.set_owned_record_count(1);
    let mut runtime_package = runtime_header
        .encode(ChangeSetId::from_bytes([0; 32]))
        .unwrap();
    runtime_package.extend_from_slice(&runtime_bytes);
    let runtime_package =
        Package::from_source(Arc::new(MemoryPackageSource::new(runtime_package))).unwrap();
    let runtime_index = runtime_package.build_index().unwrap();
    let runtime = read_field_merge_record(
        runtime_index
            .record(RecordId::from_raw(0x800))
            .unwrap()
            .read()
            .unwrap(),
    );

    let committed = merge_packages_with_options(
        MergeRequest {
            destination: &destination,
            source: &source,
            author: "dialogue editor",
            message: "compose greeting registrations",
            timestamp_seconds: 1_700_000_201,
            parents: vec![],
        },
        &ExampleSchema,
        &MergeOptions {
            override_mode: OverrideMergeMode::SelectedSubrecords(rules),
            ..MergeOptions::default()
        },
    )
    .unwrap();
    let committed =
        Package::from_source(Arc::new(MemoryPackageSource::new(committed.package_bytes))).unwrap();
    let committed_index = committed.build_index().unwrap();
    let committed = read_field_merge_record(
        committed_index
            .record(RecordId::from_raw(0x800))
            .unwrap()
            .read()
            .unwrap(),
    );
    assert_eq!(runtime, committed);
    assert_eq!(runtime.0, "Original");
    assert_eq!(runtime.1, 9);
    assert_eq!(runtime.2, vec![10, 20, 30]);
    assert_eq!(runtime.3, vec!["shared", "added"]);
    println!(
        "[subrecord-merge] runtime and offline composition kept EDID, replaced VALU, appended QSTS by index, and deduplicated TAGS"
    );
}

fn block_on<F: Future>(future: F) -> F::Output {
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(Noop));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match Pin::as_mut(&mut future).poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::yield_now(),
        }
    }
}
