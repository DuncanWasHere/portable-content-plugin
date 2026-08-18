use pluginable_content_package_core::{
    ChangeSetId, GroupLabel, GroupType, GroupWriter, LoadOrder, MemoryPackageSource, MergeOptions,
    MergeRequest, MergeSelection, NoReferenceRewriter, Package, PackageDependency, PackageEntry,
    PackageHeader, PackageId, RecordFlags, RecordId, RecordWriter, RuntimeRecordId, Signature,
    ValidationReport, merge_packages, merge_packages_with_options, scene_offset_tables_from_index,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

const SCENE: Signature = Signature::from_bytes(*b"SCEN");
const ENTITY: Signature = Signature::from_bytes(*b"ENTY");

fn record(signature: Signature, id: u32, payload: Option<(Signature, &[u8])>) -> Vec<u8> {
    let mut writer = RecordWriter::new(
        signature,
        RecordFlags::default(),
        RecordId::from_raw(id),
        1.0,
        ChangeSetId::from_bytes([0; 32]),
    );
    if let Some((field, bytes)) = payload {
        writer.write_subrecord(field, bytes).unwrap();
    }
    writer.finish().unwrap()
}

fn entity(id: u32, persistent: bool) -> Vec<u8> {
    RecordWriter::new(
        ENTITY,
        if persistent {
            RecordFlags::PERSISTENT
        } else {
            RecordFlags::default()
        },
        RecordId::from_raw(id),
        1.0,
        ChangeSetId::from_bytes([0; 32]),
    )
    .finish()
    .unwrap()
}

fn chunk_group(
    chunk_id: u32,
    label: GroupLabel,
    group_type: GroupType,
    persistent_id: u32,
    temporary_id: u32,
) -> Vec<u8> {
    let mut persistent = GroupWriter::new(
        GroupLabel::from_record_id(RecordId::from_raw(chunk_id)),
        GroupType::ScenePersistentChildren,
    );
    persistent.push_entry(&entity(persistent_id, true));
    let mut temporary = GroupWriter::new(
        GroupLabel::from_record_id(RecordId::from_raw(chunk_id)),
        GroupType::SceneTemporaryChildren,
    );
    temporary.push_entry(&entity(temporary_id, false));
    let mut chunk = GroupWriter::new(label, group_type);
    chunk.push_entry(&record(SCENE, chunk_id, None));
    let mut children = GroupWriter::new(
        GroupLabel::from_record_id(RecordId::from_raw(chunk_id)),
        GroupType::SceneChildren,
    );
    children.push_entry(&persistent.finish().unwrap());
    children.push_entry(&temporary.finish().unwrap());
    chunk.push_entry(&children.finish().unwrap());
    chunk.finish().unwrap()
}

fn build_scene_package() -> Package {
    let mut header = PackageHeader::new(PackageId::from_bytes([9; 16])).unwrap();
    header.set_record_count(10);
    header.set_owned_record_count(10);
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();

    let interior = chunk_group(
        0x801,
        GroupLabel::from_i32(0),
        GroupType::InteriorSceneSubBlock,
        0x804,
        0x805,
    );
    let exterior_a = chunk_group(
        0x802,
        GroupLabel::from_grid(0, 0),
        GroupType::ExteriorSceneSubBlock,
        0x806,
        0x807,
    );
    let exterior_b = chunk_group(
        0x803,
        GroupLabel::from_grid(0, 1),
        GroupType::ExteriorSceneSubBlock,
        0x808,
        0x809,
    );
    let mut interior_block =
        GroupWriter::new(GroupLabel::from_i32(0), GroupType::InteriorSceneBlock);
    interior_block.push_entry(&interior);
    let mut exterior_block =
        GroupWriter::new(GroupLabel::from_grid(0, 0), GroupType::ExteriorSceneBlock);
    exterior_block.push_entry(&exterior_a);
    exterior_block.push_entry(&exterior_b);
    let mut scene_children = GroupWriter::new(
        GroupLabel::from_record_id(RecordId::from_raw(0x800)),
        GroupType::WorldChildren,
    );
    scene_children.push_entry(&interior_block.finish().unwrap());
    scene_children.push_entry(&exterior_block.finish().unwrap());
    let mut top = GroupWriter::new(GroupLabel::from_signature(SCENE), GroupType::TopLevel);
    top.push_entry(&record(SCENE, 0x800, None));
    top.push_entry(&scene_children.finish().unwrap());
    bytes.extend_from_slice(&top.finish().unwrap());
    Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap()
}

fn is_in_group(
    index: &pluginable_content_package_core::PackageIndex,
    record: &pluginable_content_package_core::RecordView,
    group_type: GroupType,
) -> bool {
    index.groups().iter().any(|group| {
        group.header().group_type() == group_type
            && group.payload_offset() <= record.header_offset()
            && record.header_offset() < group.end_offset()
    })
}

fn load_group(package: &Package, start: u64, end: u64) -> HashSet<RecordId> {
    fn visit(
        reader: &mut pluginable_content_package_core::PackageReader,
        loaded: &mut HashSet<RecordId>,
        persistent: bool,
    ) {
        while let Some(entry) = reader.next_entry().unwrap() {
            match entry {
                PackageEntry::Record(record)
                    if record.header().signature() == ENTITY && !persistent =>
                {
                    loaded.insert(record.header().record_id());
                }
                PackageEntry::Record(_) => {}
                PackageEntry::Group(group) => visit(
                    &mut group.children().unwrap(),
                    loaded,
                    persistent || group.header().group_type() == GroupType::ScenePersistentChildren,
                ),
            }
        }
    }
    let mut loaded = HashSet::new();
    visit(
        &mut package.reader_with_range(start, end).unwrap(),
        &mut loaded,
        false,
    );
    loaded
}

#[test]
fn empty_temporary_groups_still_index_the_scene_record() {
    let mut header = PackageHeader::new(PackageId::from_bytes([8; 16])).unwrap();
    header.set_record_count(1);
    header.set_owned_record_count(1);
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
    bytes.extend_from_slice(&record(SCENE, 0x801, None));
    let group = GroupWriter::new(
        GroupLabel::from_record_id(RecordId::from_raw(0x801)),
        GroupType::SceneTemporaryChildren,
    );
    bytes.extend_from_slice(&group.finish().unwrap());
    let package = Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap();
    let index = package.build_index().unwrap();

    let tables = scene_offset_tables_from_index(&index).unwrap();
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].world_id(), None);
    assert_eq!(tables[0].offsets().len(), 1);
    assert_eq!(tables[0].offsets()[0].scene_id(), RecordId::from_raw(0x801));
}

#[test]
fn persistent_registry_and_scene_streaming_use_cached_group_offsets() {
    let package = build_scene_package();
    let index = package.build_index().unwrap();
    let tables = scene_offset_tables_from_index(&index).unwrap();
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].world_id(), Some(RecordId::from_raw(0x800)));
    assert_eq!(tables[0].offsets().len(), 3);
    for offset in tables[0].offsets() {
        assert_eq!(
            offset.start_offset(),
            index.record(offset.scene_id()).unwrap().header_offset()
        );
        let children_end = index
            .groups()
            .iter()
            .find(|group| {
                group.header().group_type() == GroupType::SceneChildren
                    && group.header().label().record_id() == offset.scene_id()
            })
            .unwrap()
            .end_offset();
        assert_eq!(offset.end_offset(), children_end);
        let loaded = load_group(&package, offset.start_offset(), offset.end_offset());
        assert_eq!(
            loaded.len(),
            1,
            "only temporary children are in scene offsets"
        );
    }
    let persistent: HashSet<_> = index
        .records_by_signature(ENTITY)
        .filter(|record| is_in_group(&index, record, GroupType::ScenePersistentChildren))
        .map(|record| record.header().record_id())
        .collect();
    println!("[structure] startup registry instantiated persistent entities {persistent:?}");
    assert_eq!(persistent.len(), 3);

    let mut interior = None;
    let mut exterior = HashMap::new();
    for group in index.groups() {
        match group.header().group_type() {
            GroupType::InteriorSceneSubBlock => {
                interior = Some((group.payload_offset(), group.end_offset()))
            }
            GroupType::ExteriorSceneSubBlock => {
                exterior.insert(
                    group.header().label().grid(),
                    (group.payload_offset(), group.end_offset()),
                );
            }
            _ => {}
        }
    }
    println!(
        "[offset-cache] cached 1 interior and {} exterior chunk ranges",
        exterior.len()
    );
    assert_eq!(exterior.len(), 2);

    let interior_loaded = load_group(&package, interior.unwrap().0, interior.unwrap().1);
    println!("[interior] loaded temporary batch {interior_loaded:?}");
    assert_eq!(interior_loaded, HashSet::from([RecordId::from_raw(0x805)]));
    drop(interior_loaded);
    assert_eq!(persistent.len(), 3);
    println!("[interior] unloaded representations; persistent registry remains intact");

    let first = exterior[&(0, 0)];
    let second = exterior[&(0, 1)];
    let first_loaded = load_group(&package, first.0, first.1);
    println!("[exterior] window at (0,0) loaded {first_loaded:?}");
    assert!(first_loaded.contains(&RecordId::from_raw(0x807)));
    let second_loaded = load_group(&package, second.0, second.1);
    println!("[exterior] moved window to (0,1), unloaded first batch and loaded {second_loaded:?}");
    assert_eq!(second_loaded, HashSet::from([RecordId::from_raw(0x809)]));
}

fn build_streaming_override_package() -> Package {
    let mut header = PackageHeader::new(PackageId::from_bytes([10; 16])).unwrap();
    header
        .add_dependency(
            PackageDependency::new(PackageId::from_bytes([9; 16]), "world.pcp").unwrap(),
        )
        .unwrap();
    header.set_record_count(2);
    header.set_owned_record_count(0);
    header.add_streaming_override(RecordId::from_raw(0x806));
    header.add_streaming_override(RecordId::from_raw(0x807));
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
    let mut persistent = GroupWriter::new(
        GroupLabel::from_record_id(RecordId::from_raw(0x802)),
        GroupType::ScenePersistentChildren,
    );
    persistent.push_entry(&entity(0x806, true));
    let mut temporary = GroupWriter::new(
        GroupLabel::from_record_id(RecordId::from_raw(0x802)),
        GroupType::SceneTemporaryChildren,
    );
    temporary.push_entry(&entity(0x807, false));
    let mut exterior = GroupWriter::new(
        GroupLabel::from_grid(0, 0),
        GroupType::ExteriorSceneSubBlock,
    );
    exterior.push_entry(&persistent.finish().unwrap());
    exterior.push_entry(&temporary.finish().unwrap());
    bytes.extend_from_slice(&exterior.finish().unwrap());
    Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap()
}

#[test]
fn multi_package_streaming_uses_cached_offsets_and_load_order_winners() {
    let main = Arc::new(build_scene_package());
    let override_package = Arc::new(build_streaming_override_package());
    let load_order = LoadOrder::build(vec![main.clone(), override_package.clone()]).unwrap();
    let record_index = load_order.build_record_index().unwrap();
    let main_index = main.build_index().unwrap();
    let override_index = override_package.build_index().unwrap();

    let persistent_winners: HashSet<_> = record_index
        .records()
        .filter(|chain| chain.winner().record().header().signature() == ENTITY)
        .filter(|chain| {
            let winner = chain.winner();
            let index = if winner.package_index() == 0 {
                &main_index
            } else {
                &override_index
            };
            is_in_group(index, winner.record(), GroupType::ScenePersistentChildren)
        })
        .map(|chain| chain.runtime_id())
        .collect();
    assert_eq!(persistent_winners.len(), 3);
    assert_eq!(
        record_index
            .winning_record(RuntimeRecordId::from_raw(0x806))
            .unwrap()
            .package_index(),
        1
    );

    let override_range = override_index
        .groups()
        .iter()
        .find(|group| group.header().group_type() == GroupType::ExteriorSceneSubBlock)
        .map(|group| (group.payload_offset(), group.end_offset()))
        .unwrap();
    let temporary = load_group(&override_package, override_range.0, override_range.1);
    assert_eq!(temporary, HashSet::from([RecordId::from_raw(0x807)]));
    assert_eq!(
        load_order.streaming_winner(RuntimeRecordId::from_raw(0x807)),
        Some(1)
    );
    println!(
        "[multi-package-streaming] cached override offsets {:?}; persistent and temporary winners came from package 1",
        override_range
    );
}

fn hierarchy_package(package_id: u8, dependency: Option<u8>, include_parent: bool) -> Package {
    let mut header = PackageHeader::new(PackageId::from_bytes([package_id; 16])).unwrap();
    if let Some(dependency) = dependency {
        header
            .add_dependency(
                PackageDependency::new(PackageId::from_bytes([dependency; 16]), "scene-master.pcp")
                    .unwrap(),
            )
            .unwrap();
    }
    let child_id = if dependency.is_some() {
        0x0100_0800
    } else {
        0x801
    };
    header.set_record_count(1 + include_parent as u32);
    header.set_owned_record_count(if dependency.is_some() {
        1
    } else {
        1 + include_parent as u32
    });
    header
        .set_next_local_identifier(if dependency.is_some() { 0x801 } else { 0x802 })
        .unwrap();
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
    let mut children = GroupWriter::new(
        GroupLabel::from_record_id(RecordId::from_raw(0x800)),
        GroupType::WorldChildren,
    );
    children.push_entry(&entity(child_id, false));
    let mut top = GroupWriter::new(GroupLabel::from_signature(SCENE), GroupType::TopLevel);
    if include_parent {
        top.push_entry(&record(SCENE, 0x800, None));
    }
    top.push_entry(&children.finish().unwrap());
    bytes.extend_from_slice(&top.finish().unwrap());
    Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap()
}

#[test]
fn hierarchy_merge_places_injected_records_at_source_paths_and_unions_children() {
    let destination = hierarchy_package(41, None, true);
    let source = hierarchy_package(42, Some(41), true);
    let merged = merge_packages_with_options(
        MergeRequest {
            destination: &destination,
            source: &source,
            author: "scene editor",
            message: "add table",
            timestamp_seconds: 1_700_000_100,
            parents: vec![],
        },
        &NoReferenceRewriter,
        &MergeOptions {
            selection: MergeSelection::RecordAndDescendants(RecordId::from_raw(0x800)),
            ..MergeOptions::default()
        },
    )
    .unwrap();
    let package =
        Package::from_source(Arc::new(MemoryPackageSource::new(merged.package_bytes))).unwrap();
    let index = package.build_index().unwrap();
    let scene_children = index
        .groups()
        .iter()
        .find(|group| group.header().group_type() == GroupType::WorldChildren)
        .unwrap();
    let mut direct_records = Vec::new();
    let mut reader = scene_children.children().unwrap();
    while let Some(entry) = reader.next_entry().unwrap() {
        if let PackageEntry::Record(record) = entry {
            direct_records.push(record.header().record_id());
        }
    }
    assert_eq!(
        direct_records,
        vec![RecordId::from_raw(0x801), RecordId::from_raw(0x802)]
    );
    assert_eq!(index.records_by_signature(SCENE).len(), 1);
    println!(
        "[path-merge] placed the injected record at SCEN/SceneChildren(00000800) and unioned it with the existing child"
    );
}

fn relocation_destination() -> Package {
    let mut header = PackageHeader::new(PackageId::from_bytes([70; 16])).unwrap();
    header.set_record_count(3);
    header.set_owned_record_count(3);
    header.set_next_local_identifier(0x803).unwrap();
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();

    let mut scene_a_children = GroupWriter::new(
        GroupLabel::from_record_id(RecordId::from_raw(0x800)),
        GroupType::WorldChildren,
    );
    scene_a_children.push_entry(&entity(0x802, false));
    let mut top = GroupWriter::new(GroupLabel::from_signature(SCENE), GroupType::TopLevel);
    top.push_entry(&record(SCENE, 0x800, None));
    top.push_entry(&scene_a_children.finish().unwrap());
    top.push_entry(&record(SCENE, 0x801, None));
    bytes.extend_from_slice(&top.finish().unwrap());
    Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap()
}

fn relocation_source(destination: &Package) -> Package {
    let mut header = PackageHeader::new(PackageId::from_bytes([71; 16])).unwrap();
    header
        .add_dependency(
            PackageDependency::new(destination.header().package_id(), "scene-master.pcp").unwrap(),
        )
        .unwrap();
    header.set_record_count(2);
    header.set_owned_record_count(0);
    let mut bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();

    let mut scene_b_children = GroupWriter::new(
        GroupLabel::from_record_id(RecordId::from_raw(0x801)),
        GroupType::WorldChildren,
    );
    scene_b_children.push_entry(&entity(0x802, false));
    let mut top = GroupWriter::new(GroupLabel::from_signature(SCENE), GroupType::TopLevel);
    top.push_entry(&record(
        SCENE,
        0x801,
        Some((Signature::from_bytes(*b"NAME"), b"Scene B override")),
    ));
    top.push_entry(&scene_b_children.finish().unwrap());
    bytes.extend_from_slice(&top.finish().unwrap());
    Package::from_source(Arc::new(MemoryPackageSource::new(bytes))).unwrap()
}

#[test]
fn override_identity_uses_record_id_while_placement_uses_the_source_path() {
    let destination = relocation_destination();
    let source = relocation_source(&destination);
    let merged = merge_packages_with_options(
        MergeRequest {
            destination: &destination,
            source: &source,
            author: "scene editor",
            message: "move child to scene B",
            timestamp_seconds: 1_700_000_103,
            parents: vec![],
        },
        &NoReferenceRewriter,
        &MergeOptions {
            selection: MergeSelection::Record(RecordId::from_raw(0x802)),
            ..MergeOptions::default()
        },
    )
    .unwrap();
    assert_eq!(merged.change_set.operations().len(), 2);

    let package =
        Package::from_source(Arc::new(MemoryPackageSource::new(merged.package_bytes))).unwrap();
    let index = package.build_index().unwrap();
    let child_path = index.record_path(RecordId::from_raw(0x802)).unwrap();
    assert_eq!(child_path.len(), 2);
    assert_eq!(child_path[1].group_type(), GroupType::WorldChildren);
    assert_eq!(child_path[1].label().record_id(), RecordId::from_raw(0x801));

    let scene_b = index.record(RecordId::from_raw(0x801)).unwrap();
    let mut reader = scene_b.read().unwrap();
    let field = reader.next_subrecord().unwrap().unwrap();
    assert_eq!(field.signature(), Signature::from_bytes(*b"NAME"));
    assert_eq!(
        reader.current_subrecord_payload().unwrap(),
        b"Scene B override"
    );
    println!(
        "[path-relocation] matched child 00000802 by ID, moved it from scene 00000800 to 00000801, and automatically merged the scene-B parent carrier"
    );
}

#[test]
fn hierarchy_merge_rejects_child_edits_without_a_parent_override() {
    let destination = hierarchy_package(51, None, true);
    let source = hierarchy_package(52, Some(51), false);
    let result = merge_packages(
        MergeRequest {
            destination: &destination,
            source: &source,
            author: "scene editor",
            message: "invalid child-only edit",
            timestamp_seconds: 1_700_000_101,
            parents: vec![],
        },
        &NoReferenceRewriter,
    );
    assert!(result.is_err());
    println!(
        "[path-merge] rejected SceneChildren edit because the labelled parent was not overridden"
    );
}

#[test]
fn deleting_a_parent_does_not_silently_delete_independent_children() {
    let destination = hierarchy_package(61, None, true);
    let mut header = PackageHeader::new(PackageId::from_bytes([62; 16])).unwrap();
    header
        .add_dependency(
            PackageDependency::new(destination.header().package_id(), "scene-master.pcp").unwrap(),
        )
        .unwrap();
    header.set_record_count(1);
    header.set_owned_record_count(0);
    let mut source_bytes = header.encode(ChangeSetId::from_bytes([0; 32])).unwrap();
    source_bytes.extend_from_slice(
        &RecordWriter::new(
            SCENE,
            RecordFlags::DELETED,
            RecordId::from_raw(0x800),
            1.0,
            ChangeSetId::from_bytes([0; 32]),
        )
        .finish()
        .unwrap(),
    );
    let source = Package::from_source(Arc::new(MemoryPackageSource::new(source_bytes))).unwrap();
    let merged = merge_packages(
        MergeRequest {
            destination: &destination,
            source: &source,
            author: "scene editor",
            message: "delete scene parent",
            timestamp_seconds: 1_700_000_102,
            parents: vec![],
        },
        &NoReferenceRewriter,
    )
    .unwrap();
    let package =
        Package::from_source(Arc::new(MemoryPackageSource::new(merged.package_bytes))).unwrap();
    let index = package.build_index().unwrap();
    assert!(index.record(RecordId::from_raw(0x800)).is_none());
    assert!(index.record(RecordId::from_raw(0x801)).is_some());
    let validation = ValidationReport::for_indexed_package(&package, &index);
    assert!(
        validation
            .issues()
            .iter()
            .any(|issue| issue.code == "PCP-ORPHANED-RECORD-PATH")
    );
    println!(
        "[path-delete] removed the parent only, retained independently merged children, and reported the orphaned path"
    );
}
