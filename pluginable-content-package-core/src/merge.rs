use crate::{
    ChangeOperation, ChangeSet, ChangeSetError, ChangeSetId, CollectionError, CollectionLimits,
    GroupLabel, GroupType, GroupWriter, ListAppendMode, Package, PackageEntry, PackageHeaderError,
    PackageId, PackageIndex, PackageIndexError, PackageReadError, PackageReader, PackageWriteError,
    RecordFlags, RecordId, RecordReadError, RecordWriter, Signature, append_encoded_list,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt,
};

/// Translates serialized references from the source package's internal load order
/// into the destination package's internal load order (relative to dependencies).
pub struct RecordIdMapper {
    source_dependency_to_destination_index: Vec<u8>,
    source_owned_index: u8,
    injected: HashMap<RecordId, RecordId>,
}

impl RecordIdMapper {
    pub fn map(&self, source: RecordId) -> Result<RecordId, MergeError> {
        if source.package_index() == self.source_owned_index {
            return self
                .injected
                .get(&source)
                .copied()
                .ok_or(MergeError::UnmappedSourceRecord(source));
        }
        let destination_index = self
            .source_dependency_to_destination_index
            .get(source.package_index() as usize)
            .copied()
            .ok_or(MergeError::InvalidSourceReference(source))?;
        RecordId::new(destination_index, source.local_identifier())
            .map_err(|_| MergeError::InvalidSourceReference(source))
    }
}

/// Implemented by games to rewrite only fields that contain record IDs.
pub trait ReferenceRewriter {
    fn rewrite_subrecord(
        &self,
        record_signature: Signature,
        subrecord_signature: Signature,
        payload: &mut Vec<u8>,
        ids: &RecordIdMapper,
    ) -> Result<(), String>;

    /// Allows games to declare additional `GroupType::Unknown` values.
    /// Where their label is a parent record ID that needs to be rewritten.
    fn group_label_is_record_id(&self, group_type: GroupType) -> bool {
        built_in_group_label_is_record_id(group_type)
    }
}

#[derive(Default)]
pub struct NoReferenceRewriter;
impl ReferenceRewriter for NoReferenceRewriter {
    fn rewrite_subrecord(
        &self,
        _record_signature: Signature,
        _subrecord_signature: Signature,
        _payload: &mut Vec<u8>,
        _ids: &RecordIdMapper,
    ) -> Result<(), String> {
        Ok(())
    }
}

pub struct MergeRequest<'a> {
    pub destination: &'a Package,
    pub source: &'a Package,
    pub author: &'a str,
    pub message: &'a str,
    pub timestamp_seconds: i64,
    pub parents: Vec<ChangeSetId>,
}

pub struct MergeResult {
    pub package_bytes: Vec<u8>,
    pub change_set: ChangeSet,
    pub injected_ids: HashMap<RecordId, RecordId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeSelection {
    All,
    /// Merges this record and every parent required by its serialized path.
    Record(RecordId),
    /// Same as above and also merges all serialized children (recursively),
    RecordAndDescendants(RecordId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubrecordMergeStrategy {
    Replace,
    KeepDestination,
    AppendOccurrences {
        deduplicate: bool,
    },
    AppendEncodedList {
        mode: ListAppendMode,
        limits: CollectionLimits,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubrecordMergeRule {
    pub signature: Signature,
    pub strategy: SubrecordMergeStrategy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OverrideMergeMode {
    ReplaceRecord,
    SelectedSubrecords(Vec<SubrecordMergeRule>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeOptions {
    pub selection: MergeSelection,
    pub include_overrides: bool,
    pub override_mode: OverrideMergeMode,
}
impl Default for MergeOptions {
    fn default() -> Self {
        Self {
            selection: MergeSelection::All,
            include_overrides: true,
            override_mode: OverrideMergeMode::ReplaceRecord,
        }
    }
}

#[derive(Clone)]
struct LogicalRecord {
    signature: Signature,
    flags: RecordFlags,
    id: RecordId,
    version: f32,
    last_change_set: ChangeSetId,
    subrecords: Vec<(Signature, Vec<u8>)>,
}

#[derive(Clone)]
enum TreeEntry {
    Record(RecordId),
    Group {
        label: GroupLabel,
        group_type: GroupType,
        children: Vec<TreeEntry>,
    },
}

pub fn merge_packages(
    request: MergeRequest<'_>,
    rewriter: &impl ReferenceRewriter,
) -> Result<MergeResult, MergeError> {
    merge_packages_with_options(request, rewriter, &MergeOptions::default())
}

pub fn merge_packages_with_options(
    request: MergeRequest<'_>,
    rewriter: &impl ReferenceRewriter,
    options: &MergeOptions,
) -> Result<MergeResult, MergeError> {
    let destination_id = request.destination.header().package_id();
    let source_id = request.source.header().package_id();
    let source_dependencies = request.source.header().dependencies();
    let destination_dependency_position = source_dependencies
        .iter()
        .position(|dependency| dependency.package_id() == destination_id)
        .ok_or(MergeError::SourceDoesNotDependOnDestination)?;
    let source_owned_index =
        u8::try_from(source_dependencies.len()).map_err(|_| MergeError::TooManyDependencies)?;
    let destination_owned_index = u8::try_from(request.destination.header().dependencies().len())
        .map_err(|_| MergeError::TooManyDependencies)?;

    let mut dependency_map = Vec::with_capacity(source_dependencies.len());
    for dependency in source_dependencies {
        let index = if dependency.package_id() == destination_id {
            destination_owned_index
        } else {
            request
                .destination
                .header()
                .dependencies()
                .iter()
                .position(|candidate| candidate.package_id() == dependency.package_id())
                .ok_or(MergeError::DependencyUnavailableInDestination(
                    dependency.package_id(),
                ))? as u8
        };
        dependency_map.push(index);
    }

    let source_index = request.source.build_index()?;
    let destination_index = request.destination.build_index()?;
    let source_tree = read_tree(request.source.content_reader())?;
    let selected = selected_records(&source_tree, &source_index, options.selection, rewriter)?;
    let mut next_local = request.destination.header().next_local_identifier();
    let mut injected = HashMap::new();
    for record in source_index.records() {
        let id = record.header().record_id();
        if selected.contains(&id) && id.package_index() == source_owned_index {
            let destination = RecordId::new(destination_owned_index, next_local)
                .map_err(|_| MergeError::RecordIdCapacityExhausted)?;
            next_local = next_local
                .checked_add(1)
                .filter(|value| *value <= RecordId::MAXIMUM_LOCAL_IDENTIFIER)
                .ok_or(MergeError::RecordIdCapacityExhausted)?;
            injected.insert(id, destination);
        }
    }
    let mapper = RecordIdMapper {
        source_dependency_to_destination_index: dependency_map,
        source_owned_index,
        injected: injected.clone(),
    };

    let mut records = HashMap::new();
    for view in destination_index.records() {
        let record = read_logical(view)?;
        records.insert(record.id, record);
    }
    let mut destination_tree = read_tree(request.destination.content_reader())?;

    let mut pending = Vec::new();
    let mut actions = HashMap::new();
    for view in source_index.records() {
        if !selected.contains(&view.header().record_id()) {
            continue;
        }
        let source_record = read_logical(view)?;
        let is_new = source_record.id.package_index() == source_owned_index;
        if !is_new && !options.include_overrides {
            continue;
        }
        let destination_record_id = if is_new {
            mapper.map(source_record.id)?
        } else if source_record.id.package_index() as usize == destination_dependency_position {
            RecordId::new(destination_owned_index, source_record.id.local_identifier())
                .map_err(|_| MergeError::InvalidSourceReference(source_record.id))?
        } else {
            return Err(MergeError::OverrideTargetsAnotherDependency(
                source_record.id,
            ));
        };

        if source_record.flags.contains(RecordFlags::DELETED) {
            let previous = records
                .remove(&destination_record_id)
                .ok_or(MergeError::DeleteTargetMissing(destination_record_id))?;
            remove_record(&mut destination_tree, destination_record_id);
            pending.push(PendingOperation::Delete {
                id: destination_record_id,
                previous: previous.last_change_set,
            });
            continue;
        }

        let source_record_id = source_record.id;
        let mut source_record = source_record;
        for (signature, payload) in &mut source_record.subrecords {
            rewriter
                .rewrite_subrecord(source_record.signature, *signature, payload, &mapper)
                .map_err(MergeError::SchemaRewrite)?;
        }
        let mut rewritten = if !is_new {
            match &options.override_mode {
                OverrideMergeMode::ReplaceRecord => source_record,
                OverrideMergeMode::SelectedSubrecords(rules) => {
                    let destination = records
                        .get(&destination_record_id)
                        .ok_or(MergeError::OverrideTargetMissing(destination_record_id))?;
                    compose_logical_override(destination, &source_record, rules)?
                }
            }
        } else {
            source_record
        };
        rewritten.id = destination_record_id;
        let digest = digest_record(&rewritten)?;
        if is_new {
            pending.push(PendingOperation::Add {
                id: destination_record_id,
                digest,
            });
        } else {
            let previous = records
                .get(&destination_record_id)
                .ok_or(MergeError::OverrideTargetMissing(destination_record_id))?
                .last_change_set;
            pending.push(PendingOperation::Override {
                id: destination_record_id,
                previous,
                digest,
            });
        }
        records.insert(destination_record_id, rewritten);
        actions.insert(source_record_id, destination_record_id);
    }
    for destination_id in actions.values() {
        remove_record(&mut destination_tree, *destination_id);
    }
    let source_result = translated_selected_tree(&source_tree, &actions, &mapper, rewriter)?;
    union_tree(&mut destination_tree, source_result);

    let operations = pending.iter().map(PendingOperation::to_public).collect();
    let change_set = ChangeSet::create(
        request.parents,
        destination_id,
        source_id,
        request.author,
        request.message,
        request.timestamp_seconds,
        operations,
    )?;
    for operation in &pending {
        if let Some(record) = records.get_mut(&operation.id()) {
            record.last_change_set = change_set.id();
        }
    }

    let mut header = request.destination.header().clone();
    header.set_next_local_identifier(next_local)?;
    header.set_record_count(records.len() as u32);
    let owned_index = header.dependencies().len() as u8;
    header.set_owned_record_count(
        records
            .keys()
            .filter(|id| id.package_index() == owned_index)
            .count() as u32,
    );
    let mut bytes = header.encode(change_set.id())?;
    for entry in &destination_tree {
        bytes.extend_from_slice(&encode_tree_entry(entry, &records)?);
    }
    Ok(MergeResult {
        package_bytes: bytes,
        change_set,
        injected_ids: injected,
    })
}

enum PendingOperation {
    Add {
        id: RecordId,
        digest: [u8; 32],
    },
    Override {
        id: RecordId,
        previous: ChangeSetId,
        digest: [u8; 32],
    },
    Delete {
        id: RecordId,
        previous: ChangeSetId,
    },
}
impl PendingOperation {
    fn id(&self) -> RecordId {
        match self {
            Self::Add { id, .. } | Self::Override { id, .. } | Self::Delete { id, .. } => *id,
        }
    }
    fn to_public(&self) -> ChangeOperation {
        let runtime = crate::RuntimeRecordId::from_raw(self.id().raw());
        match self {
            Self::Add { digest, .. } => ChangeOperation::Add {
                record_id: runtime,
                content_digest: *digest,
            },
            Self::Override {
                previous, digest, ..
            } => ChangeOperation::Override {
                record_id: runtime,
                previous_change_set: *previous,
                content_digest: *digest,
            },
            Self::Delete { previous, .. } => ChangeOperation::Delete {
                record_id: runtime,
                previous_change_set: *previous,
            },
        }
    }
}

fn selected_records(
    tree: &[TreeEntry],
    source_index: &PackageIndex,
    selection: MergeSelection,
    rewriter: &impl ReferenceRewriter,
) -> Result<HashSet<RecordId>, MergeError> {
    let mut selected = match selection {
        MergeSelection::All => source_index
            .records()
            .map(|record| record.header().record_id())
            .collect(),
        MergeSelection::Record(id) => {
            if source_index.record(id).is_none() {
                return Err(MergeError::SelectedRecordMissing(id));
            }
            HashSet::from([id])
        }
        MergeSelection::RecordAndDescendants(id) => {
            if source_index.record(id).is_none() {
                return Err(MergeError::SelectedRecordMissing(id));
            }
            let mut selected = HashSet::from([id]);
            collect_descendants(tree, id, &mut selected, rewriter);
            selected
        }
    };
    include_serialized_ancestors(&mut selected, source_index, rewriter)?;
    Ok(selected)
}

fn include_serialized_ancestors(
    selected: &mut HashSet<RecordId>,
    source_index: &PackageIndex,
    rewriter: &impl ReferenceRewriter,
) -> Result<(), MergeError> {
    let mut pending: Vec<_> = selected.iter().copied().collect();
    while let Some(id) = pending.pop() {
        let path = source_index
            .record_path(id)
            .ok_or(MergeError::SelectedRecordMissing(id))?;
        for group in path {
            if !rewriter.group_label_is_record_id(group.group_type()) {
                continue;
            }
            let parent = group.label().record_id();
            if source_index.record(parent).is_none() {
                return Err(MergeError::HierarchyParentRecordMissing {
                    group_type: group.group_type(),
                    parent,
                });
            }
            if selected.insert(parent) {
                pending.push(parent);
            }
        }
    }
    Ok(())
}

fn collect_descendants(
    entries: &[TreeEntry],
    parent: RecordId,
    output: &mut HashSet<RecordId>,
    rewriter: &impl ReferenceRewriter,
) {
    for entry in entries {
        if let TreeEntry::Group {
            label,
            group_type,
            children,
            ..
        } = entry
        {
            if rewriter.group_label_is_record_id(*group_type) && label.record_id() == parent {
                collect_record_ids(children, output);
            } else {
                collect_descendants(children, parent, output, rewriter);
            }
        }
    }
}

fn collect_record_ids(entries: &[TreeEntry], output: &mut HashSet<RecordId>) {
    for entry in entries {
        match entry {
            TreeEntry::Record(id) => {
                output.insert(*id);
            }
            TreeEntry::Group { children, .. } => collect_record_ids(children, output),
        }
    }
}

/// Composes an override in memory without writing or mutating either package on disk.
/// This is the runtime counterpart to `OverrideMergeMode::SelectedSubrecords`.
pub fn compose_record_override(
    destination: &crate::RecordView,
    source: &crate::RecordView,
    rules: &[SubrecordMergeRule],
) -> Result<Vec<u8>, MergeError> {
    if destination.header().signature() != source.header().signature() {
        return Err(MergeError::OverrideSignatureMismatch);
    }
    let destination = read_logical(destination)?;
    let source = read_logical(source)?;
    encode_logical(&compose_logical_override(&destination, &source, rules)?)
}

/// Folds an entire load-order override chain from origin to winner using the merge rules.
pub fn compose_override_chain(
    origins: &[&crate::RecordView],
    rules: &[SubrecordMergeRule],
) -> Result<Vec<u8>, MergeError> {
    let (first, remaining) = origins
        .split_first()
        .ok_or(MergeError::EmptyOverrideChain)?;
    let signature = first.header().signature();
    let mut composed = read_logical(first)?;
    for origin in remaining {
        if origin.header().signature() != signature {
            return Err(MergeError::OverrideSignatureMismatch);
        }
        composed = compose_logical_override(&composed, &read_logical(origin)?, rules)?;
    }
    encode_logical(&composed)
}

fn compose_logical_override(
    destination: &LogicalRecord,
    source: &LogicalRecord,
    rules: &[SubrecordMergeRule],
) -> Result<LogicalRecord, MergeError> {
    let mut result = destination.clone();
    result.flags = source.flags;
    result.version = source.version;
    result.last_change_set = source.last_change_set;
    for rule in rules {
        let source_values: Vec<_> = source
            .subrecords
            .iter()
            .filter(|(signature, _)| *signature == rule.signature)
            .map(|(_, payload)| payload.clone())
            .collect();
        match &rule.strategy {
            SubrecordMergeStrategy::KeepDestination => {}
            SubrecordMergeStrategy::Replace => {
                replace_occurrences(&mut result.subrecords, rule.signature, source_values);
            }
            SubrecordMergeStrategy::AppendOccurrences { deduplicate } => {
                for payload in source_values {
                    if !*deduplicate
                        || !result.subrecords.iter().any(|(signature, existing)| {
                            *signature == rule.signature && *existing == payload
                        })
                    {
                        result.subrecords.push((rule.signature, payload));
                    }
                }
            }
            SubrecordMergeStrategy::AppendEncodedList { mode, limits } => {
                if source_values.len() > 1 {
                    return Err(MergeError::ListSubrecordMultiplicity(rule.signature));
                }
                let destination_values: Vec<_> = result
                    .subrecords
                    .iter()
                    .filter(|(signature, _)| *signature == rule.signature)
                    .map(|(_, payload)| payload.as_slice())
                    .collect();
                if destination_values.len() > 1 {
                    return Err(MergeError::ListSubrecordMultiplicity(rule.signature));
                }
                if let Some(source_value) = source_values.first() {
                    let merged = if let Some(destination_value) = destination_values.first() {
                        append_encoded_list(destination_value, source_value, *mode, *limits)?
                    } else {
                        source_value.clone()
                    };
                    replace_occurrences(&mut result.subrecords, rule.signature, vec![merged]);
                }
            }
        }
    }
    Ok(result)
}

fn replace_occurrences(
    subrecords: &mut Vec<(Signature, Vec<u8>)>,
    signature: Signature,
    replacements: Vec<Vec<u8>>,
) {
    let insertion = subrecords
        .iter()
        .position(|(candidate, _)| *candidate == signature)
        .unwrap_or(subrecords.len());
    subrecords.retain(|(candidate, _)| *candidate != signature);
    for (offset, payload) in replacements.into_iter().enumerate() {
        subrecords.insert(insertion + offset, (signature, payload));
    }
}

fn read_tree(mut reader: PackageReader) -> Result<Vec<TreeEntry>, MergeError> {
    let mut entries = Vec::new();
    while let Some(entry) = reader.next_entry()? {
        match entry {
            PackageEntry::Record(record) => {
                entries.push(TreeEntry::Record(record.header().record_id()));
            }
            PackageEntry::Group(group) => {
                let header = group.header();
                entries.push(TreeEntry::Group {
                    label: header.label(),
                    group_type: header.group_type(),
                    children: read_tree(group.children()?)?,
                });
            }
        }
    }
    Ok(entries)
}

fn built_in_group_label_is_record_id(group_type: GroupType) -> bool {
    matches!(
        group_type,
        GroupType::WorldChildren
            | GroupType::SceneChildren
            | GroupType::ConversationChildren
            | GroupType::ScenePersistentChildren
            | GroupType::SceneTemporaryChildren
            | GroupType::SceneDistantChildren
    )
}

fn translated_group_label(
    label: GroupLabel,
    group_type: GroupType,
    mapper: &RecordIdMapper,
    rewriter: &impl ReferenceRewriter,
) -> Result<GroupLabel, MergeError> {
    if rewriter.group_label_is_record_id(group_type) {
        Ok(GroupLabel::from_record_id(mapper.map(label.record_id())?))
    } else {
        Ok(label)
    }
}

fn translated_selected_tree(
    source: &[TreeEntry],
    actions: &HashMap<RecordId, RecordId>,
    mapper: &RecordIdMapper,
    rewriter: &impl ReferenceRewriter,
) -> Result<Vec<TreeEntry>, MergeError> {
    let mut result = Vec::new();
    for entry in source {
        match entry {
            TreeEntry::Record(source_id) => {
                let Some(destination_id) = actions.get(source_id) else {
                    continue;
                };
                result.push(TreeEntry::Record(*destination_id));
            }
            TreeEntry::Group {
                label,
                group_type,
                children,
            } => {
                let translated_children =
                    translated_selected_tree(children, actions, mapper, rewriter)?;
                if translated_children.is_empty() {
                    continue;
                }
                let destination_label =
                    translated_group_label(*label, *group_type, mapper, rewriter)?;
                result.push(TreeEntry::Group {
                    label: destination_label,
                    group_type: *group_type,
                    children: translated_children,
                });
            }
        }
    }
    Ok(result)
}

fn union_tree(destination: &mut Vec<TreeEntry>, source: Vec<TreeEntry>) {
    for entry in source {
        match entry {
            TreeEntry::Record(_) => destination.push(entry),
            TreeEntry::Group {
                label,
                group_type,
                children,
            } => {
                if let Some(TreeEntry::Group {
                    children: destination_children,
                    ..
                }) = destination.iter_mut().find(|candidate| {
                    matches!(candidate, TreeEntry::Group { label: candidate_label, group_type: candidate_type, .. }
                        if *candidate_label == label && *candidate_type == group_type)
                }) {
                    union_tree(destination_children, children);
                } else {
                    destination.push(TreeEntry::Group {
                        label,
                        group_type,
                        children,
                    });
                }
            }
        }
    }
}

fn remove_record(entries: &mut Vec<TreeEntry>, id: RecordId) {
    entries.retain(|entry| !matches!(entry, TreeEntry::Record(candidate) if *candidate == id));
    for entry in entries {
        if let TreeEntry::Group { children, .. } = entry {
            remove_record(children, id);
        }
    }
}

fn encode_tree_entry(
    entry: &TreeEntry,
    records: &HashMap<RecordId, LogicalRecord>,
) -> Result<Vec<u8>, MergeError> {
    match entry {
        TreeEntry::Record(id) => encode_logical(
            records
                .get(id)
                .ok_or(MergeError::TreeReferencesMissingRecord(*id))?,
        ),
        TreeEntry::Group {
            label,
            group_type,
            children,
        } => {
            let mut writer = GroupWriter::new(*label, *group_type);
            for child in children {
                writer.push_entry(&encode_tree_entry(child, records)?);
            }
            Ok(writer.finish()?)
        }
    }
}

fn read_logical(view: &crate::RecordView) -> Result<LogicalRecord, MergeError> {
    let header = view.header();
    let mut reader = view.read()?;
    let mut subrecords = Vec::new();
    while let Some(subrecord) = reader.next_subrecord()? {
        subrecords.push((
            subrecord.signature(),
            reader.current_subrecord_payload()?.to_vec(),
        ));
    }
    Ok(LogicalRecord {
        signature: header.signature(),
        flags: header.flags(),
        id: header.record_id(),
        version: header.version(),
        last_change_set: header.last_change_set(),
        subrecords,
    })
}
fn encode_logical(record: &LogicalRecord) -> Result<Vec<u8>, MergeError> {
    let mut writer = RecordWriter::new(
        record.signature,
        record.flags,
        record.id,
        record.version,
        record.last_change_set,
    );
    for (signature, payload) in &record.subrecords {
        writer.write_subrecord(*signature, payload)?;
    }
    Ok(writer.finish()?)
}
fn digest_record(record: &LogicalRecord) -> Result<[u8; 32], MergeError> {
    let mut copy = record.clone();
    copy.last_change_set = ChangeSetId::from_bytes([0; 32]);
    Ok(Sha256::digest(encode_logical(&copy)?).into())
}

#[derive(Debug)]
pub enum MergeError {
    SourceDoesNotDependOnDestination,
    TooManyDependencies,
    DependencyUnavailableInDestination(PackageId),
    RecordIdCapacityExhausted,
    InvalidSourceReference(RecordId),
    UnmappedSourceRecord(RecordId),
    OverrideTargetsAnotherDependency(RecordId),
    OverrideTargetMissing(RecordId),
    DeleteTargetMissing(RecordId),
    HierarchyParentRecordMissing {
        group_type: GroupType,
        parent: RecordId,
    },
    TreeReferencesMissingRecord(RecordId),
    SelectedRecordMissing(RecordId),
    OverrideSignatureMismatch,
    EmptyOverrideChain,
    ListSubrecordMultiplicity(Signature),
    SchemaRewrite(String),
    Read(RecordReadError),
    PackageRead(PackageReadError),
    Io(std::io::Error),
    Write(PackageWriteError),
    Header(PackageHeaderError),
    ChangeSet(ChangeSetError),
    Collection(CollectionError),
    Index(PackageIndexError),
}
impl fmt::Display for MergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for MergeError {}
impl From<RecordReadError> for MergeError {
    fn from(v: RecordReadError) -> Self {
        Self::Read(v)
    }
}
impl From<PackageReadError> for MergeError {
    fn from(v: PackageReadError) -> Self {
        Self::PackageRead(v)
    }
}
impl From<std::io::Error> for MergeError {
    fn from(v: std::io::Error) -> Self {
        Self::Io(v)
    }
}
impl From<PackageWriteError> for MergeError {
    fn from(v: PackageWriteError) -> Self {
        Self::Write(v)
    }
}
impl From<PackageHeaderError> for MergeError {
    fn from(v: PackageHeaderError) -> Self {
        Self::Header(v)
    }
}
impl From<ChangeSetError> for MergeError {
    fn from(v: ChangeSetError) -> Self {
        Self::ChangeSet(v)
    }
}
impl From<CollectionError> for MergeError {
    fn from(v: CollectionError) -> Self {
        Self::Collection(v)
    }
}
impl From<PackageIndexError> for MergeError {
    fn from(value: PackageIndexError) -> Self {
        Self::Index(value)
    }
}
