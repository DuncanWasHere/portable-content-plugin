use crate::{ChangeSetId, PackageId, RuntimeRecordId};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangeOperation {
    Add {
        record_id: RuntimeRecordId,
        content_digest: [u8; 32],
    },
    Override {
        record_id: RuntimeRecordId,
        previous_change_set: ChangeSetId,
        content_digest: [u8; 32],
    },
    Delete {
        record_id: RuntimeRecordId,
        previous_change_set: ChangeSetId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeSet {
    id: ChangeSetId,
    parents: Vec<ChangeSetId>,
    destination: PackageId,
    source: PackageId,
    author: String,
    message: String,
    timestamp_seconds: i64,
    operations: Vec<ChangeOperation>,
}

impl ChangeSet {
    pub fn create(
        parents: Vec<ChangeSetId>,
        destination: PackageId,
        source: PackageId,
        author: impl Into<String>,
        message: impl Into<String>,
        timestamp_seconds: i64,
        operations: Vec<ChangeOperation>,
    ) -> Result<Self, ChangeSetError> {
        if destination.is_nil() || source.is_nil() {
            return Err(ChangeSetError::NilPackageId);
        }
        if destination == source {
            return Err(ChangeSetError::SameSourceAndDestination);
        }
        let author = author.into();
        let message = message.into();
        if author.is_empty() {
            return Err(ChangeSetError::EmptyAuthor);
        }
        if operations.is_empty() {
            return Err(ChangeSetError::NoOperations);
        }
        let mut ids = HashSet::new();
        for operation in &operations {
            let id = match operation {
                ChangeOperation::Add { record_id, .. }
                | ChangeOperation::Override { record_id, .. }
                | ChangeOperation::Delete { record_id, .. } => *record_id,
            };
            if !ids.insert(id) {
                return Err(ChangeSetError::DuplicateRecordOperation(id));
            }
        }
        let id = compute_id(
            &parents,
            destination,
            source,
            &author,
            &message,
            timestamp_seconds,
            &operations,
        );
        Ok(Self {
            id,
            parents,
            destination,
            source,
            author,
            message,
            timestamp_seconds,
            operations,
        })
    }
    pub const fn id(&self) -> ChangeSetId {
        self.id
    }
    pub fn parents(&self) -> &[ChangeSetId] {
        &self.parents
    }
    pub const fn destination(&self) -> PackageId {
        self.destination
    }
    pub const fn source(&self) -> PackageId {
        self.source
    }
    pub fn author(&self) -> &str {
        &self.author
    }
    pub fn message(&self) -> &str {
        &self.message
    }
    pub const fn timestamp_seconds(&self) -> i64 {
        self.timestamp_seconds
    }
    pub fn operations(&self) -> &[ChangeOperation] {
        &self.operations
    }
}

fn compute_id(
    parents: &[ChangeSetId],
    destination: PackageId,
    source: PackageId,
    author: &str,
    message: &str,
    timestamp: i64,
    operations: &[ChangeOperation],
) -> ChangeSetId {
    let mut hash = Sha256::new();
    hash.update(b"PCP-CHANGE-SET\0");
    hash.update((parents.len() as u32).to_le_bytes());
    for parent in parents {
        hash.update(parent.bytes());
    }
    hash.update(destination.bytes());
    hash.update(source.bytes());
    hash.update(timestamp.to_le_bytes());
    hash.update((author.len() as u32).to_le_bytes());
    hash.update(author.as_bytes());
    hash.update((message.len() as u32).to_le_bytes());
    hash.update(message.as_bytes());
    hash.update((operations.len() as u32).to_le_bytes());
    for operation in operations {
        match operation {
            ChangeOperation::Add {
                record_id,
                content_digest,
            } => {
                hash.update([0]);
                hash.update(record_id.raw().to_le_bytes());
                hash.update(content_digest);
            }
            ChangeOperation::Override {
                record_id,
                previous_change_set,
                content_digest,
            } => {
                hash.update([1]);
                hash.update(record_id.raw().to_le_bytes());
                hash.update(previous_change_set.bytes());
                hash.update(content_digest);
            }
            ChangeOperation::Delete {
                record_id,
                previous_change_set,
            } => {
                hash.update([2]);
                hash.update(record_id.raw().to_le_bytes());
                hash.update(previous_change_set.bytes());
            }
        }
    }
    ChangeSetId::from_bytes(hash.finalize().into())
}

#[derive(Default)]
pub struct ChangeSetStore {
    entries: HashMap<ChangeSetId, ChangeSet>,
}
impl ChangeSetStore {
    pub fn insert(&mut self, change_set: ChangeSet) -> Result<(), ChangeSetError> {
        for parent in change_set.parents() {
            if !self.entries.contains_key(parent) {
                return Err(ChangeSetError::MissingParent(*parent));
            }
        }
        let id = change_set.id();
        if self.entries.contains_key(&id) {
            return Err(ChangeSetError::DuplicateChangeSet);
        }
        self.entries.insert(id, change_set);
        Ok(())
    }
    pub fn get(&self, id: ChangeSetId) -> Option<&ChangeSet> {
        self.entries.get(&id)
    }
    pub fn is_ancestor(&self, ancestor: ChangeSetId, descendant: ChangeSetId) -> bool {
        let mut pending = vec![descendant];
        let mut visited = HashSet::new();
        while let Some(id) = pending.pop() {
            if id == ancestor {
                return true;
            }
            if visited.insert(id)
                && let Some(item) = self.entries.get(&id)
            {
                pending.extend_from_slice(item.parents());
            }
        }
        false
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Encodes a merge history stream.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ChangeSetError> {
        let mut entries: Vec<_> = self.entries.values().collect();
        entries.sort_by_key(|item| item.id().bytes());
        let mut bytes = b"PCVH\x01\0\0\0".to_vec();
        put_u32(&mut bytes, entries.len())?;
        for entry in entries {
            bytes.extend_from_slice(&entry.id().bytes());
            put_u32(&mut bytes, entry.parents.len())?;
            for parent in &entry.parents {
                bytes.extend_from_slice(&parent.bytes());
            }
            bytes.extend_from_slice(&entry.destination.bytes());
            bytes.extend_from_slice(&entry.source.bytes());
            bytes.extend_from_slice(&entry.timestamp_seconds.to_le_bytes());
            put_blob(&mut bytes, entry.author.as_bytes())?;
            put_blob(&mut bytes, entry.message.as_bytes())?;
            put_u32(&mut bytes, entry.operations.len())?;
            for operation in &entry.operations {
                match operation {
                    ChangeOperation::Add {
                        record_id,
                        content_digest,
                    } => {
                        bytes.push(0);
                        bytes.extend_from_slice(&record_id.raw().to_le_bytes());
                        bytes.extend_from_slice(content_digest);
                    }
                    ChangeOperation::Override {
                        record_id,
                        previous_change_set,
                        content_digest,
                    } => {
                        bytes.push(1);
                        bytes.extend_from_slice(&record_id.raw().to_le_bytes());
                        bytes.extend_from_slice(&previous_change_set.bytes());
                        bytes.extend_from_slice(content_digest);
                    }
                    ChangeOperation::Delete {
                        record_id,
                        previous_change_set,
                    } => {
                        bytes.push(2);
                        bytes.extend_from_slice(&record_id.raw().to_le_bytes());
                        bytes.extend_from_slice(&previous_change_set.bytes());
                    }
                }
            }
        }
        Ok(bytes)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChangeSetError> {
        let mut cursor = HistoryCursor { bytes, position: 0 };
        if cursor.take(8)? != b"PCVH\x01\0\0\0" {
            return Err(ChangeSetError::MalformedHistory(
                "unsupported history header".into(),
            ));
        }
        let count = cursor.u32()? as usize;
        let mut decoded = Vec::with_capacity(count);
        for _ in 0..count {
            let expected = ChangeSetId::from_bytes(cursor.array()?);
            let parent_count = cursor.u32()? as usize;
            let mut parents = Vec::with_capacity(parent_count);
            for _ in 0..parent_count {
                parents.push(ChangeSetId::from_bytes(cursor.array()?));
            }
            let destination = PackageId::from_bytes(cursor.array()?);
            let source = PackageId::from_bytes(cursor.array()?);
            let timestamp = i64::from_le_bytes(cursor.array()?);
            let author = cursor.string()?;
            let message = cursor.string()?;
            let operation_count = cursor.u32()? as usize;
            let mut operations = Vec::with_capacity(operation_count);
            for _ in 0..operation_count {
                let tag = cursor.byte()?;
                let record_id = RuntimeRecordId::from_raw(cursor.u32()?);
                operations.push(match tag {
                    0 => ChangeOperation::Add {
                        record_id,
                        content_digest: cursor.array()?,
                    },
                    1 => ChangeOperation::Override {
                        record_id,
                        previous_change_set: ChangeSetId::from_bytes(cursor.array()?),
                        content_digest: cursor.array()?,
                    },
                    2 => ChangeOperation::Delete {
                        record_id,
                        previous_change_set: ChangeSetId::from_bytes(cursor.array()?),
                    },
                    _ => {
                        return Err(ChangeSetError::MalformedHistory(format!(
                            "unknown operation tag {tag}"
                        )));
                    }
                });
            }
            let item = ChangeSet::create(
                parents,
                destination,
                source,
                author,
                message,
                timestamp,
                operations,
            )?;
            if item.id() != expected {
                return Err(ChangeSetError::HistoryIdentifierMismatch {
                    expected,
                    actual: item.id(),
                });
            }
            decoded.push(item);
        }
        if cursor.position != bytes.len() {
            return Err(ChangeSetError::MalformedHistory("trailing bytes".into()));
        }
        let all_ids: HashSet<_> = decoded.iter().map(ChangeSet::id).collect();
        for item in &decoded {
            for parent in item.parents() {
                if !all_ids.contains(parent) {
                    return Err(ChangeSetError::MissingParent(*parent));
                }
            }
        }
        Ok(Self {
            entries: decoded.into_iter().map(|item| (item.id(), item)).collect(),
        })
    }
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), ChangeSetError> {
    let value = u32::try_from(value).map_err(|_| ChangeSetError::HistoryTooLarge)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}
fn put_blob(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), ChangeSetError> {
    put_u32(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}
struct HistoryCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> HistoryCursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ChangeSetError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| ChangeSetError::MalformedHistory("offset overflow".into()))?;
        let result = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| ChangeSetError::MalformedHistory("unexpected end of history".into()))?;
        self.position = end;
        Ok(result)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ChangeSetError> {
        Ok(self.take(N)?.try_into().expect("exact size"))
    }
    fn byte(&mut self) -> Result<u8, ChangeSetError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, ChangeSetError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn string(&mut self) -> Result<String, ChangeSetError> {
        let count = self.u32()? as usize;
        String::from_utf8(self.take(count)?.to_vec())
            .map_err(|_| ChangeSetError::MalformedHistory("invalid UTF-8".into()))
    }
}

#[derive(Debug)]
pub enum ChangeSetError {
    NilPackageId,
    SameSourceAndDestination,
    EmptyAuthor,
    NoOperations,
    DuplicateRecordOperation(RuntimeRecordId),
    MissingParent(ChangeSetId),
    DuplicateChangeSet,
    HistoryTooLarge,
    MalformedHistory(String),
    HistoryIdentifierMismatch {
        expected: ChangeSetId,
        actual: ChangeSetId,
    },
}
impl fmt::Display for ChangeSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NilPackageId => write!(f, "Change-set package identities cannot be nil."),
            Self::SameSourceAndDestination => write!(
                f,
                "A merge source and destination must be different packages."
            ),
            Self::EmptyAuthor => write!(f, "A change set requires an author."),
            Self::NoOperations => write!(f, "A change set requires at least one operation."),
            Self::DuplicateRecordOperation(id) => write!(
                f,
                "Change set contains multiple operations for record {id}."
            ),
            Self::MissingParent(id) => {
                write!(f, "Parent change set {id} is absent from the store.")
            }
            Self::DuplicateChangeSet => write!(f, "Change set already exists."),
            Self::HistoryTooLarge => write!(
                f,
                "Merge history exceeds portable 32-bit collection limits."
            ),
            Self::MalformedHistory(message) => write!(f, "Malformed merge history: {message}."),
            Self::HistoryIdentifierMismatch { expected, actual } => write!(
                f,
                "Merge history expected change set {expected}, but its verified identifier is {actual}."
            ),
        }
    }
}
impl std::error::Error for ChangeSetError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn package_id(byte: u8) -> PackageId {
        PackageId::from_bytes([byte; 16])
    }

    #[test]
    fn canonical_change_sets_are_deterministic_and_form_an_ancestry_graph() {
        let operation = ChangeOperation::Add {
            record_id: RuntimeRecordId::from_raw(0x800),
            content_digest: [7; 32],
        };
        let first = ChangeSet::create(
            vec![],
            package_id(1),
            package_id(2),
            "developer",
            "merge feature",
            1234,
            vec![operation.clone()],
        )
        .unwrap();
        let duplicate = ChangeSet::create(
            vec![],
            package_id(1),
            package_id(2),
            "developer",
            "merge feature",
            1234,
            vec![operation],
        )
        .unwrap();
        assert_eq!(first.id(), duplicate.id());
        println!("[change-set] canonical merge receipt ID: {}", first.id());

        let second = ChangeSet::create(
            vec![first.id()],
            package_id(1),
            package_id(3),
            "developer",
            "merge follow-up",
            1235,
            vec![ChangeOperation::Override {
                record_id: RuntimeRecordId::from_raw(0x800),
                previous_change_set: first.id(),
                content_digest: [8; 32],
            }],
        )
        .unwrap();
        let second_id = second.id();
        let mut store = ChangeSetStore::default();
        store.insert(first.clone()).unwrap();
        store.insert(second).unwrap();
        assert!(store.is_ancestor(first.id(), second_id));
        println!(
            "[change-set] ancestry graph confirms {} -> {second_id}",
            first.id()
        );
    }

    #[test]
    fn rejecting_a_duplicate_does_not_replace_the_stored_change_set() {
        let original = ChangeSet::create(
            vec![],
            package_id(1),
            package_id(2),
            "original author",
            "merge",
            1,
            vec![ChangeOperation::Add {
                record_id: RuntimeRecordId::from_raw(0x800),
                content_digest: [3; 32],
            }],
        )
        .unwrap();
        let id = original.id();
        let mut invalid_duplicate = original.clone();
        invalid_duplicate.author = "replacement author".into();
        let mut store = ChangeSetStore::default();
        store.insert(original).unwrap();

        assert!(matches!(
            store.insert(invalid_duplicate),
            Err(ChangeSetError::DuplicateChangeSet)
        ));
        assert_eq!(store.get(id).unwrap().author(), "original author");
    }
}
