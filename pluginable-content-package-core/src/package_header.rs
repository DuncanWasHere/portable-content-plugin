use std::{collections::HashSet, fmt};

use crate::{
    ChangeSetId, PACKAGE_HEADER_SIGNATURE, PackageId, PackageWriteError, RecordFlags, RecordId,
    RecordReadError, RecordReader, RecordWriter, Signature,
};

const FORMAT_VERSION: Signature = Signature::from_bytes(*b"FMTV");
const PACKAGE_ID: Signature = Signature::from_bytes(*b"PKID");
const LOAD_CLASS: Signature = Signature::from_bytes(*b"CLAS");
const NEXT_RECORD_ID: Signature = Signature::from_bytes(*b"NXID");
const RECORD_COUNT: Signature = Signature::from_bytes(*b"RCNT");
const OWNED_RECORD_COUNT: Signature = Signature::from_bytes(*b"ORCT");
const AUTHOR: Signature = Signature::from_bytes(*b"AUTH");
const DESCRIPTION: Signature = Signature::from_bytes(*b"DESC");
const SCHEMA_NAMESPACE: Signature = Signature::from_bytes(*b"SCHM");
const PACKAGE_VERSION: Signature = Signature::from_bytes(*b"PVER");
const DEPENDENCY: Signature = Signature::from_bytes(*b"DEPN");
const INCOMPATIBILITY: Signature = Signature::from_bytes(*b"INCM");
const STREAMING_OVERRIDE: Signature = Signature::from_bytes(*b"SOVR");
const SCENE_OFFSET_TABLE: Signature = Signature::from_bytes(*b"SOFF");

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SceneOffset {
    scene_id: RecordId,
    start_offset: u64,
    end_offset: u64,
}

impl SceneOffset {
    pub const BYTE_COUNT: usize = 20;

    pub fn new(
        scene_id: RecordId,
        start_offset: u64,
        end_offset: u64,
    ) -> Result<Self, PackageHeaderError> {
        if start_offset >= end_offset {
            return Err(PackageHeaderError::InvalidSceneOffset {
                start_offset,
                end_offset,
            });
        }
        Ok(Self {
            scene_id,
            start_offset,
            end_offset,
        })
    }

    pub const fn scene_id(self) -> RecordId {
        self.scene_id
    }
    pub const fn start_offset(self) -> u64 {
        self.start_offset
    }
    pub const fn end_offset(self) -> u64 {
        self.end_offset
    }
    pub fn shifted(self, delta: i64) -> Result<Self, PackageHeaderError> {
        let start_offset = self
            .start_offset
            .checked_add_signed(delta)
            .ok_or(PackageHeaderError::SceneOffsetOverflow)?;
        let end_offset = self
            .end_offset
            .checked_add_signed(delta)
            .ok_or(PackageHeaderError::SceneOffsetOverflow)?;
        Self::new(self.scene_id, start_offset, end_offset)
    }

    fn encode(self) -> [u8; Self::BYTE_COUNT] {
        let mut result = [0; Self::BYTE_COUNT];
        result[0..4].copy_from_slice(&self.scene_id.raw().to_le_bytes());
        result[4..12].copy_from_slice(&self.start_offset.to_le_bytes());
        result[12..20].copy_from_slice(&self.end_offset.to_le_bytes());
        result
    }

    fn decode(payload: &[u8]) -> Result<Self, PackageHeaderError> {
        if payload.len() != Self::BYTE_COUNT {
            return Err(PackageHeaderError::InvalidFieldSize {
                signature: SCENE_OFFSET_TABLE,
                expected: Self::BYTE_COUNT,
                actual: payload.len(),
            });
        }
        Self::new(
            RecordId::from_raw(u32::from_le_bytes(payload[0..4].try_into().unwrap())),
            u64::from_le_bytes(payload[4..12].try_into().unwrap()),
            u64::from_le_bytes(payload[12..20].try_into().unwrap()),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SceneOffsetTable {
    world_id: Option<RecordId>,
    offsets: Vec<SceneOffset>,
}

impl SceneOffsetTable {
    pub fn new(
        world_id: Option<RecordId>,
        offsets: Vec<SceneOffset>,
    ) -> Result<Self, PackageHeaderError> {
        let mut scene_ids = HashSet::with_capacity(offsets.len());
        for offset in &offsets {
            if !scene_ids.insert(offset.scene_id()) {
                return Err(PackageHeaderError::DuplicateSceneOffset {
                    world_id,
                    scene_id: offset.scene_id(),
                });
            }
        }
        Ok(Self { world_id, offsets })
    }

    pub const fn world_id(&self) -> Option<RecordId> {
        self.world_id
    }
    pub fn offsets(&self) -> &[SceneOffset] {
        &self.offsets
    }

    fn shifted(&self, delta: i64) -> Result<Self, PackageHeaderError> {
        Self::new(
            self.world_id,
            self.offsets
                .iter()
                .copied()
                .map(|offset| offset.shifted(delta))
                .collect::<Result<_, _>>()?,
        )
    }

    fn encode(&self) -> Result<Vec<u8>, PackageHeaderError> {
        let count = u32::try_from(self.offsets.len())
            .map_err(|_| PackageHeaderError::TooManySceneOffsets(self.offsets.len()))?;
        let mut payload = Vec::with_capacity(8 + self.offsets.len() * SceneOffset::BYTE_COUNT);
        payload.extend_from_slice(&self.world_id.map_or(0, RecordId::raw).to_le_bytes());
        payload.extend_from_slice(&count.to_le_bytes());
        for offset in &self.offsets {
            payload.extend_from_slice(&offset.encode());
        }
        Ok(payload)
    }

    fn decode(payload: &[u8]) -> Result<Self, PackageHeaderError> {
        if payload.len() < 8 {
            return Err(PackageHeaderError::InvalidSceneOffsetTableSize(
                payload.len(),
            ));
        }
        let world_raw = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        let count = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
        let expected = 8usize
            .checked_add(count.checked_mul(SceneOffset::BYTE_COUNT).ok_or(
                PackageHeaderError::InvalidSceneOffsetTableSize(payload.len()),
            )?)
            .ok_or(PackageHeaderError::InvalidSceneOffsetTableSize(
                payload.len(),
            ))?;
        if payload.len() != expected {
            return Err(PackageHeaderError::InvalidSceneOffsetTableSize(
                payload.len(),
            ));
        }
        let offsets = payload[8..]
            .chunks_exact(SceneOffset::BYTE_COUNT)
            .map(SceneOffset::decode)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            (world_raw != 0).then(|| RecordId::from_raw(world_raw)),
            offsets,
        )
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageVersion(semver::Version);

impl PackageVersion {
    pub fn parse(value: &str) -> Result<Self, PackageHeaderError> {
        semver::Version::parse(value)
            .map(Self)
            .map_err(|error| PackageHeaderError::InvalidPackageVersion(error.to_string()))
    }
}

impl Default for PackageVersion {
    fn default() -> Self {
        Self(semver::Version::new(0, 1, 0))
    }
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PackageVersionRequirement(semver::VersionReq);

impl PackageVersionRequirement {
    pub fn parse(value: &str) -> Result<Self, PackageHeaderError> {
        semver::VersionReq::parse(value)
            .map(Self)
            .map_err(|error| PackageHeaderError::InvalidVersionRequirement(error.to_string()))
    }

    pub fn matches(&self, version: &PackageVersion) -> bool {
        self.0.matches(&version.0)
    }
}

impl fmt::Display for PackageVersionRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PackageLoadClass {
    Full,
    Compact,
    Overlay,
}

impl PackageLoadClass {
    const fn byte(self) -> u8 {
        match self {
            Self::Full => 0,
            Self::Compact => 1,
            Self::Overlay => 2,
        }
    }

    fn from_byte(value: u8) -> Result<Self, PackageHeaderError> {
        match value {
            0 => Ok(Self::Full),
            1 => Ok(Self::Compact),
            2 => Ok(Self::Overlay),
            _ => Err(PackageHeaderError::InvalidLoadClass(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackageRelationship {
    package_id: PackageId,
    name: String,
    version_requirement: Option<PackageVersionRequirement>,
}

impl PackageRelationship {
    fn new(package_id: PackageId, name: impl Into<String>) -> Result<Self, PackageHeaderError> {
        if package_id.is_nil() {
            return Err(PackageHeaderError::NilRelatedPackageId);
        }
        let name = name.into();
        if name.is_empty() {
            return Err(PackageHeaderError::EmptyRelationshipName);
        }
        if name.contains('\0') {
            return Err(PackageHeaderError::RelationshipNameContainsNull);
        }
        Ok(Self {
            package_id,
            name,
            version_requirement: None,
        })
    }
}

macro_rules! relationship_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name(PackageRelationship);

        impl $name {
            pub fn new(
                package_id: PackageId,
                name: impl Into<String>,
            ) -> Result<Self, PackageHeaderError> {
                PackageRelationship::new(package_id, name).map(Self)
            }

            pub const fn package_id(&self) -> PackageId {
                self.0.package_id
            }

            pub fn name(&self) -> &str {
                &self.0.name
            }

            pub fn version_requirement(&self) -> Option<&PackageVersionRequirement> {
                self.0.version_requirement.as_ref()
            }

            pub fn set_version_requirement(&mut self, value: Option<PackageVersionRequirement>) {
                self.0.version_requirement = value;
            }

            pub fn with_version_requirement(mut self, value: PackageVersionRequirement) -> Self {
                self.set_version_requirement(Some(value));
                self
            }
        }
    };
}

relationship_type!(PackageDependency);
relationship_type!(PackageIncompatibility);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageHeader {
    package_id: PackageId,
    load_class: PackageLoadClass,
    next_local_identifier: u32,
    record_count: u32,
    owned_record_count: u32,
    author: String,
    description: String,
    schema_namespace: String,
    package_version: PackageVersion,
    dependencies: Vec<PackageDependency>,
    incompatibilities: Vec<PackageIncompatibility>,
    streaming_overrides: Vec<RecordId>,
    scene_offset_tables: Vec<SceneOffsetTable>,
}

impl PackageHeader {
    pub const CURRENT_FORMAT_VERSION: u32 = 4;
    pub const FIRST_USER_LOCAL_IDENTIFIER: u32 = 0x800;
    pub const FIRST_COMPACT_LOCAL_IDENTIFIER: u32 = 1;
    pub const MAXIMUM_COMPACT_RECORD_COUNT: u32 = 4096;

    pub fn new(package_id: PackageId) -> Result<Self, PackageHeaderError> {
        if package_id.is_nil() {
            return Err(PackageHeaderError::NilPackageId);
        }
        Ok(Self {
            package_id,
            load_class: PackageLoadClass::Full,
            next_local_identifier: Self::FIRST_USER_LOCAL_IDENTIFIER,
            record_count: 0,
            owned_record_count: 0,
            author: String::new(),
            description: String::new(),
            schema_namespace: String::new(),
            package_version: PackageVersion::default(),
            dependencies: Vec::new(),
            incompatibilities: Vec::new(),
            streaming_overrides: Vec::new(),
            scene_offset_tables: Vec::new(),
        })
    }

    pub const fn format_version(&self) -> u32 {
        Self::CURRENT_FORMAT_VERSION
    }
    pub const fn package_id(&self) -> PackageId {
        self.package_id
    }
    pub const fn load_class(&self) -> PackageLoadClass {
        self.load_class
    }
    pub const fn next_local_identifier(&self) -> u32 {
        self.next_local_identifier
    }
    pub const fn record_count(&self) -> u32 {
        self.record_count
    }
    pub const fn owned_record_count(&self) -> u32 {
        self.owned_record_count
    }
    pub const fn first_owned_local_identifier(&self) -> u32 {
        match self.load_class {
            PackageLoadClass::Compact => Self::FIRST_COMPACT_LOCAL_IDENTIFIER,
            PackageLoadClass::Full | PackageLoadClass::Overlay => Self::FIRST_USER_LOCAL_IDENTIFIER,
        }
    }
    pub fn author(&self) -> &str {
        &self.author
    }
    pub fn description(&self) -> &str {
        &self.description
    }
    pub fn schema_namespace(&self) -> &str {
        &self.schema_namespace
    }
    pub fn package_version(&self) -> &PackageVersion {
        &self.package_version
    }
    pub fn dependencies(&self) -> &[PackageDependency] {
        &self.dependencies
    }
    pub fn incompatibilities(&self) -> &[PackageIncompatibility] {
        &self.incompatibilities
    }
    pub fn streaming_overrides(&self) -> &[RecordId] {
        &self.streaming_overrides
    }
    pub fn scene_offset_tables(&self) -> &[SceneOffsetTable] {
        &self.scene_offset_tables
    }
    pub fn scene_offset_table(&self, world_id: Option<RecordId>) -> Option<&SceneOffsetTable> {
        self.scene_offset_tables
            .iter()
            .find(|table| table.world_id() == world_id)
    }

    pub fn set_load_class(&mut self, value: PackageLoadClass) {
        if self.record_count == 0 && self.next_local_identifier == Self::FIRST_USER_LOCAL_IDENTIFIER
        {
            self.next_local_identifier = match value {
                PackageLoadClass::Compact => Self::FIRST_COMPACT_LOCAL_IDENTIFIER,
                PackageLoadClass::Full | PackageLoadClass::Overlay => {
                    Self::FIRST_USER_LOCAL_IDENTIFIER
                }
            };
        }
        self.load_class = value;
    }
    pub fn set_next_local_identifier(&mut self, value: u32) -> Result<(), PackageHeaderError> {
        if value > RecordId::MAXIMUM_LOCAL_IDENTIFIER {
            return Err(PackageHeaderError::NextRecordIdOutOfRange(value));
        }
        self.next_local_identifier = value;
        Ok(())
    }
    pub fn set_record_count(&mut self, value: u32) {
        self.record_count = value;
    }
    pub fn set_owned_record_count(&mut self, value: u32) {
        self.owned_record_count = value;
    }
    pub fn set_author(&mut self, value: impl Into<String>) {
        self.author = value.into();
    }
    pub fn set_description(&mut self, value: impl Into<String>) {
        self.description = value.into();
    }
    pub fn set_schema_namespace(&mut self, value: impl Into<String>) {
        self.schema_namespace = value.into();
    }
    pub fn set_package_version(&mut self, value: PackageVersion) {
        self.package_version = value;
    }

    pub fn add_dependency(&mut self, value: PackageDependency) -> Result<(), PackageHeaderError> {
        if self.dependencies.len() >= u8::MAX as usize {
            return Err(PackageHeaderError::TooManyDependencies);
        }
        if value.package_id() == self.package_id {
            return Err(PackageHeaderError::SelfDependency);
        }
        if self
            .dependencies
            .iter()
            .any(|item| item.package_id() == value.package_id())
        {
            return Err(PackageHeaderError::DuplicateDependency(value.package_id()));
        }
        self.dependencies.push(value);
        Ok(())
    }

    pub fn remove_dependency(&mut self, package_id: PackageId) -> bool {
        let old_len = self.dependencies.len();
        self.dependencies
            .retain(|item| item.package_id() != package_id);
        self.dependencies.len() != old_len
    }

    pub fn replace_dependencies(
        &mut self,
        values: Vec<PackageDependency>,
    ) -> Result<(), PackageHeaderError> {
        if values.len() >= u8::MAX as usize {
            return Err(PackageHeaderError::TooManyDependencies);
        }
        let mut package_ids = HashSet::with_capacity(values.len());
        for value in &values {
            if value.package_id() == self.package_id {
                return Err(PackageHeaderError::SelfDependency);
            }
            if !package_ids.insert(value.package_id()) {
                return Err(PackageHeaderError::DuplicateDependency(value.package_id()));
            }
        }
        self.dependencies = values;
        Ok(())
    }

    pub fn add_incompatibility(
        &mut self,
        value: PackageIncompatibility,
    ) -> Result<(), PackageHeaderError> {
        if value.package_id() == self.package_id {
            return Err(PackageHeaderError::SelfIncompatibility);
        }
        if self
            .incompatibilities
            .iter()
            .any(|item| item.package_id() == value.package_id())
        {
            return Err(PackageHeaderError::DuplicateIncompatibility(
                value.package_id(),
            ));
        }
        self.incompatibilities.push(value);
        Ok(())
    }

    pub fn remove_incompatibility(&mut self, package_id: PackageId) -> bool {
        let old_len = self.incompatibilities.len();
        self.incompatibilities
            .retain(|item| item.package_id() != package_id);
        self.incompatibilities.len() != old_len
    }

    pub fn replace_incompatibilities(
        &mut self,
        values: Vec<PackageIncompatibility>,
    ) -> Result<(), PackageHeaderError> {
        let mut package_ids = HashSet::with_capacity(values.len());
        for value in &values {
            if value.package_id() == self.package_id {
                return Err(PackageHeaderError::SelfIncompatibility);
            }
            if !package_ids.insert(value.package_id()) {
                return Err(PackageHeaderError::DuplicateIncompatibility(
                    value.package_id(),
                ));
            }
        }
        self.incompatibilities = values;
        Ok(())
    }

    pub fn add_streaming_override(&mut self, value: RecordId) -> bool {
        if self.streaming_overrides.contains(&value) {
            false
        } else {
            self.streaming_overrides.push(value);
            true
        }
    }

    pub fn replace_streaming_overrides(&mut self, values: Vec<RecordId>) {
        let mut seen = HashSet::with_capacity(values.len());
        self.streaming_overrides = values
            .into_iter()
            .filter(|value| seen.insert(*value))
            .collect();
    }

    pub fn replace_scene_offset_tables(
        &mut self,
        values: Vec<SceneOffsetTable>,
    ) -> Result<(), PackageHeaderError> {
        let mut worlds = HashSet::with_capacity(values.len());
        for table in &values {
            if !worlds.insert(table.world_id()) {
                return Err(PackageHeaderError::DuplicateSceneOffsetTable(
                    table.world_id(),
                ));
            }
        }
        self.scene_offset_tables = values;
        Ok(())
    }

    pub fn shift_scene_offsets(&mut self, delta: i64) -> Result<(), PackageHeaderError> {
        self.scene_offset_tables = self
            .scene_offset_tables
            .iter()
            .map(|table| table.shifted(delta))
            .collect::<Result<_, _>>()?;
        Ok(())
    }

    pub fn validate_load_class(&self) -> Result<(), PackageHeaderError> {
        match self.load_class {
            PackageLoadClass::Full => Ok(()),
            PackageLoadClass::Compact => {
                if self.owned_record_count > Self::MAXIMUM_COMPACT_RECORD_COUNT {
                    return Err(PackageHeaderError::TooManyCompactOwnedRecords(
                        self.owned_record_count,
                    ));
                }
                if self.next_local_identifier > 0x1000 {
                    return Err(PackageHeaderError::CompactNextRecordIdOutOfRange(
                        self.next_local_identifier,
                    ));
                }
                Ok(())
            }
            PackageLoadClass::Overlay => {
                if self.owned_record_count != 0 {
                    return Err(PackageHeaderError::OverlayOwnsRecords(
                        self.owned_record_count,
                    ));
                }
                Ok(())
            }
        }
    }

    pub fn encode(&self, last_change_set: ChangeSetId) -> Result<Vec<u8>, PackageWriteError> {
        self.validate_load_class()
            .map_err(|error| PackageWriteError::InvalidPackageHeader(Box::new(error)))?;
        let mut writer = RecordWriter::new(
            PACKAGE_HEADER_SIGNATURE,
            RecordFlags::default(),
            RecordId::from_raw(0),
            1.0,
            last_change_set,
        );
        writer.write_u32(FORMAT_VERSION, Self::CURRENT_FORMAT_VERSION)?;
        writer.write_subrecord(PACKAGE_ID, &self.package_id.bytes())?;
        writer.write_subrecord(LOAD_CLASS, &[self.load_class.byte()])?;
        writer.write_u32(NEXT_RECORD_ID, self.next_local_identifier)?;
        writer.write_u32(RECORD_COUNT, self.record_count)?;
        writer.write_u32(OWNED_RECORD_COUNT, self.owned_record_count)?;
        if !self.author.is_empty() {
            writer.write_subrecord(AUTHOR, self.author.as_bytes())?;
        }
        if !self.description.is_empty() {
            writer.write_subrecord(DESCRIPTION, self.description.as_bytes())?;
        }
        if !self.schema_namespace.is_empty() {
            writer.write_subrecord(SCHEMA_NAMESPACE, self.schema_namespace.as_bytes())?;
        }
        writer.write_subrecord(PACKAGE_VERSION, self.package_version.to_string().as_bytes())?;
        for dependency in &self.dependencies {
            writer.write_subrecord(DEPENDENCY, &encode_relationship(&dependency.0))?;
        }
        for incompatibility in &self.incompatibilities {
            writer.write_subrecord(INCOMPATIBILITY, &encode_relationship(&incompatibility.0))?;
        }
        for record_id in &self.streaming_overrides {
            writer.write_u32(STREAMING_OVERRIDE, record_id.raw())?;
        }
        for table in &self.scene_offset_tables {
            writer.write_subrecord(
                SCENE_OFFSET_TABLE,
                &table
                    .encode()
                    .map_err(|error| PackageWriteError::InvalidPackageHeader(Box::new(error)))?,
            )?;
        }
        writer.finish()
    }

    pub fn decode(mut reader: RecordReader) -> Result<Self, PackageHeaderError> {
        if reader.header().signature() != PACKAGE_HEADER_SIGNATURE {
            return Err(PackageHeaderError::WrongRecordSignature);
        }

        let mut format_version = None;
        let mut package_id = None;
        let mut load_class = None;
        let mut next_id = None;
        let mut record_count = None;
        let mut owned_record_count = None;
        let mut author = None;
        let mut description = None;
        let mut schema_namespace = None;
        let mut package_version = None;
        let mut dependencies = Vec::new();
        let mut incompatibilities = Vec::new();
        let mut streaming_overrides = Vec::new();
        let mut streaming_override_ids = HashSet::new();
        let mut scene_offset_tables = Vec::new();
        let mut scene_offset_worlds = HashSet::new();

        while let Some(header) = reader.next_subrecord()? {
            let signature = header.signature();
            let payload = reader.current_subrecord_payload()?;
            match signature {
                FORMAT_VERSION => set_once(
                    &mut format_version,
                    signature,
                    read_u32(payload, signature)?,
                )?,
                PACKAGE_ID => set_once(
                    &mut package_id,
                    signature,
                    PackageId::from_bytes(read_array(payload, signature)?),
                )?,
                LOAD_CLASS => {
                    if payload.len() != 1 {
                        return Err(PackageHeaderError::InvalidFieldSize {
                            signature,
                            expected: 1,
                            actual: payload.len(),
                        });
                    }
                    set_once(
                        &mut load_class,
                        signature,
                        PackageLoadClass::from_byte(payload[0])?,
                    )?;
                }
                NEXT_RECORD_ID => set_once(&mut next_id, signature, read_u32(payload, signature)?)?,
                RECORD_COUNT => {
                    set_once(&mut record_count, signature, read_u32(payload, signature)?)?
                }
                OWNED_RECORD_COUNT => set_once(
                    &mut owned_record_count,
                    signature,
                    read_u32(payload, signature)?,
                )?,
                AUTHOR => set_once(&mut author, signature, read_string(payload, signature)?)?,
                DESCRIPTION => set_once(
                    &mut description,
                    signature,
                    read_string(payload, signature)?,
                )?,
                SCHEMA_NAMESPACE => set_once(
                    &mut schema_namespace,
                    signature,
                    read_string(payload, signature)?,
                )?,
                PACKAGE_VERSION => set_once(
                    &mut package_version,
                    signature,
                    PackageVersion::parse(&read_string(payload, signature)?)?,
                )?,
                DEPENDENCY => {
                    dependencies.push(PackageDependency(decode_relationship(payload, signature)?));
                }
                INCOMPATIBILITY => incompatibilities.push(PackageIncompatibility(
                    decode_relationship(payload, signature)?,
                )),
                STREAMING_OVERRIDE => {
                    let record_id = RecordId::from_raw(read_u32(payload, signature)?);
                    if !streaming_override_ids.insert(record_id) {
                        return Err(PackageHeaderError::DuplicateStreamingOverride(record_id));
                    }
                    streaming_overrides.push(record_id);
                }
                SCENE_OFFSET_TABLE => {
                    let table = SceneOffsetTable::decode(payload)?;
                    if !scene_offset_worlds.insert(table.world_id()) {
                        return Err(PackageHeaderError::DuplicateSceneOffsetTable(
                            table.world_id(),
                        ));
                    }
                    scene_offset_tables.push(table);
                }
                _ => return Err(PackageHeaderError::UnknownField(signature)),
            }
        }

        let format_version = required(format_version, FORMAT_VERSION)?;
        if format_version != Self::CURRENT_FORMAT_VERSION {
            return Err(PackageHeaderError::UnsupportedFormatVersion(format_version));
        }
        let mut result = Self::new(required(package_id, PACKAGE_ID)?)?;
        result.load_class = required(load_class, LOAD_CLASS)?;
        result.set_next_local_identifier(required(next_id, NEXT_RECORD_ID)?)?;
        result.record_count = required(record_count, RECORD_COUNT)?;
        result.owned_record_count = required(owned_record_count, OWNED_RECORD_COUNT)?;
        result.author = author.unwrap_or_default();
        result.description = description.unwrap_or_default();
        result.schema_namespace = schema_namespace.unwrap_or_default();
        result.package_version = required(package_version, PACKAGE_VERSION)?;
        result.replace_dependencies(dependencies)?;
        result.replace_incompatibilities(incompatibilities)?;
        result.streaming_overrides = streaming_overrides;
        result.scene_offset_tables = scene_offset_tables;
        result.validate_load_class()?;
        Ok(result)
    }
}

fn encode_relationship(value: &PackageRelationship) -> Vec<u8> {
    let mut payload = value.package_id.bytes().to_vec();
    if let Some(requirement) = &value.version_requirement {
        payload.extend_from_slice(requirement.to_string().as_bytes());
        payload.push(0);
    }
    payload.extend_from_slice(value.name.as_bytes());
    payload
}

fn decode_relationship(
    payload: &[u8],
    signature: Signature,
) -> Result<PackageRelationship, PackageHeaderError> {
    if payload.len() <= PackageId::BYTE_COUNT {
        return Err(PackageHeaderError::InvalidRelationship(signature));
    }
    let package_id = PackageId::from_bytes(
        payload[..PackageId::BYTE_COUNT]
            .try_into()
            .expect("checked package ID length"),
    );
    let tail = &payload[PackageId::BYTE_COUNT..];
    let (name, requirement) = if let Some(separator) = tail.iter().position(|byte| *byte == 0) {
        let requirement =
            PackageVersionRequirement::parse(&read_string(&tail[..separator], signature)?)?;
        (
            read_string(&tail[separator + 1..], signature)?,
            Some(requirement),
        )
    } else {
        (read_string(tail, signature)?, None)
    };
    let mut relationship = PackageRelationship::new(package_id, name)?;
    relationship.version_requirement = requirement;
    Ok(relationship)
}

fn set_once<T>(
    slot: &mut Option<T>,
    signature: Signature,
    value: T,
) -> Result<(), PackageHeaderError> {
    if slot.replace(value).is_some() {
        Err(PackageHeaderError::DuplicateField(signature))
    } else {
        Ok(())
    }
}

fn required<T>(slot: Option<T>, signature: Signature) -> Result<T, PackageHeaderError> {
    slot.ok_or(PackageHeaderError::MissingField(signature))
}

fn read_u32(payload: &[u8], signature: Signature) -> Result<u32, PackageHeaderError> {
    Ok(u32::from_le_bytes(read_array(payload, signature)?))
}

fn read_array<const N: usize>(
    payload: &[u8],
    signature: Signature,
) -> Result<[u8; N], PackageHeaderError> {
    payload
        .try_into()
        .map_err(|_| PackageHeaderError::InvalidFieldSize {
            signature,
            expected: N,
            actual: payload.len(),
        })
}

fn read_string(payload: &[u8], signature: Signature) -> Result<String, PackageHeaderError> {
    std::str::from_utf8(payload)
        .map(str::to_owned)
        .map_err(|_| PackageHeaderError::InvalidUtf8(signature))
}

#[derive(Debug)]
pub enum PackageHeaderError {
    Record(RecordReadError),
    WrongRecordSignature,
    MissingField(Signature),
    DuplicateField(Signature),
    UnknownField(Signature),
    InvalidFieldSize {
        signature: Signature,
        expected: usize,
        actual: usize,
    },
    InvalidUtf8(Signature),
    UnsupportedFormatVersion(u32),
    InvalidLoadClass(u8),
    NilPackageId,
    NilRelatedPackageId,
    EmptyRelationshipName,
    RelationshipNameContainsNull,
    InvalidRelationship(Signature),
    InvalidPackageVersion(String),
    InvalidVersionRequirement(String),
    SelfDependency,
    SelfIncompatibility,
    DuplicateDependency(PackageId),
    DuplicateIncompatibility(PackageId),
    DuplicateStreamingOverride(RecordId),
    DuplicateSceneOffsetTable(Option<RecordId>),
    DuplicateSceneOffset {
        world_id: Option<RecordId>,
        scene_id: RecordId,
    },
    InvalidSceneOffset {
        start_offset: u64,
        end_offset: u64,
    },
    SceneOffsetOverflow,
    InvalidSceneOffsetTableSize(usize),
    TooManySceneOffsets(usize),
    SceneRecordMissingForOffset(RecordId),
    TooManyCompactOwnedRecords(u32),
    CompactNextRecordIdOutOfRange(u32),
    OverlayOwnsRecords(u32),
    TooManyDependencies,
    NextRecordIdOutOfRange(u32),
}

impl fmt::Display for PackageHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record(error) => write!(formatter, "Could not read package metadata: {error}"),
            Self::WrongRecordSignature => {
                write!(formatter, "Package metadata must be decoded from PKHD.")
            }
            Self::MissingField(signature) => {
                write!(formatter, "PKHD is missing required {signature}.")
            }
            Self::DuplicateField(signature) => {
                write!(formatter, "PKHD field {signature} appears more than once.")
            }
            Self::UnknownField(signature) => write!(
                formatter,
                "PKHD field {signature} is not defined by format version {}.",
                PackageHeader::CURRENT_FORMAT_VERSION
            ),
            Self::InvalidFieldSize {
                signature,
                expected,
                actual,
            } => write!(
                formatter,
                "PKHD field {signature} requires {expected} bytes, but has {actual}."
            ),
            Self::InvalidUtf8(signature) => {
                write!(formatter, "PKHD field {signature} is not valid UTF-8.")
            }
            Self::UnsupportedFormatVersion(version) => write!(
                formatter,
                "PCP format version {version} is unsupported; this build requires version {}.",
                PackageHeader::CURRENT_FORMAT_VERSION
            ),
            Self::InvalidLoadClass(value) => {
                write!(formatter, "Package load class {value} is invalid.")
            }
            Self::NilPackageId => write!(formatter, "Package ID cannot be nil."),
            Self::NilRelatedPackageId => write!(formatter, "Related package ID cannot be nil."),
            Self::EmptyRelationshipName => {
                write!(formatter, "Related package display name cannot be empty.")
            }
            Self::RelationshipNameContainsNull => write!(
                formatter,
                "Related package display name cannot contain a null byte."
            ),
            Self::InvalidRelationship(signature) => write!(
                formatter,
                "{signature} must contain a package ID, optional version requirement, and UTF-8 name."
            ),
            Self::InvalidPackageVersion(error) => {
                write!(formatter, "Package version is invalid: {error}")
            }
            Self::InvalidVersionRequirement(error) => {
                write!(formatter, "Package version requirement is invalid: {error}")
            }
            Self::SelfDependency => write!(formatter, "A package cannot depend on itself."),
            Self::SelfIncompatibility => {
                write!(formatter, "A package cannot be incompatible with itself.")
            }
            Self::DuplicateDependency(package_id) => {
                write!(formatter, "Dependency {package_id} appears more than once.")
            }
            Self::DuplicateIncompatibility(package_id) => write!(
                formatter,
                "Incompatibility {package_id} appears more than once."
            ),
            Self::DuplicateStreamingOverride(record_id) => write!(
                formatter,
                "Streaming override {record_id} appears more than once."
            ),
            Self::DuplicateSceneOffsetTable(world_id) => match world_id {
                Some(id) => write!(
                    formatter,
                    "Scene offset table for world {id} appears more than once."
                ),
                None => write!(
                    formatter,
                    "Interior scene offset table appears more than once."
                ),
            },
            Self::DuplicateSceneOffset { world_id, scene_id } => write!(
                formatter,
                "Scene {scene_id} appears more than once in the {:?} scene offset table.",
                world_id
            ),
            Self::InvalidSceneOffset {
                start_offset,
                end_offset,
            } => write!(
                formatter,
                "Scene offset range {start_offset}..{end_offset} is empty or reversed."
            ),
            Self::SceneOffsetOverflow => {
                write!(formatter, "Scene offset adjustment overflowed u64.")
            }
            Self::InvalidSceneOffsetTableSize(size) => write!(
                formatter,
                "Scene offset table has an invalid payload size of {size} bytes."
            ),
            Self::TooManySceneOffsets(count) => write!(
                formatter,
                "Scene offset table contains {count} entries, exceeding u32 capacity."
            ),
            Self::SceneRecordMissingForOffset(scene_id) => write!(
                formatter,
                "Temporary children group refers to missing scene record {scene_id}."
            ),
            Self::TooManyCompactOwnedRecords(count) => write!(
                formatter,
                "Compact package owns {count} records; at most {} are allowed.",
                PackageHeader::MAXIMUM_COMPACT_RECORD_COUNT
            ),
            Self::CompactNextRecordIdOutOfRange(value) => write!(
                formatter,
                "Compact package next local record ID {value:#X} exceeds its 12-bit range."
            ),
            Self::OverlayOwnsRecords(count) => write!(
                formatter,
                "Overlay package declares {count} owned records, but overlays may only contain overrides or injected records."
            ),
            Self::TooManyDependencies => {
                write!(formatter, "A package may have at most 254 dependencies.")
            }
            Self::NextRecordIdOutOfRange(value) => write!(
                formatter,
                "Next local record identifier {value:#X} exceeds 24-bit capacity."
            ),
        }
    }
}

impl std::error::Error for PackageHeaderError {}

impl From<RecordReadError> for PackageHeaderError {
    fn from(value: RecordReadError) -> Self {
        Self::Record(value)
    }
}
