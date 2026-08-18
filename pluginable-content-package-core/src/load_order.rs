use crate::{
    Package, PackageId, PackageIndex, PackageIndexError, PackageLoadClass, RecordId, RecordView,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadOrderPolicy {
    pub allow_incompatible_packages: bool,
}

impl LoadOrderPolicy {
    pub const STRICT: Self = Self {
        allow_incompatible_packages: false,
    };
    pub const EDITOR: Self = Self {
        allow_incompatible_packages: true,
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadOrderMove {
    pub package: PackageId,
    pub from: usize,
    pub to: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LoadOrderRepairReport {
    pub moves: Vec<LoadOrderMove>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PackageIssueSeverity {
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PackageIssueCode {
    MissingDependency,
    DependencyVersionMismatch,
    DependencyUnavailable,
    IncompatiblePackage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageAvailabilityIssue {
    pub code: PackageIssueCode,
    pub severity: PackageIssueSeverity,
    pub package: PackageId,
    pub related_package: PackageId,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeRecordId(u32);
impl RuntimeRecordId {
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }
    pub const fn raw(self) -> u32 {
        self.0
    }
}
impl fmt::Display for RuntimeRecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08X}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeSlot {
    Full(u8),
    Compact(u16),
}

#[derive(Clone)]
pub struct RecordOrigin {
    package_index: usize,
    record: RecordView,
}
impl RecordOrigin {
    pub const fn package_index(&self) -> usize {
        self.package_index
    }
    pub fn record(&self) -> &RecordView {
        &self.record
    }
}

pub struct OverrideChain {
    runtime_id: RuntimeRecordId,
    origins: Vec<RecordOrigin>,
}
impl OverrideChain {
    pub const fn runtime_id(&self) -> RuntimeRecordId {
        self.runtime_id
    }
    pub fn origins(&self) -> &[RecordOrigin] {
        &self.origins
    }
    pub fn winner(&self) -> &RecordOrigin {
        self.origins.last().expect("nonempty chain")
    }
}

pub struct LoadOrder {
    packages: Vec<Arc<Package>>,
    slots: HashMap<PackageId, RuntimeSlot>,
    streaming_winners: HashMap<RuntimeRecordId, usize>,
}

/// Optional record-origin index for editors.
pub struct LoadOrderRecordIndex {
    chains: HashMap<RuntimeRecordId, OverrideChain>,
}

impl LoadOrder {
    pub fn build(packages: Vec<Arc<Package>>) -> Result<Self, LoadOrderError> {
        Self::build_with_policy(packages, LoadOrderPolicy::STRICT)
    }

    pub fn build_for_editor(packages: Vec<Arc<Package>>) -> Result<Self, LoadOrderError> {
        Self::build_with_policy(packages, LoadOrderPolicy::EDITOR)
    }

    pub fn build_with_policy(
        packages: Vec<Arc<Package>>,
        policy: LoadOrderPolicy,
    ) -> Result<Self, LoadOrderError> {
        let mut slots = HashMap::new();
        let mut loaded = HashSet::new();
        let mut full = 0u16;
        let mut compact = 0u16;
        for (index, package) in packages.iter().enumerate() {
            let package_id = package.header().package_id();
            if !loaded.insert(package_id) {
                return Err(LoadOrderError::DuplicatePackage(package_id));
            }
            package.header().validate_load_class().map_err(|source| {
                LoadOrderError::InvalidLoadClassMetadata {
                    package: package_id,
                    source,
                }
            })?;
            for dependency in package.header().dependencies() {
                if !loaded.contains(&dependency.package_id()) {
                    return Err(LoadOrderError::DependencyNotLoaded {
                        package_index: index,
                        dependency: dependency.package_id(),
                    });
                }
                if let Some(requirement) = dependency.version_requirement() {
                    let dependency_package = packages[..index]
                        .iter()
                        .find(|candidate| {
                            candidate.header().package_id() == dependency.package_id()
                        })
                        .expect("slot and earlier package are added together");
                    let version = dependency_package.header().package_version();
                    if !requirement.matches(version) {
                        return Err(LoadOrderError::DependencyVersionMismatch {
                            package: package_id,
                            dependency: dependency.package_id(),
                            requirement: requirement.to_string(),
                            actual: version.to_string(),
                        });
                    }
                }
            }
            let slot = match package.header().load_class() {
                PackageLoadClass::Full => {
                    if full >= 0xFE {
                        return Err(LoadOrderError::TooManyFullPackages);
                    }
                    let slot = RuntimeSlot::Full(full as u8);
                    full += 1;
                    Some(slot)
                }
                PackageLoadClass::Compact => {
                    if compact >= 4096 {
                        return Err(LoadOrderError::TooManyCompactPackages);
                    }
                    let slot = RuntimeSlot::Compact(compact);
                    compact += 1;
                    Some(slot)
                }
                PackageLoadClass::Overlay => None,
            };
            if let Some(slot) = slot {
                slots.insert(package_id, slot);
            }
        }
        if !policy.allow_incompatible_packages {
            for package in &packages {
                for incompatibility in package.header().incompatibilities() {
                    let Some(other) = packages.iter().find(|candidate| {
                        candidate.header().package_id() == incompatibility.package_id()
                    }) else {
                        continue;
                    };
                    let applies = incompatibility
                        .version_requirement()
                        .is_none_or(|requirement| {
                            requirement.matches(other.header().package_version())
                        });
                    if applies {
                        return Err(LoadOrderError::IncompatiblePackages {
                            package: package.header().package_id(),
                            incompatible: incompatibility.package_id(),
                        });
                    }
                }
            }
        }
        let mut streaming_winners = HashMap::new();
        for (package_index, package) in packages.iter().enumerate() {
            for id in package.header().streaming_overrides() {
                streaming_winners.insert(translate(package, *id, &slots)?, package_index);
            }
        }
        Ok(Self {
            packages,
            slots,
            streaming_winners,
        })
    }
    pub fn packages(&self) -> &[Arc<Package>] {
        &self.packages
    }
    pub fn slot(&self, id: PackageId) -> Option<RuntimeSlot> {
        self.slots.get(&id).copied()
    }
    pub fn streaming_winner(&self, id: RuntimeRecordId) -> Option<usize> {
        self.streaming_winners.get(&id).copied()
    }
    pub fn build_record_index(&self) -> Result<LoadOrderRecordIndex, LoadOrderError> {
        let indexes = self
            .packages
            .iter()
            .enumerate()
            .map(|(package_index, package)| {
                package
                    .build_index()
                    .map_err(|source| LoadOrderError::Index {
                        package_index,
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.build_record_index_from(&indexes.iter().collect::<Vec<_>>())
    }

    /// Builds the record view from caller-owned indexes.
    /// Editors use this after mutations to avoid rescanning unchanged package bytes.
    pub fn build_record_index_from(
        &self,
        indexes: &[&PackageIndex],
    ) -> Result<LoadOrderRecordIndex, LoadOrderError> {
        if indexes.len() != self.packages.len() {
            return Err(LoadOrderError::IndexCountMismatch {
                packages: self.packages.len(),
                indexes: indexes.len(),
            });
        }

        let mut chains: HashMap<RuntimeRecordId, OverrideChain> = HashMap::new();
        for (package_index, (package, index)) in
            self.packages.iter().zip(indexes.iter()).enumerate()
        {
            for record in index.records() {
                let runtime_id = translate(package, record.header().record_id(), &self.slots)?;
                chains
                    .entry(runtime_id)
                    .or_insert_with(|| OverrideChain {
                        runtime_id,
                        origins: Vec::new(),
                    })
                    .origins
                    .push(RecordOrigin {
                        package_index,
                        record: record.clone(),
                    });
            }
        }
        Ok(LoadOrderRecordIndex { chains })
    }
    pub fn resolve_record_id(
        &self,
        package_index: usize,
        serialized: RecordId,
    ) -> Result<RuntimeRecordId, LoadOrderError> {
        let package = self
            .packages
            .get(package_index)
            .ok_or(LoadOrderError::PackageIndexOutOfRange(package_index))?;
        translate(package, serialized, &self.slots)
    }
    pub fn serialize_record_id(
        &self,
        package_index: usize,
        runtime: RuntimeRecordId,
    ) -> Result<RecordId, LoadOrderError> {
        let package = self
            .packages
            .get(package_index)
            .ok_or(LoadOrderError::PackageIndexOutOfRange(package_index))?;
        let (slot, local) = if runtime.raw() & 0xFF00_0000 == 0xFE00_0000 {
            (
                RuntimeSlot::Compact(((runtime.raw() >> 12) & 0xFFF) as u16),
                runtime.raw() & 0xFFF,
            )
        } else {
            (
                RuntimeSlot::Full((runtime.raw() >> 24) as u8),
                runtime.raw() & 0x00FF_FFFF,
            )
        };
        let owner = self
            .slots
            .iter()
            .find_map(|(package_id, candidate)| (*candidate == slot).then_some(*package_id))
            .ok_or(LoadOrderError::RuntimeOwnerUnavailable(runtime))?;
        let serialized_index = package
            .header()
            .dependencies()
            .iter()
            .position(|dependency| dependency.package_id() == owner)
            .or_else(|| {
                (package.header().package_id() == owner)
                    .then_some(package.header().dependencies().len())
            })
            .ok_or(LoadOrderError::RuntimeOwnerUnavailable(runtime))?;
        RecordId::new(
            u8::try_from(serialized_index)
                .map_err(|_| LoadOrderError::RuntimeOwnerUnavailable(runtime))?,
            local,
        )
        .map_err(|_| LoadOrderError::RuntimeOwnerUnavailable(runtime))
    }
}

impl LoadOrderRecordIndex {
    pub fn override_chain(&self, id: RuntimeRecordId) -> Option<&OverrideChain> {
        self.chains.get(&id)
    }
    pub fn winning_record(&self, id: RuntimeRecordId) -> Option<&RecordOrigin> {
        self.override_chain(id).map(OverrideChain::winner)
    }
    pub fn records(&self) -> impl ExactSizeIterator<Item = &OverrideChain> {
        self.chains.values()
    }
}

pub fn repair_load_order(
    packages: &mut Vec<Arc<Package>>,
) -> Result<LoadOrderRepairReport, LoadOrderError> {
    let mut report = LoadOrderRepairReport::default();
    let mut previous_orders = HashSet::new();
    loop {
        let order: Vec<_> = packages
            .iter()
            .map(|package| package.header().package_id())
            .collect();
        if !previous_orders.insert(order) {
            return Err(LoadOrderError::DependencyCycle);
        }
        let positions: HashMap<_, _> = packages
            .iter()
            .enumerate()
            .map(|(index, package)| (package.header().package_id(), index))
            .collect();
        let mut move_request = None;
        for (index, package) in packages.iter().enumerate() {
            let mut last_dependency = None;
            for dependency in package.header().dependencies() {
                let Some(position) = positions.get(&dependency.package_id()).copied() else {
                    return Err(LoadOrderError::DependencyNotLoaded {
                        package_index: index,
                        dependency: dependency.package_id(),
                    });
                };
                last_dependency =
                    Some(last_dependency.map_or(position, |last: usize| last.max(position)));
            }
            if let Some(last_dependency) = last_dependency
                && last_dependency >= index
            {
                move_request = Some((index, last_dependency, package.header().package_id()));
                break;
            }
        }
        let Some((from, dependency_index, package_id)) = move_request else {
            return Ok(report);
        };
        let package = packages.remove(from);
        let dependency_index = if dependency_index > from {
            dependency_index - 1
        } else {
            dependency_index
        };
        let to = dependency_index + 1;
        packages.insert(to, package);
        report.moves.push(LoadOrderMove {
            package: package_id,
            from,
            to,
        });
    }
}

pub fn inspect_package_availability(
    packages: &[Arc<Package>],
) -> HashMap<PackageId, Vec<PackageAvailabilityIssue>> {
    let by_package_id: HashMap<_, _> = packages
        .iter()
        .map(|package| (package.header().package_id(), package))
        .collect();
    let mut issues: HashMap<_, Vec<_>> = packages
        .iter()
        .map(|package| (package.header().package_id(), Vec::new()))
        .collect();
    for package in packages {
        let package_id = package.header().package_id();
        for dependency in package.header().dependencies() {
            let Some(loaded) = by_package_id.get(&dependency.package_id()) else {
                issues
                    .get_mut(&package_id)
                    .expect("package was initialized")
                    .push(PackageAvailabilityIssue {
                        code: PackageIssueCode::MissingDependency,
                        severity: PackageIssueSeverity::Error,
                        package: package_id,
                        related_package: dependency.package_id(),
                        message: format!(
                            "Missing dependency {} ({})",
                            dependency.name(),
                            dependency.package_id()
                        ),
                    });
                continue;
            };
            if let Some(requirement) = dependency.version_requirement() {
                let version = loaded.header().package_version();
                if !requirement.matches(version) {
                    issues
                        .get_mut(&package_id)
                        .expect("package was initialized")
                        .push(PackageAvailabilityIssue {
                            code: PackageIssueCode::DependencyVersionMismatch,
                            severity: PackageIssueSeverity::Error,
                            package: package_id,
                            related_package: dependency.package_id(),
                            message: format!(
                                "Dependency {} has version {}, but {} is required",
                                dependency.name(),
                                version,
                                requirement
                            ),
                        });
                }
            }
        }
        for incompatibility in package.header().incompatibilities() {
            let Some(other) = by_package_id.get(&incompatibility.package_id()) else {
                continue;
            };
            let applies = incompatibility
                .version_requirement()
                .is_none_or(|requirement| requirement.matches(other.header().package_version()));
            if applies {
                issues
                    .get_mut(&package_id)
                    .expect("package was initialized")
                    .push(PackageAvailabilityIssue {
                        code: PackageIssueCode::IncompatiblePackage,
                        severity: PackageIssueSeverity::Warning,
                        package: package_id,
                        related_package: incompatibility.package_id(),
                        message: format!(
                            "Package is incompatible with {} ({})",
                            incompatibility.name(),
                            incompatibility.package_id()
                        ),
                    });
            }
        }
    }
    loop {
        let errored: HashSet<_> = issues
            .iter()
            .filter(|(_, values)| {
                values
                    .iter()
                    .any(|issue| issue.severity == PackageIssueSeverity::Error)
            })
            .map(|(package_id, _)| *package_id)
            .collect();
        let mut changed = false;
        for package in packages {
            let package_id = package.header().package_id();
            for dependency in package.header().dependencies() {
                if errored.contains(&dependency.package_id())
                    && !issues[&package_id].iter().any(|issue| {
                        issue.code == PackageIssueCode::DependencyUnavailable
                            && issue.related_package == dependency.package_id()
                    })
                {
                    issues
                        .get_mut(&package_id)
                        .expect("package was initialized")
                        .push(PackageAvailabilityIssue {
                            code: PackageIssueCode::DependencyUnavailable,
                            severity: PackageIssueSeverity::Error,
                            package: package_id,
                            related_package: dependency.package_id(),
                            message: format!(
                                "Dependency {} cannot be loaded because it has errors",
                                dependency.name()
                            ),
                        });
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    issues
}

fn translate(
    package: &Package,
    serialized: RecordId,
    slots: &HashMap<PackageId, RuntimeSlot>,
) -> Result<RuntimeRecordId, LoadOrderError> {
    let dependencies = package.header().dependencies();
    let index = serialized.package_index() as usize;
    let owner = if index < dependencies.len() {
        dependencies[index].package_id()
    } else if index == dependencies.len() {
        package.header().package_id()
    } else {
        return Err(LoadOrderError::InvalidSerializedPackageIndex {
            package: package.header().package_id(),
            record_id: serialized,
        });
    };
    let local = serialized.local_identifier();
    let slot = slots.get(&owner).copied().ok_or_else(|| {
        if owner == package.header().package_id()
            && package.header().load_class() == PackageLoadClass::Overlay
        {
            LoadOrderError::OverlayOwnsRecord {
                package: owner,
                record_id: serialized,
            }
        } else {
            LoadOrderError::SerializedOwnerHasNoSlot {
                package: package.header().package_id(),
                owner,
                record_id: serialized,
            }
        }
    })?;
    let raw = match slot {
        RuntimeSlot::Full(slot) => ((slot as u32) << 24) | local,
        RuntimeSlot::Compact(slot) => {
            if local > 0xFFF {
                return Err(LoadOrderError::CompactRecordIdOutOfRange {
                    package: owner,
                    local_identifier: local,
                });
            }
            0xFE00_0000 | ((slot as u32) << 12) | local
        }
    };
    Ok(RuntimeRecordId(raw))
}

#[derive(Debug)]
pub enum LoadOrderError {
    PackageIndexOutOfRange(usize),
    RuntimeOwnerUnavailable(RuntimeRecordId),
    DuplicatePackage(PackageId),
    DependencyNotLoaded {
        package_index: usize,
        dependency: PackageId,
    },
    DependencyVersionMismatch {
        package: PackageId,
        dependency: PackageId,
        requirement: String,
        actual: String,
    },
    IncompatiblePackages {
        package: PackageId,
        incompatible: PackageId,
    },
    DependencyCycle,
    TooManyFullPackages,
    TooManyCompactPackages,
    InvalidLoadClassMetadata {
        package: PackageId,
        source: crate::PackageHeaderError,
    },
    OverlayOwnsRecord {
        package: PackageId,
        record_id: RecordId,
    },
    SerializedOwnerHasNoSlot {
        package: PackageId,
        owner: PackageId,
        record_id: RecordId,
    },
    InvalidSerializedPackageIndex {
        package: PackageId,
        record_id: RecordId,
    },
    CompactRecordIdOutOfRange {
        package: PackageId,
        local_identifier: u32,
    },
    Index {
        package_index: usize,
        source: PackageIndexError,
    },
    IndexCountMismatch {
        packages: usize,
        indexes: usize,
    },
}
impl fmt::Display for LoadOrderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackageIndexOutOfRange(index) => {
                write!(f, "Package index {index} is outside the load order.")
            }
            Self::RuntimeOwnerUnavailable(id) => {
                write!(
                    f,
                    "Runtime record {id} is not referenceable from this package."
                )
            }
            Self::DuplicatePackage(id) => {
                write!(f, "Package ID {id} is loaded more than once.")
            }
            Self::DependencyNotLoaded {
                package_index,
                dependency,
            } => write!(
                f,
                "Package {package_index} depends on {dependency}, which was not loaded earlier."
            ),
            Self::DependencyVersionMismatch {
                package,
                dependency,
                requirement,
                actual,
            } => write!(
                f,
                "Package {package} requires {dependency} at {requirement}, but version {actual} is loaded."
            ),
            Self::IncompatiblePackages {
                package,
                incompatible,
            } => write!(
                f,
                "Package {package} is incompatible with loaded package {incompatible}."
            ),
            Self::DependencyCycle => write!(f, "Package dependencies contain a cycle."),
            Self::TooManyFullPackages => write!(f, "Full package slots are exhausted."),
            Self::TooManyCompactPackages => write!(f, "Compact package slots are exhausted."),
            Self::InvalidLoadClassMetadata { package, source } => {
                write!(
                    f,
                    "Package {package} has invalid load-class metadata: {source}"
                )
            }
            Self::OverlayOwnsRecord { package, record_id } => write!(
                f,
                "Overlay package {package} contains owned record {record_id}."
            ),
            Self::SerializedOwnerHasNoSlot {
                package,
                owner,
                record_id,
            } => write!(
                f,
                "Record {record_id} in package {package} refers to slotless package {owner}."
            ),
            Self::InvalidSerializedPackageIndex { package, record_id } => write!(
                f,
                "Record {record_id} in package {package} refers to an absent dependency index."
            ),
            Self::CompactRecordIdOutOfRange {
                package,
                local_identifier,
            } => write!(
                f,
                "Compact package {package} uses local ID {local_identifier:#X}, exceeding 12-bit capacity."
            ),
            Self::Index {
                package_index,
                source,
            } => write!(
                f,
                "Could not index load-order package {package_index}: {source}"
            ),
            Self::IndexCountMismatch { packages, indexes } => write!(
                f,
                "Load order contains {packages} packages, but {indexes} structural indexes were supplied."
            ),
        }
    }
}
impl std::error::Error for LoadOrderError {}
