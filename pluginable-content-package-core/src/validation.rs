use crate::{GroupType, LoadOrderRecordIndex, Package, PackageIndex, RuntimeRecordId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationSeverity {
    Information,
    Warning,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationIssue {
    pub severity: ValidationSeverity,
    pub code: &'static str,
    pub message: String,
    pub package_index: Option<usize>,
    pub runtime_record_id: Option<RuntimeRecordId>,
}

#[derive(Default)]
pub struct ValidationReport {
    issues: Vec<ValidationIssue>,
}
impl ValidationReport {
    pub fn for_indexed_package(package: &Package, index: &PackageIndex) -> Self {
        let mut report = Self::default();
        let owned_index = package.header().dependencies().len() as u8;
        let largest_owned = index
            .records()
            .map(|record| record.header().record_id())
            .filter(|id| id.package_index() == owned_index)
            .map(|id| id.local_identifier())
            .max();
        if let Some(largest_owned) = largest_owned
            && package.header().next_local_identifier() <= largest_owned
        {
            report.issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                code: "PCP-NEXT-ID-COLLISION",
                message: format!(
                    "Next local identifier {:#X} is not above owned identifier {:#X}.",
                    package.header().next_local_identifier(),
                    largest_owned
                ),
                package_index: None,
                runtime_record_id: None,
            });
        }
        for id in package.header().streaming_overrides() {
            if index.record(*id).is_none() {
                report.issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    code: "PCP-STREAMING-OVERRIDE-MISSING",
                    message: format!(
                        "Streaming override {id} has no matching record in this package."
                    ),
                    package_index: None,
                    runtime_record_id: None,
                });
            }
        }
        for group in index.groups() {
            let group_type = group.header().group_type();
            if matches!(
                group_type,
                GroupType::WorldChildren
                    | GroupType::SceneChildren
                    | GroupType::ConversationChildren
                    | GroupType::ScenePersistentChildren
                    | GroupType::SceneTemporaryChildren
                    | GroupType::SceneDistantChildren
            ) {
                let parent = group.header().label().record_id();
                if index.record(parent).is_none() {
                    report.issues.push(ValidationIssue {
                        severity: ValidationSeverity::Error,
                        code: "PCP-ORPHANED-RECORD-PATH",
                        message: format!(
                            "Group {group_type:?} refers to absent parent record {parent}."
                        ),
                        package_index: None,
                        runtime_record_id: None,
                    });
                }
            }
        }
        report
    }
    pub fn for_load_order(load_order: &LoadOrderRecordIndex) -> Self {
        let mut report = Self::default();
        for chain in load_order.records() {
            if chain.origins().len() > 1 {
                let first = chain.origins()[0].record().header().signature();
                let mismatched = chain
                    .origins()
                    .iter()
                    .any(|origin| origin.record().header().signature() != first);
                report.issues.push(ValidationIssue {
                    severity: if mismatched {
                        ValidationSeverity::Error
                    } else {
                        ValidationSeverity::Information
                    },
                    code: if mismatched {
                        "PCP-OVERRIDE-TYPE-MISMATCH"
                    } else {
                        "PCP-OVERRIDE-CHAIN"
                    },
                    message: if mismatched {
                        format!(
                            "Override chain {} changes record signature.",
                            chain.runtime_id()
                        )
                    } else {
                        format!(
                            "Override chain {} contains {} origins; the last wins.",
                            chain.runtime_id(),
                            chain.origins().len()
                        )
                    },
                    package_index: Some(chain.winner().package_index()),
                    runtime_record_id: Some(chain.runtime_id()),
                });
            }
        }
        report
    }
    pub fn issues(&self) -> &[ValidationIssue] {
        &self.issues
    }
    pub fn has_errors(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| issue.severity == ValidationSeverity::Error)
    }
}
