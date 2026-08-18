mod atomic_write;
mod change_set;
mod change_set_id;
mod collection_codec;
mod group_header;
mod group_view;
mod load_order;
mod merge;
mod package;
mod package_header;
mod package_id;
mod package_index;
mod package_reader;
mod package_source;
mod record_flags;
mod record_header;
mod record_id;
mod record_reader;
mod record_view;
mod signature;
mod subrecord_header;
mod validation;
mod writer;

pub use atomic_write::{AtomicWriteError, write_package_atomically};
pub use change_set::{ChangeOperation, ChangeSet, ChangeSetError, ChangeSetStore};
pub use change_set_id::ChangeSetId;
pub use collection_codec::{
    CollectionError, CollectionLimits, ListAppendMode, append_encoded_list, decode_list,
    decode_map, decode_set, encode_list, encode_map, encode_set,
};
pub use group_header::{GROUP_SIGNATURE, GroupHeader, GroupHeaderError, GroupLabel, GroupType};
pub use group_view::GroupView;
pub use load_order::{
    LoadOrder, LoadOrderError, LoadOrderMove, LoadOrderPolicy, LoadOrderRecordIndex,
    LoadOrderRepairReport, OverrideChain, PackageAvailabilityIssue, PackageIssueCode,
    PackageIssueSeverity, RecordOrigin, RuntimeRecordId, RuntimeSlot, inspect_package_availability,
    repair_load_order,
};
pub use merge::{
    MergeError, MergeOptions, MergeRequest, MergeResult, MergeSelection, NoReferenceRewriter,
    OverrideMergeMode, RecordIdMapper, ReferenceRewriter, SubrecordMergeRule,
    SubrecordMergeStrategy, compose_override_chain, compose_record_override, merge_packages,
    merge_packages_with_options,
};
pub use package::{
    PACKAGE_HEADER_SIGNATURE, Package, PackageOpenError, PackageRewriteError,
    rewrite_package_header_bytes, scene_offset_tables_from_index,
};
pub use package_header::{
    PackageDependency, PackageHeader, PackageHeaderError, PackageIncompatibility, PackageLoadClass,
    PackageVersion, PackageVersionRequirement, SceneOffset, SceneOffsetTable,
};
pub use package_id::PackageId;
pub use package_index::{PackageIndex, PackageIndexError};
pub use package_reader::{PackageEntry, PackageReadError, PackageReader};
pub use package_source::{FilePackageSource, MemoryPackageSource, PackageSource};
pub use record_flags::RecordFlags;
pub use record_header::{RecordHeader, RecordHeaderError};
pub use record_id::RecordId;
pub use record_reader::{RecordReadError, RecordReader};
pub use record_view::RecordView;
pub use signature::Signature;
pub use subrecord_header::SubrecordHeader;
pub use validation::{ValidationIssue, ValidationReport, ValidationSeverity};
pub use writer::{GroupWriter, PackageWriteError, RecordWriter};

pub const PLUGINABLE_CONTENT_PACKAGE_EXTENSION: &str = "pcp";
pub const SAVE_DATA_PACKAGE_EXTENSION: &str = "sdp";
