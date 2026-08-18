#ifndef PLUGINABLE_CONTENT_PACKAGE_H
#define PLUGINABLE_CONTENT_PACKAGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PcpPackageHandle PcpPackageHandle;
typedef struct PcpRecordReaderHandle PcpRecordReaderHandle;
typedef struct PcpPackageCursorHandle PcpPackageCursorHandle;
typedef struct PcpLoadOrderHandle PcpLoadOrderHandle;

typedef enum PcpPackageEntryKind {
    PCP_PACKAGE_ENTRY_RECORD = 0,
    PCP_PACKAGE_ENTRY_GROUP = 1
} PcpPackageEntryKind;

typedef enum PcpResult {
    PCP_RESULT_SUCCESS = 0,
    PCP_RESULT_INVALID_ARGUMENT = 1,
    PCP_RESULT_INPUT_OUTPUT_ERROR = 2,
    PCP_RESULT_INVALID_PACKAGE = 3,
    PCP_RESULT_END_OF_RECORDS = 4,
    PCP_RESULT_END_OF_SUBRECORDS = 5,
    PCP_RESULT_BUFFER_TOO_SMALL = 6,
    PCP_RESULT_INDEX_UNAVAILABLE = 7,
    PCP_RESULT_NOT_EDITABLE = 8,
    PCP_RESULT_PANIC = 255
} PcpResult;

#define PCP_RECORD_FLAG_DELETED (UINT32_C(1) << 0)
#define PCP_RECORD_FLAG_PERSISTENT (UINT32_C(1) << 1)

typedef struct PcpRecordHeader {
    uint8_t signature[4];
    uint32_t payload_byte_count;
    uint32_t flags;
    uint32_t record_id;
    float version;
    uint8_t last_change_set[32];
} PcpRecordHeader;

typedef struct PcpSubrecordHeader {
    uint8_t signature[4];
    uint32_t payload_byte_count;
} PcpSubrecordHeader;

typedef struct PcpIndexedRecord {
    uint64_t header_offset;
    PcpRecordHeader header;
} PcpIndexedRecord;

typedef struct PcpRecordOrigin {
    size_t package_index;
    PcpIndexedRecord record;
} PcpRecordOrigin;

typedef struct PcpIndexedGroup {
    uint64_t header_offset;
    uint64_t payload_offset;
    uint64_t end_offset;
    uint32_t group_byte_count;
    uint8_t label[4];
    int32_t group_type;
} PcpIndexedGroup;

typedef struct PcpSceneOffset {
    uint32_t world_record_id;
    uint32_t scene_record_id;
    uint64_t start_offset;
    uint64_t end_offset;
} PcpSceneOffset;

typedef struct PcpPackageMetadata {
    uint32_t format_version;
    uint8_t package_id[16];
    uint8_t load_class;
    uint8_t has_package_version;
    uint8_t reserved[2];
    uint32_t next_local_identifier;
    uint32_t record_count;
    uint32_t owned_record_count;
    size_t dependency_count;
    size_t incompatibility_count;
} PcpPackageMetadata;

typedef struct PcpPackageRelationship {
    uint8_t package_id[16];
    uint8_t has_version_requirement;
    uint8_t reserved[7];
} PcpPackageRelationship;

typedef struct PcpPackageRelationshipInput {
    uint8_t package_id[16];
    const char *name;
    const char *version_requirement;
} PcpPackageRelationshipInput;

typedef struct PcpRecordMutation {
    int32_t kind; // 0 replace, 1 insert, 2 delete
    uint32_t record_signature;
    uint32_t record_id;
    uint32_t reserved;
    uint64_t target_group_offset; // UINT64_MAX insets at package root.
    const uint8_t *payload;
    size_t payload_byte_count;
} PcpRecordMutation;

PcpResult pcp_package_create(const char *path, const uint8_t package_id[16], const char *schema_namespace, const char *package_version, PcpPackageHandle **output);
PcpResult pcp_package_open(const char *path, PcpPackageHandle **output);
PcpResult pcp_package_open_for_editing(const char *path, PcpPackageHandle **output);
PcpResult pcp_package_build_index(PcpPackageHandle *handle);
void pcp_package_destroy(PcpPackageHandle *handle);
PcpResult pcp_package_byte_count(const PcpPackageHandle *handle, uint64_t *output);
PcpResult pcp_package_record_count(const PcpPackageHandle *handle, size_t *output);
PcpResult pcp_package_indexed_record(const PcpPackageHandle *handle, size_t index, PcpIndexedRecord *output);
PcpResult pcp_package_group_count(const PcpPackageHandle *handle, size_t *output);
PcpResult pcp_package_indexed_group(const PcpPackageHandle *handle, size_t index, PcpIndexedGroup *output);
PcpResult pcp_package_cursor_create(const PcpPackageHandle *handle, PcpPackageCursorHandle **output);
PcpResult pcp_package_cursor_next(PcpPackageCursorHandle *handle, PcpPackageEntryKind *output_kind, PcpIndexedRecord *output_record, PcpIndexedGroup *output_group);
PcpResult pcp_package_cursor_enter_group(PcpPackageCursorHandle *handle);
void pcp_package_cursor_destroy(PcpPackageCursorHandle *handle);
PcpResult pcp_package_streaming_override_count(const PcpPackageHandle *handle, size_t *output);
PcpResult pcp_package_streaming_override_at(const PcpPackageHandle *handle, size_t index, uint32_t *output);
PcpResult pcp_package_replace_streaming_overrides(PcpPackageHandle *handle, const uint32_t *record_ids, size_t count);
PcpResult pcp_package_scene_offset_count(const PcpPackageHandle *handle, size_t *output);
PcpResult pcp_package_scene_offset_at(const PcpPackageHandle *handle, size_t index, PcpSceneOffset *output);
PcpResult pcp_package_rebuild_scene_offsets(PcpPackageHandle *handle);
PcpResult pcp_package_metadata(const PcpPackageHandle *handle, PcpPackageMetadata *output);
PcpResult pcp_package_copy_version(const PcpPackageHandle *handle, char *destination, size_t destination_byte_count, size_t *required_byte_count);
PcpResult pcp_package_copy_author(const PcpPackageHandle *handle, char *destination, size_t destination_byte_count, size_t *required_byte_count);
PcpResult pcp_package_copy_description(const PcpPackageHandle *handle, char *destination, size_t destination_byte_count, size_t *required_byte_count);
PcpResult pcp_package_copy_schema_namespace(const PcpPackageHandle *handle, char *destination, size_t destination_byte_count, size_t *required_byte_count);
PcpResult pcp_package_set_metadata(PcpPackageHandle *handle, const char *package_version, const char *author, const char *description, const char *schema_namespace, uint8_t load_class);
PcpResult pcp_package_dependency(const PcpPackageHandle *handle, size_t index, PcpPackageRelationship *output);
PcpResult pcp_package_copy_dependency_name(const PcpPackageHandle *handle, size_t index, char *destination, size_t destination_byte_count, size_t *required_byte_count);
PcpResult pcp_package_copy_dependency_version_requirement(const PcpPackageHandle *handle, size_t index, char *destination, size_t destination_byte_count, size_t *required_byte_count);
PcpResult pcp_package_incompatibility(const PcpPackageHandle *handle, size_t index, PcpPackageRelationship *output);
PcpResult pcp_package_copy_incompatibility_name(const PcpPackageHandle *handle, size_t index, char *destination, size_t destination_byte_count, size_t *required_byte_count);
PcpResult pcp_package_copy_incompatibility_version_requirement(const PcpPackageHandle *handle, size_t index, char *destination, size_t destination_byte_count, size_t *required_byte_count);
PcpResult pcp_package_add_dependency(PcpPackageHandle *handle, const uint8_t package_id[16], const char *name, const char *version_requirement);
PcpResult pcp_package_remove_dependency(PcpPackageHandle *handle, const uint8_t package_id[16]);
PcpResult pcp_package_add_incompatibility(PcpPackageHandle *handle, const uint8_t package_id[16], const char *name, const char *version_requirement);
PcpResult pcp_package_remove_incompatibility(PcpPackageHandle *handle, const uint8_t package_id[16]);
PcpResult pcp_version_requirement_matches(const char *version_requirement, const char *package_version, uint8_t *output);
PcpResult pcp_package_read_record_at(const PcpPackageHandle *handle, uint64_t offset, PcpRecordReaderHandle **output_reader, PcpRecordHeader *output_header);
PcpResult pcp_package_replace_subrecord(PcpPackageHandle *handle, uint32_t record_id, uint32_t signature, size_t occurrence, const uint8_t *payload, size_t payload_byte_count);
PcpResult pcp_package_replace_record_payload(PcpPackageHandle *handle, uint32_t record_id, const uint8_t *payload, size_t payload_byte_count);
PcpResult pcp_package_insert_record(PcpPackageHandle *handle, uint64_t target_group_offset, uint32_t signature, const uint8_t *payload, size_t payload_byte_count, uint32_t *output_record_id);
PcpResult pcp_package_insert_record_with_id(PcpPackageHandle *handle, uint64_t target_group_offset, uint32_t signature, uint32_t record_id, const uint8_t *payload, size_t payload_byte_count);
PcpResult pcp_package_apply_record_batch(PcpPackageHandle *handle, const PcpRecordMutation *mutations, size_t mutation_count);
PcpResult pcp_package_remove_record(PcpPackageHandle *handle, uint32_t record_id);
PcpResult pcp_package_is_dirty(const PcpPackageHandle *handle, uint8_t *output);
PcpResult pcp_package_save(PcpPackageHandle *handle);
PcpResult pcp_package_save_as(PcpPackageHandle *handle, const char *path);
PcpResult pcp_load_order_open(const char *const *paths, size_t path_count, PcpLoadOrderHandle **output);
PcpResult pcp_load_order_open_for_editor(const char *const *paths, size_t path_count, PcpLoadOrderHandle **output);
PcpResult pcp_load_order_build_record_index(PcpLoadOrderHandle *handle);
void pcp_load_order_destroy(PcpLoadOrderHandle *handle);
PcpResult pcp_load_order_record_count(const PcpLoadOrderHandle *handle, size_t *output);
PcpResult pcp_load_order_winning_record_at(const PcpLoadOrderHandle *handle, size_t index, uint32_t *output_runtime_record_id, PcpRecordOrigin *output_origin);
PcpResult pcp_load_order_resolve_record_id(const PcpLoadOrderHandle *handle, size_t package_index, uint32_t serialized_record_id, uint32_t *output_runtime_record_id);
PcpResult pcp_load_order_override_count(const PcpLoadOrderHandle *handle, uint32_t runtime_record_id, size_t *output);
PcpResult pcp_load_order_override_origin(const PcpLoadOrderHandle *handle, uint32_t runtime_record_id, size_t origin_index, PcpRecordOrigin *output);
void pcp_record_reader_destroy(PcpRecordReaderHandle *handle);
PcpResult pcp_record_reader_next_subrecord(PcpRecordReaderHandle *handle, PcpSubrecordHeader *output);
PcpResult pcp_record_reader_copy_current_subrecord_payload(const PcpRecordReaderHandle *handle, uint8_t *destination, size_t destination_byte_count, size_t *required_byte_count);
size_t pcp_last_error_message(char *destination, size_t destination_byte_count);

#ifdef __cplusplus
}
#endif

#endif
