# Pluginable Content Package

Pluginable Content Package (PCP) is the official Rust implementation of a binary file format of
the same name. Inspired by the Interchange File Format, the PCP format is designed as an extendable,
portable, and pluginable solution to game content and save data serialization. It is particularly suited for
open world content streaming, concurrent scene development, conflict resolution and version control, working with
32-bit global entity IDs, as well as creating, loading, and distributing game patches, DLCs, and mods.
The extensible nature of the PCP format allows for record types/payloads to be defined by a game's schema.

Pluginable Content Packages use the `.pcp` extension, while Save Data Packages use `.sdp`.
However, both follow essentially the same spec, although their schemas may differ substantially.
Just as packages can contain records that override records from other packages, 
save data packages exclusively contain override records.

### The PCP format specification requires that the following is true for all schemas:

There are three kinds of chunks that file readers can navigate:

- Groups
- Records
- Subrecords

Each chunk begins with a fixed-size header followed by a payload. The header includes:

- the 4CC signature that maps the chunk to a schema type
- the size of the payload in bytes
- the 32-bit record ID (records only)
- header flags (records only)
- version control metadata (records only)
- the group label (groups only; usually the 4CC of the children records)
- the group type enum (groups only)

The first chunk of a package file is the package header record. The signature and payload types of this
record and its subrecords should be identical across all PCP files.

The first two bits of record header flags are reserved by the standard; schemas may define the rest.
Bit 0 marks deleted records and bit 1 requests persistent placement. Serialized hierarchy remains the
authoritative source of residency; the persistent bit is an authoring signal that editors validate against it.

The core library does not validate or decode payloads. It is agnostic to schema types.
The game layer is responsible for parsing records and subrecords into its own runtime types,
as well as driving the file readers and other library helpers as needed.

The core also provides optional deterministic source-order indexes, load-order override chains,
uniform 32-bit subrecord sizes, bounded list/set/map codecs, semantic package versions and version-constrained relationships,
compatibility diagnostics, deterministic dependency-order repair, validation-safe atomic writes, and merge application.
The native editing ABI also accepts record insertions, replacements, and deletions as one validated batch so
authoring integrations can rewrite and reindex a package once per save rather than once per edited record.
Merging allocates destination IDs, translates dependency-relative IDs, applies add/override/delete operations,
and creates SHA-256 changeset receipts.

Because the library does not distinguish between a record ID and any other 32-bit type within a subrecord payload,
the game layer must implement `ReferenceRewriter` to rewrite reference fields through the provided `RecordIdMapper`.
Merge application uses record IDs exclusively to match overrides.

Merge policies can target the complete package, one record, or one record plus all children.
Overrides can be included or ignored. Override records may replace the whole record, or only certain subrecords,
 according to replace, keep, repeated-occurrence append, or encoded-list append rules.
List append supports duplicates, unique append, and append-only-new-indices.
The same composition rules can be used to merge records across loaded packages only in runtime.

Run the Rust test suite:

```bash
cargo test --workspace -- --nocapture --test-threads=1
```
