//! Hard format limits, enforced before content allocation.

/// Outer format version; decoders reject anything else.
///
/// v3 frames every `EntryHash` as a 34-byte BLAKE3 multihash
/// (`[0x1e, 0x20]` prefix plus digest); v2 bytes fail.
pub const FORMAT_VERSION: u32 = 3;

/// Crash-semantics version bound by the manifest and `ExecutionIdentity`.
pub const CRASH_SEMANTICS_VERSION: u32 = 1;

/// Maximum bytes in a container header (16-byte prefix plus CBOR header).
pub const MAX_HEADER_BYTES: usize = 1024 * 1024;

/// Maximum bytes of one canonical entry.
pub const MAX_ENTRY_BYTES: usize = 17 * 1024 * 1024;

/// Maximum entries in one journal or segment store.
pub const MAX_ENTRY_COUNT: u64 = 16_777_216;

/// Maximum parents referenced by one entry.
pub const MAX_PARENTS_PER_ENTRY: usize = 4096;

/// Maximum actors present in one vector clock.
pub const MAX_VECTOR_CLOCK_ACTORS: usize = 65_536;

/// Maximum bytes of one compressed segment frame block.
pub const MAX_COMPRESSED_SEGMENT_BYTES: usize = 256 * 1024 * 1024;

/// Maximum bytes of one decompressed segment frame block.
pub const MAX_DECOMPRESSED_SEGMENT_BYTES: usize = 1024 * 1024 * 1024;

/// Maximum canonical path bytes after canonicalization.
pub const MAX_CANONICAL_PATH_BYTES: usize = 4096;

/// Maximum bytes written by one filesystem mutation.
pub const MAX_WRITE_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum bytes returned by one read observation.
pub const MAX_READ_BYTES: u64 = 16 * 1024 * 1024;

/// Hard logical extent of one sparse file.
pub const MAX_FILE_EXTENT_HARD: u64 = 1024 * 1024 * 1024 * 1024;

/// Maximum bytes of one network message.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Maximum nesting depth of a canonical value.
pub const MAX_CANONICAL_VALUE_DEPTH: usize = 32;

/// Maximum total collection items inside one canonical value.
pub const MAX_CANONICAL_VALUE_ITEMS: usize = 65_536;

/// Maximum bytes of one text or byte string inside a canonical value.
pub const MAX_CANONICAL_VALUE_STRING_BYTES: usize = 1024 * 1024;
