//! Hard format limits enforced before content allocation.
//!
//! Every decoder enforces these bounds before reserving vectors, cloning
//! content, or converting lengths to platform sizes. The limits are the
//! format-level contract from the v2 format review; run-level budgets live
//! in `ExecutionIdentity` and may be lower.

/// Outer format version. Every durable container carries this value and a
/// decoder rejects anything else.
pub const FORMAT_VERSION: u32 = 2;

/// Crash-semantics version bound by the manifest and `ExecutionIdentity`.
pub const CRASH_SEMANTICS_VERSION: u32 = 1;

/// Maximum bytes in a container header (the 16-byte raw prefix plus the
/// canonical CBOR header that follows it).
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
