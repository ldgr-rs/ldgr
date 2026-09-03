//! Allocation gate: hostile declared lengths fail before content allocation.
//!
//! A counting allocator measures the delta around a hostile decode; a
//! length beyond remaining input must fail with `LengthOverflow` with only
//! harness noise (4 KiB bound), never the declared content.

use ledger_format::cbor::{CborError, CborValue};
use ledger_format::frame::{FrameError, MAGIC_SEGMENT, parse_prefix};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

// Test harness only: standard counting allocator; never runs in no_std.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.fetch_add(layout.size(), Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATED.fetch_add(new_size.saturating_sub(layout.size()), Ordering::SeqCst);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Maximum allocation delta a bound-rejected decode may produce.
const MAX_HARNESS_DELTA: usize = 4 * 1024;

/// Serializes the tests in this binary: the counting allocator is process
static MEASURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn allocated_delta_around(call: impl FnOnce()) -> usize {
    let before = ALLOCATED.load(Ordering::SeqCst);
    call();
    ALLOCATED.load(Ordering::SeqCst) - before
}

#[test]
fn oversized_array_length_fails_before_content_allocation() {
    let _guard = MEASURE_LOCK.lock().unwrap();
    let _ = CborValue::from_canonical_bytes(&[0xf6]);
    // Array declares 2^32 items with 4 bytes remaining; must fail before
    // `Vec::with_capacity(2^32)`.
    let hostile = [0x9A, 0x01, 0x00, 0x00, 0x00];
    let delta = allocated_delta_around(|| {
        let result = CborValue::from_canonical_bytes(&hostile);
        assert!(matches!(result, Err(CborError::LengthOverflow)));
    });
    assert!(
        delta < MAX_HARNESS_DELTA,
        "hostile array length allocated {delta} bytes; bound check must run first"
    );
}

#[test]
fn oversized_text_length_fails_before_content_allocation() {
    let _guard = MEASURE_LOCK.lock().unwrap();
    let _ = CborValue::from_canonical_bytes(&[0xf6]);
    // Text declares 2^32 bytes with 3 bytes remaining.
    let hostile = [0x7A, 0x01, 0x00, 0x00, 0x00, b'a', b'b', b'c'];
    let delta = allocated_delta_around(|| {
        let result = CborValue::from_canonical_bytes(&hostile);
        assert!(matches!(result, Err(CborError::LengthOverflow)));
    });
    assert!(
        delta < MAX_HARNESS_DELTA,
        "hostile text length allocated {delta} bytes; bound check must run first"
    );
}

#[test]
fn oversized_frame_header_fails_before_any_header_copy() {
    let _guard = MEASURE_LOCK.lock().unwrap();
    let _ = CborValue::from_canonical_bytes(&[0xf6]);
    // Frame declares beyond the 1 MiB cap; the cap checks before allocation.
    let mut hostile = Vec::new();
    hostile.extend_from_slice(MAGIC_SEGMENT);
    hostile.extend_from_slice(&ledger_format::limits::FORMAT_VERSION.to_le_bytes());
    hostile.extend_from_slice(&(u32::MAX).to_le_bytes());
    hostile.extend_from_slice(&0u32.to_le_bytes());
    let delta = allocated_delta_around(|| {
        let result = parse_prefix(&hostile, MAGIC_SEGMENT);
        assert!(matches!(result, Err(FrameError::HeaderTooLarge(_))));
    });
    assert!(
        delta < MAX_HARNESS_DELTA,
        "hostile frame header allocated {delta} bytes; bound check must run first"
    );
}

#[test]
fn encoder_rejects_an_entry_the_decoder_would_reject() {
    // The encoder must reject what the decoder rejects, or a journal could
    // seal an entry that then fails on every read.
    let _guard = MEASURE_LOCK.lock().unwrap();
    use ledger_format::{ActorId, EntryData, EntryKind, EntryPayload, RngDrawPayload};
    use ledger_format::{SequenceNumber, StreamId};
    let oversized = EntryData {
        format_version: ledger_format::FORMAT_VERSION,
        kind: EntryKind::RngDraw,
        actor: ActorId(1),
        parents: smallvec::SmallVec::new(),
        vector_clock: Vec::new(),
        sequence: SequenceNumber(0),
        payload: EntryPayload::RngDraw(RngDrawPayload {
            stream: StreamId(0),
            draw_index: 0,
            content: vec![0xab; ledger_format::limits::MAX_ENTRY_BYTES],
        }),
    };
    let mut scratch = Vec::new();
    let error = oversized.encode_into(&mut scratch).unwrap_err();
    assert!(
        matches!(error, CborError::EntryTooLarge(_)),
        "encoder must reject an entry over the cap, got {error:?}"
    );
    assert!(
        scratch.is_empty(),
        "the rejected encode must not leave partial bytes in the buffer"
    );

    // A valid entry just under the cap still round-trips.
    let valid = EntryData {
        payload: EntryPayload::RngDraw(RngDrawPayload {
            stream: StreamId(0),
            draw_index: 0,
            content: vec![0xab; ledger_format::limits::MAX_ENTRY_BYTES - 4096],
        }),
        ..oversized
    };
    let mut scratch = Vec::new();
    valid
        .encode_into(&mut scratch)
        .expect("valid entry encodes");
    let decoded = EntryData::from_canonical_bytes(&scratch).expect("valid entry decodes");
    match decoded.payload {
        EntryPayload::RngDraw(draw) => {
            assert_eq!(
                draw.content.len(),
                ledger_format::limits::MAX_ENTRY_BYTES - 4096
            )
        }
        other => panic!("wrong payload kind: {other:?}"),
    }
}
