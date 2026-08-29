//! Allocation instrumentation: bounds execute before content allocation.
//!
//! The section-14 matrix row requires proof that hostile declared lengths
//! fail before any content-sized allocation. A counting global allocator
//! measures the live-allocation delta around a hostile decode: a declared
//! array length larger than the remaining input must be rejected with
//! `LengthOverflow` while allocating at most a few bytes of harness noise,
//! never the declared content.
//!
//! The delta assertion is intentionally generous (4 KiB) because tests in
//! this binary share a process; a hostile 2^32-byte allocation would blow
//! the bound by nine orders of magnitude, so the check is decisive without
//! being flaky.

use ledger_format::cbor::{CborError, CborValue};
use ledger_format::frame::{FrameError, MAGIC_SEGMENT, parse_prefix};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

// Test harness only: counts every allocation the process makes. The unsafe
// impl is the standard counting-allocator pattern and never runs in the
// no_std library surface under test.
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

/// The maximum live-allocation delta a bound-rejected decode may produce.
const MAX_HARNESS_DELTA: usize = 4 * 1024;

fn allocated_delta_around(call: impl FnOnce()) -> usize {
    let before = ALLOCATED.load(Ordering::SeqCst);
    call();
    ALLOCATED.load(Ordering::SeqCst) - before
}

#[test]
fn oversized_array_length_fails_before_content_allocation() {
    // A canonical CBOR array header declaring 2^32 items with only four
    // bytes of remaining input. The decoder must reject with LengthOverflow
    // before `Vec::with_capacity(2^32)` can run.
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
    // A canonical CBOR text header declaring 2^32 bytes with three bytes of
    // remaining input.
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
    // An outer frame prefix declaring a header length beyond the 1 MiB cap.
    // parse_prefix validates the cap before any header allocation.
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
    // The 17 MiB entry cap is enforced on decode; the encoder must reject
    // the same shape, or a journal could seal and hash-verify an entry that
    // then fails on every read.
    use ledger_format::{EntryData, EntryKind, EntryPayload, RngDrawPayload};
    let oversized = EntryData {
        format_version: ledger_format::FORMAT_VERSION,
        kind: EntryKind::RngDraw,
        actor: 1,
        parents: Vec::new(),
        vector_clock: Vec::new(),
        sequence: 0,
        payload: EntryPayload::RngDraw(RngDrawPayload {
            stream: 0,
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
            stream: 0,
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
