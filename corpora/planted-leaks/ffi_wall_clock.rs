//! Planted leak class: FFI wall-clock reads.

extern "C" {
    fn time() -> i64;
}

fn main() {
    let _secs = unsafe { time() };
}
