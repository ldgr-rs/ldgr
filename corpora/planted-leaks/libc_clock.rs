//! Planted leak class: libc clock reads.

fn main() {
    let mut _ts = std::mem::zeroed();
    let _ = libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut _ts);
}
