//! Planted leak class: RDRAND hardware entropy.

fn main() {
    let mut _v: u64 = 0;
    let _ = std::arch::x86_64::_rdrand64_step(&mut _v);
}
