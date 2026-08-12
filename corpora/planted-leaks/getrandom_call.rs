//! Planted leak class: OS entropy via the getrandom crate.

fn main() {
    let mut _buf = [0u8; 32];
    let _ = getrandom::getrandom(&mut _buf);
}
