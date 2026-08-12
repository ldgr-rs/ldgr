//! Planted leak class: raw thread spawning.

fn main() {
    let _handle = std::thread::spawn(|| {});
}
