//! Planted leak class: environment-variable entropy.

fn main() {
    let _seed = std::env::var("SEED");
}
