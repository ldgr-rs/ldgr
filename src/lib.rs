#![deny(unsafe_code)]
#![allow(missing_docs)]

//! A small deterministic simulation and causal journal prototype.

pub mod cbor;
pub mod config;
pub mod format;
pub mod journal;
pub mod net;
pub mod runtime;
pub mod scheduler;
pub mod seedtree;
pub mod time;
