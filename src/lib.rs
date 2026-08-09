#![deny(unsafe_code)]
#![allow(missing_docs)]

//! A small deterministic simulation and causal journal prototype.

pub mod cbor;
pub mod config;
pub mod explorer;
pub mod format;
pub mod journal;
pub mod ldfi;
pub mod minimizer;
pub mod net;
pub mod oracle;
pub mod runtime;
pub mod scheduler;
pub mod seedtree;
pub mod simfs;
pub mod time;
