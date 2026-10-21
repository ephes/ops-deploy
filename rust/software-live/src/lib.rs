//! The library of the `software-live` binary (PLAN.md 5.1): one module per
//! part of `software_live.py`, so the fixture tests reach every step.

pub mod atomic;
pub mod error;
pub mod http;
pub mod policy;
pub mod probe;
pub mod pyjson;
pub mod report;
pub mod traefik;
pub mod upstream;
pub mod version;

#[cfg(test)]
mod testutil;
