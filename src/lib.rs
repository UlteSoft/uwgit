//! Core WebAssembly audit API, shared by the CLI and corpus verification tools.
pub mod audit;
mod core_view;
mod decode_error;
pub mod merge;
pub mod patch;
pub mod standard;
pub mod trace;
mod value_guard;
