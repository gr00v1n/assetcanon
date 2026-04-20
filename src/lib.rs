//! assetcanon — domain/asset canonicalization and DNS validation.
//!
//! This crate provides a pipeline for cleaning dirty domain input:
//! `extract` → `normalize` → `classify` → `dedupe` → `scope` → `dns`.
//!
//! Each stage is independently usable as a library function. The CLI wraps
//! them into Unix-style subcommands.

pub mod classify;
pub mod dedupe;
pub mod dns;
pub mod extract;
pub mod model;
pub mod normalize;
pub mod psl;
pub mod scope;
