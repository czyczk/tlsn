//! TDN core protocol library.
//!
//! This crate contains core types for the TDN protocol.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::Serialize;

pub mod msg;
pub mod proof;
pub mod session;
pub mod signature;

/// Represents an entry in the serialization result using [`ToTdnStandardSerialized`].
#[derive(Serialize)]
#[serde(untagged)]
pub enum TdnStandardSerializedEntry {
    /// An object is serialized as a sorted map.
    Object(BTreeMap<&'static str, TdnStandardSerializedEntry>),
    /// A String or Vec<u8> is serialized as a String.
    String(String),
    /// An array is serialized as a Vec<TdnStandardSerializedEntry>.
    Array(Vec<TdnStandardSerializedEntry>),
}

/// A trait for types that can be serialized in TDN standard (a language-agnostic way).
pub trait ToTdnStandardSerialized {
    /// Serializes in a language-agnostic way:
    /// - JSON
    /// - camel case
    /// - no indent and new line (compact)
    /// - fields sorted alphabetically
    /// - all Vec<u8> as base64 string
    fn to_tdn_standard_serialized(&self) -> TdnStandardSerializedEntry;
}
