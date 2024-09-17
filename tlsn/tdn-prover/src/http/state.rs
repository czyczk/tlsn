//! HTTP prover state.

use tlsn_formats::http::HttpTranscript;

use crate::tls::{state as prover_state, Prover};

/// The state of an HTTP prover
pub trait State: sealed::Sealed {}

/// Connection closed state. TDN mode.
pub struct TdnClosed {
    pub(super) prover: Prover<prover_state::TdnClosed>,
    pub(super) transcript: HttpTranscript,
}

/// Notarizing state.
pub struct Notarize {
    pub(super) prover: Prover<prover_state::Notarize>,
    pub(super) transcript: HttpTranscript,
}

impl State for TdnClosed {}
impl State for Notarize {}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::TdnClosed {}
    impl Sealed for super::Notarize {}
}
