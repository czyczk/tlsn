//! HTTP Prover.
//!
//! An HTTP prover can be created from a TLS [`Prover`](crate::tls::Prover), after the TLS connection has been closed, by calling the
//! [`to_http`](crate::tls::Prover::to_http) method.
//!
//! The [`HttpProver`] provides higher-level APIs for committing and proving data communicated during an HTTP connection.

pub mod state;

use tlsn_formats::{http::HttpTranscript, ParseError};

use crate::tls::{state as prover_state, TdnProver, ProverError};

pub use tlsn_formats::http::NotarizedHttpSession;

/// HTTP prover error.
#[derive(Debug, thiserror::Error)]
pub enum HttpProverError {
    /// An error originated from the TLS prover.
    #[error(transparent)]
    Prover(#[from] ProverError),
    /// An error occurred while parsing the HTTP data.
    #[error(transparent)]
    Parse(#[from] ParseError),
}

/// An HTTP prover.
pub struct HttpProver<S: state::State> {
    state: S,
}

impl HttpProver<state::TdnClosed> {
    /// Creates a new HTTP prover.
    pub fn new(prover: TdnProver<prover_state::TdnClosed>) -> Result<Self, HttpProverError> {
        let transcript = HttpTranscript::parse(prover.sent_transcript(), prover.recv_transcript())?;

        Ok(Self {
            state: state::TdnClosed { prover, transcript },
        })
    }
}
