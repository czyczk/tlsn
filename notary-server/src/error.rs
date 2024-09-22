use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use eyre::Report;
use std::error::Error;
use tdn_verifier::tls::{TdnVerifierConfigBuilderError, TdnVerifierError};

use tlsn_verifier::tls::{VerifierConfigBuilderError, VerifierError};

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
    #[error(transparent)]
    Unexpected(#[from] Report),
    #[error("Failed to connect to prover: {0}")]
    Connection(String),
    #[error("Error occurred during notarization: {0}")]
    Notarization(Box<dyn Error + Send + 'static>),
    #[error("Invalid request from prover: {0}")]
    BadProverRequest(String),
    #[error("Unauthorized request from prover: {0}")]
    UnauthorizedProverRequest(String),
    #[error("Bad config for TDN mode: {0}")]
    BadConfigForTdn(String),
}

impl From<VerifierError> for NotaryServerError {
    fn from(error: VerifierError) -> Self {
        Self::Notarization(Box::new(error))
    }
}

impl From<TdnVerifierError> for NotaryServerError {
    fn from(error: TdnVerifierError) -> Self {
        Self::Notarization(Box::new(error))
    }
}

impl From<VerifierConfigBuilderError> for NotaryServerError {
    fn from(error: VerifierConfigBuilderError) -> Self {
        Self::Notarization(Box::new(error))
    }
}

impl From<TdnVerifierConfigBuilderError> for NotaryServerError {
    fn from(error: TdnVerifierConfigBuilderError) -> Self {
        Self::Notarization(Box::new(error))
    }
}

/// Trait implementation to convert this error into an axum http response
impl IntoResponse for NotaryServerError {
    fn into_response(self) -> Response {
        match self {
            bad_request_error @ NotaryServerError::BadProverRequest(_) => {
                (StatusCode::BAD_REQUEST, bad_request_error.to_string()).into_response()
            }
            unauthorized_request_error @ NotaryServerError::UnauthorizedProverRequest(_) => (
                StatusCode::UNAUTHORIZED,
                unauthorized_request_error.to_string(),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something wrong happened.",
            )
                .into_response(),
        }
    }
}
