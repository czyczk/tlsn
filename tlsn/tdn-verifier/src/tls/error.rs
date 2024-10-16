use std::error::Error;
use tls_mpc::MpcTlsError;

/// An error that can occur during TLS verification.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum TdnVerifierError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error("error occurred in MPC protocol: {0}")]
    MpcError(Box<dyn Error + Send + Sync + 'static>),
    #[error("Range exceeds transcript length")]
    InvalidRange,
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
    #[error("Error occurred while using private key: {0}")]
    PrivateKeyError(String),
    #[error("Error occurred while performing encryption: {0}")]
    EncryptionError(String),
}

impl From<MpcTlsError> for TdnVerifierError {
    fn from(e: MpcTlsError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_ot::OTError> for TdnVerifierError {
    fn from(e: mpz_ot::OTError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_ot::actor::kos::SenderActorError> for TdnVerifierError {
    fn from(e: mpz_ot::actor::kos::SenderActorError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_ot::actor::kos::ReceiverActorError> for TdnVerifierError {
    fn from(e: mpz_ot::actor::kos::ReceiverActorError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::VerifyError> for TdnVerifierError {
    fn from(e: mpz_garble::VerifyError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::MemoryError> for TdnVerifierError {
    fn from(e: mpz_garble::MemoryError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<tlsn_core::proof::SessionProofError> for TdnVerifierError {
    fn from(e: tlsn_core::proof::SessionProofError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

impl From<mpz_garble::VmError> for TdnVerifierError {
    fn from(e: mpz_garble::VmError) -> Self {
        Self::MpcError(Box::new(e))
    }
}
