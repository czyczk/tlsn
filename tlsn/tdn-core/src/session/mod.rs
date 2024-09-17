//! TLS session types.

pub mod certificate;
pub mod ciphertext;
pub mod commitment;
pub mod keyexchange;
pub mod settlement;

use base64::{prelude::BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum TdnSessionDataError {
    #[error("Input has incorrect number of parts: expected {0}, got {1}")]
    InvalidInputPartNumber(usize, usize),
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
}

/// Contains info that can uniquely identify a TLS session. Uniquely used in TDN mode.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TdnSessionId {
    /// Client random.
    pub random_client: Vec<u8>,
    /// Server random.
    pub random_server: Vec<u8>,
}

/// TDN collect result from the leader.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TdnCollectLeaderResult {
    /// Session ID.
    pub session_id: TdnSessionId,
    /// Client random.
    pub random_client: Vec<u8>,
    /// Server random.
    pub random_server: Vec<u8>,
    /// Ciphertext of the application data from the server collected in this session.
    pub ciphertext_application_data_server: Vec<u8>,
}

/// TDN session data to be stored in Notary. Should be persisted in databases in future iterations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TdnSessionData {
    /// Session ID.
    pub session_id: TdnSessionId,
    /// Client random.
    pub random_client: Vec<u8>,
    /// Server random.
    pub random_server: Vec<u8>,
    /// Notary private key used in this session.
    pub priv_key_session_notary: Vec<u8>,
    /// Ciphertext of the application data from the server collected in this session.
    pub ciphertext_application_data_server: Vec<u8>,
    /// Handshake commitment.
    pub commitment_handshake: Vec<u8>,
}

impl TdnSessionId {
    /// Creates a new `TdnSessionId` with the given random client and server values.
    pub fn new(random_client: Vec<u8>, random_server: Vec<u8>) -> Self {
        Self {
            random_client,
            random_server,
        }
    }

    /// Formats the session ID as its parts encoded in base64 concatenated. Specifically `${base64(random_client)}__${base64(random_server)}`.
    pub fn to_base64_concat(&self) -> String {
        format!(
            "{}__{}",
            BASE64_STANDARD.encode(&self.random_client),
            BASE64_STANDARD.encode(&self.random_server)
        )
    }

    /// Parses the session ID from its base64 concatenated form.
    pub fn from_base64_concat(base64_concat: &str) -> Result<Self, TdnSessionDataError> {
        let parts: Vec<&str> = base64_concat.split("__").collect();
        if parts.len() != 2 {
            return Err(TdnSessionDataError::InvalidInputPartNumber(2, parts.len()));
        }

        Ok(Self {
            random_client: BASE64_STANDARD.decode(parts[0].as_bytes())?,
            random_server: BASE64_STANDARD.decode(parts[1].as_bytes())?,
        })
    }
}
