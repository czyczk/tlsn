//! Ciphertexts collected from the server in this TDN session.

use serde::{Deserialize, Serialize};

/// Contains the ciphertexts in this TDN session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertexts {
    /// The ciphertext of the application data from the server.
    pub ciphertext_application_data_server: Vec<u8>,
    /// The ciphertext of the Notary private key used in this TLS session.
    pub ciphertext_priv_key_session_notary: Vec<u8>,
    /// The ciphertext of the Prover private key used in this TLS session.
    pub ciphertext_priv_key_session_prover: Vec<u8>,
}
