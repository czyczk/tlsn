//! Commitments to the data exchanged during the TLS session.

use mpz_core::hash::Hash;
use serde::{Deserialize, Serialize};

/// Contains the commitments in this TDN session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitments {
    /// The commitment to the ciphertext of the application data from the server.
    pub commitment_ciphertext_application: Hash,
    /// The commitment to the handshake data from the server.
    pub commitment_handshake: Hash,
    /// The commitment to the password to protect the proof.
    pub commitment_pwd_proof: Hash,
    /// The commitment to the ciphertext of the Notary private key used in this TLS session.
    pub commitment_ciphertext_priv_key_session_notary: Hash,
}
