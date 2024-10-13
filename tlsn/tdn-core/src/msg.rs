//! Protocol message types.

use serde::{Deserialize, Serialize};
use tls_core::key::PublicKey;

use crate::{
    proof::{Certificates, ProofNotary},
    sig::Signature,
};

/// Top-level enum for all messages
#[derive(Debug, Serialize, Deserialize)]
pub enum TdnMessage {
    /// Public key of the consumer.
    PubKeyConsumer(PublicKey),
    /// Commitment of the password to protect the proof.
    CommitmentPwdProof(Vec<u8>),
    /// Prover public key used in this TLS session.
    PubKeySessionProver(PublicKey),
    /// Server certificates.
    Certificates(Certificates),
    /// Notarization result: notary proof + signature.
    NotarizationResult(NotarizationResult),
}

/// A signed notary proof.
#[derive(Debug, Serialize, Deserialize)]
pub struct NotarizationResult {
    /// The notary proof.
    pub proof_notary: ProofNotary,
    /// The notary's signature.
    pub signature: Signature,
    /// 1st-level ciphertext of the notary's private key used in this TLS session.
    pub ciphertext1_priv_key_session_notary: Vec<u8>,
}
