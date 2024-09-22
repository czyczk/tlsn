//! Protocol message types.

use serde::{Deserialize, Serialize};
use tls_core::key::PublicKey;

use crate::{
    proof::{Certificates, ProofNotary},
    signature::Signature,
};

/// Top-level enum for all messages
#[derive(Debug, Serialize, Deserialize)]
pub enum TdnMessage {
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
}
