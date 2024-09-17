//! Contains the structures used in the key exchange phase of the TDN protocol.

use serde::{Deserialize, Serialize};
use tls_core::{
    key::PublicKey,
    msgs::{
        enums::{NamedGroup, SignatureScheme},
        handshake::ECParameters,
    },
};

/// Handshake summary is part of the session header signed by the Notary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotaryHandshakeSummary {
    /// Time when the TLS handshake was established. It can also be seen roughly as the time the TDN proof is signed by Notary.
    pub time: u64,
    /// Notary public key used in this TLS session.
    pub pub_key_session_notary: PublicKey,
    /// Prover public key used in this TLS session.
    pub pub_key_session_prover: PublicKey,
    /// Server public key used in this TLS session.
    pub pub_key_session_server: PublicKey,
    /// Curve parameters used in this TLS session.
    pub curve_params: ECParams,
    /// Signature scheme used in this TLS session.
    pub sig_scheme_server: SignatureScheme,
    /// Signature of the key exchange data by the server.
    pub sig_kx_server: Vec<u8>,
}

/// Contains the curve parameters in this TDN session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECParams {
    /// Named group used in this TDN session.
    pub named_group: NamedGroup,
}

impl From<ECParameters> for ECParams {
    fn from(params: ECParameters) -> Self {
        ECParams {
            named_group: params.named_group,
        }
    }
}
