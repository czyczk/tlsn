//! TDN proof types.

use crate::{
    session::TdnSessionId, sig::Signature, TdnStandardSerializedEntry, ToTdnStandardSerialized,
};
use base64::{prelude::BASE64_STANDARD, Engine as _};
use mpz_core::hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tls_core::{cert::ServerCertDetails, key::Certificate};

#[derive(Clone, Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum TdnProofError {
    #[error("Cannot extract certificates")]
    CertificateError,
}

/// A validated notarization from Notary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedProofNotary {
    /// Notary proof.
    pub proof_notary: ProofNotary,
    /// Signature of Notary proof.
    pub signature: Signature,
}

impl ToTdnStandardSerialized for SignedProofNotary {
    fn to_tdn_standard_serialized(&self) -> TdnStandardSerializedEntry {
        let mut map = BTreeMap::new();
        map.insert(
            "proofNotary",
            self.proof_notary.to_tdn_standard_serialized(),
        );
        map.insert("signature", self.signature.to_tdn_standard_serialized());

        TdnStandardSerializedEntry::Object(map)
    }
}

/// Proof produced by Notary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofNotary {
    /// TLS data.
    pub tls_data: TlsData,
    /// Commitments.
    pub commitments: Commitments,
    /// Notary settlement address.
    pub settlement_addr_notary: String,
}

impl ToTdnStandardSerialized for ProofNotary {
    fn to_tdn_standard_serialized(&self) -> TdnStandardSerializedEntry {
        let mut map = BTreeMap::new();
        map.insert("tlsData", self.tls_data.to_tdn_standard_serialized());
        map.insert("commitments", self.commitments.to_tdn_standard_serialized());
        map.insert(
            "settlementAddrNotary",
            TdnStandardSerializedEntry::String(self.settlement_addr_notary.clone()),
        );

        TdnStandardSerializedEntry::Object(map)
    }
}

/// TLS data contained in the proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsData {
    /// ID that can uniquely identify a TLS session.
    pub session_id: TdnSessionId,
    /// Key exchange data.
    pub kx: Kx,
    /// Server certificates.
    pub certificates: Certificates,
}

impl ToTdnStandardSerialized for TlsData {
    fn to_tdn_standard_serialized(&self) -> TdnStandardSerializedEntry {
        let mut map = BTreeMap::new();
        map.insert(
            "sessionId",
            TdnStandardSerializedEntry::String(self.session_id.to_base64_concat()),
        );
        map.insert("kx", self.kx.to_tdn_standard_serialized());
        map.insert(
            "certificates",
            self.certificates.to_tdn_standard_serialized(),
        );

        TdnStandardSerializedEntry::Object(map)
    }
}

/// Key exchange data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Kx {
    /// Notary public key used in this TLS session.
    pub pub_key_session_notary: Vec<u8>,
    /// Prover public key used in this TLS session.
    pub pub_key_session_prover: Vec<u8>,
    /// Server public key used in this TLS session.
    pub pub_key_session_server: Vec<u8>,
    /// Key exchange parameters used in this TLS session.
    pub kx_params: Vec<u8>,
}

impl ToTdnStandardSerialized for Kx {
    fn to_tdn_standard_serialized(&self) -> TdnStandardSerializedEntry {
        let mut map = BTreeMap::new();
        map.insert(
            "pubKeySessionNotary",
            TdnStandardSerializedEntry::String(
                BASE64_STANDARD.encode(&self.pub_key_session_notary),
            ),
        );
        map.insert(
            "pubKeySessionProver",
            TdnStandardSerializedEntry::String(
                BASE64_STANDARD.encode(&self.pub_key_session_prover),
            ),
        );
        map.insert(
            "pubKeySessionServer",
            TdnStandardSerializedEntry::String(
                BASE64_STANDARD.encode(&self.pub_key_session_server),
            ),
        );
        map.insert(
            "kxParams",
            TdnStandardSerializedEntry::String(BASE64_STANDARD.encode(&self.kx_params)),
        );

        TdnStandardSerializedEntry::Object(map)
    }
}

/// Contains the certificates in this TDN session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificates {
    /// The current certificate of the server.
    pub end_entity: Certificate,
    /// The intermediate certificates on the path to the root certificate.
    pub intermediates: Vec<Certificate>,
}

impl TryFrom<&ServerCertDetails> for Certificates {
    type Error = TdnProofError;

    fn try_from(cert_details: &ServerCertDetails) -> Result<Self, Self::Error> {
        if cert_details.cert_chain().is_empty() {
            return Err(TdnProofError::CertificateError);
        }

        let cert_chain = cert_details.cert_chain();
        Ok(Self {
            end_entity: cert_chain[0].clone(),
            intermediates: cert_details.cert_chain().iter().skip(1).cloned().collect(),
        })
    }
}

impl ToTdnStandardSerialized for Certificates {
    fn to_tdn_standard_serialized(&self) -> TdnStandardSerializedEntry {
        let mut map_certificates = BTreeMap::new();
        map_certificates.insert(
            "endEntity",
            TdnStandardSerializedEntry::String(BASE64_STANDARD.encode(&self.end_entity.0)),
        );

        let mut intermediates = Vec::new();
        for cert in &self.intermediates {
            intermediates.push(BASE64_STANDARD.encode(&cert.0));
        }

        let mut map = BTreeMap::new();
        map.insert(
            "endEntity",
            TdnStandardSerializedEntry::String(BASE64_STANDARD.encode(&self.end_entity.0)),
        );
        map.insert(
            "intermediates",
            TdnStandardSerializedEntry::Array(
                self.intermediates
                    .iter()
                    .map(|cert| TdnStandardSerializedEntry::String(BASE64_STANDARD.encode(&cert.0)))
                    .collect(),
            ),
        );

        TdnStandardSerializedEntry::Object(map)
    }
}

/// Contains the commitments in this TDN session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitments {
    /// The commitment to the ciphertext of the application data from the server.
    pub commitment_ciphertext_application_data: Hash,
    /// The commitment to the handshake data from the server.
    pub commitment_handshake: Hash,
    /// The commitment to the password to protect the proof.
    pub commitment_pwd_proof: Hash,
    /// The commitment to the 1st-level ciphertext of the Notary private key used in this TLS session.
    pub commitment_cipher1_priv_key_session_notary: Hash,
}

impl ToTdnStandardSerialized for Commitments {
    fn to_tdn_standard_serialized(&self) -> TdnStandardSerializedEntry {
        let mut map = BTreeMap::new();
        map.insert(
            "commitmentCiphertextApplicationData",
            TdnStandardSerializedEntry::String(
                BASE64_STANDARD.encode(self.commitment_ciphertext_application_data.as_bytes()),
            ),
        );
        map.insert(
            "commitmentHandshake",
            TdnStandardSerializedEntry::String(
                BASE64_STANDARD.encode(self.commitment_handshake.as_bytes()),
            ),
        );
        map.insert(
            "commitmentPwdProof",
            TdnStandardSerializedEntry::String(
                BASE64_STANDARD.encode(self.commitment_pwd_proof.as_bytes()),
            ),
        );
        map.insert(
            "commitmentCipher1PrivKeySessionNotary",
            TdnStandardSerializedEntry::String(
                BASE64_STANDARD.encode(self.commitment_cipher1_priv_key_session_notary.as_bytes()),
            ),
        );

        TdnStandardSerializedEntry::Object(map)
    }
}
