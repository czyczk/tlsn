//! Signature types and utilities.

use crate::{SignatureResult, TdnStandardSerializedEntry, ToTdnStandardSerialized};
use base64::{prelude::BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use p256::ecdsa::{signature::Verifier, VerifyingKey};
use sha3::{Digest, Keccak256};

/// A private key used for signatures.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SignaturePrivateKey {
    /// A NIST P-256 private key.
    P256(p256::ecdsa::SigningKey),
    /// A secp256k1 private key.
    Secp256k1(secp256k1::SecretKey),
}

impl From<p256::ecdsa::SigningKey> for SignaturePrivateKey {
    fn from(key: p256::ecdsa::SigningKey) -> Self {
        Self::P256(key)
    }
}

impl From<secp256k1::SecretKey> for SignaturePrivateKey {
    fn from(key: secp256k1::SecretKey) -> Self {
        Self::Secp256k1(key)
    }
}

impl<T> signature::Signer<T> for SignaturePrivateKey
where
    T: From<Signature> + Into<Signature>,
{
    fn try_sign(&self, msg: &[u8]) -> SignatureResult<T> {
        match self {
            Self::P256(key) => key
                .try_sign(msg)
                .map(|sig: p256::ecdsa::Signature| T::from(Signature::from(sig))),
            Self::Secp256k1(key) => {
                // Hash
                let mut hasher = Keccak256::new();
                hasher.update(msg);
                let msg_hash = hasher.finalize();

                // Sign
                let secp = secp256k1::Secp256k1::new();
                let message = secp256k1::Message::from_digest_slice(&msg_hash).expect("32 bytes");
                let signature = secp.sign_ecdsa_low_r(&message, &key);
                Ok(T::from(Signature::from(signature)))
            }
        }
    }
}

/// A public key used for signatures.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub enum SignaturePublicKey {
    /// A NIST P-256 public key.
    P256(p256::PublicKey),
    /// A secp256k1 public key.
    Secp256k1(secp256k1::PublicKey),
}

impl From<p256::PublicKey> for SignaturePublicKey {
    fn from(key: p256::PublicKey) -> Self {
        Self::P256(key)
    }
}

impl From<secp256k1::PublicKey> for SignaturePublicKey {
    fn from(key: secp256k1::PublicKey) -> Self {
        Self::Secp256k1(key)
    }
}

/// An error occurred while verifying a signature.
#[derive(Debug, thiserror::Error)]
#[error("signature verification failed: {0}")]
pub struct SignatureVerifyError(String);

/// A Notary signature.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub enum Signature {
    /// A secp256r1 signature.
    P256(p256::ecdsa::Signature),
    /// A secp256k1 signature.
    Secp256k1(secp256k1::ecdsa::Signature),
}

impl From<p256::ecdsa::Signature> for Signature {
    fn from(sig: p256::ecdsa::Signature) -> Self {
        Self::P256(sig)
    }
}

impl From<secp256k1::ecdsa::Signature> for Signature {
    fn from(sig: secp256k1::ecdsa::Signature) -> Self {
        Self::Secp256k1(sig)
    }
}

impl Signature {
    /// Returns the bytes of this signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(sig) => sig.to_vec(),
            Self::Secp256k1(sig) => sig.serialize_der().to_vec(),
        }
    }

    /// Verifies the signature.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to verify.
    /// * `notary_public_key` - The public key of the notary.
    pub fn verify(
        &self,
        msg: &[u8],
        notary_public_key: impl Into<SignaturePublicKey>,
    ) -> Result<(), SignatureVerifyError> {
        match (self, notary_public_key.into()) {
            (Self::P256(sig), SignaturePublicKey::P256(key)) => VerifyingKey::from(key)
                .verify(msg, sig)
                .map_err(|e| SignatureVerifyError(e.to_string())),
            (Self::Secp256k1(sig), SignaturePublicKey::Secp256k1(key)) => key
                .verify(
                    &secp256k1::Secp256k1::new(),
                    &secp256k1::Message::from_digest_slice(msg).expect("32 bytes"),
                    sig,
                )
                .map_err(|_| SignatureVerifyError("invalid signature".to_string())),
            _ => Err(SignatureVerifyError(
                "invalid combination of signature and public key or unsupported curve".to_string(),
            )),
        }
    }
}

impl ToTdnStandardSerialized for Signature {
    fn to_tdn_standard_serialized(&self) -> TdnStandardSerializedEntry {
        match self {
            Self::P256(sig) => {
                TdnStandardSerializedEntry::String(BASE64_STANDARD.encode(sig.to_bytes()))
            }
            Self::Secp256k1(sig) => TdnStandardSerializedEntry::String(
                BASE64_STANDARD.encode(sig.serialize_der().to_vec()),
            ),
        }
    }
}
