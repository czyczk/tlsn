//! Signature types and utilities.

use crate::{SignatureResult, TdnStandardSerializedEntry, ToTdnStandardSerialized};
use base64::{prelude::BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use p256::ecdsa::{signature::Verifier, VerifyingKey};
use sha3::{Digest, Keccak256};

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Message hash has invalid length: expected {0}, got {1}")]
    InvalidMessageHashLength(usize, usize),
    #[error("Failed to load message hash: {0}")]
    LoadMessageHashError(secp256k1::Error),
    #[error("Failed to verify secp256k1 signature: {0}")]
    SignatureVerificationError(String),
}

/// A private key used for signatures.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SignaturePrivateKey {
    /// A NIST P-256 private key.
    P256(p256::ecdsa::SigningKey),
    /// A secp256k1 private key.
    Secp256k1(secp256k1::SecretKey),
}

impl SignaturePrivateKey {
    /// Returns the public key of this private key.
    pub fn public_key(&self) -> SignaturePublicKey {
        match self {
            Self::P256(key) => {
                let priv_key = p256::SecretKey::from_sec1_der(&key.to_bytes()).unwrap();
                SignaturePublicKey::P256(priv_key.public_key())
            }
            Self::Secp256k1(key) => SignaturePublicKey::Secp256k1(
                secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), key),
            ),
        }
    }
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

impl ToTdnStandardSerialized for SignaturePrivateKey {
    fn to_tdn_standard_serialized(&self) -> TdnStandardSerializedEntry {
        match self {
            Self::P256(key) => {
                TdnStandardSerializedEntry::String(BASE64_STANDARD.encode(key.to_bytes()))
            }
            Self::Secp256k1(key) => {
                TdnStandardSerializedEntry::String(BASE64_STANDARD.encode(key[..].to_vec()))
            }
        }
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
                // Hash the message in the Ethereum Signed Message format.
                let msg_hash = gen_hash_ethereum_signed_message(msg);

                // Sign
                let secp = secp256k1::Secp256k1::new();
                let message = secp256k1::Message::from_digest_slice(&msg_hash).expect("32 bytes");
                let signature = secp.sign_ecdsa_recoverable(&message, &key);
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

/// A Notary signature.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub enum Signature {
    /// A secp256r1 signature.
    P256(p256::ecdsa::Signature),
    /// A secp256k1 signature.
    Secp256k1(Secp256k1RecoverableSignature),
}

/// A secp256k1 recoverable signature, wrapping a `secp256k1::ecdsa::RecoverableSignature` for extensions.
#[derive(Debug, Clone)]
pub struct Secp256k1RecoverableSignature(secp256k1::ecdsa::RecoverableSignature);

impl Secp256k1RecoverableSignature {
    /// Gets the internal representation of the struct.
    pub fn internal(&self) -> &secp256k1::ecdsa::RecoverableSignature {
        &self.0
    }

    /// Gets the serialized bytes in the Ethereum Signed Message format.
    pub fn to_bytes_ethereum_signed_message(&self) -> [u8; 65] {
        // Ethereum Signed Message format:
        // 32 bytes of r, 32 bytes of s, 1 byte of v.
        // v is 27 + rec_id for Ethereum.
        let (rec_id, sig_bytes_compact) = self.internal().serialize_compact();
        let v = (27 + rec_id.to_i32()) as u8;

        let mut result = [0u8; 65];
        result[0..64].copy_from_slice(&sig_bytes_compact[0..64]);
        result[64] = v;
        result
    }

    /// Creates a `Secp256k1RecoverableSignature` from the bytes in the Ethereum Signed Message format.
    pub fn from_bytes_ethereum_signed_message(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 65 {
            return Err("invalid length");
        }

        let rec_id = secp256k1::ecdsa::RecoveryId::from_i32(bytes[64] as i32 - 27)
            .map_err(|_| "invalid recovery id")?;
        let sig_bytes_compact = &bytes[0..64];

        let sig = secp256k1::ecdsa::RecoverableSignature::from_compact(sig_bytes_compact, rec_id)
            .map_err(|_| "invalid signature")?;

        Ok(Self(sig))
    }

    /// Verifies an Ethereum signed message.
    ///
    /// # Arguments
    ///
    /// * `msg_hash` - The Keccak256 hash of the original message (with the "\x19Ethereum Signed Message" prefix) that was signed.
    /// * `public_key` - The expected public key.
    ///
    /// # Returns
    ///
    /// * `Result<bool, Error>` - Returns `Ok(true)` if the signature is valid, otherwise returns an error.
    pub fn verify_ethereum_signed_message(
        &self,
        msg_hash: &[u8],
        public_key: &secp256k1::PublicKey,
    ) -> Result<bool, Error> {
        // Step 1: Create a Message object.
        let msg = secp256k1::Message::from_digest_slice(msg_hash)
            .map_err(|e| Error::LoadMessageHashError(e))?;

        // Step 2: Recover the public key from the signature.
        let secp = secp256k1::Secp256k1::verification_only();
        let recovered_pubkey = secp
            .recover_ecdsa(&msg, self.internal())
            .map_err(|e| Error::SignatureVerificationError(e.to_string()))?;

        // Step 3: Compare the recovered public key with the expected public key.
        Ok(recovered_pubkey == *public_key)
    }
}

impl Serialize for Secp256k1RecoverableSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes_ethereum_signed_message())
    }
}

impl<'de> Deserialize<'de> for Secp256k1RecoverableSignature {
    fn deserialize<D>(deserializer: D) -> Result<Secp256k1RecoverableSignature, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Secp256k1RecoverableSignature::from_bytes_ethereum_signed_message(&bytes)
            .map_err(serde::de::Error::custom)
    }
}

impl From<p256::ecdsa::Signature> for Signature {
    fn from(sig: p256::ecdsa::Signature) -> Self {
        Self::P256(sig)
    }
}

impl From<Secp256k1RecoverableSignature> for Signature {
    fn from(sig: Secp256k1RecoverableSignature) -> Self {
        Self::Secp256k1(sig)
    }
}

impl From<secp256k1::ecdsa::RecoverableSignature> for Signature {
    fn from(sig: secp256k1::ecdsa::RecoverableSignature) -> Self {
        Self::Secp256k1(Secp256k1RecoverableSignature(sig))
    }
}

impl Signature {
    /// Returns the bytes of this signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(sig) => sig.to_vec(),
            Self::Secp256k1(sig) => sig.to_bytes_ethereum_signed_message().to_vec(),
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
    ) -> Result<bool, Error> {
        match (self, notary_public_key.into()) {
            (Self::P256(sig), SignaturePublicKey::P256(key)) => VerifyingKey::from(key)
                .verify(msg, sig)
                .map(|_| true)
                .map_err(|e| Error::SignatureVerificationError(e.to_string())),
            (Self::Secp256k1(sig), SignaturePublicKey::Secp256k1(key)) => {
                let ethereum_signed_message_hash = gen_hash_ethereum_signed_message(msg);
                sig.verify_ethereum_signed_message(&ethereum_signed_message_hash, &key)
                    .map_err(|e| Error::SignatureVerificationError(e.to_string()))
            }
            _ => Err(Error::SignatureVerificationError(
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
                BASE64_STANDARD.encode(sig.to_bytes_ethereum_signed_message()),
            ),
        }
    }
}

/// Generates the hash of some bytes in the Ethereum Signed Message format (i.e. with the prefix "\x19Ethereum Signed Message").
pub fn gen_hash_ethereum_signed_message(message: &[u8]) -> [u8; 32] {
    // Compute the hash of the original message (with the "\x19Ethereum Signed Message" prefix).
    let eth_prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(eth_prefix.as_bytes());
    hasher.update(message);
    let hash = hasher.finalize();
    hash.into()
}
