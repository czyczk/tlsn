//! ABI encoding extension.

use alloy::dyn_abi::DynSolValue;

use crate::{proof::ProofNotary, Error, ToAbiEncodable};

use super::{Certificates, Commitments, Kx, ProofProver, Security, TlsData};

impl ToAbiEncodable for ProofProver {
    fn to_abi_encodable(&self) -> Result<DynSolValue, Error> {
        // Decode hex string to [u8; 20].
        let settlement_address_prover: [u8; 20] =
            hex::decode(&self.settlement_address_prover.trim_start_matches("0x"))
                .map_err(|e| {
                    Error::AbiSerializationError(format!(
                        "Failed to decode settlementAddressProver hex string: {}",
                        e
                    ))
                })?
                .try_into()
                .map_err(|_| {
                    Error::AbiSerializationError(
                        "Failed to treat settlementAddressProver as [u8; 20]".to_owned(),
                    )
                })?;

        // Manually sort the keys lexicographically.
        Ok(DynSolValue::Tuple(vec![
            // proofNotary
            self.proof_notary.to_abi_encodable()?,
            // security
            self.security.to_abi_encodable()?,
            // settlementAddressProver
            DynSolValue::Address(settlement_address_prover.into()),
        ]))
    }
}

impl ToAbiEncodable for ProofNotary {
    fn to_abi_encodable(&self) -> Result<DynSolValue, Error> {
        // Decode hex string to [u8; 20].
        let settlement_address_notary: [u8; 20] =
            hex::decode(&self.settlement_address_notary.trim_start_matches("0x"))
                .map_err(|e| {
                    Error::AbiSerializationError(format!(
                        "Failed to decode settlementAddressNotary hex string: {}",
                        e
                    ))
                })?
                .try_into()
                .map_err(|_| {
                    Error::AbiSerializationError(
                        "Failed to treat settlementAddressNotary as [u8; 20]".to_owned(),
                    )
                })?;

        // Manually sort the keys lexicographically.
        Ok(DynSolValue::Tuple(vec![
            // commitments
            self.commitments.to_abi_encodable()?,
            // settlementAddressNotary
            DynSolValue::Address(settlement_address_notary.into()),
            // tlsData
            self.tls_data.to_abi_encodable()?,
        ]))
    }
}

impl ToAbiEncodable for TlsData {
    fn to_abi_encodable(&self) -> Result<DynSolValue, Error> {
        // Manually sort the keys lexicographically.
        Ok(DynSolValue::Tuple(vec![
            // certificates
            self.certificates.to_abi_encodable()?,
            // kx
            self.kx.to_abi_encodable()?,
            // sessionId
            self.session_id.to_abi_encodable()?,
        ]))
    }
}

impl ToAbiEncodable for Certificates {
    fn to_abi_encodable(&self) -> Result<DynSolValue, Error> {
        // Manually sort the keys lexicographically.
        Ok(DynSolValue::Tuple(vec![
            // certsServer
            DynSolValue::Array(
                self.certs_server
                    .iter()
                    .map(|cert| DynSolValue::Bytes(cert.0.clone()))
                    .collect(),
            ),
        ]))
    }
}

impl ToAbiEncodable for Kx {
    fn to_abi_encodable(&self) -> Result<DynSolValue, Error> {
        // Manually sort the keys lexicographically.
        Ok(DynSolValue::Tuple(vec![
            // kxParams
            DynSolValue::Bytes(self.kx_params.clone()),
            // pubKeySessionNotary
            DynSolValue::Bytes(self.pub_key_session_notary.clone()),
            // pubKeySessionProver
            DynSolValue::Bytes(self.pub_key_session_prover.clone()),
            // pubKeySessionServer
            DynSolValue::Bytes(self.pub_key_session_server.clone()),
            // signatureKxParamsServer
            DynSolValue::Bytes(self.signature_kx_params_server.clone()),
        ]))
    }
}

impl ToAbiEncodable for Commitments {
    fn to_abi_encodable(&self) -> Result<DynSolValue, Error> {
        // Manually sort the keys lexicographically.
        Ok(DynSolValue::Tuple(vec![
            // commitmentCiphertext1PrivKeySessionNotary
            DynSolValue::Bytes(
                self.commitment_ciphertext1_priv_key_session_notary
                    .as_bytes()
                    .to_vec(),
            ),
            // commitmentCiphertextApplicationData
            DynSolValue::Bytes(
                self.commitment_ciphertext_application_data
                    .as_bytes()
                    .to_vec(),
            ),
            // commitmentHandshake
            DynSolValue::Bytes(self.commitment_handshake.as_bytes().to_vec()),
            // commitmentPwdProof
            DynSolValue::Bytes(self.commitment_pwd_proof.as_bytes().to_vec()),
        ]))
    }
}

impl ToAbiEncodable for Security {
    fn to_abi_encodable(&self) -> Result<DynSolValue, Error> {
        // Manually sort the keys lexicographically.
        Ok(DynSolValue::Tuple(vec![
            // ciphertext2PrivKeySessionNotary
            DynSolValue::Bytes(self.ciphertext2_priv_key_session_notary.clone()),
            // ciphertext2PrivKeySessionProver
            DynSolValue::Bytes(self.ciphertext2_priv_key_session_prover.clone()),
        ]))
    }
}
