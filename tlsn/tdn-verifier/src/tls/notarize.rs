//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier is only a notary.

use crate::tls::state::Notarize;

use super::{TdnVerifier, TdnVerifierError};
use futures::{FutureExt as _, SinkExt, StreamExt, TryFutureExt};
use mpz_core::{hash::Hash, serialize::CanonicalSerialize};
use signature::Signer;
use tdn_core::crypto::hybrid_encrypt_ecies;
use tdn_core::sig::Signature;
use tdn_core::{
    msg::{NotarizationResult, TdnMessage},
    proof::{Commitments, Kx, ProofNotary, TlsData},
    ToTdnStandardSerialized,
};
use tls_core::key::PublicKey;
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

#[cfg(feature = "tracing")]
use tracing::info;

impl TdnVerifier<Notarize> {
    /// Notarizes the TLS session.
    pub async fn notarize<T>(
        self,
        evm_priv_key: &impl Signer<T>,
        evm_settlement_addr: String,
    ) -> Result<ProofNotary, TdnVerifierError>
    where
        T: Into<Signature>,
    {
        // TDN log
        println!("TdnVerifier::notarize()");

        let Notarize {
            mut mux_ctrl,
            mut mux_fut,
            ot_send,
            ot_recv,
            ot_fut,
            start_time,
            server_ephemeral_key,
            handshake_commitment,
            tdn_session_data,
            ..
        } = self.state;

        let notarize_fut = async {
            let mut notarize_channel = mux_ctrl.get_channel("notarize").await?;

            // TDN log
            println!("TDN log: N<-recv-P: TdnMessage::CommitmentPwdProof");
            let commitment_pwd_proof =
                expect_msg_or_err!(notarize_channel, TdnMessage::CommitmentPwdProof)?;

            // TDN log
            println!("TDN log: N<-recv-P: TdnMessage::PubKeyConsumer");
            let pub_key_consumer =
                expect_msg_or_err!(notarize_channel, TdnMessage::PubKeyConsumer)?;

            // TDN log
            println!("TDN log: N<-recv-P: TdnMessage::PubKeySessionProver");
            let pub_key_session_prover =
                expect_msg_or_err!(notarize_channel, TdnMessage::PubKeySessionProver)?;

            // TDN log
            println!("TDN log: N<-recv-P: TdnMessage::Certificates");
            // TDN TODO: verify the certificates. See if this should be passed from TLS MPC instead of from the prover here.
            // If passed down from TLS MPC, a verification should be done there.
            let certificates = expect_msg_or_err!(notarize_channel, TdnMessage::Certificates)?;

            // Prepare
            // Hash ciphertext_application_data_server
            let commitment_ciphertext_application_data_server: [u8; 32] =
                blake3::hash(&tdn_session_data.ciphertext_application_data_server).into();

            // Encrypt `priv_key_session_notary` from `tdn_session_data` against `pub_key_consumer`.
            let ciphertext1_priv_key_session_notary = hybrid_encrypt_ecies(
                // The public key bytes are already in SEC1 uncompressed format which can be directly used here.
                &pub_key_consumer.to_bytes(),
                &tdn_session_data.priv_key_session_notary,
                None,
                None,
                None,
            )
            .map_err(|e| TdnVerifierError::EncryptionError(e.to_string()))?
            .serialize();
            let commitment_ciphertext1_priv_key_session_notary = {
                // Blake3 hash it.
                let hash: [u8; 32] = blake3::hash(&ciphertext1_priv_key_session_notary).into();
                Hash::from(hash)
            };

            // TDN TODO: Whether this step can be skipped?
            // Finalize all MPC before signing the session header
            println!("TDN log: Finalize all MPC");
            let (mut ot_sender_actor, _, _) = futures::try_join!(
                ot_fut,
                ot_send.shutdown().map_err(TdnVerifierError::from),
                ot_recv.shutdown().map_err(TdnVerifierError::from)
            )?;

            ot_sender_actor.reveal().await?;

            #[cfg(feature = "tracing")]
            info!("Finalized all MPC");

            println!("Finalized all MPC");

            // let handshake_summary =
            //     HandshakeSummary::new(start_time, server_ephemeral_key, handshake_commitment);

            // TDN log
            println!("TDN log: Assemble ProofNotary");

            let proof_notary = ProofNotary {
                tls_data: TlsData {
                    session_id: tdn_session_data.session_id,
                    kx: Kx {
                        pub_key_session_notary: PublicKey::from(
                            p256::SecretKey::from_slice(&tdn_session_data.priv_key_session_notary)
                                .map_err(|e| TdnVerifierError::PrivateKeyError(e.to_string()))?
                                .public_key(),
                        )
                        .to_bytes(),
                        pub_key_session_prover: pub_key_session_prover.to_bytes(),
                        pub_key_session_server: server_ephemeral_key.to_bytes(),
                        kx_params: tdn_session_data.kx_params,
                    },
                    certificates,
                },
                commitments: Commitments {
                    commitment_ciphertext_application_data: Hash::from(
                        commitment_ciphertext_application_data_server,
                    ),
                    commitment_handshake: {
                        let arr: [u8; 32] = tdn_session_data
                            .commitment_handshake
                            .try_into()
                            .expect("expecting 32 bytes");
                        Hash::from(arr)
                    },
                    commitment_pwd_proof: {
                        let arr: [u8; 32] =
                            commitment_pwd_proof.try_into().expect("expecting 32 bytes");
                        Hash::from(arr)
                    },
                    commitment_ciphertext1_priv_key_session_notary,
                },
                evm_settlement_addr_notary: evm_settlement_addr,
            };
            let signature = evm_priv_key.sign(&serde_json::to_vec(
                &proof_notary.to_tdn_standard_serialized(),
            )?);

            // TDN log
            let signature: Signature = signature.into();
            #[cfg(feature = "tracing")]
            info!(
                notary_proof_signature = ?signature,
                "TDN log: generated notary proof signature; sent through channel 'notarize' later.",
            );
            println!("TDN log: generated notary proof signature; sent through channel 'notarize' later; notary_proof_signature: {:?}", signature);

            notarize_channel
                .send(TdnMessage::NotarizationResult(NotarizationResult {
                    proof_notary: proof_notary.clone(),
                    signature: signature.into(),
                    ciphertext1_priv_key_session_notary,
                }))
                .await?;

            #[cfg(feature = "tracing")]
            info!("Sent session header");

            Ok::<_, TdnVerifierError>(proof_notary)
        };

        let proof_notary = futures::select! {
            res = notarize_fut.fuse() => res?,
            _ = &mut mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        let mut mux_ctrl = mux_ctrl.into_inner();

        futures::try_join!(mux_ctrl.close().map_err(TdnVerifierError::from), mux_fut)?;

        Ok(proof_notary)
    }
}
