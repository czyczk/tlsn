//! This module handles the notarization phase of the prover.
//!
//! The prover deals with a TLS verifier that is only a notary.

use crate::tls::error::OTShutdownError;

use super::{ff::ShareConversionReveal, state::Notarize, ProverError, TdnProver};
use futures::{FutureExt, SinkExt, StreamExt};
use tdn_core::{
    msg::{NotarizationResult, TdnMessage},
    proof::SignedProofNotary,
};
use tls_core::{key::PublicKey, msgs::enums::NamedGroup};
use tlsn_core::{commitment::TranscriptCommitmentBuilder, transcript::Transcript};
#[cfg(feature = "tracing")]
use tracing::{info, instrument};
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

impl TdnProver<Notarize> {
    /// Returns the transcript of the sent requests
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    /// Returns the transcript of the received responses
    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    /// Returns the transcript commitment builder
    pub fn commitment_builder(&mut self) -> &mut TranscriptCommitmentBuilder {
        &mut self.state.builder
    }

    /// Start the notarization process, returning a [`NotarizedSession`]
    #[cfg_attr(feature = "tracing", instrument(level = "info", skip(self), err))]
    pub async fn notarize(
        self,
        commitment_pwd_proof: Vec<u8>,
        pub_key_consumer: Vec<u8>,
    ) -> Result<SignedProofNotary, ProverError> {
        let Notarize {
            mut mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_fut,
            mut gf2,
            start_time,
            handshake_decommitment,
            server_public_key,
            builder,
            pub_key_session_prover,
            certificates_server,
            ..
        } = self.state;

        let mut notarize_fut = Box::pin(async move {
            let mut channel = mux_ctrl.get_channel("notarize").await?;

            // TDN log
            #[cfg(feature = "tracing")]
            info!("TDN log: P-send->N: TdnMessage::CommitmentPwdProof");

            channel
                .send(TdnMessage::CommitmentPwdProof(commitment_pwd_proof))
                .await?;

            // TDN log
            #[cfg(feature = "tracing")]
            info!("TDN log: P-send->N: TdnMessage::PubKeyConsumer");

            let pub_key_consumer = PublicKey::new(NamedGroup::secp256r1, &pub_key_consumer);
            channel
                .send(TdnMessage::PubKeyConsumer(pub_key_consumer))
                .await?;

            // TDN log
            #[cfg(feature = "tracing")]
            info!("TDN log: P-send->N: TdnMessage::PubKeySessionProver");

            channel
                .send(TdnMessage::PubKeySessionProver(pub_key_session_prover))
                .await?;

            // TDN log
            #[cfg(feature = "tracing")]
            info!("TDN log: P-send->N: TdnMessage::Certificates");

            channel
                .send(TdnMessage::Certificates(certificates_server))
                .await?;

            // TDN TODO: Whether this can be skipped?
            // This is a temporary approach until a maliciously secure share conversion protocol is implemented.
            // The prover is essentially revealing the TLS MAC key. In some exotic scenarios this allows a malicious
            // TLS verifier to modify the prover's request.
            gf2.reveal()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?;

            let notarization_result = expect_msg_or_err!(channel, TdnMessage::NotarizationResult)?;

            Ok::<_, ProverError>(notarization_result)
        })
        .fuse();

        // TDN log
        #[cfg(feature = "tracing")]
        info!("TDN log: Waiting for notarization result.");

        let NotarizationResult {
            proof_notary,
            signature,
        } = futures::select_biased! {
            res = notarize_fut => res?,
            _ = ot_fut => return Err(OTShutdownError)?,
            _ = &mut mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };
        // Wait for the notary to correctly close the connection
        mux_fut.await?;

        Ok(SignedProofNotary {
            proof_notary,
            signature,
        })
    }
}
