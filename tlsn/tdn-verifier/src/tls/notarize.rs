//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier is only a notary.

use super::{state::Closed, TdnVerifier, TdnVerifierError};
use base64::{prelude::BASE64_STANDARD, Engine};
use futures::{FutureExt, SinkExt, StreamExt, TryFutureExt};
use mpz_core::serialize::CanonicalSerialize;
use signature::Signer;
use tlsn_core::{
    msg::{SignedSessionHeader, TlsnMessage},
    HandshakeSummary, SessionHeader, Signature,
};
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

#[cfg(feature = "tracing")]
use tracing::info;

impl TdnVerifier<Closed> {
    /// Notarizes the TLS session.
    pub async fn finalize<T>(
        self,
        signer: &impl Signer<T>,
    ) -> Result<SessionHeader, TdnVerifierError>
    where
        T: Into<Signature>,
    {
        // TDN log
        tracing::info!("TdnVerifier::finalize()");

        let Closed {
            mut mux_ctrl,
            mut mux_fut,
            ot_send,
            ot_recv,
            ot_fut,
            encoder_seed,
            start_time,
            server_ephemeral_key,
            handshake_commitment,
            sent_len,
            recv_len,
            ..
        } = self.state;

        let notarize_fut = async {
            let mut notarize_channel = mux_ctrl.get_channel("notarize").await?;

            let merkle_root =
                expect_msg_or_err!(notarize_channel, TlsnMessage::TranscriptCommitmentRoot)?;

            // Finalize all MPC before signing the session header
            let (mut ot_sender_actor, _, _) = futures::try_join!(
                ot_fut,
                ot_send.shutdown().map_err(TdnVerifierError::from),
                ot_recv.shutdown().map_err(TdnVerifierError::from)
            )?;

            ot_sender_actor.reveal().await?;

            // TDN log
            {
                let encoder_seed_base64 = BASE64_STANDARD.encode(encoder_seed);
                let merkle_root_base64 = BASE64_STANDARD.encode(merkle_root.to_bytes());
                let server_ephemeral_key_json = serde_json::json!({
                        "group": server_ephemeral_key.group,
                        "key": BASE64_STANDARD.encode(server_ephemeral_key.key.to_bytes()),
                });
                let handshake_commitment_base64 =
                    BASE64_STANDARD.encode(handshake_commitment.to_bytes());
                info!(
                    encoder_seed_existing = %encoder_seed_base64,
                    merkle_root = %merkle_root_base64,
                    start_time_existing = %start_time,
                    server_ephemeral_key_existing = ?server_ephemeral_key_json,
                    handshake_commitment_existing = ?handshake_commitment_base64,
                    "TDN log: MPC finalize; got merkle root; handshake summary = start time + server ephemeral key + handshake commitment; session header = encoder seed + merkle root + handshake summary.",
                );
            }

            #[cfg(feature = "tracing")]
            info!("Finalized all MPC");

            let handshake_summary =
                HandshakeSummary::new(start_time, server_ephemeral_key, handshake_commitment);

            let session_header = SessionHeader::new(
                encoder_seed,
                merkle_root,
                sent_len,
                recv_len,
                handshake_summary,
            );

            let signature = signer.sign(&session_header.to_bytes());

            // TDN log
            let signature: Signature = signature.into();
            info!(
                session_header_signature = ?signature,
                "TDN log: MPC finalize; generated session hander signature; sent through io later.",
            );

            #[cfg(feature = "tracing")]
            info!("Signed session header");

            notarize_channel
                .send(TlsnMessage::SignedSessionHeader(SignedSessionHeader {
                    header: session_header.clone(),
                    signature: signature.into(),
                }))
                .await?;

            #[cfg(feature = "tracing")]
            info!("Sent session header");

            Ok::<_, TdnVerifierError>(session_header)
        };

        let session_header = futures::select! {
            res = notarize_fut.fuse() => res?,
            _ = &mut mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        let mut mux_ctrl = mux_ctrl.into_inner();

        futures::try_join!(mux_ctrl.close().map_err(TdnVerifierError::from), mux_fut)?;

        Ok(session_header)
    }
}
