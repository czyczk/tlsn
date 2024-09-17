//! TLS Verifier

pub(crate) mod config;
mod error;
mod future;
mod notarize;
pub mod state;

use base64::{prelude::BASE64_STANDARD, Engine};
pub use config::{TdnVerifierConfig, TdnVerifierConfigBuilder, TdnVerifierConfigBuilderError};
pub use error::TdnVerifierError;
use mpz_core::serialize::CanonicalSerialize;
use tdn_core::session::{TdnSessionData, TdnSessionId};

use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex as AsyncMutex;

use crate::tls::future::OTFuture;
use future::MuxFuture;
use futures::{
    stream::{SplitSink, SplitStream},
    AsyncRead, AsyncWrite, FutureExt, StreamExt, TryFutureExt,
};
use mpz_garble::{config::Role as GarbleRole, protocol::deap::DEAPVm};
use mpz_ot::{
    actor::kos::{
        msgs::Message as ActorMessage, ReceiverActor, SenderActor, SharedReceiver, SharedSender,
    },
    chou_orlandi, kos,
};
use mpz_share_conversion as ff;
use rand::Rng;
use signature::Signer;
use tls_mpc::{setup_components, MpcTlsFollower, MpcTlsFollowerData, TlsRole};
use tlsn_common::{
    mux::{attach_mux, MuxControl},
    Role,
};
use tlsn_core::{SessionHeader, Signature};
use utils_aio::{duplex::Duplex, mux::MuxChannel};

#[cfg(feature = "tracing")]
use tracing::{debug, info, instrument};

type OTSenderActor = SenderActor<
    chou_orlandi::Receiver,
    SplitSink<
        Box<dyn Duplex<ActorMessage<chou_orlandi::msgs::Message>>>,
        ActorMessage<chou_orlandi::msgs::Message>,
    >,
    SplitStream<Box<dyn Duplex<ActorMessage<chou_orlandi::msgs::Message>>>>,
>;

/// A Verifier instance.
pub struct TdnVerifier<T: state::VerifierState> {
    config: TdnVerifierConfig,
    state: T,
}

impl TdnVerifier<state::Initialized> {
    /// Create a new verifier.
    pub fn new(config: TdnVerifierConfig) -> Self {
        Self {
            config,
            state: state::Initialized,
        }
    }

    /// Set up the verifier.
    ///
    /// This performs all MPC setup.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the prover.
    pub async fn setup<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<TdnVerifier<state::Setup>, TdnVerifierError> {
        let (mut mux, mux_ctrl) = attach_mux(socket, Role::Verifier);

        let mut mux_fut = MuxFuture {
            fut: Box::pin(async move { mux.run().await.map_err(TdnVerifierError::from) }.fuse()),
        };

        let encoder_seed: [u8; 32] = rand::rngs::OsRng.gen();

        // TDN log
        {
            let encoder_seed_base64 = BASE64_STANDARD.encode(&encoder_seed);
            println!(
                "TDN log: MPC setup: encoder seed generated. encoder_seed={}",
                encoder_seed_base64
            );
        }

        let mpc_setup_fut = setup_mpc_backend(&self.config, mux_ctrl.clone(), encoder_seed);
        let (mpc_tls, vm, ot_send, ot_recv, gf2, ot_fut) = futures::select! {
            res = mpc_setup_fut.fuse() => res?,
            _ = &mut mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        Ok(TdnVerifier {
            config: self.config,
            state: state::Setup {
                mux_ctrl,
                mux_fut,
                mpc_tls,
                vm,
                ot_send,
                ot_recv,
                ot_fut,
                gf2,
                encoder_seed,
            },
        })
    }

    /// Runs the TLS verifier to completion, notarizing the TLS session.
    ///
    /// This is a convenience method which runs all the steps needed for notarization.
    pub async fn collect<S: AsyncWrite + AsyncRead + Send + Unpin + 'static, T>(
        self,
        socket: S,
        signer: &impl Signer<T>,
        tdn_store: Arc<AsyncMutex<HashMap<String, TdnSessionData>>>,
    ) -> Result<SessionHeader, TdnVerifierError>
    where
        T: Into<Signature>,
    {
        self.setup(socket)
            .await?
            .run(tdn_store)
            .await?
            .finalize(signer)
            .await
    }
}

impl TdnVerifier<state::Setup> {
    /// Runs the verifier until the TLS connection is closed.
    pub async fn run(
        self,
        tdn_store: Arc<AsyncMutex<HashMap<String, TdnSessionData>>>,
    ) -> Result<TdnVerifier<state::Closed>, TdnVerifierError> {
        // TDN log
        println!("TDN log: TdnVerifider::run()");

        let state::Setup {
            mux_ctrl,
            mut mux_fut,
            mpc_tls,
            vm,
            ot_send,
            ot_recv,
            mut ot_fut,
            gf2,
            encoder_seed,
        } = self.state;

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (_, mpc_fut) = mpc_tls.run();

        let MpcTlsFollowerData {
            handshake_commitment,
            server_key: server_ephemeral_key,
            bytes_sent: sent_len,
            bytes_recv: recv_len,
            random_client,
            random_server,
            priv_key_session_notary,
            ciphertext_application_data_server,
        } = futures::select! {
            res = mpc_fut.fuse() => res?,
            _ = &mut mux_fut => {
                println!("TDN log: Here! I got you! mux_fut ends immaturally. UnexpectedEof");
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?
            }
            res = ot_fut => return Err(res.map(|_| ()).expect_err("future will not return Ok here"))
        };

        let random_client = random_client.expect("random client is not set");
        let random_server = random_server.expect("random server is not set");
        let priv_key_session_notary =
            priv_key_session_notary.expect("notary private key is not set");
        let ciphertext_application_data_server = ciphertext_application_data_server
            .expect("server application data ciphertext is not set");

        // TDN log
        {
            let handshake_commitment_base64 =
                handshake_commitment.map(|it| BASE64_STANDARD.encode(it.clone().to_bytes()));
            let server_key_json = serde_json::json!({
                "group": server_ephemeral_key.group,
                "key": BASE64_STANDARD.encode(server_ephemeral_key.key.to_bytes()),
            });
            println!(
                "TDN log: MPC run (MpcTlsFollowerData). handshake_commitment={:?}; server_key={}",
                handshake_commitment_base64, server_key_json,
            );
        }

        #[cfg(feature = "tracing")]
        info!("Finished TLS session");

        println!("Finished TLS session");

        // TODO: We should be able to skip this commitment and verify the handshake directly.
        let handshake_commitment = handshake_commitment.expect("handshake commitment is set");

        // Persist the TDN session data in TDN mode.
        let tdn_session_data = TdnSessionData {
            session_id: TdnSessionId::new(random_client.clone(), random_server.clone()),
            random_client,
            random_server,
            priv_key_session_notary,
            ciphertext_application_data_server,
            commitment_handshake: handshake_commitment.as_bytes().to_vec(),
        };
        tdn_store.lock().await.insert(
            tdn_session_data.session_id.to_base64_concat(),
            tdn_session_data.clone(),
        );

        // TDN log
        println!("TDN log: TDN session data stored");

        Ok(TdnVerifier {
            config: self.config,
            state: state::Closed {
                mux_ctrl,
                mux_fut,
                vm,
                ot_send,
                ot_recv,
                ot_fut,
                gf2,
                encoder_seed,
                start_time,
                server_ephemeral_key,
                handshake_commitment,
                sent_len,
                recv_len,
            },
        })
    }
}

impl TdnVerifier<state::Closed> {}

/// Performs a setup of the various MPC subprotocols.
#[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
#[allow(clippy::type_complexity)]
async fn setup_mpc_backend(
    config: &TdnVerifierConfig,
    mut mux_ctrl: MuxControl,
    encoder_seed: [u8; 32],
) -> Result<
    (
        MpcTlsFollower,
        DEAPVm<SharedSender, SharedReceiver>,
        SharedSender,
        SharedReceiver,
        ff::ConverterReceiver<ff::Gf2_128, SharedReceiver>,
        OTFuture,
    ),
    TdnVerifierError,
> {
    let (ot_send_sink, ot_send_stream) = mux_ctrl.get_channel("ot/1").await?.split();
    let (ot_recv_sink, ot_recv_stream) = mux_ctrl.get_channel("ot/0").await?.split();

    let mut ot_sender_actor = OTSenderActor::new(
        kos::Sender::new(
            config.build_ot_sender_config(),
            chou_orlandi::Receiver::new(config.build_base_ot_receiver_config()),
        ),
        ot_send_sink,
        ot_send_stream,
    );

    let mut ot_receiver_actor = ReceiverActor::new(
        kos::Receiver::new(
            config.build_ot_receiver_config(),
            chou_orlandi::Sender::new(config.build_base_ot_sender_config()),
        ),
        ot_recv_sink,
        ot_recv_stream,
    );

    let ot_send = ot_sender_actor.sender();
    let ot_recv = ot_receiver_actor.receiver();

    #[cfg(feature = "tracing")]
    debug!("Starting OT setup");

    futures::try_join!(
        ot_sender_actor
            .setup(config.ot_sender_setup_count())
            .map_err(TdnVerifierError::from),
        ot_receiver_actor
            .setup(config.ot_receiver_setup_count())
            .map_err(TdnVerifierError::from)
    )?;

    #[cfg(feature = "tracing")]
    debug!("OT setup complete");

    let ot_fut = OTFuture {
        fut: Box::pin(
            async move {
                futures::try_join!(
                    ot_sender_actor.run().map_err(TdnVerifierError::from),
                    ot_receiver_actor.run().map_err(TdnVerifierError::from)
                )?;

                Ok(ot_sender_actor)
            }
            .fuse(),
        ),
    };

    let mut vm = DEAPVm::new(
        "vm",
        GarbleRole::Follower,
        encoder_seed,
        mux_ctrl.get_channel("vm").await?,
        Box::new(mux_ctrl.clone()),
        ot_send.clone(),
        ot_recv.clone(),
    );

    let p256_sender_config = config.build_p256_sender_config();
    let channel = mux_ctrl.get_channel(p256_sender_config.id()).await?;
    let p256_send =
        ff::ConverterSender::<ff::P256, _>::new(p256_sender_config, ot_send.clone(), channel);

    let p256_receiver_config = config.build_p256_receiver_config();
    let channel = mux_ctrl.get_channel(p256_receiver_config.id()).await?;
    let p256_recv =
        ff::ConverterReceiver::<ff::P256, _>::new(p256_receiver_config, ot_recv.clone(), channel);

    let gf2_config = config.build_gf2_config();
    let channel = mux_ctrl.get_channel(gf2_config.id()).await?;
    let gf2 = ff::ConverterReceiver::<ff::Gf2_128, _>::new(gf2_config, ot_recv.clone(), channel);

    let mpc_tls_config = config.build_mpc_tls_config();

    let (ke, prf, encrypter, decrypter) = setup_components(
        mpc_tls_config.common(),
        TlsRole::Follower,
        &mut mux_ctrl,
        &mut vm,
        p256_send,
        p256_recv,
        gf2.handle()
            .map_err(|e| TdnVerifierError::MpcError(Box::new(e)))?,
    )
    .await
    .map_err(|e| TdnVerifierError::MpcError(Box::new(e)))?;

    let channel = mux_ctrl.get_channel(mpc_tls_config.common().id()).await?;
    let mut mpc_tls = MpcTlsFollower::new(mpc_tls_config, channel, ke, prf, encrypter, decrypter);

    mpc_tls.setup().await?;

    #[cfg(feature = "tracing")]
    debug!("MPC backend setup complete");

    Ok((mpc_tls, vm, ot_send, ot_recv, gf2, ot_fut))
}
