//! TLS prover states.

use crate::tls::{MuxFuture, OTFuture};
use mpz_core::commit::Decommitment;
use mpz_garble::protocol::deap::{DEAPVm, PeerEncodings};
use mpz_garble_core::{encoding_state, EncodedValue};
use mpz_ot::actor::kos::{SharedReceiver, SharedSender};
use mpz_share_conversion::{ConverterSender, Gf2_128};
use std::collections::HashMap;
use tdn_core::proof::Certificates;
use tls_client::SignatureScheme;
use tls_core::{handshake::HandshakeData, key::PublicKey};
use tls_mpc::MpcTlsLeader;
use tlsn_common::mux::MuxControl;
use tlsn_core::{commitment::TranscriptCommitmentBuilder, Transcript};

/// Entry state
pub struct Initialized;

opaque_debug::implement!(Initialized);

/// State after MPC setup has completed.
pub struct Setup {
    /// A muxer for communication with the Notary
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) mpc_tls: MpcTlsLeader,
    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterSender<Gf2_128, SharedSender>,
}

opaque_debug::implement!(Setup);

/// State after the TLS connection has been closed.
pub struct Closed {
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterSender<Gf2_128, SharedSender>,

    pub(crate) start_time: u64,
    pub(crate) handshake_decommitment: Decommitment<HandshakeData>,
    pub(crate) server_public_key: PublicKey,

    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,
}

opaque_debug::implement!(Closed);

/// State after the TLS connection has been closed. Based on [Closed] but contains additional necessary info in TDN mode.
pub struct TdnClosed {
    pub(crate) closed: Closed,

    pub(crate) random_client: [u8; 32],
    pub(crate) random_server: [u8; 32],

    pub(crate) pub_key_session_notary: PublicKey,
    pub(crate) pub_key_session_prover: PublicKey,
    pub(crate) curve_params: Vec<u8>,
    pub(crate) sig_scheme_server: SignatureScheme,
    pub(crate) sig_kx_server: Vec<u8>,
    pub(crate) certificates_server: Certificates,
    pub(crate) ciphertext_application_data_server: Vec<u8>,
}

opaque_debug::implement!(TdnClosed);

/// Notarizing state.
pub struct Notarize {
    /// A muxer for communication with the Notary
    pub(crate) mux_ctrl: MuxControl,
    pub(crate) mux_fut: MuxFuture,

    pub(crate) vm: DEAPVm<SharedSender, SharedReceiver>,
    pub(crate) ot_fut: OTFuture,
    pub(crate) gf2: ConverterSender<Gf2_128, SharedSender>,

    pub(crate) start_time: u64,
    pub(crate) handshake_decommitment: Decommitment<HandshakeData>,
    pub(crate) server_public_key: PublicKey,

    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,

    pub(crate) builder: TranscriptCommitmentBuilder,

    pub(crate) pub_key_session_prover: PublicKey,
    pub(crate) certificates_server: Certificates,
}

opaque_debug::implement!(Notarize);

impl From<TdnClosed> for Notarize {
    fn from(state: TdnClosed) -> Self {
        let encodings = collect_encodings(
            &state.closed.vm,
            &state.closed.transcript_tx,
            &state.closed.transcript_rx,
        );

        let encoding_provider = Box::new(move |ids: &[&str]| {
            ids.iter().map(|id| encodings.get(*id).cloned()).collect()
        });

        let builder = TranscriptCommitmentBuilder::new(
            encoding_provider,
            state.closed.transcript_tx.data().len(),
            state.closed.transcript_rx.data().len(),
        );

        Self {
            mux_ctrl: state.closed.mux_ctrl,
            mux_fut: state.closed.mux_fut,
            vm: state.closed.vm,
            ot_fut: state.closed.ot_fut,
            gf2: state.closed.gf2,
            start_time: state.closed.start_time,
            handshake_decommitment: state.closed.handshake_decommitment,
            server_public_key: state.closed.server_public_key,
            transcript_tx: state.closed.transcript_tx,
            transcript_rx: state.closed.transcript_rx,
            builder,
            pub_key_session_prover: state.pub_key_session_prover,
            certificates_server: state.certificates_server,
        }
    }
}

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl ProverState for Setup {}
impl ProverState for Closed {}
impl ProverState for TdnClosed {}
impl ProverState for Notarize {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Setup {}
    impl Sealed for super::Closed {}
    impl Sealed for super::TdnClosed {}
    impl Sealed for super::Notarize {}
}

fn collect_encodings(
    vm: &DEAPVm<SharedSender, SharedReceiver>,
    transcript_tx: &Transcript,
    transcript_rx: &Transcript,
) -> HashMap<String, EncodedValue<encoding_state::Active>> {
    let tx_ids = (0..transcript_tx.data().len()).map(|id| format!("tx/{id}"));
    let rx_ids = (0..transcript_rx.data().len()).map(|id| format!("rx/{id}"));

    let ids = tx_ids.chain(rx_ids).collect::<Vec<_>>();
    let id_refs = ids.iter().map(|id| id.as_ref()).collect::<Vec<_>>();

    vm.get_peer_encodings(&id_refs)
        .expect("encodings for all transcript values should be present")
        .into_iter()
        .zip(ids)
        .map(|(encoding, id)| (id, encoding))
        .collect()
}
