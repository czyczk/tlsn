use crate::{CtrCircuit, KeyStream, StreamCipherError};
use async_trait::async_trait;
use mpz_circuits::Circuit;
use mpz_garble::{value::ValueRef, Decode, DecodePrivate, Execute, Load, Thread};
use std::{collections::VecDeque, marker::PhantomData, sync::Arc};
use tracing::instrument;
use utils::id::NestedId;

pub(crate) struct MpcKeyStream<C, E> {
    thread: E,
    key: Option<ValueRef>,
    iv: Option<ValueRef>,
    block_counter: NestedId,
    preprocessed: BlockVars,
    _pd: PhantomData<C>,
}

impl<C, E> MpcKeyStream<C, E>
where
    C: CtrCircuit,
    E: Thread + Load + Execute + Decode + DecodePrivate + Send + Sync,
{
    pub(crate) fn new(id: &str, thread: E) -> Self {
        let block_counter = NestedId::new(id).append_counter();
        Self {
            key: None,
            iv: None,
            thread,
            block_counter,
            preprocessed: BlockVars::default(),
            _pd: PhantomData,
        }
    }

    fn key(&self) -> Result<ValueRef, StreamCipherError> {
        self.key
            .clone()
            .ok_or_else(|| StreamCipherError::key_not_set())
    }

    fn iv(&self) -> Result<ValueRef, StreamCipherError> {
        self.iv
            .clone()
            .ok_or_else(|| StreamCipherError::key_not_set())
    }

    async fn preprocess_shared(&mut self, len: usize) -> Result<(), StreamCipherError> {}

    async fn preprocess(&mut self, len: usize) -> Result<(), StreamCipherError> {
        self.preprocess_for(C::circuit(), len).await
    }

    async fn preprocess_for(
        &mut self,
        circuit: Arc<Circuit>,
        len: usize,
    ) -> Result<(), StreamCipherError> {
        let key = self.key()?;
        let iv = self.iv()?;

        let block_count = (len / C::BLOCK_LEN) + (len % C::BLOCK_LEN != 0) as usize;
        let vars = self.define_vars(block_count, circuit)?;

        let calls = vars
            .iter()
            .map(|(circuit, block, nonce, ctr)| {
                (
                    circuit,
                    vec![key.clone(), iv.clone(), nonce.clone(), ctr.clone()],
                    vec![block.clone()],
                )
            })
            .collect::<Vec<_>>();

        for (circ, inputs, outputs) in calls {
            self.thread.load(circ.clone(), &inputs, &outputs).await?;
        }

        self.preprocessed.extend(vars);

        Ok(())
    }

    fn define_vars(
        &mut self,
        count: usize,
        circuit: Arc<Circuit>,
    ) -> Result<BlockVars, StreamCipherError> {
        let mut vars = BlockVars::default();
        for _ in 0..count {
            let block_id = self.block_counter.increment_in_place();
            let block = self.thread.new_output::<C::BLOCK>(&block_id.to_string())?;
            let nonce = self
                .thread
                .new_public_input::<C::NONCE>(&block_id.append_string("nonce").to_string())?;
            let ctr = self
                .thread
                .new_public_input::<[u8; 4]>(&block_id.append_string("ctr").to_string())?;

            vars.circuits.push_back(circuit.clone());
            vars.blocks.push_back(block);
            vars.nonces.push_back(nonce);
            vars.ctrs.push_back(ctr);
        }

        Ok(vars)
    }
}

#[async_trait]
impl<C, E> KeyStream for MpcKeyStream<C, E>
where
    C: CtrCircuit,
    E: Thread + Load + Execute + Decode + DecodePrivate + Send + Sync,
{
    fn set_key_and_iv(&mut self, key: ValueRef, iv: ValueRef) {
        self.key = Some(key);
        self.iv = Some(iv);
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn preprocess(&mut self, len: usize) -> Result<(), StreamCipherError> {
        let key = self.key()?;
        let iv = self.iv()?;

        let block_count = (len / C::BLOCK_LEN) + (len % C::BLOCK_LEN != 0) as usize;
        let vars = self.define_vars(block_count)?;

        let calls = vars
            .iter()
            .map(|(circuit, block, nonce, ctr)| {
                (
                    circuit,
                    vec![key.clone(), iv.clone(), nonce.clone(), ctr.clone()],
                    vec![block.clone()],
                )
            })
            .collect::<Vec<_>>();

        for (circ, inputs, outputs) in calls {
            self.thread.load(circ.clone(), &inputs, &outputs).await?;
        }

        self.preprocessed.extend(vars);

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn setup_keystream(
        &mut self,
        explicit_nonce: Vec<u8>,
        start_ctr: usize,
        len: usize,
    ) -> Result<ValueRef, StreamCipherError> {
        let key = self.key()?;
        let iv = self.iv()?;

        let block_count = (len / C::BLOCK_LEN) + (len % C::BLOCK_LEN != 0) as usize;
        let explicit_nonce_len = explicit_nonce.len();
        let explicit_nonce: C::NONCE = explicit_nonce
            .try_into()
            .map_err(|_| StreamCipherError::explicit_nonce_len::<C>(explicit_nonce_len))?;

        // Take any preprocessed blocks if available, and define new ones if needed.
        let vars = if !self.preprocessed.is_empty() {
            let mut vars = self
                .preprocessed
                .drain(block_count.min(self.preprocessed.len()));
            if vars.len() < block_count {
                vars.extend(self.define_vars(block_count - vars.len())?)
            }
            vars
        } else {
            self.define_vars(block_count)?
        };

        let mut calls = Vec::with_capacity(vars.len());
        let mut inputs = Vec::with_capacity(vars.len() * 4);
        for (i, (_, block, nonce_ref, ctr_ref)) in vars.iter().enumerate() {
            self.thread.assign(nonce_ref, explicit_nonce)?;
            self.thread
                .assign(ctr_ref, ((start_ctr + i) as u32).to_be_bytes())?;

            inputs.push(key.clone());
            inputs.push(iv.clone());
            inputs.push(nonce_ref.clone());
            inputs.push(ctr_ref.clone());

            // TODO: Circuit should not be part of this.
            calls.push((
                C::circuit(),
                vec![key.clone(), iv.clone(), nonce_ref.clone(), ctr_ref.clone()],
                vec![block.clone()],
            ));
        }

        let keystream = self.thread.array_from_values(&vars.blocks(len))?;
        // TODO: We need to return more here than just the keysteam, if we want to separate the
        // execution.
        Ok(keystream)
    }

    async fn share_zero_block(
        &mut self,
        explicit_nonce: Vec<u8>,
        ctr: usize,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let keystream = self.setup_keystream(explicit_nonce, 1, 1).await?;
        todo!()
    }
}

#[derive(Default)]
struct BlockVars {
    circuits: VecDeque<Arc<Circuit>>,
    nonces: VecDeque<ValueRef>,
    ctrs: VecDeque<ValueRef>,
    blocks: VecDeque<ValueRef>,
}

impl BlockVars {
    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn len(&self) -> usize {
        self.blocks.len()
    }

    fn drain(&mut self, count: usize) -> BlockVars {
        let circuits = self.circuits.drain(0..count).collect();
        let nonces = self.nonces.drain(0..count).collect();
        let ctrs = self.ctrs.drain(0..count).collect();
        let blocks = self.blocks.drain(0..count).collect();

        BlockVars {
            circuits,
            nonces,
            ctrs,
            blocks,
        }
    }

    fn extend(&mut self, vars: BlockVars) {
        self.circuits.extend(vars.circuits);
        self.blocks.extend(vars.blocks);
        self.nonces.extend(vars.nonces);
        self.ctrs.extend(vars.ctrs);
    }

    fn iter(&self) -> impl Iterator<Item = (&Arc<Circuit>, &ValueRef, &ValueRef, &ValueRef)> {
        self.circuits
            .iter()
            .zip(self.nonces.iter())
            .zip(self.ctrs.iter())
            .zip(self.blocks.iter())
            .map(|(((circuit, block), nonce), ctr)| (circuit, block, nonce, ctr))
    }

    fn blocks(&self, len: usize) -> Vec<ValueRef> {
        self.blocks
            .iter()
            .flat_map(|block| block.iter())
            .cloned()
            .take(len)
            .map(|byte| ValueRef::Value { id: byte })
            .collect()
    }
}
