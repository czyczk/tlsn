use std::collections::HashMap;

use bimap::BiMap;
use rand::Rng;
use serde::{Deserialize, Serialize};
use utils::range::RangeSet;

use crate::{
    encoding::proof::{EncodingProof, Opening},
    hash::{Hash, HashAlgorithm},
    merkle::MerkleTree,
    transcript::{Subsequence, SubsequenceIdx},
    Direction,
};

/// Encoding tree builder error.
#[derive(Debug, thiserror::Error)]
pub enum EncodingTreeError {
    /// Attempted to commit to an empty range.
    #[error("attempted to commit to an empty range")]
    EmptyRange,
    /// Attempted to commit to a range that exceeds the transcript length.
    #[error(
        "attempted to commit to a range that exceeds the transcript length: \
        {input_end} > {transcript_length}"
    )]
    OutOfBounds {
        /// The end of the input range.
        input_end: usize,
        /// The transcript length.
        transcript_length: usize,
        /// The direction of the transcript.
        direction: Direction,
    },
    /// The encoding provider is missing the encoding for the given range.
    #[error(
        "the encoding provider is missing the encoding for the given range: \
        {direction:?} {ranges:?}"
    )]
    MissingEncoding {
        /// The input ranges.
        ranges: RangeSet<usize>,
        /// The direction of the transcript.
        direction: Direction,
    },
}

/// A leaf in the encoding tree.
pub(crate) struct EncodingLeaf {
    pub(crate) encoding: Vec<u8>,
    pub(crate) nonce: [u8; 16],
}

impl EncodingLeaf {
    pub(super) fn new(encoding: Vec<u8>, nonce: [u8; 16]) -> Self {
        Self { encoding, nonce }
    }
}

/// A merkle tree of transcript encodings.
#[derive(Serialize, Deserialize)]
pub struct EncodingTree {
    /// Merkle tree of the commitments.
    tree: MerkleTree,
    /// Nonces used to blind the hashes.
    nonces: Vec<[u8; 16]>,
    /// Mapping between the index of a leaf and the subsequence it
    /// corresponds to.
    seqs: BiMap<usize, SubsequenceIdx>,
}

opaque_debug::implement!(EncodingTree);

impl EncodingTree {
    pub(crate) fn new(alg: HashAlgorithm) -> Self {
        Self {
            tree: MerkleTree::new(alg),
            nonces: Vec::new(),
            seqs: BiMap::new(),
        }
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    /// Returns the hash algorithm of the tree.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.tree.algorithm()
    }

    pub(super) fn proof(&self, seqs: Vec<(SubsequenceIdx, Vec<u8>)>) -> EncodingProof {
        let mut openings = HashMap::new();
        for (seq, data) in seqs {
            let idx = *self
                .seqs
                .get_by_right(&seq)
                .expect("subsequence is in the tree");
            let nonce = self.nonces[idx];
            openings.insert(
                idx,
                Opening {
                    seq: Subsequence { idx: seq, data },
                    nonce,
                },
            );
        }

        let mut indices = openings.keys().copied().collect::<Vec<_>>();
        indices.sort();
        let inclusion_proof = self.tree.proof(&indices);

        EncodingProof {
            inclusion_proof,
            openings,
        }
    }

    pub(super) fn contains(&self, seq: &SubsequenceIdx) -> bool {
        self.seqs.contains_right(seq)
    }

    pub(super) fn add_leaf(&mut self, seq: SubsequenceIdx, encoding: Vec<u8>) {
        if self.seqs.contains_right(&seq) {
            // The subsequence is already in the tree.
            return;
        }

        let nonce: [u8; 16] = rand::thread_rng().gen();
        let leaf = EncodingLeaf::new(encoding, nonce);

        self.tree.insert(&leaf);
        self.nonces.push(nonce);
        self.seqs.insert(self.seqs.len(), seq);
    }
}
