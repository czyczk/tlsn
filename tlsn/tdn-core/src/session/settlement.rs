//! Settlement struct for the TDN session.
use serde::{Deserialize, Serialize};

/// Contains the settlement info in this TDN session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settlement {
    /// Notary's settlement address.
    pub settlement_addr_notary: String,
    /// Prover's settlement address.
    pub settlement_addr_prover: String,
}
