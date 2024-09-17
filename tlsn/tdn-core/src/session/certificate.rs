//! Certificate chain info from the server in this TDN session.

use serde::{Deserialize, Serialize};
use tls_core::key::Certificate;

/// Contains the certificates in this TDN session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificates {
    /// The current certificate of the server.
    pub end_entity: Certificate,
    /// The intermediate certificates on the path to the root certificate.
    pub intermediates: Vec<Certificate>,
}
