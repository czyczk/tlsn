//! ABI encoding extension.

use alloy::dyn_abi::DynSolValue;

use crate::{Error, ToAbiEncodable};

use super::TdnSessionId;

impl ToAbiEncodable for TdnSessionId {
    fn to_abi_encodable(&self) -> Result<DynSolValue, Error> {
        let random_client: [u8; 32] = self.random_client.clone().try_into().map_err(|_| {
            Error::AbiSerializationError("Failed to treat random_client as [u8; 32]".to_owned())
        })?;
        let random_server: [u8; 32] = self.random_server.clone().try_into().map_err(|_| {
            Error::AbiSerializationError("Failed to treat random_server as [u8; 32]".to_owned())
        })?;
        Ok(DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(random_client.into(), 32),
            DynSolValue::FixedBytes(random_server.into(), 32),
        ]))
    }
}
