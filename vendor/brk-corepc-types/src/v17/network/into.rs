// SPDX-License-Identifier: CC0-1.0

use super::error::GetNetworkInfoError;
use super::{GetNetworkInfo, GetNetworkInfoAddress, GetNetworkInfoNetwork};
use crate::model;

impl GetNetworkInfo {
    /// Converts version specific type to a version nonspecific, more strongly typed type.
    pub fn into_model(self) -> Result<model::GetNetworkInfo, GetNetworkInfoError> {
        use GetNetworkInfoError as E;

        let relay_fee = crate::btc_per_kb(self.relay_fee).map_err(E::RelayFee)?;
        let incremental_fee = crate::btc_per_kb(self.incremental_fee).map_err(E::IncrementalFee)?;

        Ok(model::GetNetworkInfo {
            version: self.version,
            subversion: self.subversion,
            protocol_version: self.protocol_version,
            local_services: self.local_services,
            local_services_names: None,
            local_relay: self.local_relay,
            time_offset: self.time_offset,
            connections: self.connections,
            connections_in: None,
            connections_out: None,
            network_active: self.network_active,
            networks: self.networks.into_iter().map(|n| n.into_model()).collect(),
            relay_fee,
            incremental_fee,
            local_addresses: self.local_addresses.into_iter().map(|a| a.into_model()).collect(),
            warnings: vec![self.warnings],
        })
    }
}

impl GetNetworkInfoNetwork {
    /// Converts version specific type to a version nonspecific, more strongly typed type.
    pub fn into_model(self) -> model::GetNetworkInfoNetwork {
        model::GetNetworkInfoNetwork {
            name: self.name,
            limited: self.limited,
            reachable: self.reachable,
            proxy: self.proxy,
            proxy_randomize_credentials: self.proxy_randomize_credentials,
        }
    }
}

impl GetNetworkInfoAddress {
    /// Converts version specific type to a version nonspecific, more strongly typed type.
    pub fn into_model(self) -> model::GetNetworkInfoAddress {
        model::GetNetworkInfoAddress { address: self.address, port: self.port, score: self.score }
    }
}
