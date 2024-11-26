// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Observable;
use async_trait::async_trait;
use ethers::providers::Provider;
use ethers::types::{Address as EthAddress, U256};
use prometheus::IntGauge;
use std::sync::Arc;
use sui_bridge::abi::EthERC20;
use sui_bridge::metered_eth_provider::MeteredEthHttpProvier;
use tokio::time::Duration;
use tracing::{error, info};

#[derive(Debug)]
pub enum VaultAsset {
    WETH,
    USDT,
}

pub struct EthereumVaultBalance {
    coin_contract: EthERC20<Provider<MeteredEthHttpProvier>>,
    asset: VaultAsset,
    decimals: u8,
    vault_address: EthAddress,
    metric: IntGauge,
}

impl EthereumVaultBalance {
    pub fn new(
        provider: Arc<Provider<MeteredEthHttpProvier>>,
        vault_address: EthAddress,
        coin_address: EthAddress, // for now this only support one coin which is WETH
        asset: VaultAsset,
        metric: IntGauge,
    ) -> anyhow::Result<Self> {
        let coin_contract = EthERC20::new(coin_address, provider);
        let decimals = coin_contract
            .decimals()
            .call()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get decimals from token contract: {e}"))?;
        Ok(Self {
            coin_contract,
            vault_address,
            decimals,
            asset,
            metric,
        })
    }
}

#[async_trait]
impl Observable for EthereumVaultBalance {
    fn name(&self) -> &str {
        "EthereumVaultBalance"
    }

    async fn observe_and_report(&self) {
        match self
            .coin_contract
            .balance_of(self.vault_address)
            .call()
            .await
        {
            Ok(balance) => {
                // Why downcasting is safe:
                // 1. On Ethereum we only take the first 8 decimals into account,
                // meaning the trailing 10 digits can be ignored. For other assets,
                // we will also assume this max level of precision for metrics purposes.
                // 2. i64::MAX is 9_223_372_036_854_775_807, with 8 decimal places is
                // 92_233_720_368. We likely won't see any balance higher than this
                // in the next 12 months.
                // For USDT, for example, this will be 10^6 - 8 = 10^(-2) = 0.01,
                // therefore we will add 2 zeroes of precision.
                let denom = U256::from(10).pow(self.decimals - 8);
                let normalized_balance = (balance / denom).as_u64() as i64;
                self.metric.set(normalized_balance);
                info!(
                    "{:?} Vault Balance: {:?} ({:?} {:?})",
                    self.asset, balance, normalized_balance, self.asset,
                );
            }
            Err(e) => {
                error!("Error getting balance from vault: {:?}", e);
            }
        }
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(10)
    }
}
