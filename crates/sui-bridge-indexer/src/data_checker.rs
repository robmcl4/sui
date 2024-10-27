// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use clap::Parser;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, TextExpressionMethods};
use diesel_async::RunQueryDsl;
use mysten_metrics::start_prometheus_server;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use strum_macros::Display;
use sui_bridge::metrics::BridgeMetrics;
use sui_bridge::sui_client::SuiBridgeClient;
use sui_bridge_indexer::config::IndexerConfig;
use sui_bridge_indexer::postgres_manager::{get_connection_pool, PgPool};
use sui_bridge_indexer::schema;
use sui_bridge_indexer::schema::data_audits::dsl::data_audits;
use sui_config::Config;
use tracing::info;

#[derive(Parser, Clone, Debug)]
struct Args {
    /// Path to a yaml config
    #[clap(long, short)]
    config_path: Option<PathBuf>,
}
struct TokenTransferCheckerTask {
    status: TaskStatus,
    from_nonce: u64,
    to_nonce: u64,
    start_time: u64,
    end_time: u64,
}
#[derive(Display, Debug)]
enum TaskStatus {
    NEW,
    RUNNING,
    FINISHED,
    FAILED,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_env()
        .init();

    let args = Args::parse();

    // load config
    let config_path = if let Some(path) = args.config_path {
        path
    } else {
        env::current_dir()
            .expect("Couldn't get current directory")
            .join("config.yaml")
    };
    let config = <IndexerConfig as Config>::load(&config_path)?;

    // Init metrics server
    let metrics_address =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), config.metric_port);
    let registry_service = start_prometheus_server(metrics_address);
    let registry = registry_service.default_registry();
    mysten_metrics::init_metrics(&registry);
    info!("Metrics server started at port {}", config.metric_port);

    let bridge_metrics = Arc::new(BridgeMetrics::new(&registry));

    let data_checker = SuiTokenTransferDataChecker::new(config, bridge_metrics).await?;
    data_checker.start().await?;
    Ok(())
}

struct SuiTokenTransferDataChecker {
    bridge_client: SuiBridgeClient,
    pg_pool: PgPool,
}

impl SuiTokenTransferDataChecker {
    async fn new(
        config: IndexerConfig,
        metrics: Arc<BridgeMetrics>,
    ) -> Result<Self, anyhow::Error> {
        let bridge_client = SuiBridgeClient::new(&config.sui_rpc_url, metrics).await?;
        let pg_pool = get_connection_pool(config.db_url).await;
        Ok(Self {
            bridge_client,
            pg_pool,
        })
    }

    pub async fn start(self) -> Result<(), anyhow::Error> {
        // 1, resume unfinished tasks if any.
        self.maybe_resume_pending_task().await?;
        // 2, load last checked nonce.

        // 3, Create new task from previous finished nonce up to current token transfer nonce.
        let (_, current_nonce) = self
            .bridge_client
            .get_bridge_summary()
            .await
            .map_err(|e| anyhow!("{e:?}"))?
            .sequence_nums
            .into_iter()
            .find(|(msg_type, _)| *msg_type == 0)
            .expect("Cannot read latest token transfer nonce from the bridge object");

        let last_checked_nonce = self.last_checked_nonce().await?.unwrap_or_default();

        println!("Current nonce :{current_nonce}");
        println!("Last checked nonce :{last_checked_nonce}");

        Ok(())
    }

    async fn maybe_resume_pending_task(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }
    async fn last_checked_nonce(&self) -> Result<Option<u64>, anyhow::Error> {
        use schema::data_audits::columns;
        let mut conn = self.pg_pool.get().await?;
        Ok(data_audits
            .select(columns::to_nonce)
            .filter(columns::status.not_like(TaskStatus::FAILED.to_string()))
            .order_by(columns::to_nonce.desc())
            .first::<i64>(&mut conn)
            .await
            .optional()?
            .map(|i| i as u64))
    }
}
