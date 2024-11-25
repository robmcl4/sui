// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, sync::Arc};

use mysten_metrics::spawn_monitored_task;
use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{interval, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::{
    metrics::IndexerMetrics,
    pipeline::{Indexed, PipelineConfig, WatermarkPart},
};

use super::{Batched, Handler};

/// Processed values that are waiting to be written to the database. This is an internal type used
/// by the concurrent collector to hold data it is waiting to send to the committer.
struct Pending<H: Handler> {
    /// Values to be inserted into the database from this checkpoint
    values: Vec<H::Value>,
    /// The watermark associated with this checkpoint and the part of it that is left to commit
    watermark: WatermarkPart,
}

impl<H: Handler> Pending<H> {
    /// Whether there are values left to commit from this indexed checkpoint.
    fn is_empty(&self) -> bool {
        let empty = self.values.is_empty();
        if empty {
            debug_assert!(self.watermark.batch_rows == 0);
        }
        empty
    }

    /// Adds data from this indexed checkpoint to the `batch`, honoring the handler's bounds on
    /// chunk size.
    fn batch_into(&mut self, batch: &mut Batched<H>) {
        if batch.values.len() + self.values.len() > H::MAX_CHUNK_ROWS {
            let mut for_batch = self
                .values
                .split_off(H::MAX_CHUNK_ROWS - batch.values.len());

            std::mem::swap(&mut self.values, &mut for_batch);
            batch.watermark.push(self.watermark.take(for_batch.len()));
            batch.values.extend(for_batch);
        } else {
            batch.watermark.push(self.watermark.take(self.values.len()));
            batch.values.extend(std::mem::take(&mut self.values));
        }
    }
}

impl<H: Handler> From<Indexed<H>> for Pending<H> {
    fn from(indexed: Indexed<H>) -> Self {
        Self {
            watermark: WatermarkPart {
                watermark: indexed.watermark,
                batch_rows: indexed.values.len(),
                total_rows: indexed.values.len(),
            },
            values: indexed.values,
        }
    }
}

/// The collector task is responsible for gathering rows into batches which it then sends to a
/// committer task to write to the database. The task publishes batches in the following
/// circumstances:
///
/// - If `H::BATCH_SIZE` rows are pending, it will immediately schedule a batch to be gathered.
///
/// - If after sending one batch there is more data to be sent, it will immediately schedule the
///   next batch to be gathered (Each batch will contain at most `H::CHUNK_SIZE` rows).
///
/// - Otherwise, it will check for any data to write out at a regular interval (controlled by
///   `config.collect_interval`).
///
/// This task will shutdown if canceled via the `cancel` token, or if any of its channels are
/// closed.
pub(super) fn collector<H: Handler + 'static>(
    config: PipelineConfig,
    mut rx: mpsc::Receiver<Indexed<H>>,
    tx: mpsc::Sender<Batched<H>>,
    metrics: Arc<IndexerMetrics>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    spawn_monitored_task!(async move {
        // The `poll` interval controls the maximum time to wait between collecting batches,
        // regardless of number of rows pending.
        let mut poll = interval(config.collect_interval);
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // Data for checkpoints that haven't been written yet.
        let mut pending: BTreeMap<u64, Pending<H>> = BTreeMap::new();
        let mut pending_rows = 0;

        info!(pipeline = H::NAME, "Starting collector");

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!(pipeline = H::NAME, "Shutdown received, stopping collector");
                    break;
                }

                // Time to create another batch and push it to the committer.
                _ = poll.tick() => {
                    let guard = metrics
                        .collector_gather_latency
                        .with_label_values(&[H::NAME])
                        .start_timer();

                    let mut batch = Batched::new();
                    while !batch.is_full() {
                        let Some(mut entry) = pending.first_entry() else {
                            break;
                        };

                        let indexed = entry.get_mut();
                        indexed.batch_into(&mut batch);
                        if indexed.is_empty() {
                            entry.remove();
                        }
                    }

                    pending_rows -= batch.len();
                    let elapsed = guard.stop_and_record();
                    debug!(
                        pipeline = H::NAME,
                        elapsed_ms = elapsed * 1000.0,
                        rows = batch.len(),
                        pending_rows = pending_rows,
                        "Gathered batch",
                    );

                    metrics
                        .total_collector_batches_created
                        .with_label_values(&[H::NAME])
                        .inc();

                    metrics
                        .collector_batch_size
                        .with_label_values(&[H::NAME])
                        .observe(batch.len() as f64);

                    if tx.send(batch).await.is_err() {
                        info!(pipeline = H::NAME, "Committer closed channel, stopping collector");
                        break;
                    }

                    if pending_rows > 0 {
                        poll.reset_immediately();
                    } else if rx.is_closed() && rx.is_empty() {
                        info!(
                            pipeline = H::NAME,
                            "Processor closed channel, pending rows empty, stopping collector",
                        );
                        break;
                    }
                }

                Some(indexed) = rx.recv(), if pending_rows < H::MAX_PENDING_ROWS => {
                    metrics
                        .total_collector_rows_received
                        .with_label_values(&[H::NAME])
                        .inc_by(indexed.len() as u64);

                    pending_rows += indexed.len();
                    pending.insert(indexed.checkpoint(), indexed.into());

                    if pending_rows >= H::MIN_EAGER_ROWS {
                        poll.reset_immediately()
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::{db, pipeline::Processor};

    use super::*;
    use prometheus::Registry;
    use std::time::Duration;
    use sui_types::full_checkpoint_content::CheckpointData;
    use tokio::sync::mpsc;

    struct TestHandler;
    impl Processor for TestHandler {
        type Value = u64;
        const NAME: &'static str = "test_handler";
        const FANOUT: usize = 1;

        fn process(&self, _checkpoint: &Arc<CheckpointData>) -> anyhow::Result<Vec<Self::Value>> {
            Ok(vec![])
        }
    }

    #[async_trait::async_trait]
    impl Handler for TestHandler {
        const MIN_EAGER_ROWS: usize = 3;
        const MAX_CHUNK_ROWS: usize = 4;
        const MAX_PENDING_ROWS: usize = 10;

        async fn commit(
            _values: &[Self::Value],
            _conn: &mut db::Connection<'_>,
        ) -> anyhow::Result<usize> {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            Ok(0)
        }
    }

    #[tokio::test]
    async fn test_collector_batches_data() {
        let (processor_tx, processor_rx) = mpsc::channel(10);
        let (collector_tx, mut collector_rx) = mpsc::channel(10);
        let metrics = Arc::new(IndexerMetrics::new(&Registry::new()));
        let cancel = CancellationToken::new();

        let _collector = collector::<TestHandler>(
            PipelineConfig::default(),
            processor_rx,
            collector_tx,
            metrics,
            cancel.clone(),
        );

        // Send test data
        let test_data = vec![
            Indexed::new(0, 1, 10, 1000, vec![1, 2]),
            Indexed::new(0, 2, 20, 2000, vec![3, 4]),
            Indexed::new(0, 3, 30, 3000, vec![5, 6]),
        ];

        for data in test_data {
            processor_tx.send(data).await.unwrap();
        }

        let batch1 = collector_rx.recv().await.unwrap();
        assert_eq!(batch1.len(), 4);

        let batch2 = collector_rx.recv().await.unwrap();
        assert_eq!(batch2.len(), 2);

        let batch3 = collector_rx.recv().await.unwrap();
        assert_eq!(batch3.len(), 0);

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_collector_shutdown() {
        let (processor_tx, processor_rx) = mpsc::channel(10);
        let (collector_tx, mut collector_rx) = mpsc::channel(10);
        let metrics = Arc::new(IndexerMetrics::new(&Registry::new()));
        let cancel = CancellationToken::new();

        let _collector = collector::<TestHandler>(
            PipelineConfig::default(),
            processor_rx,
            collector_tx,
            metrics,
            cancel.clone(),
        );

        processor_tx
            .send(Indexed::new(0, 1, 10, 1000, vec![1, 2]))
            .await
            .unwrap();

        let batch = collector_rx.recv().await.unwrap();
        assert_eq!(batch.len(), 2);

        // Drop processor sender to simulate shutdown
        drop(processor_tx);

        // After a short delay, collector should shut down
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(collector_rx.try_recv().is_err());

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_collector_respects_max_pending() {
        let processor_channel_size = 5; // unit is checkpoint
        let collector_channel_size = 10; // unit is batch, aka rows / MAX_CHUNK_ROWS
        let (processor_tx, processor_rx) = mpsc::channel(processor_channel_size);
        let (collector_tx, _collector_rx) = mpsc::channel(collector_channel_size);

        let metrics = Arc::new(IndexerMetrics::new(&Registry::new()));

        let cancel = CancellationToken::new();

        let _collector = collector::<TestHandler>(
            PipelineConfig::default(),
            processor_rx,
            collector_tx,
            metrics.clone(),
            cancel.clone(),
        );

        // Send more data than MAX_PENDING_ROWS plus collector channel buffer
        let data = Indexed::new(
            0,
            1,
            10,
            1000,
            vec![
                1;
                TestHandler::MAX_PENDING_ROWS
                    + TestHandler::MAX_CHUNK_ROWS * collector_channel_size
            ],
        );
        processor_tx.send(data).await.unwrap();

        // Now fill up the processor channel with minimum data to trigger send blocking
        for _ in 0..processor_channel_size {
            let more_data = Indexed::new(0, 2, 11, 1000, vec![1]);
            processor_tx.send(more_data).await.unwrap();
        }

        // Now sending even more data should block.
        let even_more_data = Indexed::new(0, 3, 12, 1000, vec![1]);

        let send_result = tokio::time::timeout(
            Duration::from_millis(2000),
            processor_tx.send(even_more_data),
        )
        .await;
        assert!(
            send_result.is_err(),
            "Send should timeout due to MAX_PENDING_ROWS limit"
        );

        cancel.cancel();
    }
}
