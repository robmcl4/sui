// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use async_graphql::{connection::Connection, *};

use crate::context_data::{context_ext::DataProviderContextExt, db_data_provider::PgManager};

use super::name_service::NameService;
use super::{
    balance::Balance,
    coin::Coin,
    object::{Object, ObjectFilter},
    stake::Stake,
    sui_address::SuiAddress,
    transaction_block::{TransactionBlock, TransactionBlockFilter},
};

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub(crate) struct Address {
    pub address: SuiAddress,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub(crate) enum AddressTransactionBlockRelationship {
    Sign, // Transactions this address has signed
    Sent, // Transactions that transferred objects from this address
    Recv, // Transactions that received objects into this address
    Paid, // Transactions that were paid for by this address
}

#[allow(unreachable_code)]
#[allow(unused_variables)]
#[Object]
impl Address {
    /// Similar behavior to the `transactionBlockConnection` in Query but
    /// supports additional `AddressTransactionBlockRelationship` filter
    async fn transaction_block_connection(
        &self,
        ctx: &Context<'_>,
        first: Option<u64>,
        after: Option<String>,
        last: Option<u64>,
        before: Option<String>,
        relation: Option<AddressTransactionBlockRelationship>,
        filter: Option<TransactionBlockFilter>,
    ) -> Result<Option<Connection<String, TransactionBlock>>> {
        ctx.data_unchecked::<PgManager>()
            .fetch_txs(
                first,
                after,
                last,
                before,
                filter,
                Some(self.address),
                relation,
            )
            .await
            .extend()
    }

    // =========== Owner interface methods =============

    pub async fn location(&self) -> SuiAddress {
        self.address
    }

    pub async fn object_connection(
        &self,
        ctx: &Context<'_>,
        first: Option<u64>,
        after: Option<String>,
        last: Option<u64>,
        before: Option<String>,
        filter: Option<ObjectFilter>,
    ) -> Result<Option<Connection<String, Object>>> {
        let filter = filter.map(|mut x| {
            x.owner = Some(self.address);
            x
        });
        ctx.data_unchecked::<PgManager>()
            .fetch_objs(first, after, last, before, filter)
            .await
            .extend()
    }

    pub async fn balance(&self, ctx: &Context<'_>, type_: Option<String>) -> Result<Balance> {
        ctx.data_provider()
            .fetch_balance(&self.address, type_)
            .await
    }

    pub async fn balance_connection(
        &self,
        ctx: &Context<'_>,
        first: Option<u64>,
        after: Option<String>,
        last: Option<u64>,
        before: Option<String>,
    ) -> Result<Connection<String, Balance>> {
        ctx.data_provider()
            .fetch_balance_connection(&self.address, first, after, last, before)
            .await
    }

    pub async fn coin_connection(
        &self,
        first: Option<u64>,
        after: Option<String>,
        last: Option<u64>,
        before: Option<String>,
        type_: Option<String>,
    ) -> Option<Connection<String, Coin>> {
        unimplemented!()
    }

    pub async fn stake_connection(
        &self,
        first: Option<u64>,
        after: Option<String>,
        last: Option<u64>,
        before: Option<String>,
    ) -> Option<Connection<String, Stake>> {
        unimplemented!()
    }

    pub async fn default_name_service_name(&self) -> Option<String> {
        unimplemented!()
    }

    pub async fn name_service_connection(
        &self,
        first: Option<u64>,
        after: Option<String>,
        last: Option<u64>,
        before: Option<String>,
    ) -> Option<Connection<String, NameService>> {
        unimplemented!()
    }
}
