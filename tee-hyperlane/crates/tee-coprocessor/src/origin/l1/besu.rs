//! Gathers what the enclave needs to verify a Besu QBFT chain: the newest headers its
//! validators commit-sealed, as `debug_getRawHeader` serves them, and tree proofs at them.
//!
//! Every QBFT block is final when sealed, so the newest one the RPC can prove is attested,
//! as Base's newest signed block is. Each header is checked here exactly as the enclave
//! checks it, and against the RPC's own block hash, before it is offered.

use alloy_primitives::B256;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::json;
use tee_node::chains::l1::besu::{self, BESU, TREE_SLOT, VALIDATORS};
use tee_node::state::IsmState;
use tracing::debug;

use crate::origin::evm::hex_number;
use crate::origin::l2::sequenced::{Config, Sequenced, SignedHead, TRIES};
use crate::origin::{Indexer, Message, Step};

pub struct Besu {
    chain: Sequenced,
}

impl Besu {
    pub fn new(config: Config) -> Result<Self> {
        anyhow::ensure!(
            config.domain == BESU.domain,
            "chain `besu` has domain {}, but the enclave attests Besu as {}",
            config.domain,
            BESU.domain
        );
        Ok(Self {
            chain: Sequenced::new(&BESU, TREE_SLOT, &config),
        })
    }

    /// Block `number`, sealed, as the enclave will take it.
    async fn sealed(&self, number: u64) -> Result<SignedHead> {
        let rpc = self.chain.rpc();
        let raw = rpc
            .call("debug_getRawHeader", json!([hex_number(number)]))
            .await
            .context("debug_getRawHeader; the node must enable the DEBUG RPC API")?;
        let rlp = hex::decode(
            raw.as_str()
                .context("debug_getRawHeader returned no header")?
                .trim_start_matches("0x"),
        )?;
        let block = besu::verify_block(&rlp, &VALIDATORS)
            .with_context(|| format!("Besu block {number}"))?;
        let reported: B256 = rpc.block(number).await?["hash"]
            .as_str()
            .context("hash")?
            .parse()?;
        anyhow::ensure!(
            reported == block.hash,
            "Besu block {number} hashes to {}, but the RPC reports {reported}",
            block.hash
        );
        Ok(SignedHead {
            height: block.number,
            state_root: block.state_root,
            timestamp: block.timestamp,
            input: serde_json::to_value(besu::Input { header: rlp.into() })?,
        })
    }
}

#[async_trait]
impl Indexer for Besu {
    async fn gather(&self, trusted: &IsmState) -> Result<Step> {
        let tip = self.chain.rpc().block_number().await?;
        let mut heads = Vec::new();
        let mut n = tip;
        while n > trusted.height && heads.len() < TRIES {
            match self.sealed(n).await {
                Ok(head) => heads.push(head),
                Err(e) => debug!(height = n, error = %e, "skipping a Besu block"),
            }
            n -= 1;
        }
        self.chain.step(trusted, &heads).await
    }

    async fn index(&self, from: u64, to: u64) -> Result<Vec<Message>> {
        self.chain.index(from, to).await
    }

    async fn bootstrap(&self, identity: [u8; 32], height: Option<u64>) -> Result<IsmState> {
        let number = match height {
            Some(h) => h,
            None => self.chain.rpc().block_number().await?,
        };
        Ok(self.chain.genesis(&self.sealed(number).await?, identity))
    }
}
