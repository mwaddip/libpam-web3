//! Pluggable backends for blockchain data retrieval
//!
//! Each backend implements the `BlockchainBackend` trait and can be
//! selected via configuration.

pub mod etherscan;
pub mod jsonrpc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("NFT not found")]
    NftNotFound,
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("rate limited")]
    RateLimited,
    #[error("configuration error: {0}")]
    ConfigError(String),
}

impl From<reqwest::Error> for BackendError {
    fn from(e: reqwest::Error) -> Self {
        BackendError::HttpError(e.to_string())
    }
}

/// NFT ownership information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftOwnership {
    /// Token ID
    pub token_id: String,
    /// Contract address
    pub contract_address: String,
    /// Owner address
    pub owner: String,
}

/// NFT metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub animation_url: Option<String>,
    /// Raw access data from metadata
    pub access: Option<AccessData>,
}

/// Access control data from NFT metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessData {
    pub server_encrypted: String,
    pub user_encrypted: Option<String>,
}

/// Trait for blockchain data backends
#[async_trait]
pub trait BlockchainBackend: Send + Sync {
    /// Get the name of this backend
    fn name(&self) -> &'static str;

    /// Get all NFTs owned by an address for a specific contract
    async fn get_nfts_owned(
        &self,
        contract_address: &str,
        owner_address: &str,
    ) -> Result<Vec<NftOwnership>, BackendError>;

    /// Get metadata for a specific NFT
    async fn get_nft_metadata(
        &self,
        contract_address: &str,
        token_id: &str,
    ) -> Result<NftMetadata, BackendError>;

    /// Check if an address owns any NFT from a contract
    async fn check_ownership(
        &self,
        contract_address: &str,
        owner_address: &str,
    ) -> Result<bool, BackendError> {
        let nfts = self.get_nfts_owned(contract_address, owner_address).await?;
        Ok(!nfts.is_empty())
    }
}

/// Backend type enum for configuration
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    #[default]
    JsonRpc,
    Etherscan,
}
