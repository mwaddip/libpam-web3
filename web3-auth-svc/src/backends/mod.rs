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
    pub user_encrypted: Option<String>,
    pub public_secret: Option<String>,
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

}

/// Backend type enum for configuration
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    #[default]
    JsonRpc,
    Etherscan,
}

/// Default timeout for backend requests (in seconds)
pub(crate) fn default_timeout() -> u64 {
    30
}

/// Decode ABI-encoded string from hex
pub(crate) fn decode_abi_string(hex_str: &str) -> Option<String> {
    let hex_str = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(hex_str).ok()?;

    if bytes.len() < 64 {
        return None;
    }

    // ABI: offset (32) + length (32) + data
    let length = u64::from_be_bytes([
        bytes[56], bytes[57], bytes[58], bytes[59], bytes[60], bytes[61], bytes[62], bytes[63],
    ]) as usize;

    if bytes.len() < 64 + length {
        return None;
    }

    String::from_utf8(bytes[64..64 + length].to_vec()).ok()
}

/// Resolve IPFS/Arweave URIs to HTTP gateway URLs
pub(crate) fn resolve_uri(uri: &str) -> String {
    if let Some(hash) = uri.strip_prefix("ipfs://") {
        format!("https://ipfs.io/ipfs/{}", hash)
    } else if let Some(hash) = uri.strip_prefix("ar://") {
        format!("https://arweave.net/{}", hash)
    } else {
        uri.to_string()
    }
}

/// Fetch and parse NFT metadata from a URI
///
/// Handles data URIs (base64 and URL-encoded JSON), HTTP, IPFS, and Arweave URIs.
pub(crate) async fn fetch_metadata_from_uri(
    client: &reqwest::Client,
    uri: &str,
) -> Result<NftMetadata, BackendError> {
    let json: serde_json::Value =
        if let Some(data) = uri.strip_prefix("data:application/json;base64,") {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|e| {
                    BackendError::InvalidResponse(format!("base64 decode failed: {}", e))
                })?;
            serde_json::from_slice(&decoded)
                .map_err(|e| BackendError::InvalidResponse(format!("JSON parse failed: {}", e)))?
        } else if let Some(data) = uri.strip_prefix("data:application/json,") {
            serde_json::from_str(data)
                .map_err(|e| BackendError::InvalidResponse(format!("JSON parse failed: {}", e)))?
        } else {
            let uri = resolve_uri(uri);
            let response = client.get(&uri).send().await?;

            if !response.status().is_success() {
                return Err(BackendError::HttpError(format!(
                    "HTTP {}",
                    response.status()
                )));
            }

            response.json().await?
        };

    let access = json.get("access").and_then(|a| {
        Some(AccessData {
            user_encrypted: a
                .get("user_encrypted")
                .and_then(|u| u.as_str())
                .map(|s| s.to_string()),
            public_secret: a
                .get("public_secret")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string()),
        })
    });

    Ok(NftMetadata {
        name: json.get("name").and_then(|v| v.as_str()).map(String::from),
        description: json
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from),
        image: json.get("image").and_then(|v| v.as_str()).map(String::from),
        animation_url: json
            .get("animation_url")
            .and_then(|v| v.as_str())
            .map(String::from),
        access,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_uri() {
        assert_eq!(
            resolve_uri("ipfs://QmTest"),
            "https://ipfs.io/ipfs/QmTest"
        );
        assert_eq!(
            resolve_uri("https://example.com/meta.json"),
            "https://example.com/meta.json"
        );
    }
}
