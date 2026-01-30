//! Blockchain verification client
//!
//! Connects to a local web3-auth-svc daemon via Unix socket to query
//! NFT ownership. The daemon handles the actual RPC communication and
//! supports multiple backends (JSON-RPC, Etherscan, etc.)
//!
//! Authentication model (v0.4.0+):
//! - No server-side decryption needed
//! - PAM queries blockchain for wallet's NFT token IDs
//! - Token IDs are matched against GECOS entries in /etc/passwd

use crate::config::BlockchainConfig;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;
use thiserror::Error;

/// Default socket path for the web3-auth service
pub const DEFAULT_SOCKET_PATH: &str = "/run/web3-auth/web3-auth.sock";

#[derive(Debug, Error)]
pub enum BlockchainError {
    #[error("service connection failed: {0}")]
    ConnectionFailed(String),
    #[error("service request failed: {0}")]
    RequestFailed(String),
    #[error("NFT not found for wallet")]
    NftNotFound,
    #[error("invalid response from service")]
    InvalidResponse,
    #[error("service error: {0}")]
    ServiceError(String),
}

/// Request to get NFT token IDs for a wallet
#[derive(Debug, Serialize)]
pub struct GetNftsRequest {
    /// Wallet address (checksummed or lowercase)
    pub wallet_address: String,
    /// NFT contract address (optional, uses config default if not set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<String>,
    /// Chain ID (optional, uses config default if not set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
}

/// Response from NFT query
#[derive(Debug, Deserialize)]
pub struct GetNftsResponse {
    /// Whether the query succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// All token IDs owned by the wallet
    pub token_ids: Option<Vec<String>>,
}

/// Blockchain client that communicates with local web3-auth-svc
pub struct BlockchainClient {
    socket_path: String,
    timeout: Duration,
    contract_address: Option<String>,
    chain_id: Option<u64>,
}

impl BlockchainClient {
    /// Create a new blockchain client
    pub fn new(config: BlockchainConfig) -> Result<Self, BlockchainError> {
        Ok(Self {
            socket_path: config.socket_path,
            timeout: Duration::from_secs(config.timeout_seconds),
            contract_address: Some(config.nft_contract),
            chain_id: Some(config.chain_id),
        })
    }

    /// Get all NFT token IDs owned by a wallet
    ///
    /// Returns a list of token IDs that the PAM module can match
    /// against GECOS entries in /etc/passwd.
    pub async fn get_wallet_nfts(
        &self,
        wallet_address: &alloy_primitives::Address,
    ) -> Result<Vec<String>, BlockchainError> {
        let request = GetNftsRequest {
            wallet_address: format!("{}", wallet_address),
            contract_address: self.contract_address.clone(),
            chain_id: self.chain_id,
        };

        let response = self.send_request("get_nfts", &request)?;

        if response.success {
            Ok(response.token_ids.unwrap_or_default())
        } else {
            let error = response.error.unwrap_or_else(|| "Unknown error".to_string());
            if error.contains("not found") || error.contains("no NFT") {
                Err(BlockchainError::NftNotFound)
            } else {
                Err(BlockchainError::ServiceError(error))
            }
        }
    }

    /// Send a request to the local service
    fn send_request<T: Serialize>(
        &self,
        method: &str,
        params: &T,
    ) -> Result<GetNftsResponse, BlockchainError> {
        // Connect to Unix socket
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| BlockchainError::ConnectionFailed(e.to_string()))?;

        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| BlockchainError::ConnectionFailed(e.to_string()))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| BlockchainError::ConnectionFailed(e.to_string()))?;

        // Build request
        let request = serde_json::json!({
            "method": method,
            "params": params,
        });

        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| BlockchainError::RequestFailed(e.to_string()))?;

        // Send length-prefixed message
        let len = request_bytes.len() as u32;
        stream
            .write_all(&len.to_be_bytes())
            .map_err(|e| BlockchainError::RequestFailed(e.to_string()))?;
        stream
            .write_all(&request_bytes)
            .map_err(|e| BlockchainError::RequestFailed(e.to_string()))?;

        // Read response
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| BlockchainError::RequestFailed(e.to_string()))?;
        let response_len = u32::from_be_bytes(len_buf) as usize;

        let mut response_buf = vec![0u8; response_len];
        stream
            .read_exact(&mut response_buf)
            .map_err(|e| BlockchainError::RequestFailed(e.to_string()))?;

        // Parse response
        serde_json::from_slice(&response_buf).map_err(|_| BlockchainError::InvalidResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let request = GetNftsRequest {
            wallet_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            contract_address: None,
            chain_id: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("wallet_address"));
        // Optional fields should not be present when None
        assert!(!json.contains("contract_address"));
        assert!(!json.contains("chain_id"));
    }
}
