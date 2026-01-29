//! Blockchain verification client
//!
//! Connects to a local web3-auth-svc daemon via Unix socket to verify
//! NFT ownership. The daemon handles the actual RPC communication and
//! supports multiple backends (JSON-RPC, Etherscan, etc.)

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

/// Request to verify NFT access
#[derive(Debug, Serialize)]
pub struct VerifyAccessRequest {
    /// Wallet address (checksummed or lowercase)
    pub wallet_address: String,
    /// Machine's ECIES private key (hex) for decrypting metadata
    pub machine_private_key: String,
    /// Expected machine ID after decryption
    pub expected_machine_id: String,
    /// NFT contract address (optional, uses config default if not set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<String>,
    /// Chain ID (optional, uses config default if not set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
}

/// Response from NFT verification
#[derive(Debug, Deserialize)]
pub struct VerifyAccessResponse {
    /// Whether verification succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Token ID that matched (if successful)
    pub token_id: Option<String>,
    /// Full metadata (if successful)
    pub metadata: Option<NftMetadata>,
}

/// NFT metadata structure
#[derive(Debug, Clone, Deserialize)]
pub struct NftMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub animation_url: Option<String>,
}

/// Result of NFT verification
#[derive(Debug)]
pub struct NftVerificationResult {
    /// The token ID that was verified
    pub token_id: String,
    /// The decrypted machine ID from the NFT
    pub machine_id: String,
    /// The full metadata
    pub metadata: NftMetadata,
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

    /// Verify that a wallet owns an NFT with access to this machine
    pub async fn verify_nft_access(
        &self,
        wallet_address: &alloy_primitives::Address,
        machine_private_key: &[u8],
        expected_machine_id: &str,
    ) -> Result<NftVerificationResult, BlockchainError> {
        let request = VerifyAccessRequest {
            wallet_address: format!("{}", wallet_address),
            machine_private_key: hex::encode(machine_private_key),
            expected_machine_id: expected_machine_id.to_string(),
            contract_address: self.contract_address.clone(),
            chain_id: self.chain_id,
        };

        let response = self.send_request("verify_access", &request)?;

        if response.success {
            Ok(NftVerificationResult {
                token_id: response.token_id.unwrap_or_default(),
                machine_id: expected_machine_id.to_string(),
                metadata: response.metadata.unwrap_or(NftMetadata {
                    name: None,
                    description: None,
                    image: None,
                    animation_url: None,
                }),
            })
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
    ) -> Result<VerifyAccessResponse, BlockchainError> {
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
        serde_json::from_slice(&response_buf).map_err(|e| {
            BlockchainError::InvalidResponse
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let request = VerifyAccessRequest {
            wallet_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            machine_private_key: "abcd".to_string(),
            expected_machine_id: "server-01".to_string(),
            contract_address: None,
            chain_id: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("wallet_address"));
        assert!(json.contains("server-01"));
        // Optional fields should not be present when None
        assert!(!json.contains("contract_address"));
    }
}
