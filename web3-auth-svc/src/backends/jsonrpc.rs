//! Standard Ethereum JSON-RPC backend
//!
//! Works with any EVM-compatible node or RPC provider
//! (Alchemy, Infura, QuickNode, self-hosted, etc.)

use super::{AccessData, BackendError, BlockchainBackend, NftMetadata, NftOwnership};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// JSON-RPC backend configuration
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcConfig {
    /// RPC endpoint URL
    pub rpc_url: String,
    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    30
}

/// JSON-RPC request
#[derive(Debug, Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    method: &'static str,
    params: Vec<serde_json::Value>,
    id: u64,
}

/// JSON-RPC response
#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<String>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    message: String,
}

/// JSON-RPC backend implementation
pub struct JsonRpcBackend {
    config: JsonRpcConfig,
    client: reqwest::Client,
}

impl JsonRpcBackend {
    pub fn new(config: JsonRpcConfig) -> Result<Self, BackendError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| BackendError::ConfigError(e.to_string()))?;

        Ok(Self { config, client })
    }

    async fn eth_call(&self, to: &str, data: &str) -> Result<String, BackendError> {
        let request = RpcRequest {
            jsonrpc: "2.0",
            method: "eth_call",
            params: vec![
                serde_json::json!({
                    "to": to,
                    "data": data
                }),
                serde_json::json!("latest"),
            ],
            id: 1,
        };

        let response = self
            .client
            .post(&self.config.rpc_url)
            .json(&request)
            .send()
            .await?;

        let rpc_response: RpcResponse = response.json().await?;

        if let Some(error) = rpc_response.error {
            return Err(BackendError::RpcError(error.message));
        }

        rpc_response
            .result
            .ok_or_else(|| BackendError::InvalidResponse("empty result".to_string()))
    }

    /// Get balance of NFTs for an address (ERC-721 balanceOf)
    async fn get_balance(&self, contract: &str, owner: &str) -> Result<u64, BackendError> {
        // balanceOf(address) selector: 0x70a08231
        let owner_padded = format!("{:0>64}", owner.trim_start_matches("0x"));
        let data = format!("0x70a08231{}", owner_padded);

        let result = self.eth_call(contract, &data).await?;
        parse_uint256(&result)
    }

    /// Get token ID at index for owner (ERC-721 Enumerable)
    async fn get_token_of_owner_by_index(
        &self,
        contract: &str,
        owner: &str,
        index: u64,
    ) -> Result<String, BackendError> {
        // tokenOfOwnerByIndex(address,uint256) selector: 0x2f745c59
        let owner_padded = format!("{:0>64}", owner.trim_start_matches("0x"));
        let data = format!("0x2f745c59{}{:064x}", owner_padded, index);

        self.eth_call(contract, &data).await
    }

    /// Get token URI (ERC-721 tokenURI)
    async fn get_token_uri(&self, contract: &str, token_id: &str) -> Result<String, BackendError> {
        // tokenURI(uint256) selector: 0xc87b56dd
        let token_id_clean = token_id.trim_start_matches("0x");
        let data = format!("0xc87b56dd{:0>64}", token_id_clean);

        let result = self.eth_call(contract, &data).await?;
        decode_abi_string(&result)
            .ok_or_else(|| BackendError::InvalidResponse("failed to decode tokenURI".to_string()))
    }

    /// Fetch metadata from URI
    async fn fetch_metadata(&self, uri: &str) -> Result<NftMetadata, BackendError> {
        // Handle data URIs (on-chain metadata)
        let json: serde_json::Value = if let Some(data) = uri.strip_prefix("data:application/json;base64,") {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|e| BackendError::InvalidResponse(format!("base64 decode failed: {}", e)))?;
            serde_json::from_slice(&decoded)
                .map_err(|e| BackendError::InvalidResponse(format!("JSON parse failed: {}", e)))?
        } else if let Some(data) = uri.strip_prefix("data:application/json,") {
            // URL-encoded JSON (less common)
            serde_json::from_str(data)
                .map_err(|e| BackendError::InvalidResponse(format!("JSON parse failed: {}", e)))?
        } else {
            // HTTP/IPFS/Arweave URIs
            let uri = resolve_uri(uri);
            let response = self.client.get(&uri).send().await?;

            if !response.status().is_success() {
                return Err(BackendError::HttpError(format!(
                    "HTTP {}",
                    response.status()
                )));
            }

            response.json().await?
        };

        // Parse as generic JSON first to extract access data

        let access = json.get("access").and_then(|a| {
            Some(AccessData {
                server_encrypted: a.get("server_encrypted")?.as_str()?.to_string(),
                user_encrypted: a
                    .get("user_encrypted")
                    .and_then(|u| u.as_str())
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
}

#[async_trait]
impl BlockchainBackend for JsonRpcBackend {
    fn name(&self) -> &'static str {
        "jsonrpc"
    }

    async fn get_nfts_owned(
        &self,
        contract_address: &str,
        owner_address: &str,
    ) -> Result<Vec<NftOwnership>, BackendError> {
        let balance = self.get_balance(contract_address, owner_address).await?;

        if balance == 0 {
            return Ok(vec![]);
        }

        let mut nfts = Vec::with_capacity(balance as usize);

        for i in 0..balance {
            let token_id = self
                .get_token_of_owner_by_index(contract_address, owner_address, i)
                .await?;

            nfts.push(NftOwnership {
                token_id,
                contract_address: contract_address.to_string(),
                owner: owner_address.to_string(),
            });
        }

        Ok(nfts)
    }

    async fn get_nft_metadata(
        &self,
        contract_address: &str,
        token_id: &str,
    ) -> Result<NftMetadata, BackendError> {
        let token_uri = self.get_token_uri(contract_address, token_id).await?;
        self.fetch_metadata(&token_uri).await
    }
}

/// Parse a uint256 hex result to u64
fn parse_uint256(hex_str: &str) -> Result<u64, BackendError> {
    let hex_str = hex_str.trim_start_matches("0x");

    // Take the last 16 hex chars (8 bytes) for u64
    let start = if hex_str.len() > 16 {
        hex_str.len() - 16
    } else {
        0
    };

    u64::from_str_radix(&hex_str[start..], 16)
        .map_err(|_| BackendError::InvalidResponse("failed to parse uint256".to_string()))
}

/// Decode ABI-encoded string
fn decode_abi_string(hex_str: &str) -> Option<String> {
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

/// Resolve IPFS/Arweave URIs to HTTP
fn resolve_uri(uri: &str) -> String {
    if let Some(hash) = uri.strip_prefix("ipfs://") {
        format!("https://ipfs.io/ipfs/{}", hash)
    } else if let Some(hash) = uri.strip_prefix("ar://") {
        format!("https://arweave.net/{}", hash)
    } else {
        uri.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uint256() {
        assert_eq!(
            parse_uint256(
                "0x0000000000000000000000000000000000000000000000000000000000000005"
            )
            .unwrap(),
            5
        );
    }

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
