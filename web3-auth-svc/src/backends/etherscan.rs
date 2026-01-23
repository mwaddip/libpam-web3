//! Etherscan V2 API backend
//!
//! Uses Etherscan's REST API for NFT data retrieval.
//! Supports Etherscan, Polygonscan, Arbiscan, etc.

use super::{AccessData, BackendError, BlockchainBackend, NftMetadata, NftOwnership};
use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

/// Etherscan backend configuration
#[derive(Debug, Clone, Deserialize)]
pub struct EtherscanConfig {
    /// Etherscan API base URL (e.g., https://api.etherscan.io)
    pub api_url: String,
    /// API key
    pub api_key: String,
    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    30
}

/// Etherscan API response wrapper
#[derive(Debug, Deserialize)]
struct EtherscanResponse<T> {
    status: String,
    message: String,
    result: Option<T>,
}

/// NFT transfer event from Etherscan
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NftTransfer {
    token_id: String,
    contract_address: String,
    to: String,
    from: String,
}

/// Token info from Etherscan
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenInfo {
    token_id: String,
    token_uri: Option<String>,
}

/// Etherscan V2 backend implementation
pub struct EtherscanBackend {
    config: EtherscanConfig,
    client: reqwest::Client,
}

impl EtherscanBackend {
    pub fn new(config: EtherscanConfig) -> Result<Self, BackendError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| BackendError::ConfigError(e.to_string()))?;

        Ok(Self { config, client })
    }

    /// Build API URL with parameters
    fn build_url(&self, module: &str, action: &str, params: &[(&str, &str)]) -> String {
        let mut url = format!(
            "{}/api?module={}&action={}&apikey={}",
            self.config.api_url, module, action, self.config.api_key
        );

        for (key, value) in params {
            url.push_str(&format!("&{}={}", key, value));
        }

        url
    }

    /// Get NFT transfers for an address
    async fn get_nft_transfers(
        &self,
        contract: &str,
        address: &str,
    ) -> Result<Vec<NftTransfer>, BackendError> {
        let url = self.build_url(
            "account",
            "tokennfttx",
            &[
                ("contractaddress", contract),
                ("address", address),
                ("sort", "desc"),
            ],
        );

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(BackendError::RateLimited);
        }

        let api_response: EtherscanResponse<Vec<NftTransfer>> = response.json().await?;

        if api_response.status != "1" {
            // Status "0" with "No transactions found" is not an error
            if api_response.message.contains("No transactions found") {
                return Ok(vec![]);
            }
            return Err(BackendError::RpcError(api_response.message));
        }

        Ok(api_response.result.unwrap_or_default())
    }

    /// Get token URI using eth_call via Etherscan proxy
    async fn get_token_uri(&self, contract: &str, token_id: &str) -> Result<String, BackendError> {
        // tokenURI(uint256) selector: 0xc87b56dd
        let token_id_clean = token_id.trim_start_matches("0x");
        let token_id_num = u64::from_str_radix(token_id_clean, 16).unwrap_or(0);
        let data = format!("0xc87b56dd{:064x}", token_id_num);

        let url = self.build_url(
            "proxy",
            "eth_call",
            &[
                ("to", contract),
                ("data", &data),
                ("tag", "latest"),
            ],
        );

        let response = self.client.get(&url).send().await?;
        let json: serde_json::Value = response.json().await?;

        let result = json
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| BackendError::InvalidResponse("no result".to_string()))?;

        decode_abi_string(result)
            .ok_or_else(|| BackendError::InvalidResponse("failed to decode tokenURI".to_string()))
    }

    /// Fetch metadata from URI
    async fn fetch_metadata(&self, uri: &str) -> Result<NftMetadata, BackendError> {
        let uri = resolve_uri(uri);

        let response = self.client.get(&uri).send().await?;

        if !response.status().is_success() {
            return Err(BackendError::HttpError(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let json: serde_json::Value = response.json().await?;

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

    /// Calculate current owner from transfer history
    fn get_current_nfts_owned(
        &self,
        transfers: Vec<NftTransfer>,
        owner: &str,
    ) -> Vec<NftOwnership> {
        use std::collections::HashMap;

        // Track current owner of each token
        let mut token_owners: HashMap<String, String> = HashMap::new();

        // Process transfers in chronological order (oldest first)
        // Note: We requested desc order, so reverse
        for transfer in transfers.into_iter().rev() {
            token_owners.insert(transfer.token_id.clone(), transfer.to.clone());
        }

        // Filter tokens currently owned by the target address
        let owner_lower = owner.to_lowercase();
        token_owners
            .into_iter()
            .filter(|(_, current_owner)| current_owner.to_lowercase() == owner_lower)
            .map(|(token_id, _)| NftOwnership {
                token_id,
                contract_address: String::new(), // Will be set by caller
                owner: owner.to_string(),
            })
            .collect()
    }
}

#[async_trait]
impl BlockchainBackend for EtherscanBackend {
    fn name(&self) -> &'static str {
        "etherscan"
    }

    async fn get_nfts_owned(
        &self,
        contract_address: &str,
        owner_address: &str,
    ) -> Result<Vec<NftOwnership>, BackendError> {
        let transfers = self
            .get_nft_transfers(contract_address, owner_address)
            .await?;

        let mut nfts = self.get_current_nfts_owned(transfers, owner_address);

        // Set contract address
        for nft in &mut nfts {
            nft.contract_address = contract_address.to_string();
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

/// Decode ABI-encoded string
fn decode_abi_string(hex_str: &str) -> Option<String> {
    let hex_str = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(hex_str).ok()?;

    if bytes.len() < 64 {
        return None;
    }

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
    fn test_current_owner_calculation() {
        let backend = EtherscanBackend {
            config: EtherscanConfig {
                api_url: "https://api.etherscan.io".to_string(),
                api_key: "test".to_string(),
                timeout_seconds: 30,
            },
            client: reqwest::Client::new(),
        };

        let transfers = vec![
            NftTransfer {
                token_id: "1".to_string(),
                contract_address: "0xcontract".to_string(),
                from: "0x0".to_string(),
                to: "0xalice".to_string(),
            },
            NftTransfer {
                token_id: "1".to_string(),
                contract_address: "0xcontract".to_string(),
                from: "0xalice".to_string(),
                to: "0xbob".to_string(),
            },
            NftTransfer {
                token_id: "2".to_string(),
                contract_address: "0xcontract".to_string(),
                from: "0x0".to_string(),
                to: "0xalice".to_string(),
            },
        ];

        let alice_nfts = backend.get_current_nfts_owned(transfers.clone(), "0xalice");
        assert_eq!(alice_nfts.len(), 1);
        assert_eq!(alice_nfts[0].token_id, "2");

        let bob_nfts = backend.get_current_nfts_owned(transfers, "0xbob");
        assert_eq!(bob_nfts.len(), 1);
        assert_eq!(bob_nfts[0].token_id, "1");
    }
}
