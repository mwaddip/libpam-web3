//! Protocol for PAM module <-> service communication
//!
//! Uses length-prefixed JSON messages over Unix socket.

use serde::{Deserialize, Serialize};

/// Request from PAM module
#[derive(Debug, Deserialize)]
pub struct Request {
    pub method: String,
    pub params: serde_json::Value,
}

/// Response to PAM module
#[derive(Debug, Serialize)]
pub struct Response {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Single token ID (for backwards compatibility)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    /// All token IDs owned by wallet
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MetadataResponse>,
}

#[derive(Debug, Serialize)]
pub struct MetadataResponse {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub animation_url: Option<String>,
}

/// Parameters for get_nfts method (simplified - no server-side decryption needed)
#[derive(Debug, Deserialize)]
pub struct GetNftsParams {
    pub wallet_address: String,
    pub contract_address: Option<String>,
    pub chain_id: Option<u64>,
}

impl Response {
    pub fn success_single(token_id: String, metadata: Option<MetadataResponse>) -> Self {
        Self {
            success: true,
            error: None,
            token_id: Some(token_id),
            token_ids: None,
            metadata,
        }
    }

    pub fn success_multiple(token_ids: Vec<String>) -> Self {
        Self {
            success: true,
            error: None,
            token_id: None,
            token_ids: Some(token_ids),
            metadata: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(message.into()),
            token_id: None,
            token_ids: None,
            metadata: None,
        }
    }
}
