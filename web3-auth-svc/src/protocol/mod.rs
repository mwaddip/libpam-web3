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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
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

/// Parameters for verify_access method
#[derive(Debug, Deserialize)]
pub struct VerifyAccessParams {
    pub wallet_address: String,
    pub machine_private_key: String,
    pub expected_machine_id: String,
    pub contract_address: Option<String>,
    pub chain_id: Option<u64>,
}

impl Response {
    pub fn success(token_id: String, metadata: Option<MetadataResponse>) -> Self {
        Self {
            success: true,
            error: None,
            token_id: Some(token_id),
            metadata,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(message.into()),
            token_id: None,
            metadata: None,
        }
    }
}
