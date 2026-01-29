//! web3-auth-svc - Local service for NFT-based authentication
//!
//! This daemon listens on a Unix socket and provides NFT verification
//! services to the PAM module. It supports multiple backends (JSON-RPC,
//! Etherscan, etc.) configurable via TOML config file.

mod backends;
mod protocol;

use anyhow::{Context, Result};
use backends::{etherscan, jsonrpc, BackendType, BlockchainBackend};
use clap::Parser;
use protocol::{MetadataResponse, Request, Response, VerifyAccessParams};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info};

/// web3-auth-svc - NFT authentication verification service
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/web3-auth/config.toml")]
    config: PathBuf,

    /// Socket path (overrides config)
    #[arg(short, long)]
    socket: Option<PathBuf>,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,
}

/// Service configuration
#[derive(Debug, Clone, Deserialize)]
struct Config {
    /// Unix socket path
    #[serde(default = "default_socket_path")]
    socket_path: String,

    /// Backend type
    #[serde(default)]
    backend: BackendType,

    /// Default chain ID
    #[serde(default = "default_chain_id")]
    default_chain_id: u64,

    /// Default NFT contract address
    default_contract: Option<String>,

    /// JSON-RPC backend config
    jsonrpc: Option<jsonrpc::JsonRpcConfig>,

    /// Etherscan backend config
    etherscan: Option<etherscan::EtherscanConfig>,
}

fn default_socket_path() -> String {
    "/run/web3-auth/web3-auth.sock".to_string()
}

fn default_chain_id() -> u64 {
    1
}

/// Service state
struct Service {
    config: Config,
    backend: Arc<dyn BlockchainBackend>,
}

impl Service {
    fn new(config: Config) -> Result<Self> {
        let backend: Arc<dyn BlockchainBackend> = match config.backend {
            BackendType::JsonRpc => {
                let rpc_config = config
                    .jsonrpc
                    .clone()
                    .context("jsonrpc backend requires [jsonrpc] config section")?;
                Arc::new(jsonrpc::JsonRpcBackend::new(rpc_config)?)
            }
            BackendType::Etherscan => {
                let eth_config = config
                    .etherscan
                    .clone()
                    .context("etherscan backend requires [etherscan] config section")?;
                Arc::new(etherscan::EtherscanBackend::new(eth_config)?)
            }
        };

        info!("Using {} backend", backend.name());

        Ok(Self { config, backend })
    }

    async fn handle_request(&self, request: Request) -> Response {
        match request.method.as_str() {
            "verify_access" => self.handle_verify_access(request.params).await,
            "health" => Response::success("ok".to_string(), None),
            _ => Response::error(format!("unknown method: {}", request.method)),
        }
    }

    async fn handle_verify_access(&self, params: serde_json::Value) -> Response {
        let params: VerifyAccessParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => return Response::error(format!("invalid params: {}", e)),
        };

        let contract = params
            .contract_address
            .or_else(|| self.config.default_contract.clone());

        let contract = match contract {
            Some(c) => c,
            None => return Response::error("no contract address specified"),
        };

        // Get NFTs owned by wallet
        let nfts = match self
            .backend
            .get_nfts_owned(&contract, &params.wallet_address)
            .await
        {
            Ok(nfts) => nfts,
            Err(e) => return Response::error(format!("failed to get NFTs: {}", e)),
        };

        if nfts.is_empty() {
            return Response::error("no NFT found for wallet");
        }

        // Decode private key
        let private_key = match hex::decode(&params.machine_private_key) {
            Ok(k) if k.len() == 32 => k,
            _ => return Response::error("invalid machine private key"),
        };

        // Check each NFT for matching machine ID
        for nft in nfts {
            let metadata = match self
                .backend
                .get_nft_metadata(&contract, &nft.token_id)
                .await
            {
                Ok(m) => m,
                Err(e) => {
                    debug!("Failed to get metadata for token {}: {}", nft.token_id, e);
                    continue;
                }
            };

            // Check if metadata has access data
            let access = match &metadata.access {
                Some(a) => a,
                None => {
                    debug!("Token {} has no access data", nft.token_id);
                    continue;
                }
            };

            // Decrypt server_encrypted
            let encrypted = match hex::decode(access.server_encrypted.trim_start_matches("0x")) {
                Ok(e) => e,
                Err(_) => {
                    debug!("Token {} has invalid encrypted data", nft.token_id);
                    continue;
                }
            };

            let decrypted = match ecies::decrypt(&private_key, &encrypted) {
                Ok(d) => d,
                Err(_) => {
                    debug!("Token {} decryption failed", nft.token_id);
                    continue;
                }
            };

            let machine_id = match String::from_utf8(decrypted) {
                Ok(s) => s,
                Err(_) => {
                    debug!("Token {} decrypted to invalid UTF-8", nft.token_id);
                    continue;
                }
            };

            // Check if machine ID matches
            if machine_id == params.expected_machine_id {
                info!(
                    "Verified access for wallet {} with token {}",
                    params.wallet_address, nft.token_id
                );

                return Response::success(
                    nft.token_id,
                    Some(MetadataResponse {
                        name: metadata.name,
                        description: metadata.description,
                        image: metadata.image,
                        animation_url: metadata.animation_url,
                    }),
                );
            }

            debug!(
                "Token {} machine ID mismatch: {} != {}",
                nft.token_id, machine_id, params.expected_machine_id
            );
        }

        Response::error("no NFT found with matching machine ID")
    }
}

async fn handle_connection(service: Arc<Service>, mut stream: UnixStream) {
    loop {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break; // Connection closed
        }
        let msg_len = u32::from_be_bytes(len_buf) as usize;

        if msg_len > 1024 * 1024 {
            error!("Message too large: {} bytes", msg_len);
            break;
        }

        // Read message
        let mut msg_buf = vec![0u8; msg_len];
        if stream.read_exact(&mut msg_buf).await.is_err() {
            break;
        }

        // Parse request
        let request: Request = match serde_json::from_slice(&msg_buf) {
            Ok(r) => r,
            Err(e) => {
                let response = Response::error(format!("invalid request: {}", e));
                let _ = send_response(&mut stream, &response).await;
                continue;
            }
        };

        debug!("Received request: {}", request.method);

        // Handle request
        let response = service.handle_request(request).await;

        // Send response
        if send_response(&mut stream, &response).await.is_err() {
            break;
        }
    }
}

async fn send_response(stream: &mut UnixStream, response: &Response) -> Result<(), std::io::Error> {
    let response_bytes = serde_json::to_vec(response).unwrap();
    let len = response_bytes.len() as u32;

    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&response_bytes).await?;
    stream.flush().await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("web3_auth_svc=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    // Load configuration
    let config_content = std::fs::read_to_string(&args.config)
        .with_context(|| format!("failed to read config: {:?}", args.config))?;

    let mut config: Config = toml::from_str(&config_content)
        .with_context(|| format!("failed to parse config: {:?}", args.config))?;

    // Override socket path if specified
    if let Some(socket) = args.socket {
        config.socket_path = socket.to_string_lossy().to_string();
    }

    // Create service
    let service = Arc::new(Service::new(config.clone())?);

    // Create socket directory if needed
    if let Some(parent) = std::path::Path::new(&config.socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove existing socket
    let _ = std::fs::remove_file(&config.socket_path);

    // Create Unix socket listener
    let listener = UnixListener::bind(&config.socket_path)?;

    // Set socket permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o660))?;
    }

    info!("Listening on {}", config.socket_path);

    // Accept connections
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let service = Arc::clone(&service);
                tokio::spawn(async move {
                    handle_connection(service, stream).await;
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}
