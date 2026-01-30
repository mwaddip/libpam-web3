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
use protocol::{GetNftsParams, Request, Response};
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
            "get_nfts" => self.handle_get_nfts(request.params).await,
            // Legacy method name for backwards compatibility
            "verify_access" => self.handle_get_nfts(request.params).await,
            "health" => Response::success_single("ok".to_string(), None),
            _ => Response::error(format!("unknown method: {}", request.method)),
        }
    }

    /// Get all NFT token IDs owned by a wallet
    ///
    /// The PAM module uses this to get token IDs, then matches against
    /// GECOS entries in /etc/passwd. No server-side decryption needed.
    async fn handle_get_nfts(&self, params: serde_json::Value) -> Response {
        let params: GetNftsParams = match serde_json::from_value(params) {
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

        // Return all token IDs - PAM module will match against GECOS
        let token_ids: Vec<String> = nfts.into_iter().map(|n| n.token_id).collect();

        info!(
            "Found {} NFTs for wallet {}: {:?}",
            token_ids.len(),
            params.wallet_address,
            token_ids
        );

        Response::success_multiple(token_ids)
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
