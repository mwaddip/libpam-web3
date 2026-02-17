//! web3-auth-svc - HTTPS server for callback-based signing
//!
//! This daemon serves the signing page and provides HTTPS endpoints for
//! session data retrieval and signature callback. The PAM module writes
//! session files; the browser fetches them here and POSTs back the signature.

mod https;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use tracing::{error, info};

/// web3-auth-svc - Authentication signing page server
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/web3-auth/config.toml")]
    config: PathBuf,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,
}

/// Service configuration
#[derive(Debug, Clone, Deserialize)]
struct Config {
    /// HTTPS server config (required)
    https: HttpsConfig,
}

/// HTTPS server configuration for callback-based signing
#[derive(Debug, Clone, Deserialize)]
struct HttpsConfig {
    /// HTTPS port
    #[serde(default = "default_https_port")]
    port: u16,
    /// Bind addresses (combined with port). Default: dual-stack IPv6+IPv4.
    #[serde(default = "default_https_bind")]
    bind: Vec<String>,
    /// Path to TLS certificate PEM file
    cert_path: String,
    /// Path to TLS private key PEM file
    key_path: String,
    /// Path to signing page HTML file
    #[serde(default = "default_signing_page_path")]
    signing_page_path: String,
}

fn default_https_port() -> u16 {
    8443
}

fn default_https_bind() -> Vec<String> {
    vec!["::".to_string(), "0.0.0.0".to_string()]
}

fn default_signing_page_path() -> String {
    "/usr/share/libpam-web3/signing-page/index.html".to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    // Select ring as the TLS crypto provider before any TLS context is created.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

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

    let config: Config = toml::from_str(&config_content)
        .with_context(|| format!("failed to parse config: {:?}", args.config))?;

    // Create HTTPS router
    let router = https::create_router(&config.https.signing_page_path)
        .context("failed to create HTTPS router")?;

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        &config.https.cert_path,
        &config.https.key_path,
    )
    .await
    .context("failed to load TLS config")?;

    let port = config.https.port;
    let mut bind_addrs: Vec<std::net::SocketAddr> = Vec::new();
    for addr_str in &config.https.bind {
        let ip: std::net::IpAddr = addr_str
            .parse()
            .with_context(|| format!("invalid HTTPS bind address: {}", addr_str))?;
        bind_addrs.push(std::net::SocketAddr::from((ip, port)));
    }

    // Start all but the last bind address as spawned tasks
    let last_idx = bind_addrs.len().saturating_sub(1);
    for (i, listen_addr) in bind_addrs.into_iter().enumerate() {
        let router = router.clone();
        let tls = tls_config.clone();

        info!("HTTPS server listening on {}", listen_addr);

        if i < last_idx {
            tokio::spawn(async move {
                if let Err(e) = axum_server::bind_rustls(listen_addr, tls)
                    .serve(router.into_make_service())
                    .await
                {
                    error!("HTTPS server error on {}: {}", listen_addr, e);
                }
            });
        } else {
            // Last address runs as the blocking main task
            axum_server::bind_rustls(listen_addr, tls)
                .serve(router.into_make_service())
                .await
                .with_context(|| format!("HTTPS server failed on {}", listen_addr))?;
        }
    }

    Ok(())
}
