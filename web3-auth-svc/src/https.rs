//! HTTPS server for callback-based signing.
//!
//! Serves the signing page and provides endpoints for session data retrieval
//! and signature callback. The PAM module writes `.json` session files; the
//! browser fetches them here and POSTs back the signature as a `.sig` file.

use axum::body::Body;
use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

const PENDING_DIR: &str = "/run/libpam-web3/pending";
const MAX_BODY_SIZE: usize = 256;

/// Shared state for HTTPS handlers.
struct AppState {
    signing_page: String,
}

/// Create the axum router with all callback endpoints.
pub fn create_router(signing_page_path: &str) -> Result<Router, std::io::Error> {
    let html = std::fs::read_to_string(signing_page_path)?;
    let state = Arc::new(AppState { signing_page: html });

    let router = Router::new()
        .route("/", get({
            let state = Arc::clone(&state);
            move || serve_signing_page(state)
        }))
        .route("/auth/pending/{session_id}", get(get_pending_session))
        .route("/auth/callback/{session_id}", post(post_callback));

    Ok(router)
}

/// GET / — Serve the signing page HTML.
async fn serve_signing_page(state: Arc<AppState>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(state.signing_page.clone()))
        .unwrap()
}

/// GET /auth/pending/:session_id — Return session JSON.
async fn get_pending_session(Path(session_id): Path<String>) -> Response {
    if !is_valid_session_id(&session_id) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let json_path = PathBuf::from(PENDING_DIR).join(format!("{}.json", session_id));
    match std::fs::read_to_string(&json_path) {
        Ok(contents) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(contents))
            .unwrap(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// POST /auth/callback/:session_id — Accept signature, write .sig file.
async fn post_callback(
    Path(session_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    if !is_valid_session_id(&session_id) {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Enforce body size limit
    if body.len() > MAX_BODY_SIZE {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }

    let pending = PathBuf::from(PENDING_DIR);
    let json_path = pending.join(format!("{}.json", session_id));
    let sig_path = pending.join(format!("{}.sig", session_id));
    let tmp_path = pending.join(format!("{}.sig.tmp", session_id));

    // Session must exist
    if !json_path.exists() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Prevent overwrite of existing signature
    if sig_path.exists() {
        return StatusCode::CONFLICT.into_response();
    }

    // Validate signature format
    let sig_str = match std::str::from_utf8(&body) {
        Ok(s) => s.trim(),
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid UTF-8").into_response(),
    };

    if !is_valid_signature(sig_str) {
        return (StatusCode::BAD_REQUEST, "invalid signature format").into_response();
    }

    // Atomic write: .sig.tmp → rename → .sig
    if let Err(e) = std::fs::write(&tmp_path, sig_str.as_bytes()) {
        warn!("Failed to write sig tmp: {}", e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(e) = std::fs::rename(&tmp_path, &sig_path) {
        warn!("Failed to rename sig: {}", e);
        let _ = std::fs::remove_file(&tmp_path);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    info!("Callback signature received for session {}", session_id);
    StatusCode::OK.into_response()
}

/// Validate session ID: exactly 32 lowercase hex characters.
fn is_valid_session_id(id: &str) -> bool {
    id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate signature format: optional 0x prefix + 130 hex characters.
fn is_valid_signature(sig: &str) -> bool {
    let hex_part = sig.strip_prefix("0x").unwrap_or(sig);
    hex_part.len() == 130 && hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

/// Load TLS certificate chain from a PEM file.
pub fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

/// Load a private key from a PEM file (tries PKCS8, RSA, EC formats).
pub fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
            }
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
            }
            Some(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(rustls::pki_types::PrivateKeyDer::Sec1(key));
            }
            Some(_) => continue,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "no private key found in PEM file",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_session_id() {
        assert!(is_valid_session_id("abcdef0123456789abcdef0123456789"));
        assert!(is_valid_session_id("ABCDEF0123456789abcdef0123456789"));
        assert!(!is_valid_session_id("abcdef0123456789")); // too short
        assert!(!is_valid_session_id("abcdef0123456789abcdef0123456789aa")); // too long
        assert!(!is_valid_session_id("abcdef0123456789abcdef012345678g")); // non-hex
        assert!(!is_valid_session_id("")); // empty
    }

    #[test]
    fn test_valid_signature() {
        // 130 hex chars with 0x prefix
        let sig = format!("0x{}", "ab".repeat(65));
        assert!(is_valid_signature(&sig));

        // 130 hex chars without prefix
        let sig = "ab".repeat(65);
        assert!(is_valid_signature(&sig));

        // Wrong length
        let sig = format!("0x{}", "ab".repeat(64));
        assert!(!is_valid_signature(&sig));

        // Non-hex
        let mut sig = "ab".repeat(65);
        sig.replace_range(0..1, "g");
        assert!(!is_valid_signature(&sig));
    }
}
