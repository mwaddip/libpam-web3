//! PAM Web3 Authentication Module
//!
//! Authenticate Linux users via wallet signatures.
//!
//! # Authentication Flow
//!
//! 1. PAM generates OTP challenge bound to machine ID
//! 2. User signs OTP with their wallet
//! 3. Signature is delivered via callback or manual paste
//! 4. PAM recovers/extracts wallet address (chain-specific)
//! 5. Wallet address matched against GECOS field (wallet=ADDRESS)
//! 6. User authenticated as matching Linux user
//!
//! # Signature Dispatch
//!
//! - Manual paste → always EVM (secp256k1 ecrecover)
//! - Callback `.sig` file:
//!   - Raw hex (0x + 130 chars) → EVM ecrecover (built-in)
//!   - JSON with `chain` field → dispatch to chain-specific handler
//!   - JSON without `chain` → reject
//!
//! # Security
//!
//! - OTP is bound to machine ID and timestamp (prevents replay attacks)
//! - Signature verification uses secp256k1 ecrecover (EVM)
//! - OPNet path validates OTP before trusting wallet address
//! - Fail-secure: any error results in authentication denial

pub mod callback;
pub mod config;
pub mod otp;
pub mod passwd_lookup;
pub mod signature;

pub mod plugin;

use config::Config;
use otp::Otp;
use pam::ffi::{pam_conv, pam_get_item, pam_set_item, PAM_CONV, PAM_USER};
use pam::{export_pam_module, PamHandle, PamModule, PamReturnCode};
use serde::Deserialize;
use std::ffi::{c_int, c_void, CStr, CString};
use std::os::raw::c_uint;
use std::ptr;

const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_TEXT_INFO: c_int = 4;
const CALLBACK_GRACE_SECONDS: u64 = 10;

/// Structured `.sig` file envelope — all non-EVM chains use this format.
/// The `chain` field determines which verification path to use.
#[derive(Debug, Deserialize)]
struct SigEnvelope {
    chain: String,
    // Remaining fields are chain-specific; consumed by chain handlers
    // that re-parse the full JSON. This catch-all prevents serde from
    // rejecting unknown fields during envelope extraction.
    #[serde(flatten)]
    #[allow(dead_code)]
    fields: serde_json::Value,
}

/// OPNet callback payload: wallet address + OTP delivered via trusted channel.
/// The auth-svc verifies the ML-DSA signature before writing this — PAM trusts
/// the wallet_address assertion and re-validates the OTP as defense-in-depth.
#[derive(Debug, Deserialize)]
struct OPNetSig {
    wallet_address: String,
    otp: String,
    machine_id: String,
}

/// PAM module entry point
pub struct PamWeb3;

impl PamModule for PamWeb3 {
    fn authenticate(handle: &PamHandle, _args: Vec<&CStr>, _flags: c_uint) -> PamReturnCode {
        unsafe {
            libc::openlog(
                b"pam_web3\0".as_ptr() as *const i8,
                libc::LOG_PID,
                libc::LOG_AUTH,
            );
        }

        let result = match authenticate_impl(handle) {
            Ok(username) => {
                if set_pam_user(handle, &username).is_err() {
                    PamReturnCode::Auth_Err
                } else {
                    PamReturnCode::Success
                }
            }
            Err(_) => PamReturnCode::Auth_Err,
        };

        unsafe { libc::closelog(); }
        result
    }

    fn set_credentials(_handle: &PamHandle, _args: Vec<&CStr>, _flags: c_uint) -> PamReturnCode {
        PamReturnCode::Success
    }

    fn account_management(_handle: &PamHandle, _args: Vec<&CStr>, _flags: c_uint) -> PamReturnCode {
        PamReturnCode::Success
    }
}

export_pam_module!(PamWeb3);

/// Send a message to the user and get a response via PAM conversation
fn pam_prompt(
    handle: &PamHandle,
    msg_style: c_int,
    message: &str,
) -> Result<Option<String>, AuthError> {
    let mut conv_ptr: *const c_void = ptr::null();
    let handle_ptr = handle as *const PamHandle as *mut PamHandle;

    let result = unsafe { pam_get_item(handle_ptr, PAM_CONV, &mut conv_ptr) };

    if result != 0 || conv_ptr.is_null() {
        return Err(AuthError::ConvError);
    }

    let conv = unsafe { &*(conv_ptr as *const pam_conv) };
    let conv_fn = conv.conv.ok_or(AuthError::ConvError)?;

    let msg_cstring = CString::new(message).map_err(|_| AuthError::ConvError)?;
    let pam_msg = pam::ffi::pam_message {
        msg_style,
        msg: msg_cstring.as_ptr(),
    };
    let msg_ptr: *const pam::ffi::pam_message = &pam_msg;
    let msg_ptr_ptr: *mut *const pam::ffi::pam_message = &mut (msg_ptr as *const _);

    let mut resp_ptr: *mut pam::ffi::pam_response = ptr::null_mut();

    let result = unsafe { conv_fn(1, msg_ptr_ptr, &mut resp_ptr, conv.appdata_ptr) };

    if result != 0 {
        return Err(AuthError::ConvError);
    }

    if !resp_ptr.is_null() {
        let resp = unsafe { &*resp_ptr };
        if !resp.resp.is_null() {
            let response = unsafe { CStr::from_ptr(resp.resp) }
                .to_str()
                .map_err(|_| AuthError::ConvError)?
                .to_string();
            unsafe {
                libc::free(resp.resp as *mut c_void);
                libc::free(resp_ptr as *mut c_void);
            }
            return Ok(Some(response));
        }
        unsafe {
            libc::free(resp_ptr as *mut c_void);
        }
    }

    Ok(None)
}

/// Get the PAM user (the username provided by the SSH client).
fn get_pam_user(handle: &PamHandle) -> Result<String, AuthError> {
    let mut user_ptr: *const c_void = ptr::null();
    let handle_ptr = handle as *const PamHandle as *mut PamHandle;

    let result = unsafe { pam_get_item(handle_ptr, PAM_USER, &mut user_ptr) };

    if result != 0 || user_ptr.is_null() {
        return Err(AuthError::ConvError);
    }

    let user_cstr = unsafe { CStr::from_ptr(user_ptr as *const i8) };
    let username = user_cstr
        .to_str()
        .map_err(|_| AuthError::ConvError)?
        .to_string();

    if username.is_empty() {
        return Err(AuthError::ConvError);
    }

    Ok(username)
}

/// Set the PAM user
fn set_pam_user(handle: &PamHandle, username: &str) -> Result<(), AuthError> {
    let username_cstring = CString::new(username).map_err(|_| AuthError::ConvError)?;
    let handle_ptr = handle as *const PamHandle as *mut PamHandle;

    let result =
        unsafe { pam_set_item(handle_ptr, PAM_USER, username_cstring.as_ptr() as *const c_void) };

    if result != 0 {
        return Err(AuthError::ConvError);
    }

    Ok(())
}

/// Derive the machine's FQDN for signing URL construction.
///
/// Strategy:
/// 1. `gethostname()` — returns the FQDN on cloud VMs where cloud-init sets it
/// 2. `/etc/hosts` scan — finds the dotted alias for the short hostname
/// 3. Fall back to the raw hostname if no FQDN is found
fn derive_hostname() -> String {
    let mut buf = vec![0u8; 256];
    let hostname = unsafe {
        let ret = libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len());
        if ret != 0 {
            return "localhost".to_string();
        }
        match std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return "localhost".to_string(),
        }
    };

    // Already FQDN (contains a dot)
    if hostname.contains('.') {
        return hostname;
    }

    // Scan /etc/hosts for a dotted alias for this hostname
    if let Ok(content) = std::fs::read_to_string("/etc/hosts") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 2 {
                continue;
            }
            // Check if hostname appears as any alias on this line
            if tokens[1..].iter().any(|t| *t == hostname) {
                // Return the first dotted name (FQDN) on the line
                for token in &tokens[1..] {
                    if token.contains('.') {
                        return token.to_string();
                    }
                }
            }
        }
    }

    hostname
}

/// Derive a deterministic port for a chain's auth-svc.
///
/// Convention: `1024 + (crc32(chain_name) % 64511)` — stable port in 1024..65534
/// with no cross-plugin coordination.  Must match the same CRC32 in each auth-svc.
fn chain_port(chain: &str) -> u16 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for byte in chain.as_bytes() {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    (1024 + ((crc ^ 0xFFFF_FFFF) % 64511)) as u16
}

/// Read the pre-resolved signing host from `/run/libpam-web3/signing_host`.
///
/// Written once at boot by `libpam-web3-signing-host.service` which checks
/// public DNS, falls back to sslip.io.  If the file doesn't exist (service
/// not running), falls back to `derive_hostname()`.
fn read_signing_host() -> String {
    match std::fs::read_to_string("/run/libpam-web3/signing_host") {
        Ok(s) => {
            let trimmed = s.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        Err(_) => {}
    }
    derive_hostname()
}

/// Build the signing URL for the given chain.
///
/// Format: `{scheme}://{signing_host}:{derived_port}` where scheme is
/// `https` by default, or `http` when `auth.use_tls = false` in config
/// (for backends like Tor that provide their own encryption).
fn signing_url_for(chain: &str) -> String {
    let host = read_signing_host();
    let port = chain_port(chain);
    let use_tls = Config::load().map(|c| c.auth.use_tls).unwrap_or(true);
    let scheme = if use_tls { "https" } else { "http" };
    format!("{}://{}:{}", scheme, host, port)
}

/// Log to syslog for debugging
///
/// Requires openlog() to have been called first (done in authenticate()).
fn syslog(msg: &str) {
    use std::ffi::CString;
    if let Ok(c_msg) = CString::new(format!("pam_web3: {}", msg)) {
        unsafe {
            libc::syslog(libc::LOG_INFO, b"%s\0".as_ptr() as *const i8, c_msg.as_ptr());
        }
    }
}

/// Internal authentication implementation
fn authenticate_impl(handle: &PamHandle) -> Result<String, AuthError> {
    syslog("Starting authentication");

    // Load configuration
    let config = Config::load().map_err(|e| {
        syslog(&format!("Failed to load config: {:?}", e));
        AuthError::ConfigError
    })?;
    syslog("Config loaded");

    let secret_key = config.secret_key_bytes().map_err(|_| AuthError::ConfigError)?;

    // Get the claimed username and look up their wallet from GECOS
    let username = get_pam_user(handle).map_err(|e| {
        syslog(&format!("Failed to get PAM user: {:?}", e));
        e
    })?;
    syslog(&format!("Authenticating user: {}", username));

    let expected_wallet = passwd_lookup::lookup_wallet_for_user(&username).map_err(|e| {
        syslog(&format!("No wallet in GECOS for user {}: {:?}", username, e));
        AuthError::WalletNotFound
    })?;
    syslog(&format!("GECOS wallet: {}", expected_wallet));

    // Discover installed plugins and find the one matching this wallet address.
    // If a plugin matches, use its signing URL. Otherwise fall back to EVM
    // with the signing URL from config.
    let plugins = plugin::discover_plugins();
    for p in &plugins {
        syslog(&format!("Discovered plugin: {} ({})", p.info.chain, p.info.address_pattern));
    }

    let matched_plugin = plugin::find_plugin_for_address(&plugins, &expected_wallet);
    let chain_name = match &matched_plugin {
        Some(p) => {
            syslog(&format!("Wallet matches plugin: {}", p.info.chain));
            p.info.chain.clone()
        }
        None => {
            syslog("No plugin matched wallet — using EVM default");
            "evm".to_string()
        }
    };

    // Generate OTP
    let otp_instance = Otp::generate(config.auth.otp_length, &config.machine.id, &secret_key)
        .map_err(|_| AuthError::OtpError)?;

    // Try to create a callback session (detected at runtime by directory existence)
    let session = match callback::Session::create(&otp_instance.code, &config.machine.id) {
        Ok(s) => {
            syslog(&format!("Callback session created: {}", s.session_id));
            Some(s)
        }
        Err(e) => {
            syslog(&format!("Callback not available (manual-only): {}", e));
            None
        }
    };

    // Build signing URL: https://{fqdn}:{derived_port}[?session={id}]
    let signing_url_base = signing_url_for(&chain_name);
    let signing_url = match &session {
        Some(s) => format!("{}?session={}", signing_url_base, s.session_id),
        None => signing_url_base,
    };

    // Display OTP and signing URL to user
    let info_message = format!(
        "\n=== Web3 Authentication ===\nCode: {}\nMachine: {}\nSign at: {}\n",
        otp_instance.code, config.machine.id, signing_url
    );

    pam_prompt(handle, PAM_TEXT_INFO, &info_message)?;

    // Prompt for signature
    let prompt_text = if session.is_some() {
        "Press Enter after signing in browser, or paste signature: "
    } else {
        "Paste signature: "
    };

    let sig_input = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, prompt_text)?
        .unwrap_or_default();

    // Resolve signature and track source.
    // Manual paste → always EVM ecrecover.
    // Callback .sig → chain dispatch (EVM raw hex, or JSON with chain field).
    let (sig, from_callback) = if !sig_input.is_empty() {
        (sig_input, false)
    } else if let Some(ref s) = session {
        syslog("Empty input, polling for callback signature...");
        match s.wait_for_callback(CALLBACK_GRACE_SECONDS) {
            Some(sig) => {
                syslog("Got callback signature");
                (sig, true)
            }
            None => {
                syslog("No callback signature received");
                return Err(AuthError::NoSignature);
            }
        }
    } else {
        syslog("Empty signature");
        return Err(AuthError::NoSignature);
    };
    syslog(&format!(
        "Got signature ({}): {}...{}",
        if from_callback { "callback" } else { "manual" },
        &sig[..10.min(sig.len())],
        &sig[sig.len().saturating_sub(10)..]
    ));

    // Dispatch verification
    let verified_wallet = if from_callback {
        dispatch_callback_sig(&sig, &otp_instance, &config, &secret_key, &expected_wallet)?
    } else {
        verify_evm(&sig, &otp_instance, &config, &secret_key)?
    };

    // Confirm the verified wallet matches the user's GECOS wallet
    if verified_wallet.to_lowercase() != expected_wallet.to_lowercase() {
        syslog(&format!(
            "Wallet mismatch: verified={} expected={}",
            verified_wallet, expected_wallet
        ));
        return Err(AuthError::WalletMismatch);
    }

    syslog(&format!("Auth success for user: {}", username));
    Ok(username)
}

/// Dispatch a callback `.sig` file to the appropriate chain handler.
///
/// Detection:
/// - Raw hex starting with 0x, 132 chars total → EVM (built-in ecrecover)
/// - JSON with `chain` field → chain-specific handler
/// - JSON without `chain` → reject
/// - Anything else → reject
fn dispatch_callback_sig(
    sig: &str,
    otp_instance: &Otp,
    config: &Config,
    secret_key: &[u8],
    wallet_address: &str,
) -> Result<String, AuthError> {
    let trimmed = sig.trim();

    // EVM: raw hex signature (0x + 130 hex chars = 132 total)
    if trimmed.starts_with("0x") && trimmed.len() == 132 {
        syslog("Callback .sig: EVM raw hex detected");
        return verify_evm(trimmed, otp_instance, config, secret_key);
    }

    // Must be JSON with a `chain` field
    let envelope: SigEnvelope = serde_json::from_str(trimmed).map_err(|e| {
        syslog(&format!("Callback .sig: not valid hex or JSON: {}", e));
        AuthError::InvalidSignature
    })?;

    syslog(&format!("Callback .sig: chain={}", envelope.chain));

    match envelope.chain.as_str() {
        "opnet" => verify_opnet(trimmed, otp_instance, config, secret_key),
        chain => invoke_plugin(chain, trimmed, otp_instance, wallet_address),
    }
}

/// EVM verification: secp256k1 ecrecover to recover wallet address from signature.
fn verify_evm(
    sig: &str,
    otp_instance: &Otp,
    config: &Config,
    secret_key: &[u8],
) -> Result<String, AuthError> {
    syslog("EVM signature verification");

    let message = otp_instance.signing_message();
    syslog(&format!("Message: {}", message));

    let wallet_address = signature::recover_address(&message, sig).map_err(|e| {
        syslog(&format!("Signature recovery failed: {:?}", e));
        AuthError::InvalidSignature
    })?;
    syslog(&format!("Recovered address: {}", wallet_address));

    // Verify OTP hasn't expired
    otp_instance
        .verify(
            &otp_instance.code,
            &config.machine.id,
            secret_key,
            config.auth.otp_ttl_seconds,
        )
        .map_err(|e| {
            syslog(&format!("OTP verification failed: {:?}", e));
            AuthError::OtpExpired
        })?;
    syslog("OTP verified");

    Ok(format!("{}", wallet_address))
}

/// OPNet verification: validate OTP, then trust the wallet_address from the
/// auth-svc's assertion. The auth-svc has already verified the ML-DSA signature.
fn verify_opnet(
    sig_json: &str,
    otp_instance: &Otp,
    config: &Config,
    secret_key: &[u8],
) -> Result<String, AuthError> {
    syslog("OPNet callback verification");

    let opnet: OPNetSig = serde_json::from_str(sig_json).map_err(|e| {
        syslog(&format!("OPNet JSON parse failed: {}", e));
        AuthError::InvalidSignature
    })?;

    otp_instance
        .verify(
            &opnet.otp,
            &opnet.machine_id,
            secret_key,
            config.auth.otp_ttl_seconds,
        )
        .map_err(|e| {
            syslog(&format!("OPNet OTP verification failed: {:?}", e));
            AuthError::OtpExpired
        })?;
    syslog("OPNet OTP verified");

    if opnet.wallet_address.is_empty() {
        syslog("OPNet callback has empty wallet_address");
        return Err(AuthError::InvalidSignature);
    }

    Ok(opnet.wallet_address)
}

/// Invoke an external chain plugin for verification.
/// The plugin receives the .sig JSON and OTP message on stdin,
/// returns the wallet address on stdout (exit 0) or denies (non-zero).
fn invoke_plugin(
    chain: &str,
    sig_json: &str,
    otp_instance: &Otp,
    wallet_address: &str,
) -> Result<String, AuthError> {
    syslog(&format!("Invoking plugin for chain: {}", chain));

    let sig_value: serde_json::Value = serde_json::from_str(sig_json).map_err(|e| {
        syslog(&format!("Failed to re-parse .sig JSON for plugin: {}", e));
        AuthError::InvalidSignature
    })?;

    let otp_message = otp_instance.signing_message();

    match plugin::invoke(chain, &sig_value, &otp_message, wallet_address) {
        plugin::PluginResult::Verified(wallet) => {
            syslog(&format!("Plugin verified, wallet: {}", wallet));
            Ok(wallet)
        }
        plugin::PluginResult::Denied(reason) => {
            syslog(&format!("Plugin denied: {}", reason));
            Err(AuthError::InvalidSignature)
        }
        plugin::PluginResult::NotFound => {
            syslog(&format!("No plugin found for chain: {}", chain));
            Err(AuthError::UnsupportedChain)
        }
        plugin::PluginResult::ExecError(err) => {
            syslog(&format!("Plugin exec error: {}", err));
            Err(AuthError::PluginError)
        }
    }
}

/// Authentication error types
#[derive(Debug)]
enum AuthError {
    ConfigError,
    ConvError,
    OtpError,
    OtpExpired,
    NoSignature,
    InvalidSignature,
    UnsupportedChain,
    PluginError,
    WalletNotFound,
    WalletMismatch,
}
