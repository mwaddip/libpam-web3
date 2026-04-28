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

    let conv_result = unsafe { conv_fn(1, msg_ptr_ptr, &mut resp_ptr, conv.appdata_ptr) };

    // PAM convention: the conv fn may have allocated resp/resp_ptr even on
    // a non-zero return. Free whatever is there before propagating the
    // error so we don't leak per-prompt.
    let extracted: Result<Option<String>, AuthError> = if !resp_ptr.is_null() {
        let resp_str_ptr = unsafe { (*resp_ptr).resp };
        let result = if !resp_str_ptr.is_null() {
            match unsafe { CStr::from_ptr(resp_str_ptr) }.to_str() {
                Ok(s) => Ok(Some(s.to_string())),
                Err(_) => Err(AuthError::ConvError),
            }
        } else {
            Ok(None)
        };
        unsafe {
            if !resp_str_ptr.is_null() {
                libc::free(resp_str_ptr as *mut c_void);
            }
            libc::free(resp_ptr as *mut c_void);
        }
        result
    } else {
        Ok(None)
    };

    if conv_result != 0 {
        return Err(AuthError::ConvError);
    }

    extracted
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

/// Fallback hostname when `/run/libpam-web3/signing_host` isn't available.
///
/// Returns whatever `gethostname()` reports. The signing-host service is the
/// authoritative source for the user-facing host (with public-DNS check and
/// sslip.io fallback) — this is only used when that service hasn't run.
///
/// We deliberately do not consult `/etc/hosts`: an attacker with /etc/hosts
/// write access already has root, and an unprivileged poison would be a
/// usable phishing surface (attacker-controlled FQDN displayed in the
/// auth prompt).
fn derive_hostname() -> String {
    let mut buf = vec![0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret != 0 {
        return "localhost".to_string();
    }
    match unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => "localhost".to_string(),
    }
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
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
            syslog("signing_host file is empty; falling back to gethostname()");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Expected when libpam-web3-signing-host.service hasn't run yet.
        }
        Err(e) => {
            syslog(&format!(
                "failed to read /run/libpam-web3/signing_host: {}",
                e
            ));
        }
    }
    derive_hostname()
}

/// Build the signing URL for the given chain.
///
/// Format: `{scheme}://{signing_host}:{derived_port}` where scheme is
/// `https` by default, or `http` when `auth.use_tls = false` in config
/// (for backends like Tor that provide their own encryption).
fn signing_url_for(chain: &str, config: &Config) -> String {
    let host = read_signing_host();
    let port = chain_port(chain);
    let scheme = if config.auth.use_tls { "https" } else { "http" };
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
    let signing_url_base = signing_url_for(&chain_name, &config);
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
    let head: String = sig.chars().take(10).collect();
    let tail: String = sig.chars().rev().take(10).collect::<String>().chars().rev().collect();
    syslog(&format!(
        "Got signature ({}): {}...{}",
        if from_callback { "callback" } else { "manual" },
        head,
        tail
    ));

    // Dispatch verification. Each chain-specific verifier compares its
    // recovered/derived address against expected_wallet (the GECOS value)
    // using whatever case rules apply to its chain — PAM no longer
    // post-compares, because case-insensitive folding is wrong for
    // case-sensitive Base58 chains.
    if from_callback {
        dispatch_callback_sig(&sig, &otp_instance, &config, &secret_key, &expected_wallet)?;
    } else {
        verify_evm(&sig, &otp_instance, &config, &secret_key, &expected_wallet)?;
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
    expected_wallet: &str,
) -> Result<(), AuthError> {
    let trimmed = sig.trim();

    // EVM: raw hex signature (0x + 130 hex chars = 132 total)
    if trimmed.starts_with("0x") && trimmed.len() == 132 {
        syslog("Callback .sig: EVM raw hex detected");
        return verify_evm(trimmed, otp_instance, config, secret_key, expected_wallet);
    }

    // Must be JSON with a `chain` field
    let envelope: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
        syslog(&format!("Callback .sig: not valid hex or JSON: {}", e));
        AuthError::InvalidSignature
    })?;

    let chain = match envelope.get("chain").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => {
            syslog("Callback .sig: missing or non-string `chain` field");
            return Err(AuthError::InvalidSignature);
        }
    };

    syslog(&format!("Callback .sig: chain={}", chain));

    match chain {
        "opnet" => verify_opnet(trimmed, otp_instance, config, secret_key, expected_wallet),
        other => invoke_plugin(other, trimmed, otp_instance, expected_wallet),
    }
}

/// EVM verification: ecrecover, then compare against expected_wallet.
///
/// alloy's `Address::FromStr` accepts any-case hex (with or without checksum),
/// so the `==` between the parsed expected and the recovered Address is the
/// canonical EVM-correct match.
fn verify_evm(
    sig: &str,
    otp_instance: &Otp,
    config: &Config,
    secret_key: &[u8],
    expected_wallet: &str,
) -> Result<(), AuthError> {
    syslog("EVM signature verification");

    // Cheap timestamp/HMAC check before the EC recovery — no point burning
    // ecrecover on stale OTPs, and it tightens the failure surface for spam.
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

    let message = otp_instance.signing_message();
    let recovered = signature::recover_address(&message, sig).map_err(|e| {
        syslog(&format!("Signature recovery failed: {:?}", e));
        AuthError::InvalidSignature
    })?;

    let expected: alloy_primitives::Address = expected_wallet.parse().map_err(|_| {
        syslog(&format!("GECOS wallet not a valid EVM address: {}", expected_wallet));
        AuthError::WalletMismatch
    })?;

    if recovered != expected {
        syslog(&format!(
            "EVM wallet mismatch: recovered={} expected={}",
            recovered, expected
        ));
        return Err(AuthError::WalletMismatch);
    }

    Ok(())
}

/// OPNet verification: validate OTP, then trust the wallet_address from the
/// auth-svc's assertion. The auth-svc has already verified the ML-DSA signature.
/// OPNet addresses are 0x + lowercase hex by construction, so case-sensitive
/// equality is correct here.
fn verify_opnet(
    sig_json: &str,
    otp_instance: &Otp,
    config: &Config,
    secret_key: &[u8],
    expected_wallet: &str,
) -> Result<(), AuthError> {
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

    if opnet.wallet_address != expected_wallet {
        syslog(&format!(
            "OPNet wallet mismatch: asserted={} expected={}",
            opnet.wallet_address, expected_wallet
        ));
        return Err(AuthError::WalletMismatch);
    }

    Ok(())
}

/// Invoke an external chain plugin for verification.
///
/// The plugin owns the comparison: PAM passes expected_wallet on stdin, and
/// the plugin internally derives the address from cryptographic material and
/// compares it with whatever case rules apply to that chain. PAM trusts only
/// the exit code — stdout is ignored (post-v2 protocol).
fn invoke_plugin(
    chain: &str,
    sig_json: &str,
    otp_instance: &Otp,
    expected_wallet: &str,
) -> Result<(), AuthError> {
    syslog(&format!("Invoking plugin for chain: {}", chain));

    let sig_value: serde_json::Value = serde_json::from_str(sig_json).map_err(|e| {
        syslog(&format!("Failed to re-parse .sig JSON for plugin: {}", e));
        AuthError::InvalidSignature
    })?;

    let otp_message = otp_instance.signing_message();

    match plugin::invoke(chain, &sig_value, &otp_message, expected_wallet) {
        plugin::PluginResult::Verified => {
            syslog(&format!("Plugin verified for chain: {}", chain));
            Ok(())
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
