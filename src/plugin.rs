//! Chain-specific verification plugin system.
//!
//! Plugins are standalone executables installed to [`PLUGIN_DIR`]. PAM discovers
//! them at startup by sending `{"command":"info"}` to each binary and caching
//! the response. At auth time, PAM matches the user's GECOS wallet address
//! against each plugin's `address_pattern` regex to find the right chain.
//!
//! # Plugin Protocol
//!
//! ## Discovery (info)
//!
//! **stdin:** `{"command":"info"}`
//! **stdout:** `{"chain":"cardano","address_pattern":"^addr..."}`
//! **exit:** 0 = success
//!
//! ## Verification (verify)
//!
//! **stdin:** `{"sig": <.sig JSON>, "otp_message": "...", "wallet_address": "..."}`
//! **stdout:** wallet address on success
//! **exit:** 0 = verified, non-zero = denied

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Directory where chain plugins are installed.
pub const PLUGIN_DIR: &str = "/usr/lib/libpam-web3/plugins";

/// Maximum time a plugin may run before being killed.
const PLUGIN_TIMEOUT_SECS: u64 = 10;

/// Maximum time for the info command (should be near-instant).
const INFO_TIMEOUT_SECS: u64 = 2;

// ── Discovery ────────────────────────────────────────────────────────

/// Plugin metadata returned by the `info` command.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginInfo {
    /// Chain identifier (e.g. "cardano", "opnet"). Must match the .sig `chain` field.
    pub chain: String,
    /// Regex pattern that matches wallet addresses handled by this plugin.
    pub address_pattern: String,
}

/// A discovered plugin: metadata + path to the binary.
#[derive(Debug, Clone)]
pub struct DiscoveredPlugin {
    pub info: PluginInfo,
    pub path: PathBuf,
    /// Compiled regex (compiled once at discovery, reused per auth).
    compiled_pattern: Option<regex::Regex>,
}

impl DiscoveredPlugin {
    /// Check whether a wallet address matches this plugin's address pattern.
    pub fn matches_address(&self, wallet_address: &str) -> bool {
        match &self.compiled_pattern {
            Some(re) => re.is_match(wallet_address),
            None => false,
        }
    }
}

/// Scan the plugin directory and query each plugin for its info.
/// Returns a list of successfully discovered plugins. Plugins that fail
/// to respond or return invalid info are logged and skipped.
pub fn discover_plugins() -> Vec<DiscoveredPlugin> {
    let dir = Path::new(PLUGIN_DIR);
    if !dir.is_dir() {
        return Vec::new();
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut plugins = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() || !is_executable(&path) {
            continue;
        }

        match query_plugin_info(&path) {
            Ok(info) => {
                let compiled_pattern = regex::Regex::new(&info.address_pattern).ok();
                if compiled_pattern.is_none() {
                    // Log but still register — pattern may be fixed later
                    eprintln!(
                        "plugin {}: invalid address_pattern regex: {}",
                        path.display(),
                        info.address_pattern
                    );
                }
                plugins.push(DiscoveredPlugin {
                    info,
                    path,
                    compiled_pattern,
                });
            }
            Err(e) => {
                eprintln!("plugin {}: info failed: {}", path.display(), e);
            }
        }
    }

    plugins
}

/// Send `{"command":"info"}` to a plugin and parse the response.
fn query_plugin_info(path: &Path) -> Result<PluginInfo, String> {
    let input = r#"{"command":"info"}"#;

    let mut child = Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn failed: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }

    let output = wait_with_timeout(&mut child, Duration::from_secs(INFO_TIMEOUT_SECS))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("exit {}: {}", output.status, stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    serde_json::from_str(&stdout).map_err(|e| format!("invalid info JSON: {}", e))
}

/// Find the plugin that handles a given wallet address.
pub fn find_plugin_for_address<'a>(
    plugins: &'a [DiscoveredPlugin],
    wallet_address: &str,
) -> Option<&'a DiscoveredPlugin> {
    plugins.iter().find(|p| p.matches_address(wallet_address))
}

// ── Verification ─────────────────────────────────────────────────────

/// Input passed to the plugin on stdin for verification.
#[derive(Serialize)]
pub struct VerifyInput<'a> {
    /// Full `.sig` file content (structured JSON with `chain` + chain-specific fields)
    pub sig: &'a serde_json::Value,
    /// The OTP message the user was expected to sign
    pub otp_message: &'a str,
    /// The wallet address from the user's GECOS field
    pub wallet_address: &'a str,
}

/// Result of a plugin invocation.
#[derive(Debug)]
pub enum PluginResult {
    /// Plugin verified the signature; contains the wallet address.
    Verified(String),
    /// Plugin denied authentication.
    Denied(String),
    /// Plugin binary was not found for this chain.
    NotFound,
    /// Plugin failed to execute (crash, timeout, I/O error).
    ExecError(String),
}

/// Invoke a chain plugin for verification and return the result.
pub fn invoke(
    chain: &str,
    sig_json: &serde_json::Value,
    otp_message: &str,
    wallet_address: &str,
) -> PluginResult {
    let path = plugin_path(chain);

    if !path.is_file() {
        return PluginResult::NotFound;
    }

    if !is_executable(&path) {
        return PluginResult::ExecError(format!("plugin not executable: {}", path.display()));
    }

    let input = VerifyInput {
        sig: sig_json,
        otp_message,
        wallet_address,
    };

    let input_json = match serde_json::to_string(&input) {
        Ok(j) => j,
        Err(e) => return PluginResult::ExecError(format!("failed to serialize input: {}", e)),
    };

    exec_plugin(&path, &input_json)
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Return the path to a plugin binary for the given chain.
pub fn plugin_path(chain: &str) -> PathBuf {
    Path::new(PLUGIN_DIR).join(chain)
}

/// Check whether a plugin exists for the given chain.
pub fn plugin_exists(chain: &str) -> bool {
    let path = plugin_path(chain);
    path.is_file() && is_executable(&path)
}

/// Execute a plugin binary with JSON on stdin, return the result.
fn exec_plugin(path: &Path, input_json: &str) -> PluginResult {
    let mut child = match Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return PluginResult::ExecError(format!("failed to spawn plugin: {}", e)),
    };

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(input_json.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return PluginResult::ExecError(format!("failed to write to plugin stdin: {}", e));
        }
    }

    let output = match wait_with_timeout(&mut child, Duration::from_secs(PLUGIN_TIMEOUT_SECS)) {
        Ok(o) => o,
        Err(e) => return PluginResult::ExecError(e),
    };

    if output.status.success() {
        let wallet = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if wallet.is_empty() {
            PluginResult::Denied("plugin returned empty wallet address".to_string())
        } else {
            PluginResult::Verified(wallet)
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let reason = if stderr.is_empty() {
            format!("plugin exited with status {}", output.status)
        } else {
            stderr
        };
        PluginResult::Denied(reason)
    }
}

/// Wait for a child process with a timeout, polling at short intervals.
///
/// Drains stdout and stderr concurrently with the wait so the child cannot
/// deadlock by filling a 64KB pipe buffer before the parent reads it. On
/// timeout or poll error, the child is killed and reaped before returning so
/// the drainer threads observe EOF and can be joined cleanly.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    use std::io::Read;
    use std::thread;

    let stdout_handle = child.stdout.take().map(|mut s| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|mut s| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });

    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(50);

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(h) = stdout_handle { let _ = h.join(); }
                    if let Some(h) = stderr_handle { let _ = h.join(); }
                    return Err(format!("plugin timed out after {}s", timeout.as_secs()));
                }
                thread::sleep(poll_interval);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(h) = stdout_handle { let _ = h.join(); }
                if let Some(h) = stderr_handle { let _ = h.join(); }
                return Err(format!("failed to poll plugin: {}", e));
            }
        }
    };

    let stdout = stdout_handle.and_then(|h| h.join().ok()).unwrap_or_default();
    let stderr = stderr_handle.and_then(|h| h.join().ok()).unwrap_or_default();

    Ok(std::process::Output { status, stdout, stderr })
}

/// Check whether a file is executable (Unix).
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_path() {
        assert_eq!(
            plugin_path("myplugin"),
            PathBuf::from("/usr/lib/libpam-web3/plugins/myplugin")
        );
    }

    #[test]
    fn test_plugin_not_found() {
        let sig = serde_json::json!({"chain": "nonexistent"});
        let result = invoke("nonexistent", &sig, "test message", "0xdead");
        assert!(matches!(result, PluginResult::NotFound));
    }

    #[test]
    fn test_plugin_exists_returns_false_for_missing() {
        assert!(!plugin_exists("definitely_not_a_real_chain"));
    }

    #[test]
    fn test_discover_returns_empty_when_no_dir() {
        // Plugin dir doesn't exist in test env
        let plugins = discover_plugins();
        assert!(plugins.is_empty());
    }

    /// Spawn `/bin/sh -c <script>` with piped stdio. We don't write the
    /// script to a temp file because cargo runs tests in parallel and the
    /// other test threads' open writable fds get inherited across forks,
    /// triggering ETXTBSY on exec.
    fn spawn_sh(script: &str) -> std::process::Child {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// Regression: a child writing more than the OS pipe buffer (~64KB) used to
    /// block on write() because we only drained stdout/stderr after try_wait
    /// reported exit. With concurrent drainers, output of any size completes.
    #[test]
    fn test_wait_with_timeout_handles_large_output() {
        // 200KB to stdout AND 200KB to stderr — exercises both drainers past
        // the pipe-buffer threshold simultaneously.
        let mut child = spawn_sh(
            "yes A | head -c 200000; yes B | head -c 200000 >&2; exit 0",
        );
        drop(child.stdin.take());

        let output = wait_with_timeout(&mut child, Duration::from_secs(10))
            .expect("must not deadlock or time out on large output");
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 200_000);
        assert_eq!(output.stderr.len(), 200_000);
    }

    /// Regression: if a child runs longer than the timeout, wait_with_timeout
    /// must kill it (so drainers see EOF) and return Err without leaking
    /// threads. `exec sleep` makes the shell hand its pipes to sleep — when
    /// we kill the shell, sleep is killed too and pipes close cleanly.
    #[test]
    fn test_wait_with_timeout_kills_runaway_child() {
        let mut child = spawn_sh("exec sleep 60");
        drop(child.stdin.take());

        let result = wait_with_timeout(&mut child, Duration::from_millis(500));
        assert!(result.is_err(), "expected timeout, got {:?}", result);
    }
}
