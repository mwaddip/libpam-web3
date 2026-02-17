//! Callback-based signing session management.
//!
//! Manages session files in `/run/libpam-web3/pending/` for IPC between
//! the PAM module and the auth service HTTPS endpoints. The browser fetches
//! session data from the HTTPS server and POSTs the signature back,
//! eliminating copy-paste round-trips.

use rand::Rng;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

const PENDING_DIR: &str = "/run/libpam-web3/pending";
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// A callback signing session backed by files on disk.
pub struct Session {
    pub session_id: String,
    pending_dir: PathBuf,
}

impl Session {
    /// Create a new session: generate a random ID and write the JSON file.
    ///
    /// Returns `Err` if the pending directory doesn't exist or the write fails,
    /// allowing the caller to fall back to manual-only mode.
    pub fn create(otp: &str, machine_id: &str) -> io::Result<Self> {
        let pending_dir = PathBuf::from(PENDING_DIR);
        if !pending_dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "pending directory does not exist",
            ));
        }

        let session_id = gen_session_id();
        let session = Session {
            session_id: session_id.clone(),
            pending_dir: pending_dir.clone(),
        };

        let json = serde_json::json!({
            "otp": otp,
            "machine_id": machine_id,
            "session_id": session_id,
        });
        let data = serde_json::to_string(&json).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e)
        })?;

        // Atomic write: .tmp → sync → rename
        let tmp_path = pending_dir.join(format!("{}.tmp", session_id));
        let json_path = pending_dir.join(format!("{}.json", session_id));

        fs::write(&tmp_path, data.as_bytes())?;
        // fsync the file
        let f = fs::File::open(&tmp_path)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp_path, &json_path)?;

        Ok(session)
    }

    /// Poll for a `.sig` file written by the HTTPS callback endpoint.
    ///
    /// Checks every 250ms for up to `grace_seconds`. Returns the signature
    /// contents if found, or `None` if the window expires.
    pub fn wait_for_callback(&self, grace_seconds: u64) -> Option<String> {
        let sig_path = self.pending_dir.join(format!("{}.sig", self.session_id));
        let deadline = Instant::now() + Duration::from_secs(grace_seconds);

        while Instant::now() < deadline {
            if let Ok(contents) = fs::read_to_string(&sig_path) {
                let sig = contents.trim().to_string();
                if !sig.is_empty() {
                    return Some(sig);
                }
            }
            thread::sleep(POLL_INTERVAL);
        }

        None
    }

    /// Remove all session files (`.json`, `.sig`, `.tmp`).
    pub fn cleanup(&self) {
        for ext in &["json", "sig", "tmp"] {
            let path = self.pending_dir.join(format!("{}.{}", self.session_id, ext));
            let _ = fs::remove_file(path);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Generate a 128-bit cryptographically random hex session ID.
fn gen_session_id() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper to create a temporary pending directory for tests.
    fn with_temp_session<F: FnOnce(PathBuf)>(f: F) {
        let dir = std::env::temp_dir().join(format!("pam_web3_test_{}", gen_session_id()));
        fs::create_dir_all(&dir).unwrap();
        f(dir.clone());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_gen_session_id_length() {
        let id = gen_session_id();
        assert_eq!(id.len(), 32, "session ID should be 32 hex chars (16 bytes)");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_gen_session_id_unique() {
        let a = gen_session_id();
        let b = gen_session_id();
        assert_ne!(a, b);
    }

    #[test]
    fn test_session_create_and_cleanup() {
        with_temp_session(|dir| {
            let session = Session {
                session_id: "abcd1234abcd1234abcd1234abcd1234".to_string(),
                pending_dir: dir.clone(),
            };

            // Simulate create by writing JSON directly (bypasses PENDING_DIR const)
            let json_path = dir.join("abcd1234abcd1234abcd1234abcd1234.json");
            fs::write(&json_path, r#"{"otp":"123456","machine_id":"test"}"#).unwrap();
            assert!(json_path.exists());

            session.cleanup();
            assert!(!json_path.exists());
        });
    }

    #[test]
    fn test_session_wait_timeout() {
        with_temp_session(|dir| {
            let session = Session {
                session_id: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                pending_dir: dir,
            };

            // No .sig file exists, should timeout quickly
            let result = session.wait_for_callback(1);
            assert!(result.is_none());
        });
    }

    #[test]
    fn test_session_wait_finds_sig() {
        with_temp_session(|dir| {
            let session = Session {
                session_id: "cafebabecafebabecafebabecafebabe".to_string(),
                pending_dir: dir.clone(),
            };

            // Write .sig file before polling
            let sig_path = dir.join("cafebabecafebabecafebabecafebabe.sig");
            fs::write(&sig_path, "0xdeadbeef").unwrap();

            let result = session.wait_for_callback(1);
            assert_eq!(result, Some("0xdeadbeef".to_string()));
        });
    }

    #[test]
    fn test_drop_cleans_up() {
        with_temp_session(|dir| {
            let json_path = dir.join("droptest1234droptest1234droptest12.json");
            let sig_path = dir.join("droptest1234droptest1234droptest12.sig");

            fs::write(&json_path, "{}").unwrap();
            fs::write(&sig_path, "0x").unwrap();

            {
                let _session = Session {
                    session_id: "droptest1234droptest1234droptest12".to_string(),
                    pending_dir: dir.clone(),
                };
                // session dropped here
            }

            assert!(!json_path.exists());
            assert!(!sig_path.exists());
        });
    }

    #[test]
    fn test_create_fails_without_dir() {
        let result = Session::create("123456", "test-machine");
        // Unless /run/libpam-web3/pending exists on the test system, this should fail
        if !PathBuf::from(PENDING_DIR).is_dir() {
            assert!(result.is_err());
        }
    }
}
