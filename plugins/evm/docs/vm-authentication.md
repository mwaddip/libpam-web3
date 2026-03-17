# VM Authentication

VMs use NFT-based web3 authentication instead of passwords or SSH keys:

1. VM serves signing page on port 8443 via web3-auth-svc (HTTPS, self-signed TLS)
2. User connects wallet that owns the NFT
3. User signs challenge message
4. Signing page displays 6-digit OTP
5. User SSHs to VM, enters OTP when prompted
6. PAM module verifies signature against NFT ownership

## Auth Service (web3-auth-svc)

The engine ships an HTTPS signing server as an esbuild-bundled JS file for VMs. Requires Node.js 22+ on VMs.

### Endpoints

- `GET /` — Serves the signing page HTML
- `GET /auth/pending/:session_id` — Returns session JSON from `/run/libpam-web3/pending/`
- `POST /auth/callback/:session_id` — Validates signature, writes `.sig` file atomically

### Signature Formats

Content-based detection (same as PAM module):
- **EVM**: optional `0x` prefix + 130 hex chars (secp256k1)
- **OPNet**: JSON with `otp`, `machine_id`, `wallet_address` fields

### Template Package

The auth-svc ships as `blockhost-auth-svc_<version>_all.deb`, installed on VM templates (not the host):

| File | Purpose |
|------|---------|
| `/usr/bin/web3-auth-svc` | Wrapper script (calls node) |
| `/usr/share/blockhost/web3-auth-svc.js` | Bundled server |
| `/usr/share/blockhost/signing-page/index.html` | Signing page HTML |
| `/lib/systemd/system/web3-auth-svc.service` | Systemd unit |
| `/usr/lib/tmpfiles.d/web3-auth-svc.conf` | Creates `/run/libpam-web3/pending/` on boot |

### Config

Reads `/etc/web3-auth/config.toml` (written by cloud-init template on VMs):

```toml
[https]
port = 8443
bind = ["::"]
cert_path = "/etc/libpam-web3/tls/cert.pem"
key_path = "/etc/libpam-web3/tls/key.pem"
signing_page_path = "/usr/share/blockhost/signing-page/index.html"
```
