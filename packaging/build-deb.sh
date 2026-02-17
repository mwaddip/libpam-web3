#!/bin/bash
#
# Build a .deb package for libpam-web3 (PAM module for VMs)
#
# This package contains:
#   - PAM module (pam_web3.so) for wallet-based authentication
#   - web3-auth-svc HTTPS server for callback-based signing
#   - Configuration for PAM authentication on VMs
#
# For server-side tools (pam_web3_tool), see build-deb-tools.sh
#
# Usage: ./packaging/build-deb.sh
#
# Requirements: dpkg-deb (apt install dpkg)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="0.7.0"
ARCH="amd64"
PKG_NAME="libpam-web3"
PKG_DIR="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}"

echo "=== Building libpam-web3 ${VERSION} for ${ARCH} ==="

# Clean previous build
rm -rf "$PKG_DIR"
rm -f "$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"

# Build PAM module
echo "[1/5] Building PAM module..."
cd "$PROJECT_DIR"
cargo build --release

echo "[2/5] Building web3-auth-svc..."
cd "$PROJECT_DIR/web3-auth-svc"
cargo build --release

# Create package directory structure
echo "[3/5] Creating package structure..."
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/lib/x86_64-linux-gnu/security"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/lib/systemd/system"
mkdir -p "$PKG_DIR/etc/pam_web3"
mkdir -p "$PKG_DIR/etc/web3-auth"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}/examples"
mkdir -p "$PKG_DIR/usr/share/${PKG_NAME}/signing-page"

# Copy binaries
echo "[4/5] Copying files..."
cp "$PROJECT_DIR/target/release/libpam_web3.so" "$PKG_DIR/lib/x86_64-linux-gnu/security/"
cp "$PROJECT_DIR/web3-auth-svc/target/release/web3-auth-svc" "$PKG_DIR/usr/bin/"

# Copy signing page
cp "$PROJECT_DIR/signing-page/index.html" "$PKG_DIR/usr/share/${PKG_NAME}/signing-page/"

# Create control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Depends: libc6 (>= 2.31), libpam-runtime, libssl3 | libssl1.1
Suggests: libpam-web3-tools
Maintainer: libpam-web3 maintainers
Homepage: https://github.com/mwaddip/libpam-web3
Description: PAM module for wallet-based authentication
 libpam-web3 provides Linux authentication using wallet signatures
 and GECOS-based identity mapping.
 .
 Install this package on VMs/servers where users authenticate via wallet.
 .
 This package includes:
  - PAM module (pam_web3.so)
  - web3-auth-svc HTTPS server for callback-based signing
 .
 Features:
  - EVM wallet signature verification (secp256k1 ecrecover)
  - OPNet callback support (OTP validation + trusted address)
  - GECOS-based username mapping (wallet=ADDRESS)
  - Challenge-response OTP authentication
 .
 For admin tools (key generation, encryption), install libpam-web3-tools.
EOF

# Create conffiles
cat > "$PKG_DIR/DEBIAN/conffiles" << EOF
/etc/pam_web3/config.toml
EOF

# Create postinst script
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

case "$1" in
    configure)
        # Create symlink for PAM module
        ln -sf /lib/x86_64-linux-gnu/security/libpam_web3.so \
               /lib/x86_64-linux-gnu/security/pam_web3.so 2>/dev/null || true

        # Create runtime directories
        mkdir -p /run/libpam-web3/pending
        chmod 700 /run/libpam-web3/pending

        # Create config directory permissions
        chmod 750 /etc/pam_web3 2>/dev/null || true
        chmod 750 /etc/web3-auth 2>/dev/null || true

        # Generate self-signed TLS certificate if not present
        TLS_DIR="/etc/libpam-web3/tls"
        if [ ! -f "$TLS_DIR/cert.pem" ]; then
            mkdir -p "$TLS_DIR"
            if command -v openssl >/dev/null 2>&1; then
                openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
                    -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
                    -days 3650 -nodes -subj "/CN=$(hostname)" \
                    -addext "subjectAltName=DNS:$(hostname),IP:$(hostname -I | awk '{print $1}')" \
                    2>/dev/null || true
                chmod 600 "$TLS_DIR/key.pem" 2>/dev/null || true
                chmod 644 "$TLS_DIR/cert.pem" 2>/dev/null || true
                echo "Self-signed TLS certificate generated in $TLS_DIR"
            fi
        fi

        # Reload systemd if available
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
        fi

        echo ""
        echo "=== libpam-web3 installed ==="
        echo ""
        echo "Configuration files:"
        echo "  /etc/pam_web3/config.toml   (PAM module)"
        echo "  /etc/web3-auth/config.toml  (HTTPS signing server)"
        echo ""
        echo "Quick setup:"
        echo "1. Edit configuration files with your settings"
        echo "2. Start the signing server:"
        echo "   systemctl enable --now web3-auth-svc"
        echo "3. Create user with wallet address in GECOS:"
        echo "   useradd -m -c 'wallet=0xADDRESS,nft=TOKEN_ID' username"
        echo "4. Configure PAM (see /usr/share/doc/libpam-web3/)"
        echo ""
        ;;
esac

exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Create prerm script
cat > "$PKG_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

case "$1" in
    remove|purge)
        # Stop service if running
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop web3-auth-svc 2>/dev/null || true
            systemctl disable web3-auth-svc 2>/dev/null || true
        fi
        ;;
esac

exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# Create postrm script
cat > "$PKG_DIR/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e

case "$1" in
    purge)
        rm -rf /etc/pam_web3 2>/dev/null || true
        rm -rf /etc/web3-auth 2>/dev/null || true
        rm -rf /etc/libpam-web3 2>/dev/null || true
        rm -rf /run/libpam-web3 2>/dev/null || true
        rm -f /lib/x86_64-linux-gnu/security/pam_web3.so 2>/dev/null || true
        ;;
    remove)
        rm -f /lib/x86_64-linux-gnu/security/pam_web3.so 2>/dev/null || true
        ;;
esac

exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postrm"

# Create PAM config
cat > "$PKG_DIR/etc/pam_web3/config.toml" << 'EOF'
# libpam-web3 configuration
# See /usr/share/doc/libpam-web3/ for documentation

[machine]
# Unique identifier for this machine (shown in signing prompt)
id = "my-server"
# Secret key for OTP generation (hex, 32+ bytes recommended)
# Generate with: openssl rand -hex 32
secret_key = "CHANGE_ME_generate_with_openssl_rand_hex_32"

[auth]
# URL where users can sign messages (displayed during login)
signing_url = "https://your-signing-page.example.com"
# OTP settings
otp_length = 6
otp_ttl_seconds = 300
# Callback-based signing (browser POSTs signature back automatically)
callback_enabled = true
callback_grace_seconds = 10
EOF

# Create web3-auth config
cat > "$PKG_DIR/etc/web3-auth/config.toml" << 'EOF'
# web3-auth-svc configuration
# HTTPS server for callback-based signing

[https]
port = 8443
bind = ["::"]
cert_path = "/etc/libpam-web3/tls/cert.pem"
key_path = "/etc/libpam-web3/tls/key.pem"
signing_page_path = "/usr/share/libpam-web3/signing-page/index.html"
EOF

# Create systemd service file
cat > "$PKG_DIR/usr/lib/systemd/system/web3-auth-svc.service" << 'EOF'
[Unit]
Description=Web3 Authentication Signing Server
Documentation=https://github.com/mwaddip/libpam-web3
After=network.target

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p /run/libpam-web3/pending
ExecStart=/usr/bin/web3-auth-svc --config /etc/web3-auth/config.toml --foreground
Restart=always
RestartSec=5
Environment=RUST_LOG=info

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/libpam-web3

# Runtime directories
RuntimeDirectory=libpam-web3
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF

# Create documentation
cat > "$PKG_DIR/usr/share/doc/${PKG_NAME}/README.Debian" << 'EOF'
libpam-web3 for Debian
======================

This package provides PAM authentication using wallet signatures
with GECOS-based identity mapping.

Authentication Flow
-------------------

1. User connects to SSH, sees OTP code and signing URL
2. User signs message with their wallet
3. Signature delivery: browser callback (auto) or manual paste
4. PAM module verifies signature and recovers wallet address
5. PAM matches wallet address against /etc/passwd GECOS (wallet=ADDRESS)
6. User authenticated as matching Linux user

Supported Signature Types
-------------------------

- EVM: secp256k1 ecrecover (raw hex signature)
- OPNet: JSON callback with OTP validation and wallet address

Quick Setup
-----------

1. Create a user with wallet address in GECOS:

   useradd -m -c "wallet=0x1234...abcd,nft=0" johndoe

   The "wallet=0x..." maps this user to the wallet address.
   The "nft=0" is optional metadata (NFT token ID).

2. Edit /etc/pam_web3/config.toml:
   - Set machine.id to identify this server
   - Set machine.secret_key (generate with: openssl rand -hex 32)
   - Set auth.signing_url to your signing page

3. Configure PAM. Edit /etc/pam.d/sshd:

   # Add before @include common-auth:
   auth [success=2 default=ignore] pam_succeed_if.so user != web3user
   auth [success=1 default=die] pam_web3.so

   @include common-auth

4. Enable challenge-response in /etc/ssh/sshd_config:

   KbdInteractiveAuthentication yes
   UsePAM yes

5. Restart SSH:

   systemctl restart sshd

Requirements
------------

- web3-auth-svc must be running (systemctl enable --now web3-auth-svc)
- User's wallet address must match GECOS entry

For admin tools (key generation, encryption), install libpam-web3-tools.
EOF

# Example PAM config
cat > "$PKG_DIR/usr/share/doc/${PKG_NAME}/examples/pam.d-sshd" << 'EOF'
# Example /etc/pam.d/sshd configuration for libpam-web3
#
# This allows web3user to authenticate via wallet signature, while other
# users use standard authentication methods.

# Web3 authentication for specific user
auth [success=2 default=ignore] pam_succeed_if.so user != web3user
auth [success=1 default=die] pam_web3.so

# Standard authentication
@include common-auth

# Account, session, password as usual
@include common-account
@include common-session
@include common-password
EOF

# Set correct permissions
find "$PKG_DIR" -type d -exec chmod 755 {} \;
find "$PKG_DIR" -type f -exec chmod 644 {} \;
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 755 "$PKG_DIR/DEBIAN/prerm"
chmod 755 "$PKG_DIR/DEBIAN/postrm"
chmod 755 "$PKG_DIR/usr/bin/"*
chmod 640 "$PKG_DIR/etc/pam_web3/config.toml"
chmod 640 "$PKG_DIR/etc/web3-auth/config.toml"

# Build the package
echo "[5/5] Building .deb package..."
cd "$SCRIPT_DIR"
dpkg-deb --build --root-owner-group "$PKG_DIR"

# Show result
DEB_FILE="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"
if [ -f "$DEB_FILE" ]; then
    echo ""
    echo "=== Package built successfully ==="
    echo ""
    ls -lh "$DEB_FILE"
    echo ""
    echo "Package contents:"
    dpkg-deb -c "$DEB_FILE"
    echo ""
    echo "To install:"
    echo "  sudo dpkg -i $DEB_FILE"
    echo ""
    echo "For server-side tools, also build:"
    echo "  ./build-deb-tools.sh"

    # Clean build caches so stale artifacts can't break the next build
    echo ""
    echo "Cleaning build caches..."
    cd "$PROJECT_DIR" && cargo clean
    cd "$PROJECT_DIR/web3-auth-svc" && cargo clean
else
    echo "ERROR: Package build failed"
    exit 1
fi
