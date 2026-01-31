#!/bin/bash
#
# Build a .deb package for libpam-web3 (PAM module for VMs)
#
# This package contains:
#   - PAM module (pam_web3.so) for NFT-based authentication
#   - Configuration for PAM authentication on VMs
#
# For server-side tools (web3-auth-svc, pam_web3_tool), see build-deb-tools.sh
#
# Usage: ./packaging/build-deb.sh
#
# Requirements: dpkg-deb (apt install dpkg)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="0.4.0"
ARCH="amd64"
PKG_NAME="libpam-web3"
PKG_DIR="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}"

echo "=== Building libpam-web3 ${VERSION} for ${ARCH} ==="

# Clean previous build
rm -rf "$PKG_DIR"
rm -f "$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"

# Build PAM module with NFT support
echo "[1/5] Building PAM module with NFT support..."
cd "$PROJECT_DIR"
cargo build --release --features nft

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

# Copy binaries
echo "[4/5] Copying files..."
cp "$PROJECT_DIR/target/release/libpam_web3.so" "$PKG_DIR/lib/x86_64-linux-gnu/security/"
cp "$PROJECT_DIR/web3-auth-svc/target/release/web3-auth-svc" "$PKG_DIR/usr/bin/"

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
Description: PAM module for Ethereum wallet-based NFT authentication
 libpam-web3 provides Linux authentication using Ethereum wallet signatures
 and NFT ownership verification.
 .
 Install this package on VMs/servers where users authenticate via NFT.
 .
 This package includes:
  - PAM module (pam_web3.so)
  - web3-auth-svc daemon for blockchain queries
 .
 Features:
  - NFT-based access control (wallet + token ID)
  - Ownership verification via blockchain query
  - GECOS-based username mapping (nft=TOKEN_ID)
  - Challenge-response OTP authentication
 .
 For admin tools (minting, key generation), install libpam-web3-tools.
EOF

# Create conffiles
cat > "$PKG_DIR/DEBIAN/conffiles" << EOF
/etc/pam_web3/config.toml
/etc/web3-auth/config.toml
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

        # Create runtime directory for web3-auth-svc
        mkdir -p /run/web3-auth
        chmod 755 /run/web3-auth

        # Create config directory permissions
        chmod 750 /etc/pam_web3 2>/dev/null || true
        chmod 750 /etc/web3-auth 2>/dev/null || true

        # Reload systemd if available
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
        fi

        echo ""
        echo "=== libpam-web3 installed ==="
        echo ""
        echo "Configuration files:"
        echo "  /etc/pam_web3/config.toml   (PAM module)"
        echo "  /etc/web3-auth/config.toml  (blockchain service)"
        echo ""
        echo "Quick setup:"
        echo "1. Edit configuration files with your settings"
        echo "2. Start the blockchain service:"
        echo "   systemctl enable --now web3-auth-svc"
        echo "3. Create user with NFT token ID in GECOS:"
        echo "   useradd -m -c 'nft=TOKEN_ID' username"
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
        rm -rf /run/web3-auth 2>/dev/null || true
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
# libpam-web3 configuration for NFT authentication
# See /usr/share/doc/libpam-web3/ for documentation

[machine]
# Unique identifier for this machine (shown in signing prompt)
id = "my-server"
# Secret key for OTP generation (hex, 32+ bytes recommended)
# Generate with: openssl rand -hex 32
secret_key = "CHANGE_ME_generate_with_openssl_rand_hex_32"

[auth]
# Authentication mode: "nft" for NFT-based auth
mode = "nft"
# NFT lookup method: "passwd" (check GECOS) or "ldap" (query LDAP)
nft_lookup = "passwd"
# URL where users can sign messages (displayed during login)
signing_url = "https://your-signing-page.example.com"
# OTP settings
otp_length = 6
otp_ttl_seconds = 300

[blockchain]
# Unix socket for web3-auth-svc (must be accessible from this VM)
socket_path = "/run/web3-auth/web3-auth.sock"
# Ethereum chain ID (1=mainnet, 11155111=sepolia)
chain_id = 11155111
# NFT contract address
nft_contract = "0xYourContractAddress"
# Timeout for blockchain queries
timeout_seconds = 10

# Optional LDAP configuration (only if nft_lookup = "ldap")
# [ldap]
# server = "ldap://ldap.example.com:389"
# base_dn = "ou=nft,dc=example,dc=com"
# bind_dn = "cn=pam,dc=example,dc=com"
# bind_password_file = "/etc/pam_web3/ldap.secret"
# token_id_attribute = "nftTokenId"
# revoked_attribute = "nftRevoked"
# username_attribute = "linuxUsername"
# timeout_seconds = 10
EOF

# Create web3-auth config
cat > "$PKG_DIR/etc/web3-auth/config.toml" << 'EOF'
# web3-auth-svc configuration
# Blockchain query service for libpam-web3

# Unix socket path
socket_path = "/run/web3-auth/web3-auth.sock"

# Backend type: "jsonrpc" or "etherscan"
backend = "jsonrpc"

# Default chain ID (1=mainnet, 11155111=sepolia)
default_chain_id = 11155111

# Default NFT contract address
default_contract = "0xYourContractAddress"

[jsonrpc]
# Ethereum JSON-RPC endpoint
rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"
timeout_seconds = 30

# [etherscan]
# api_url = "https://api.etherscan.io"
# api_key = "YOUR_API_KEY"
# timeout_seconds = 30
EOF

# Create systemd service file
cat > "$PKG_DIR/usr/lib/systemd/system/web3-auth-svc.service" << 'EOF'
[Unit]
Description=Web3 Authentication Service
Documentation=https://github.com/mwaddip/libpam-web3
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/web3-auth-svc --config /etc/web3-auth/config.toml --foreground
Restart=always
RestartSec=5
Environment=RUST_LOG=info

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/web3-auth

# Runtime directory
RuntimeDirectory=web3-auth
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF

# Create documentation
cat > "$PKG_DIR/usr/share/doc/${PKG_NAME}/README.Debian" << 'EOF'
libpam-web3 for Debian
======================

This package provides PAM authentication using Ethereum wallet signatures
with NFT-based access control.

Authentication Flow
-------------------

1. User connects to SSH, sees OTP code and signing URL
2. User signs message with their Ethereum wallet
3. User pastes signature into terminal
4. PAM module verifies signature and recovers wallet address
5. PAM queries blockchain for wallet's NFT token IDs
6. PAM matches token ID against /etc/passwd GECOS field (nft=TOKEN_ID)
7. User authenticated as matching Linux user

Quick Setup
-----------

1. Create a user with NFT token ID in GECOS:

   useradd -m -c "nft=0" johndoe

   The "nft=0" means this user owns NFT token ID 0.

2. Edit /etc/pam_web3/config.toml:
   - Set machine.id to identify this server
   - Set machine.secret_key (generate with: openssl rand -hex 32)
   - Set auth.signing_url to your signing page
   - Set blockchain.nft_contract to your NFT contract address

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

- NFT contract must be deployed with user's token
- User's wallet must own the NFT matching their GECOS entry
- web3-auth-svc must be running (systemctl enable --now web3-auth-svc)

For admin tools (minting, key generation), install libpam-web3-tools.
EOF

# Example PAM config
cat > "$PKG_DIR/usr/share/doc/${PKG_NAME}/examples/pam.d-sshd" << 'EOF'
# Example /etc/pam.d/sshd configuration for libpam-web3
#
# This allows web3user to authenticate via NFT, while other users
# use standard authentication methods.

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
else
    echo "ERROR: Package build failed"
    exit 1
fi
