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
echo "[1/4] Building PAM module with NFT support..."
cd "$PROJECT_DIR"
cargo build --release --features nft

# Create package directory structure
echo "[2/4] Creating package structure..."
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/lib/x86_64-linux-gnu/security"
mkdir -p "$PKG_DIR/etc/pam_web3"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}/examples"

# Copy PAM module
echo "[3/4] Copying files..."
cp "$PROJECT_DIR/target/release/libpam_web3.so" "$PKG_DIR/lib/x86_64-linux-gnu/security/"

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
 Features:
  - NFT-based access control (wallet + token ID)
  - Ownership verification via blockchain query
  - GECOS-based username mapping (nft=TOKEN_ID)
  - Challenge-response OTP authentication
 .
 For server-side tools (minting, key generation), install libpam-web3-tools.
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

        # Create config directory permissions
        chmod 750 /etc/pam_web3 2>/dev/null || true

        echo ""
        echo "=== libpam-web3 installed ==="
        echo ""
        echo "Configuration: /etc/pam_web3/config.toml"
        echo ""
        echo "Quick setup:"
        echo "1. Edit /etc/pam_web3/config.toml with your settings"
        echo "2. Create user with NFT token ID in GECOS:"
        echo "   useradd -m -c 'nft=TOKEN_ID' username"
        echo "3. Configure PAM (see /usr/share/doc/libpam-web3/)"
        echo ""
        echo "The blockchain query service (web3-auth-svc) must be running."
        echo "Install libpam-web3-tools on your management server."
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

- web3-auth-svc must be running and accessible via Unix socket
- NFT contract must be deployed with user's token
- User's wallet must own the NFT matching their GECOS entry

For server-side tools, install libpam-web3-tools.
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
chmod 640 "$PKG_DIR/etc/pam_web3/config.toml"

# Build the package
echo "[4/4] Building .deb package..."
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
