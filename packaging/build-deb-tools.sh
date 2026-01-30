#!/bin/bash
#
# Build a .deb package for libpam-web3-tools (server-side tools)
#
# This package contains:
#   - pam_web3_tool: CLI for encryption/decryption, keypair generation
#   - web3-auth-svc: Daemon for blockchain queries
#   - Signing page generator scripts
#
# Usage: ./packaging/build-deb-tools.sh
#
# Requirements: dpkg-deb (apt install dpkg)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="0.4.0"
ARCH="amd64"
PKG_NAME="libpam-web3-tools"
PKG_DIR="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}"

echo "=== Building libpam-web3-tools ${VERSION} for ${ARCH} ==="

# Clean previous build
rm -rf "$PKG_DIR"
rm -f "$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"

# Build binaries
echo "[1/5] Building pam_web3_tool..."
cd "$PROJECT_DIR"
cargo build --release --features nft

echo "[2/5] Building web3-auth-svc..."
cd "$PROJECT_DIR/web3-auth-svc"
cargo build --release

# Create package directory structure
echo "[3/5] Creating package structure..."
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/lib/systemd/system"
mkdir -p "$PKG_DIR/etc/web3-auth"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}"
mkdir -p "$PKG_DIR/usr/share/${PKG_NAME}/signing-page"
mkdir -p "$PKG_DIR/usr/share/${PKG_NAME}/ldap"

# Copy binaries
echo "[4/5] Copying files..."
cp "$PROJECT_DIR/target/release/pam_web3_tool" "$PKG_DIR/usr/bin/"
cp "$PROJECT_DIR/web3-auth-svc/target/release/web3-auth-svc" "$PKG_DIR/usr/bin/"

# Copy signing page scripts
cp "$PROJECT_DIR/signing-page/index.html" "$PKG_DIR/usr/share/${PKG_NAME}/signing-page/"
cp "$PROJECT_DIR/signing-page/build.sh" "$PKG_DIR/usr/share/${PKG_NAME}/signing-page/"
cp "$PROJECT_DIR/signing-page/generate.sh" "$PKG_DIR/usr/share/${PKG_NAME}/signing-page/"

# Create control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Depends: libc6 (>= 2.31), libssl3 | libssl1.1
Suggests: libpam-web3
Maintainer: libpam-web3 maintainers
Homepage: https://github.com/mwaddip/libpam-web3
Description: Server-side tools for libpam-web3 NFT authentication
 This package provides server-side tools for managing NFT-based authentication:
 .
  - pam_web3_tool: CLI for keypair generation, encryption, decryption
  - web3-auth-svc: Daemon for blockchain NFT queries
  - Signing page generator for NFT minting
 .
 Install this package on servers that:
  - Mint NFT access credentials
  - Manage encryption keys
  - Run the blockchain query service
 .
 For VM/client authentication, install libpam-web3 instead.
EOF

# Create conffiles
cat > "$PKG_DIR/DEBIAN/conffiles" << EOF
/etc/web3-auth/config.toml
EOF

# Create postinst script
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

case "$1" in
    configure)
        # Create runtime directory for web3-auth-svc
        mkdir -p /run/web3-auth
        chmod 755 /run/web3-auth

        # Create config directory permissions
        chmod 750 /etc/web3-auth 2>/dev/null || true

        # Reload systemd if available
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
        fi

        echo ""
        echo "=== libpam-web3-tools installed ==="
        echo ""
        echo "Tools available:"
        echo "  - pam_web3_tool: Keypair generation, encryption/decryption"
        echo "  - web3-auth-svc: Blockchain query daemon"
        echo ""
        echo "Signing page generator:"
        echo "  /usr/share/libpam-web3-tools/signing-page/"
        echo ""
        echo "To start the blockchain service:"
        echo "  1. Edit /etc/web3-auth/config.toml"
        echo "  2. systemctl enable --now web3-auth-svc"
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
        rm -rf /etc/web3-auth 2>/dev/null || true
        rm -rf /run/web3-auth 2>/dev/null || true
        ;;
esac

exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postrm"

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

# Create LDAP schema files
cat > "$PKG_DIR/usr/share/${PKG_NAME}/ldap/nft-schema.ldif" << 'EOF'
# NFT credential schema for OpenLDAP
# Install with: sudo ldapadd -Y EXTERNAL -H ldapi:/// -f nft-schema.ldif

dn: cn=nftCredential,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: nftCredential
olcAttributeTypes: {0}( 1.3.6.1.4.1.99999.1.1 NAME 'nftTokenId'
  DESC 'NFT Token ID' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: {1}( 1.3.6.1.4.1.99999.1.2 NAME 'nftRevoked'
  DESC 'NFT Revocation Status' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
olcAttributeTypes: {2}( 1.3.6.1.4.1.99999.1.3 NAME 'linuxUsername'
  DESC 'Linux Username' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: {3}( 1.3.6.1.4.1.99999.1.4 NAME 'walletAddress'
  DESC 'Ethereum Wallet Address' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: {0}( 1.3.6.1.4.1.99999.2.1 NAME 'nftCredential'
  DESC 'NFT-based access credential' SUP top AUXILIARY
  MUST ( nftTokenId $ linuxUsername ) MAY ( nftRevoked $ walletAddress ) )
EOF

# Create documentation
cat > "$PKG_DIR/usr/share/doc/${PKG_NAME}/README.Debian" << 'EOF'
libpam-web3-tools for Debian
============================

This package provides server-side tools for NFT-based authentication.

Components
----------

pam_web3_tool - CLI utility for:
  - Generating secp256k1 keypairs
  - Encrypting data with signature-derived keys (AES-GCM)
  - Decrypting user_encrypted NFT fields
  - Deriving public keys

web3-auth-svc - Blockchain query daemon:
  - Queries NFT ownership via JSON-RPC or Etherscan
  - Listens on Unix socket for PAM module queries
  - Supports Ethereum, Polygon, Arbitrum, etc.

Signing Page Generator - For NFT minting:
  - /usr/share/libpam-web3-tools/signing-page/
  - generate.sh: Creates customized signing page
  - build.sh: Base64 encodes for NFT animation_url

Usage
-----

1. Generate signing page for NFT minting:

   cd /usr/share/libpam-web3-tools/signing-page
   ./generate.sh \
       --server-pubkey "04abc123..." \
       --decrypt-message "Decrypt BlockHost credentials"
   ./build.sh

2. Generate server keypair:

   pam_web3_tool generate-keypair --output server.key --show-pubkey

3. Encrypt connection details for NFT:

   pam_web3_tool encrypt-symmetric \
       --signature "0x<user_signature>" \
       --plaintext '{"hostname":"192.168.1.100","port":22}'

4. Start blockchain query service:

   systemctl enable --now web3-auth-svc

For VM authentication, install libpam-web3 package.
EOF

# Set correct permissions
find "$PKG_DIR" -type d -exec chmod 755 {} \;
find "$PKG_DIR" -type f -exec chmod 644 {} \;
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 755 "$PKG_DIR/DEBIAN/prerm"
chmod 755 "$PKG_DIR/DEBIAN/postrm"
chmod 755 "$PKG_DIR/usr/bin/"*
chmod 755 "$PKG_DIR/usr/share/${PKG_NAME}/signing-page/"*.sh
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
else
    echo "ERROR: Package build failed"
    exit 1
fi
