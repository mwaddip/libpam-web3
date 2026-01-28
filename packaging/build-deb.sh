#!/bin/bash
#
# Build a .deb package for libpam-web3 with NFT mode support
#
# Usage: ./packaging/build-deb.sh
#
# Requirements: dpkg-deb (apt install dpkg)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="0.2.0"
ARCH="amd64"
PKG_NAME="libpam-web3"
PKG_DIR="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}"

echo "=== Building libpam-web3 ${VERSION} for ${ARCH} ==="

# Clean previous build
rm -rf "$PKG_DIR"
rm -f "$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"

# Build binaries with NFT support
echo "[1/6] Building PAM module with NFT support..."
cd "$PROJECT_DIR"
cargo build --release --features nft

echo "[2/6] Building web3-auth-svc..."
cd "$PROJECT_DIR/web3-auth-svc"
cargo build --release

# Create package directory structure
echo "[3/6] Creating package structure..."
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/lib/x86_64-linux-gnu/security"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/lib/systemd/system"
mkdir -p "$PKG_DIR/etc/pam_web3"
mkdir -p "$PKG_DIR/etc/web3-auth"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}/examples"
mkdir -p "$PKG_DIR/usr/share/${PKG_NAME}/scripts"
mkdir -p "$PKG_DIR/usr/share/${PKG_NAME}/ldap"

# Copy binaries
echo "[4/6] Copying binaries..."
cp "$PROJECT_DIR/target/release/libpam_web3.so" "$PKG_DIR/lib/x86_64-linux-gnu/security/"
cp "$PROJECT_DIR/target/release/pam_web3_tool" "$PKG_DIR/usr/bin/"
cp "$PROJECT_DIR/web3-auth-svc/target/release/web3-auth-svc" "$PKG_DIR/usr/bin/"

# Copy scripts
cp "$PROJECT_DIR/scripts/extract-signing-page.sh" "$PKG_DIR/usr/share/${PKG_NAME}/scripts/"
chmod +x "$PKG_DIR/usr/share/${PKG_NAME}/scripts/extract-signing-page.sh"

# Copy LDAP schema
if [ -d "$PROJECT_DIR/docs/ldap" ]; then
    cp "$PROJECT_DIR/docs/ldap/"*.ldif "$PKG_DIR/usr/share/${PKG_NAME}/ldap/" 2>/dev/null || true
fi

# Create control file
echo "[5/6] Creating package metadata..."
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Depends: libc6 (>= 2.31), libpam-runtime, libssl3 | libssl1.1
Recommends: slapd, ldap-utils
Maintainer: libpam-web3 maintainers
Homepage: https://github.com/mwaddip/libpam-web3
Description: PAM module for Ethereum wallet-based authentication
 libpam-web3 provides Linux authentication using Ethereum wallet signatures.
 .
 Features:
  - NFT-based access control with blockchain verification
  - LDAP integration for username mapping and revocation
  - ECIES encryption for machine ID protection
  - Built-in OTP generation for challenge-response auth
 .
 This package includes:
  - PAM module (pam_web3.so)
  - web3-auth-svc daemon for blockchain queries
  - pam_web3_tool CLI for key generation
EOF

# Create conffiles (list of config files that shouldn't be overwritten on upgrade)
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
        echo "Next steps:"
        echo "1. Generate server keypair:"
        echo "   pam_web3_tool generate-keypair --output /etc/pam_web3/server.key"
        echo ""
        echo "2. Edit configuration files:"
        echo "   /etc/pam_web3/config.toml"
        echo "   /etc/web3-auth/config.toml"
        echo ""
        echo "3. Configure LDAP (schema in /usr/share/libpam-web3/ldap/)"
        echo ""
        echo "4. Start the web3-auth-svc daemon:"
        echo "   systemctl enable --now web3-auth-svc"
        echo ""
        echo "5. Configure PAM (see /usr/share/doc/libpam-web3/)"
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
        # Remove config directories on purge
        rm -rf /etc/pam_web3 2>/dev/null || true
        rm -rf /etc/web3-auth 2>/dev/null || true
        rm -rf /run/web3-auth 2>/dev/null || true

        # Remove symlink
        rm -f /lib/x86_64-linux-gnu/security/pam_web3.so 2>/dev/null || true
        ;;

    remove)
        # Remove symlink
        rm -f /lib/x86_64-linux-gnu/security/pam_web3.so 2>/dev/null || true
        ;;
esac

exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postrm"

# Create example PAM config
cat > "$PKG_DIR/etc/pam_web3/config.toml" << 'EOF'
# libpam-web3 configuration
# See /usr/share/doc/libpam-web3/ for full documentation

[machine]
# Unique identifier for this machine (used in NFT verification)
id = "my-server"
# Path to ECIES private key (generate with: pam_web3_tool generate-keypair)
private_key_file = "/etc/pam_web3/server.key"

[auth]
# Authentication mode: "nft" for NFT-based auth
mode = "nft"
# URL where users can sign messages (displayed during login)
signing_url = "http://localhost:8080"
# OTP settings
otp_length = 6
otp_ttl_seconds = 300

[blockchain]
# Unix socket for web3-auth-svc
socket_path = "/run/web3-auth/web3-auth.sock"
# Ethereum chain ID (1=mainnet, 11155111=sepolia)
chain_id = 11155111
# NFT contract address
nft_contract = "0xYourContractAddress"
# Timeout for blockchain queries
timeout_seconds = 10

[ldap]
# LDAP server URL
server = "ldap://localhost:389"
# Base DN for NFT credential lookups
base_dn = "ou=nft,dc=example,dc=com"
# Bind credentials
bind_dn = "cn=pam,dc=example,dc=com"
bind_password_file = "/etc/pam_web3/ldap.secret"
# Attribute mappings
token_id_attribute = "nftTokenId"
revoked_attribute = "nftRevoked"
username_attribute = "linuxUsername"
timeout_seconds = 10
EOF

# Create example web3-auth config
cat > "$PKG_DIR/etc/web3-auth/config.toml" << 'EOF'
# web3-auth-svc configuration

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

Quick Start
-----------

1. Generate a server keypair:

   pam_web3_tool generate-keypair --output /etc/pam_web3/server.key
   chmod 600 /etc/pam_web3/server.key

2. Deploy an NFT contract and mint access tokens (see upstream docs)

3. Configure LDAP:
   - Import schema from /usr/share/libpam-web3/ldap/nft-schema.ldif
   - Add entries mapping NFT token IDs to Linux usernames

4. Update configuration:
   - /etc/pam_web3/config.toml (PAM module settings)
   - /etc/web3-auth/config.toml (blockchain service settings)

5. Start the blockchain service:

   systemctl enable --now web3-auth-svc

6. Configure PAM for SSH. Edit /etc/pam.d/sshd:

   # Add before @include common-auth:
   auth [success=2 default=ignore] pam_succeed_if.so user != web3user
   auth [success=1 default=die] pam_web3.so

   @include common-auth

7. Enable challenge-response in /etc/ssh/sshd_config:

   KbdInteractiveAuthentication yes
   UsePAM yes

8. Restart SSH:

   systemctl restart sshd

Files
-----

/lib/x86_64-linux-gnu/security/libpam_web3.so - PAM module
/usr/bin/web3-auth-svc - Blockchain query daemon
/usr/bin/pam_web3_tool - Key generation and encryption tool
/etc/pam_web3/config.toml - PAM module configuration
/etc/web3-auth/config.toml - Blockchain service configuration
/usr/share/libpam-web3/ldap/ - LDAP schema files
/usr/share/libpam-web3/scripts/ - Helper scripts

For full documentation, see:
https://github.com/mwaddip/libpam-web3/blob/main/docs/NFT_MODE_SETUP.md
EOF

# Copy LDAP schema files
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

cat > "$PKG_DIR/usr/share/${PKG_NAME}/ldap/example-entries.ldif" << 'EOF'
# Example LDAP entries for libpam-web3 NFT mode
# Customize the base DN (dc=example,dc=com) for your environment.
# Install with: ldapadd -x -D "cn=admin,dc=example,dc=com" -W -f example-entries.ldif

# Create the NFT organizational unit
dn: ou=nft,dc=example,dc=com
objectClass: organizationalUnit
ou: nft
description: NFT-based access credentials

# Example credential for token ID 0
dn: cn=token0,ou=nft,dc=example,dc=com
objectClass: top
objectClass: device
objectClass: nftCredential
cn: token0
nftTokenId: 0
nftRevoked: FALSE
linuxUsername: johndoe
walletAddress: 0x1234567890AbcdEF1234567890aBcdef12345678
description: Server access credential for John Doe

# PAM service account for LDAP lookups
# Note: Generate password hash with: slappasswd -s YourPassword
dn: cn=pam,dc=example,dc=com
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: pam
userPassword: {SSHA}REPLACE_WITH_HASHED_PASSWORD
description: PAM bind user for NFT credential lookups
EOF

# Set correct permissions
find "$PKG_DIR" -type d -exec chmod 755 {} \;
find "$PKG_DIR" -type f -exec chmod 644 {} \;
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 755 "$PKG_DIR/DEBIAN/prerm"
chmod 755 "$PKG_DIR/DEBIAN/postrm"
chmod 755 "$PKG_DIR/usr/bin/"*
chmod 755 "$PKG_DIR/usr/share/${PKG_NAME}/scripts/"*
chmod 640 "$PKG_DIR/etc/pam_web3/config.toml"
chmod 640 "$PKG_DIR/etc/web3-auth/config.toml"

# Build the package
echo "[6/6] Building .deb package..."
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
    dpkg-deb -c "$DEB_FILE" | head -30
    echo "..."
    echo ""
    echo "To install:"
    echo "  sudo dpkg -i $DEB_FILE"
    echo ""
    echo "To install with dependencies:"
    echo "  sudo apt install ./${PKG_NAME}_${VERSION}_${ARCH}.deb"
else
    echo "ERROR: Package build failed"
    exit 1
fi
