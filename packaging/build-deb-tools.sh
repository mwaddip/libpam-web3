#!/bin/bash
#
# Build a .deb package for libpam-web3-tools (admin/minting tools)
#
# This package contains:
#   - pam_web3_tool: CLI for encryption/decryption, keypair generation
#   - Signing page generator scripts
#
# Note: web3-auth-svc is in the main libpam-web3 package (required on VMs)
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

# Build pam_web3_tool
echo "[1/4] Building pam_web3_tool..."
cd "$PROJECT_DIR"
cargo build --release --features nft

# Create package directory structure
echo "[2/4] Creating package structure..."
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}"
mkdir -p "$PKG_DIR/usr/share/${PKG_NAME}/signing-page"
mkdir -p "$PKG_DIR/usr/share/${PKG_NAME}/ldap"

# Copy binaries
echo "[3/4] Copying files..."
cp "$PROJECT_DIR/target/release/pam_web3_tool" "$PKG_DIR/usr/bin/"

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
Description: Admin tools for libpam-web3 NFT authentication
 This package provides admin tools for managing NFT-based authentication:
 .
  - pam_web3_tool: CLI for keypair generation, encryption, decryption
  - Signing page generator for NFT minting
 .
 Install this package on servers that mint NFT access credentials.
 .
 For VM/client authentication, install libpam-web3 instead.
EOF

# Create postinst script
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

case "$1" in
    configure)
        echo ""
        echo "=== libpam-web3-tools installed ==="
        echo ""
        echo "Tools available:"
        echo "  - pam_web3_tool: Keypair generation, encryption/decryption"
        echo ""
        echo "Signing page generator:"
        echo "  /usr/share/libpam-web3-tools/signing-page/"
        echo ""
        echo "Usage:"
        echo "  cd /usr/share/libpam-web3-tools/signing-page/"
        echo "  ./generate.sh --server-pubkey '04...' --decrypt-message 'Decrypt credentials'"
        echo "  ./build.sh"
        echo ""
        ;;
esac

exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

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

This package provides admin tools for NFT-based authentication.

Components
----------

pam_web3_tool - CLI utility for:
  - Generating secp256k1 keypairs
  - Encrypting data with signature-derived keys (AES-GCM)
  - Decrypting user_encrypted NFT fields
  - Deriving public keys

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

For VM authentication, install libpam-web3 package.
EOF

# Set correct permissions
find "$PKG_DIR" -type d -exec chmod 755 {} \;
find "$PKG_DIR" -type f -exec chmod 644 {} \;
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 755 "$PKG_DIR/usr/bin/"*
chmod 755 "$PKG_DIR/usr/share/${PKG_NAME}/signing-page/"*.sh

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
else
    echo "ERROR: Package build failed"
    exit 1
fi
