#!/bin/bash
#
# Build a .deb package for libpam-web3 (PAM module for VMs)
#
# This package contains:
#   - PAM module (pam_web3.so) for wallet-based authentication
#   - Configuration for PAM authentication on VMs
#
# Usage: ./packaging/build-deb.sh
#
# Requirements: dpkg-deb, cargo-zigbuild, zig (in PATH)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="0.8.0"
ARCH="amd64"
PKG_NAME="libpam-web3"
PKG_DIR="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}"

echo "=== Building libpam-web3 ${VERSION} for ${ARCH} ==="

# Clean previous build
rm -rf "$PKG_DIR"
rm -f "$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"

# Check build dependencies
if ! command -v cargo-zigbuild &> /dev/null; then
    echo "ERROR: cargo-zigbuild not found. Install with: cargo install cargo-zigbuild"
    exit 1
fi
if ! command -v zig &> /dev/null; then
    echo "ERROR: zig not found. See https://ziglang.org/download/"
    exit 1
fi

# Build PAM module (target glibc 2.36 for Debian 12 compatibility)
echo "[1/4] Building PAM module..."
cd "$PROJECT_DIR"
ZIG_TARGET="x86_64-unknown-linux-gnu.2.36"
BINDGEN_EXTRA_CLANG_ARGS="--sysroot=/ -I/usr/include" \
RUSTFLAGS="-L /usr/lib/x86_64-linux-gnu" \
cargo zigbuild --release --target "$ZIG_TARGET"

# Create package directory structure
echo "[2/4] Creating package structure..."
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/lib/x86_64-linux-gnu/security"
mkdir -p "$PKG_DIR/etc/pam_web3"
mkdir -p "$PKG_DIR/usr/share/libpam-web3"
mkdir -p "$PKG_DIR/lib/systemd/system"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}/examples"

# Copy PAM module and signing host resolver
echo "[3/4] Copying files..."
cp "$PROJECT_DIR/target/x86_64-unknown-linux-gnu/release/libpam_web3.so" "$PKG_DIR/lib/x86_64-linux-gnu/security/"
cp "$PROJECT_DIR/signing-host/resolve-signing-host.sh" "$PKG_DIR/usr/share/libpam-web3/"
cp "$PROJECT_DIR/signing-host/libpam-web3-signing-host.service" "$PKG_DIR/lib/systemd/system/"

# Create control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Depends: libc6 (>= 2.34), libpam-runtime
Maintainer: libpam-web3 maintainers
Homepage: https://github.com/mwaddip/libpam-web3
Description: PAM module for wallet-based authentication
 libpam-web3 provides Linux authentication using wallet signatures
 and GECOS-based identity mapping.
 .
 Install this package on VMs/servers where users authenticate via wallet.
 .
 Features:
  - EVM wallet signature verification (secp256k1 ecrecover)
  - OPNet callback support (OTP validation + trusted address)
  - GECOS-based username mapping (wallet=ADDRESS)
  - Challenge-response OTP authentication
  - Runtime callback detection (no config needed)
 .
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

        systemctl daemon-reload
        systemctl enable --now libpam-web3-signing-host 2>/dev/null || true

        echo ""
        echo "=== libpam-web3 installed ==="
        echo ""
        echo "Configuration:"
        echo "  /etc/pam_web3/config.toml   (PAM module)"
        echo ""
        echo "Quick setup:"
        echo "1. Edit configuration with your settings"
        echo "2. Create user with wallet address in GECOS:"
        echo "   useradd -m -c 'wallet=0xADDRESS,nft=TOKEN_ID' username"
        echo "3. Configure PAM (see /usr/share/doc/libpam-web3/)"
        echo ""
        echo "Note: Callback mode activates automatically when an auth service"
        echo "creates /run/libpam-web3/pending/. No config flag needed."
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
    remove|upgrade)
        systemctl stop libpam-web3-signing-host 2>/dev/null || true
        systemctl disable libpam-web3-signing-host 2>/dev/null || true
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
# OTP settings
otp_length = 6
otp_ttl_seconds = 300
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

Callback mode is detected at runtime: if /run/libpam-web3/pending/
exists (created by a running auth service), callbacks are enabled
automatically. Otherwise, the user pastes the signature manually.

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
else
    echo "ERROR: Package build failed"
    exit 1
fi
