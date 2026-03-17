#!/bin/bash
#
# Build a .deb package for libpam-web3-evm
#
# This package contains:
#   - web3-auth-svc (EVM signing server — no Rust plugin needed, PAM has built-in ecrecover)
#   - Signing page HTML + engine.js + template.html
#   - Systemd unit and tmpfiles.d config
#
# Usage: ./packaging/build-deb.sh
#
# Requirements:
#   - node + npx (for esbuild bundling of auth-svc)
#   - dpkg-deb

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="0.1.0"
ARCH="all"
PKG_NAME="libpam-web3-evm"
PKG_DIR="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}"

echo "=== Building ${PKG_NAME} ${VERSION} ==="

# Clean previous build
rm -rf "$PKG_DIR"
rm -f "$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"

# 1. Bundle auth-svc with esbuild
echo "[1/3] Bundling auth-svc..."
cd "$PROJECT_DIR"
if ! command -v npx &> /dev/null; then
    echo "ERROR: npx not found. Install Node.js to bundle auth-svc."
    exit 1
fi

npm install --save-dev esbuild 2>/dev/null

npx esbuild auth-svc-src/index.ts \
    --bundle --platform=node --target=node22 --minify \
    --outfile=auth-svc.js

# 2. Create package directory structure
echo "[2/3] Creating package structure..."
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/blockhost/auth-svc/evm"
mkdir -p "$PKG_DIR/usr/share/blockhost/signing-pages/evm"
mkdir -p "$PKG_DIR/lib/systemd/system"
mkdir -p "$PKG_DIR/usr/lib/tmpfiles.d"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}"

# Copy bundled auth-svc
cp "$PROJECT_DIR/auth-svc.js" "$PKG_DIR/usr/share/blockhost/auth-svc/evm/"

# Create wrapper script for auth-svc
cat > "$PKG_DIR/usr/bin/web3-auth-svc-evm" << 'WRAPPER'
#!/bin/sh
exec node /usr/share/blockhost/auth-svc/evm/auth-svc.js "$@"
WRAPPER

# Copy signing page (served directly by auth-svc)
cp "$PROJECT_DIR/signing-page/index.html" "$PKG_DIR/usr/share/blockhost/signing-pages/evm/"
cp "$PROJECT_DIR/signing-page/engine.js" "$PKG_DIR/usr/share/blockhost/signing-pages/evm/"
cp "$PROJECT_DIR/signing-page/template.html" "$PKG_DIR/usr/share/blockhost/signing-pages/evm/"

# Copy systemd unit
cp "$PROJECT_DIR/web3-auth-svc.service" "$PKG_DIR/lib/systemd/system/web3-auth-svc-evm.service"

# Copy tmpfiles.d config
cp "$PROJECT_DIR/libpam-web3.conf" "$PKG_DIR/usr/lib/tmpfiles.d/"

# Copy config example as documentation
cp "$PROJECT_DIR/config.example.toml" "$PKG_DIR/usr/share/doc/${PKG_NAME}/"

# Create control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Depends: libpam-web3, nodejs (>= 18)
Maintainer: libpam-web3 maintainers
Homepage: https://github.com/mwaddip/libpam-web3
Description: EVM signing page and auth service for libpam-web3
 Adds an EVM (MetaMask / personal_sign) signing page for browser-based
 callback authentication with libpam-web3.
 .
 No verification plugin needed — PAM has built-in secp256k1 ecrecover.
 This package provides the signing page and callback transport only.
 .
 Requires libpam-web3 (core PAM module) to be installed.
EOF

# Create postinst
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e
case "$1" in
    configure)
        systemd-tmpfiles --create /usr/lib/tmpfiles.d/libpam-web3.conf 2>/dev/null || true
        systemctl daemon-reload
        systemctl enable --now web3-auth-svc-evm 2>/dev/null || true
        echo ""
        echo "=== libpam-web3-evm installed ==="
        echo ""
        echo "Auth-svc:     systemctl status web3-auth-svc-evm"
        echo "Signing page: https://$(hostname):63108/"
        echo ""
        echo "No configuration needed — port derived from chain name, TLS from libpam-web3."
        echo ""
        ;;
esac
exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Create prerm
cat > "$PKG_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e
case "$1" in
    remove|upgrade)
        systemctl stop web3-auth-svc-evm 2>/dev/null || true
        systemctl disable web3-auth-svc-evm 2>/dev/null || true
        ;;
esac
exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# Set permissions
find "$PKG_DIR" -type d -exec chmod 755 {} \;
find "$PKG_DIR" -type f -exec chmod 644 {} \;
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 755 "$PKG_DIR/DEBIAN/prerm"
chmod 755 "$PKG_DIR/usr/bin/web3-auth-svc-evm"

# 3. Build the package
echo "[3/3] Building .deb package..."
cd "$SCRIPT_DIR"
dpkg-deb --build --root-owner-group "$PKG_DIR"

DEB_FILE="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"
if [ -f "$DEB_FILE" ]; then
    echo ""
    echo "=== Package built successfully ==="
    ls -lh "$DEB_FILE"
    echo ""
    dpkg-deb -c "$DEB_FILE"
else
    echo "ERROR: Package build failed"
    exit 1
fi
