#!/bin/bash
#
# Resolve the signing host for libpam-web3 signing URLs and (re)generate
# the TLS cert so its SAN matches. Runs once at boot via
# libpam-web3-signing-host.service.
#
# Outputs:
#   /run/libpam-web3/signing_host   — the host the user will see in URLs
#   /etc/libpam-web3/tls/{cert,key}.pem — TLS cert with $HOST in SAN
#
# Strategy:
#   1. Get FQDN from hostname -f
#   2. Check if it resolves in public DNS (dig @1.1.1.1)
#   3. If yes → use FQDN
#   4. If no  → use <public-ipv6>.sslip.io (dashes for colons)
#   5. If no  → use <public-ipv4>.sslip.io
#   6. If no  → use <private-ipv4> (last resort)
#
# Whatever host we land on goes into the cert SAN — otherwise the user
# would see a TLS warning when their browser opens the signing URL, and
# clicking through cert errors during auth is the original sin of any
# auth UI.

set -e

OUTPUT="/run/libpam-web3/signing_host"
TLS_DIR="/etc/libpam-web3/tls"
mkdir -p "$(dirname "$OUTPUT")"

FQDN="$(hostname -f 2>/dev/null || hostname)"

# Check public DNS resolution (1.1.1.1, 2-second timeout)
fqdn_resolves() {
    # dig might not be installed — try host, then nslookup, then give up
    if command -v dig &>/dev/null; then
        dig +short +timeout=2 +tries=1 "@1.1.1.1" "$1" 2>/dev/null | grep -q .
    elif command -v host &>/dev/null; then
        host -W 2 "$1" 1.1.1.1 &>/dev/null
    else
        # No DNS tools — assume it doesn't resolve
        return 1
    fi
}

# Get first global-scope IPv6 (not loopback, not link-local, not ULA)
get_public_ipv6() {
    ip -6 addr show scope global 2>/dev/null \
        | grep -oP 'inet6\s+\K[0-9a-f:]+' \
        | grep -v '^fe80' \
        | grep -v '^fd' \
        | head -1
}

# Get first non-loopback IPv4
get_ipv4() {
    ip -4 addr show 2>/dev/null \
        | grep -oP 'inet\s+\K[0-9.]+' \
        | grep -v '^127\.' \
        | head -1
}

# sslip.io: IPv6 colons → dashes, IPv4 dots as-is
sslip_host() {
    local ip="$1"
    if [[ "$ip" == *:* ]]; then
        echo "${ip//:/-}.sslip.io"
    else
        echo "${ip}.sslip.io"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────

if [[ "$FQDN" == *"."* ]] && fqdn_resolves "$FQDN"; then
    HOST="$FQDN"
else
    V6="$(get_public_ipv6)"
    V4="$(get_ipv4)"

    if [[ -n "$V6" ]]; then
        HOST="$(sslip_host "$V6")"
    elif [[ -n "$V4" ]]; then
        HOST="$(sslip_host "$V4")"
    else
        # No public IP at all — use whatever we have
        HOST="${V4:-$FQDN}"
    fi
fi

echo "$HOST" > "$OUTPUT"
echo "[SIGN-HOST] Resolved signing host: $HOST → $OUTPUT"

# ── TLS cert: regenerate if missing or SAN doesn't match $HOST ─────────

needs_regen() {
    [ ! -f "$TLS_DIR/cert.pem" ] && return 0
    if ! command -v openssl >/dev/null 2>&1; then
        return 1
    fi
    # Match the resolved host as DNS SAN (case-insensitive — DNS labels are)
    if openssl x509 -in "$TLS_DIR/cert.pem" -noout -ext subjectAltName 2>/dev/null \
        | grep -qiF "DNS:$HOST"; then
        return 1
    fi
    return 0
}

if needs_regen; then
    if ! command -v openssl >/dev/null 2>&1; then
        echo "[SIGN-HOST] WARNING: openssl missing; cannot regenerate TLS cert"
        exit 0
    fi

    mkdir -p "$TLS_DIR"

    # Build SAN list. Always include the resolved host. Also include the
    # local short hostname and any usable FQDN/IP so existing setups (where
    # users hit the box by hostname or IP directly) still validate.
    SAN_LIST="DNS:$HOST"
    LOCAL_HN="$(hostname 2>/dev/null || true)"
    if [ -n "$LOCAL_HN" ] && [ "$LOCAL_HN" != "$HOST" ]; then
        SAN_LIST="$SAN_LIST,DNS:$LOCAL_HN"
    fi
    LOCAL_FQDN="$(hostname -f 2>/dev/null || true)"
    if [ -n "$LOCAL_FQDN" ] \
        && [ "$LOCAL_FQDN" != "$HOST" ] \
        && [ "$LOCAL_FQDN" != "$LOCAL_HN" ]; then
        SAN_LIST="$SAN_LIST,DNS:$LOCAL_FQDN"
    fi
    LOCAL_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    if [ -n "$LOCAL_IP" ]; then
        SAN_LIST="$SAN_LIST,IP:$LOCAL_IP"
    fi

    # Write to a temp dir, then move into place — openssl can leave a stale
    # half-written key.pem if it errors after writing the key but before the
    # cert. Auth-svc TLS load would then mis-pair an old cert with a new key.
    TMP_DIR="$(mktemp -d)"
    if openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$TMP_DIR/key.pem" -out "$TMP_DIR/cert.pem" \
        -days 3650 -nodes -subj "/CN=$HOST" \
        -addext "subjectAltName=$SAN_LIST" \
        2>/dev/null
    then
        chmod 600 "$TMP_DIR/key.pem"
        chmod 644 "$TMP_DIR/cert.pem"
        mv "$TMP_DIR/key.pem" "$TLS_DIR/key.pem"
        mv "$TMP_DIR/cert.pem" "$TLS_DIR/cert.pem"
        echo "[SIGN-HOST] Regenerated TLS cert. SAN=$SAN_LIST"
        # Reload any running auth-svc instances so they pick up the new cert.
        # try-restart is a no-op for inactive units (no plugin installed yet).
        if command -v systemctl >/dev/null 2>&1; then
            systemctl try-restart 'web3-auth-svc-*.service' 2>/dev/null || true
        fi
    else
        echo "[SIGN-HOST] WARNING: openssl failed to generate cert"
    fi
    rm -rf "$TMP_DIR"
fi
