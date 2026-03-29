#!/bin/bash
#
# Resolve the signing host for libpam-web3 signing URLs.
# Runs once at boot (after network-online.target).
# Writes the result to /run/libpam-web3/signing_host.
#
# Strategy:
#   1. Get FQDN from hostname -f
#   2. Check if it resolves in public DNS (dig @1.1.1.1)
#   3. If yes → use FQDN
#   4. If no  → use <public-ipv6>.sslip.io (dashes for colons)
#   5. If no  → use <public-ipv4>.sslip.io
#   6. If no  → use <private-ipv4> (last resort)

set -e

OUTPUT="/run/libpam-web3/signing_host"
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
