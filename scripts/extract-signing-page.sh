#!/bin/bash
#
# Extract and host the signing page from an NFT's metadata.
#
# This script queries an NFT contract to get the tokenURI, extracts the
# embedded signing page from the animation_url field, and hosts it locally
# so MetaMask can connect (browsers block wallet connections on file:// URLs).
#
# Requirements: curl, python3 (both typically pre-installed on Linux)
#
# Usage:
#   ./extract-signing-page.sh --contract 0x713F72Ba266dB7A11b12886514a4A7FCb3402d94
#   ./extract-signing-page.sh --rpc-url https://eth-mainnet.g.alchemy.com/v2/... --contract 0x... --token-id 5
#

set -e

# Default values
RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
CONTRACT=""
TOKEN_ID=0
PORT=8080
NO_BROWSER=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 --contract <address> [options]"
    echo ""
    echo "Options:"
    echo "  --rpc-url <url>     Ethereum JSON-RPC endpoint (default: Sepolia public RPC)"
    echo "  --contract <addr>   NFT contract address (required)"
    echo "  --token-id <id>     Token ID to query (default: 0)"
    echo "  --port <port>       Local HTTP server port (default: 8080)"
    echo "  --no-browser        Don't automatically open the browser"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --contract 0x713F72Ba266dB7A11b12886514a4A7FCb3402d94 --token-id 0"
    exit 1
}

log_status() {
    echo -e "${CYAN}[*]${NC} $1"
}

log_error() {
    echo -e "${RED}[!]${NC} $1" >&2
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --rpc-url)
            RPC_URL="$2"
            shift 2
            ;;
        --contract)
            CONTRACT="$2"
            shift 2
            ;;
        --token-id)
            TOKEN_ID="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --no-browser)
            NO_BROWSER=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate required args
if [[ -z "$CONTRACT" ]]; then
    echo "Error: --contract is required"
    usage
fi

# Check dependencies
if ! command -v curl &> /dev/null; then
    log_error "curl is required but not installed"
fi

if ! command -v python3 &> /dev/null; then
    log_error "python3 is required but not installed"
fi

log_status "Querying NFT tokenURI..."
echo "    Contract: $CONTRACT"
echo "    Token ID: $TOKEN_ID"
echo "    RPC: $RPC_URL"

# Build the call data for tokenURI(uint256)
# Function selector: 0xc87b56dd
CALL_DATA=$(printf "0xc87b56dd%064x" "$TOKEN_ID")

# Build JSON-RPC request
RPC_REQUEST=$(cat <<EOF
{
    "jsonrpc": "2.0",
    "method": "eth_call",
    "params": [
        {
            "to": "$CONTRACT",
            "data": "$CALL_DATA"
        },
        "latest"
    ],
    "id": 1
}
EOF
)

# Make RPC call
RESPONSE=$(curl -s -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "$RPC_REQUEST")

# Check for errors
if echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if 'result' in d else 1)" 2>/dev/null; then
    HEX_RESULT=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])")
else
    ERROR=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('message','Unknown error'))" 2>/dev/null || echo "Failed to parse response")
    log_error "RPC error: $ERROR"
fi

log_status "Decoding tokenURI and extracting signing page..."

# Python script to decode ABI string, parse metadata, and extract HTML
HTML=$(python3 << PYEOF
import sys
import json
import base64

hex_data = "$HEX_RESULT"

# Remove 0x prefix
hex_data = hex_data[2:] if hex_data.startswith("0x") else hex_data

# Convert hex to bytes
data = bytes.fromhex(hex_data)

# ABI string encoding:
# - bytes 0-31: offset to string data (should be 0x20 = 32)
# - bytes 32-63: string length
# - bytes 64+: string data

if len(data) < 64:
    print("Error: Response too short", file=sys.stderr)
    sys.exit(1)

# Read string length from bytes 56-63
length = int.from_bytes(data[56:64], 'big')

if len(data) < 64 + length:
    print(f"Error: Response truncated, expected {length} bytes", file=sys.stderr)
    sys.exit(1)

# Extract string
token_uri = data[64:64+length].decode('utf-8')

# Check if it's a data URI
if not token_uri.startswith("data:application/json;base64,"):
    print(f"Error: tokenURI is not an embedded data URI: {token_uri[:100]}...", file=sys.stderr)
    sys.exit(1)

# Decode base64 JSON
base64_json = token_uri.replace("data:application/json;base64,", "")
try:
    json_str = base64.b64decode(base64_json).decode('utf-8')
    metadata = json.loads(json_str)
except Exception as e:
    print(f"Error: Failed to decode metadata: {e}", file=sys.stderr)
    sys.exit(1)

print(f"    Name: {metadata.get('name', 'N/A')}", file=sys.stderr)
print(f"    Description: {metadata.get('description', 'N/A')}", file=sys.stderr)

# Extract animation_url
animation_url = metadata.get('animation_url', '')
if not animation_url:
    print("Error: NFT metadata has no animation_url field", file=sys.stderr)
    sys.exit(1)

if not animation_url.startswith("data:text/html;base64,"):
    print(f"Error: animation_url is not embedded HTML: {animation_url[:50]}...", file=sys.stderr)
    sys.exit(1)

# Decode base64 HTML
base64_html = animation_url.replace("data:text/html;base64,", "")
try:
    html = base64.b64decode(base64_html).decode('utf-8')
except Exception as e:
    print(f"Error: Failed to decode HTML: {e}", file=sys.stderr)
    sys.exit(1)

print(f"    HTML size: {len(html)} bytes", file=sys.stderr)

# Output the HTML
print(html)
PYEOF
)

if [[ -z "$HTML" ]]; then
    log_error "Failed to extract signing page"
fi

# Save to temp file
TEMP_DIR="/tmp/web3-sign"
mkdir -p "$TEMP_DIR"
TEMP_FILE="$TEMP_DIR/index.html"
echo "$HTML" > "$TEMP_FILE"
echo "    Saved to: $TEMP_FILE"

log_status "Starting HTTP server on port $PORT..."

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Signing page available at:${NC}"
echo -e "${YELLOW} http://localhost:$PORT${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Press Ctrl+C to stop the server"
echo ""

# Open browser
if [[ "$NO_BROWSER" != "true" ]]; then
    # Try different commands for opening browser
    if command -v xdg-open &> /dev/null; then
        xdg-open "http://localhost:$PORT" 2>/dev/null &
    elif command -v open &> /dev/null; then
        open "http://localhost:$PORT" 2>/dev/null &
    elif command -v sensible-browser &> /dev/null; then
        sensible-browser "http://localhost:$PORT" 2>/dev/null &
    fi
fi

# Start HTTP server
cd "$TEMP_DIR"
python3 -m http.server "$PORT" 2>&1 | while read line; do
    echo "$(date '+%H:%M:%S') - $line"
done
