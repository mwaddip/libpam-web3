#!/bin/bash
# Query and display NFT data from AccessCredentialNFT contract

set -e

# Help message
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    cat <<EOF
Usage: $(basename "$0") [TOKEN_ID] [WALLET_ADDRESS]

Query and display NFT data from the AccessCredentialNFT contract.

Arguments:
  TOKEN_ID        Token ID to query (default: 0)
  WALLET_ADDRESS  Optional wallet to check balance for

Environment variables:
  CONTRACT        Contract address (default: 0x29Fae1Ef60F37f49E6Aa0F199086aaBCe49f9536)
  RPC_URL         RPC endpoint (default: https://ethereum-sepolia-rpc.publicnode.com)
  CAST            Path to cast binary (default: cast or ~/.foundry/bin/cast)

Examples:
  $(basename "$0")                    # Query token 0
  $(basename "$0") 5                  # Query token 5
  $(basename "$0") 0 0xABC...         # Query token 0 and check wallet balance
  CONTRACT=0x... $(basename "$0") 1   # Use custom contract address
EOF
    exit 0
fi

# Configuration
RPC_URL="${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"
CONTRACT="${CONTRACT:-0x29Fae1Ef60F37f49E6Aa0F199086aaBCe49f9536}"
CAST="${CAST:-cast}"

# Check if cast is available
if ! command -v "$CAST" &> /dev/null; then
    CAST="$HOME/.foundry/bin/cast"
    if ! command -v "$CAST" &> /dev/null; then
        echo "Error: 'cast' not found. Install Foundry: curl -L https://foundry.paradigm.xyz | bash"
        exit 1
    fi
fi

# Parse arguments
TOKEN_ID="${1:-0}"
WALLET="${2:-}"

echo "========================================"
echo "  AccessCredentialNFT Query Tool"
echo "========================================"
echo ""
echo "Contract: $CONTRACT"
echo "RPC:      $RPC_URL"
echo "Token ID: $TOKEN_ID"
echo ""

# Get contract name and symbol
echo "--- Contract Info ---"
NAME=$("$CAST" call --rpc-url "$RPC_URL" "$CONTRACT" "name()(string)" 2>/dev/null || echo "N/A")
SYMBOL=$("$CAST" call --rpc-url "$RPC_URL" "$CONTRACT" "symbol()(string)" 2>/dev/null || echo "N/A")
echo "Name:   $NAME"
echo "Symbol: $SYMBOL"
echo ""

# Get total supply if available
TOTAL=$("$CAST" call --rpc-url "$RPC_URL" "$CONTRACT" "totalSupply()(uint256)" 2>/dev/null || echo "N/A")
echo "Total Supply: $TOTAL"
echo ""

# If wallet provided, check their balance
if [ -n "$WALLET" ]; then
    echo "--- Wallet: $WALLET ---"
    BALANCE=$("$CAST" call --rpc-url "$RPC_URL" "$CONTRACT" "balanceOf(address)(uint256)" "$WALLET")
    echo "NFT Balance: $BALANCE"
    echo ""
fi

# Check if token exists and get owner
echo "--- Token #$TOKEN_ID ---"
OWNER=$("$CAST" call --rpc-url "$RPC_URL" "$CONTRACT" "ownerOf(uint256)(address)" "$TOKEN_ID" 2>/dev/null)
if [ -z "$OWNER" ] || [ "$OWNER" = "0x0000000000000000000000000000000000000000" ]; then
    echo "Token does not exist"
    exit 1
fi
echo "Owner: $OWNER"

# Check if expired
EXPIRED=$("$CAST" call --rpc-url "$RPC_URL" "$CONTRACT" "isExpired(uint256)(bool)" "$TOKEN_ID" 2>/dev/null || echo "false")
echo "Expired: $EXPIRED"
echo ""

# Get access data
echo "--- Access Data ---"
ACCESS_DATA=$("$CAST" call --rpc-url "$RPC_URL" "$CONTRACT" "getAccessData(uint256)" "$TOKEN_ID")

# Decode the access data (returns bytes, bytes, uint256, uint256)
# Parse the ABI-encoded response
ACCESS_DECODED=$("$CAST" abi-decode "getAccessData(uint256)(bytes,bytes,uint256,uint256)" "$ACCESS_DATA" 2>/dev/null)

# Extract individual fields
SERVER_ENCRYPTED=$(echo "$ACCESS_DECODED" | sed -n '1p')
USER_ENCRYPTED=$(echo "$ACCESS_DECODED" | sed -n '2p')
ISSUED_AT=$(echo "$ACCESS_DECODED" | sed -n '3p')
EXPIRES_AT=$(echo "$ACCESS_DECODED" | sed -n '4p')

echo "Server Encrypted: $SERVER_ENCRYPTED"
echo "User Encrypted:   $USER_ENCRYPTED"

# Clean up timestamps (remove scientific notation from cast output)
ISSUED_AT=$(echo "$ISSUED_AT" | awk '{print $1}')
EXPIRES_AT=$(echo "$EXPIRES_AT" | awk '{print $1}')

# Convert timestamps to human-readable
if [ "$ISSUED_AT" != "0" ] && [ -n "$ISSUED_AT" ]; then
    ISSUED_DATE=$(date -d "@$ISSUED_AT" "+%Y-%m-%d %H:%M:%S %Z" 2>/dev/null || echo "$ISSUED_AT")
    echo "Issued At:        $ISSUED_DATE"
else
    echo "Issued At:        $ISSUED_AT"
fi

if [ "$EXPIRES_AT" = "0" ] || [ -z "$EXPIRES_AT" ]; then
    echo "Expires At:       Never"
else
    EXPIRES_DATE=$(date -d "@$EXPIRES_AT" "+%Y-%m-%d %H:%M:%S %Z" 2>/dev/null || echo "$EXPIRES_AT")
    echo "Expires At:       $EXPIRES_DATE"
fi

# Try to decode the encrypted data as ASCII (for test data)
echo ""
echo "--- Decoded (if plaintext test data) ---"
if [[ "$SERVER_ENCRYPTED" == 0x* ]]; then
    DECODED=$(echo "$SERVER_ENCRYPTED" | cut -c3- | xxd -r -p 2>/dev/null || echo "[binary data]")
    echo "Server Data: $DECODED"
fi
if [[ "$USER_ENCRYPTED" == 0x* ]]; then
    DECODED=$(echo "$USER_ENCRYPTED" | cut -c3- | xxd -r -p 2>/dev/null || echo "[binary data]")
    echo "User Data:   $DECODED"
fi

# Get and decode token URI
echo ""
echo "--- Token URI (Metadata) ---"
TOKEN_URI=$("$CAST" call --rpc-url "$RPC_URL" "$CONTRACT" "tokenURI(uint256)(string)" "$TOKEN_ID" 2>/dev/null)
# Remove surrounding quotes if present
TOKEN_URI=$(echo "$TOKEN_URI" | sed 's/^"//;s/"$//')

if [[ "$TOKEN_URI" == data:application/json* ]]; then
    # Extract base64 part and decode
    BASE64_DATA=$(echo "$TOKEN_URI" | sed 's/data:application\/json;base64,//')
    METADATA=$(echo "$BASE64_DATA" | base64 -d 2>/dev/null)

    # Pretty print if jq is available
    if command -v jq &> /dev/null; then
        echo "$METADATA" | jq .
    else
        echo "$METADATA"
    fi
elif [[ "$TOKEN_URI" == ipfs://* ]]; then
    echo "IPFS URI: $TOKEN_URI"
    echo "(Use an IPFS gateway to fetch metadata)"
elif [[ "$TOKEN_URI" == http* ]]; then
    echo "HTTP URI: $TOKEN_URI"
else
    echo "$TOKEN_URI"
fi

echo ""
echo "========================================"
