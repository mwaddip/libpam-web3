#!/bin/bash
#
# Build script to minify and base64 encode the signing page for NFT minting
#
# IMPORTANT: Output Format
# ========================
# This script outputs TWO files:
#   - signing-page.b64     : Raw base64 (for NFT contract mint() function)
#   - signing-page.datauri : Full data URI (for direct use in JSON metadata)
#
# The NFT contract's mint() function expects ONLY the raw base64 content.
# The contract's tokenURI() automatically prepends "data:text/html;base64,"
# when generating the metadata JSON.
#
# Usage:
#   For NFT minting (CLI/scripts):  Use signing-page.b64 (raw base64)
#   For direct metadata JSON:        Use signing-page.datauri (full data URI)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT="$SCRIPT_DIR/index.html"
OUTPUT_B64="$SCRIPT_DIR/signing-page.b64"
OUTPUT_DATAURI="$SCRIPT_DIR/signing-page.datauri"

# Check if input exists
if [ ! -f "$INPUT" ]; then
    echo "Error: $INPUT not found"
    exit 1
fi

# Minify HTML (remove comments, excess whitespace)
# This is a simple minification - for production use a proper minifier
minify_html() {
    # Remove HTML comments
    sed 's/<!--.*-->//g' |
    # Remove leading/trailing whitespace from lines
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
    # Join lines (be careful with script content)
    tr '\n' ' ' |
    # Collapse multiple spaces
    sed 's/  */ /g'
}

# Read, minify, and base64 encode
MINIFIED=$(cat "$INPUT" | minify_html)
ENCODED=$(echo -n "$MINIFIED" | base64 -w 0)

# Output raw base64 (for NFT contract mint())
echo -n "$ENCODED" > "$OUTPUT_B64"

# Output full data URI (for direct JSON metadata use)
DATA_URI="data:text/html;base64,$ENCODED"
echo "$DATA_URI" > "$OUTPUT_DATAURI"

# Show stats
ORIGINAL_SIZE=$(wc -c < "$INPUT")
B64_SIZE=${#ENCODED}
DATAURI_SIZE=${#DATA_URI}

echo "Original size:  $ORIGINAL_SIZE bytes"
echo "Base64 size:    $B64_SIZE bytes"
echo "Data URI size:  $DATAURI_SIZE bytes"
echo ""
echo "Output files:"
echo "  $OUTPUT_B64"
echo "      -> Raw base64 for NFT contract mint() animationUrlBase64 parameter"
echo ""
echo "  $OUTPUT_DATAURI"
echo "      -> Full data URI for direct use in JSON metadata"
echo ""
echo "IMPORTANT: The NFT contract expects RAW BASE64 (signing-page.b64)."
echo "           The contract's tokenURI() adds the 'data:text/html;base64,' prefix."
