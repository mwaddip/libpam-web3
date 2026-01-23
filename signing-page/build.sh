#!/bin/bash
# Build script to minify and base64 encode the signing page
# Output can be used as the animation_url in NFT metadata

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT="$SCRIPT_DIR/index.html"
OUTPUT="$SCRIPT_DIR/signing-page.b64"

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

# Output the data URI
DATA_URI="data:text/html;base64,$ENCODED"

echo "$DATA_URI" > "$OUTPUT"

# Show stats
ORIGINAL_SIZE=$(wc -c < "$INPUT")
ENCODED_SIZE=${#DATA_URI}

echo "Original size: $ORIGINAL_SIZE bytes"
echo "Data URI size: $ENCODED_SIZE bytes"
echo "Output saved to: $OUTPUT"
echo ""
echo "Use this as the 'animation_url' in your NFT metadata."
