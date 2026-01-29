<#
.SYNOPSIS
    Extract and host the signing page from an NFT's metadata.

.DESCRIPTION
    This script queries an NFT contract to get the tokenURI, extracts the
    embedded signing page from the animation_url field, and hosts it locally
    so MetaMask can connect (browsers block wallet connections on file:// URLs).

.PARAMETER RpcUrl
    Ethereum JSON-RPC endpoint URL.

.PARAMETER Contract
    NFT contract address.

.PARAMETER TokenId
    Token ID to query (default: 0).

.PARAMETER Port
    Local HTTP server port (default: 8080).

.PARAMETER NoBrowser
    Don't automatically open the browser.

.EXAMPLE
    .\extract-signing-page.ps1 -Contract "0x713F72Ba266dB7A11b12886514a4A7FCb3402d94"

.EXAMPLE
    .\extract-signing-page.ps1 -RpcUrl "https://eth-mainnet.g.alchemy.com/v2/..." -Contract "0x..." -TokenId 5
#>

param(
    [string]$RpcUrl = "https://ethereum-sepolia-rpc.publicnode.com",
    [Parameter(Mandatory=$true)]
    [string]$Contract,
    [uint64]$TokenId = 0,
    [int]$Port = 8080,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"

function Write-Status($message) {
    Write-Host "[*] $message" -ForegroundColor Cyan
}

function Write-Error-Exit($message) {
    Write-Host "[!] $message" -ForegroundColor Red
    exit 1
}

# Build the eth_call data for tokenURI(uint256)
# Function selector: 0xc87b56dd
function Get-TokenUriCallData($tokenId) {
    $selector = "0xc87b56dd"
    $paddedTokenId = $tokenId.ToString("x64")
    return "$selector$paddedTokenId"
}

# Decode ABI-encoded string from hex
function Decode-AbiString($hexData) {
    # Remove 0x prefix
    $hex = $hexData -replace "^0x", ""

    # Convert hex to bytes
    $bytes = [byte[]]::new($hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }

    # ABI string encoding:
    # - bytes 0-31: offset to string data (should be 0x20 = 32)
    # - bytes 32-63: string length
    # - bytes 64+: string data

    if ($bytes.Length -lt 64) {
        throw "Response too short to contain ABI-encoded string"
    }

    # Read string length from bytes 56-63 (last 8 bytes of second 32-byte word)
    $length = 0
    for ($i = 56; $i -lt 64; $i++) {
        $length = ($length * 256) + $bytes[$i]
    }

    if ($bytes.Length -lt 64 + $length) {
        throw "Response truncated: expected $length bytes of string data"
    }

    # Extract and decode string
    $stringBytes = $bytes[64..(64 + $length - 1)]
    return [System.Text.Encoding]::UTF8.GetString($stringBytes)
}

# Main script
Write-Status "Querying NFT tokenURI..."
Write-Host "    Contract: $Contract"
Write-Host "    Token ID: $TokenId"
Write-Host "    RPC: $RpcUrl"

# Build JSON-RPC request
$callData = Get-TokenUriCallData $TokenId
$rpcRequest = @{
    jsonrpc = "2.0"
    method = "eth_call"
    params = @(
        @{
            to = $Contract
            data = $callData
        },
        "latest"
    )
    id = 1
} | ConvertTo-Json -Depth 10

# Make RPC call
try {
    $response = Invoke-WebRequest -Uri $RpcUrl -Method POST -Body $rpcRequest -ContentType "application/json" -UseBasicParsing
    $result = $response.Content | ConvertFrom-Json

    if ($result.error) {
        Write-Error-Exit "RPC error: $($result.error.message)"
    }

    $hexResult = $result.result
} catch {
    Write-Error-Exit "Failed to query RPC: $_"
}

# Decode ABI string
Write-Status "Decoding tokenURI..."
try {
    $tokenUri = Decode-AbiString $hexResult
} catch {
    Write-Error-Exit "Failed to decode ABI string: $_"
}

# Check if it's a data URI
if (-not $tokenUri.StartsWith("data:application/json;base64,")) {
    Write-Error-Exit "tokenURI is not an embedded data URI. Got: $($tokenUri.Substring(0, [Math]::Min(100, $tokenUri.Length)))..."
}

# Decode base64 JSON
Write-Status "Decoding NFT metadata..."
$base64Json = $tokenUri -replace "^data:application/json;base64,", ""
try {
    $jsonBytes = [Convert]::FromBase64String($base64Json)
    $jsonString = [System.Text.Encoding]::UTF8.GetString($jsonBytes)
    $metadata = $jsonString | ConvertFrom-Json
} catch {
    Write-Error-Exit "Failed to decode metadata JSON: $_"
}

Write-Host "    Name: $($metadata.name)"
Write-Host "    Description: $($metadata.description)"

# Extract animation_url
if (-not $metadata.animation_url) {
    Write-Error-Exit "NFT metadata has no animation_url field"
}

$animationUrl = $metadata.animation_url

if (-not $animationUrl.StartsWith("data:text/html;base64,")) {
    Write-Error-Exit "animation_url is not embedded HTML. Got: $($animationUrl.Substring(0, [Math]::Min(50, $animationUrl.Length)))..."
}

# Decode base64 HTML
Write-Status "Extracting signing page..."
$base64Html = $animationUrl -replace "^data:text/html;base64,", ""
try {
    $htmlBytes = [Convert]::FromBase64String($base64Html)
    $html = [System.Text.Encoding]::UTF8.GetString($htmlBytes)
} catch {
    Write-Error-Exit "Failed to decode HTML: $_"
}

Write-Host "    HTML size: $($html.Length) bytes"

# Save to temp file (for reference)
$tempDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "web3-sign")
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
}
$tempFile = [System.IO.Path]::Combine($tempDir, "index.html")
[System.IO.File]::WriteAllText($tempFile, $html)
Write-Host "    Saved to: $tempFile"

# Start HTTP server
Write-Status "Starting HTTP server on port $Port..."

$listener = [System.Net.HttpListener]::new()
$prefix = "http://localhost:$Port/"
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
} catch {
    Write-Error-Exit "Failed to start HTTP server. Try running as Administrator or use a different port: $_"
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " Signing page available at:" -ForegroundColor Green
Write-Host " http://localhost:$Port" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Gray
Write-Host ""

# Open browser
if (-not $NoBrowser) {
    Start-Process "http://localhost:$Port"
}

# Serve requests
try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response

        Write-Host "$(Get-Date -Format 'HH:mm:ss') - $($request.HttpMethod) $($request.Url.LocalPath)" -ForegroundColor Gray

        # Serve the HTML for any request
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
        $response.ContentType = "text/html; charset=utf-8"
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.OutputStream.Close()
    }
} finally {
    $listener.Stop()
    Write-Host "`nServer stopped." -ForegroundColor Yellow
}
