// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/AccessCredentialNFT.sol";

/**
 * @title Deploy
 * @notice Deployment script for AccessCredentialNFT
 * @dev Run with: forge script script/Deploy.s.sol --rpc-url <RPC_URL> --broadcast
 */
contract Deploy is Script {
    function run() external {
        // Load environment variables
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        // Default values - override via environment
        string memory name = vm.envOr("NFT_NAME", string("Web3 Access Credentials"));
        string memory symbol = vm.envOr("NFT_SYMBOL", string("W3AC"));
        string memory defaultImageUri = vm.envOr(
            "DEFAULT_IMAGE_URI",
            string("ipfs://QmDefaultImageHashHere")
        );

        // Read the signing page base64 from file or environment
        string memory signingPageBase64 = vm.envOr(
            "SIGNING_PAGE_BASE64",
            string("")
        );

        // If no signing page provided, use a minimal placeholder
        if (bytes(signingPageBase64).length == 0) {
            // This is a minimal placeholder - replace with actual signing page
            signingPageBase64 = "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PHRpdGxlPldlYjMgQXV0aDwvdGl0bGU+PC9oZWFkPjxib2R5PjxoMT5TaWduaW5nIFBhZ2UgUGxhY2Vob2xkZXI8L2gxPjwvYm9keT48L2h0bWw+";
        }

        vm.startBroadcast(deployerPrivateKey);

        AccessCredentialNFT nft = new AccessCredentialNFT(
            name,
            symbol,
            signingPageBase64,
            defaultImageUri
        );

        vm.stopBroadcast();

        console.log("AccessCredentialNFT deployed at:", address(nft));
        console.log("Name:", name);
        console.log("Symbol:", symbol);
    }
}

/**
 * @title MintCredential
 * @notice Script to mint a new access credential
 * @dev Run with: forge script script/Deploy.s.sol:MintCredential --rpc-url <RPC_URL> --broadcast
 */
contract MintCredential is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address nftContract = vm.envAddress("NFT_CONTRACT");
        address recipient = vm.envAddress("RECIPIENT");

        // User-encrypted connection details (optional, hex-encoded AES-GCM ciphertext)
        bytes memory userEncrypted = vm.envOr("USER_ENCRYPTED", bytes(""));

        // Decrypt message for signature-derived decryption
        string memory decryptMessage = vm.envOr(
            "DECRYPT_MESSAGE",
            string("")
        );

        string memory description = vm.envOr(
            "CREDENTIAL_DESCRIPTION",
            string("SSH access credential")
        );
        string memory imageUri = vm.envOr("IMAGE_URI", string(""));
        string memory animationUrlBase64 = vm.envOr("ANIMATION_URL_BASE64", string(""));
        uint256 expiresAt = vm.envOr("EXPIRES_AT", uint256(0));

        vm.startBroadcast(deployerPrivateKey);

        AccessCredentialNFT nft = AccessCredentialNFT(nftContract);
        uint256 tokenId = nft.mint(
            recipient,
            userEncrypted,
            decryptMessage,
            description,
            imageUri,
            animationUrlBase64,
            expiresAt
        );

        vm.stopBroadcast();

        console.log("Minted credential with token ID:", tokenId);
        console.log("Recipient:", recipient);
    }
}
