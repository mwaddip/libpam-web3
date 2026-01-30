// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/AccessCredentialNFT.sol";

contract AccessCredentialNFTTest is Test {
    AccessCredentialNFT public nft;
    address public owner;
    address public user1;
    address public user2;

    // Sample encrypted data (in real usage, this would be AES-GCM ciphertext)
    bytes public sampleUserEncrypted = hex"04fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
    string public sampleDecryptMessage = "libpam-web3:0x1234567890abcdef1234567890abcdef12345678:12345";

    string public signingPageBase64 = "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PjxoMT5UZXN0PC9oMT48L2JvZHk+PC9odG1sPg==";
    string public defaultImageUri = "ipfs://QmTestImageHash";

    event CredentialMinted(
        uint256 indexed tokenId,
        address indexed recipient,
        uint256 issuedAt,
        uint256 expiresAt
    );

    event CredentialUpdated(uint256 indexed tokenId);

    function setUp() public {
        owner = address(this);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");

        nft = new AccessCredentialNFT(
            "Web3 Access Credentials",
            "W3AC",
            signingPageBase64,
            defaultImageUri
        );
    }

    function testDeployment() public view {
        assertEq(nft.name(), "Web3 Access Credentials");
        assertEq(nft.symbol(), "W3AC");
        assertEq(nft.owner(), owner);
    }

    function testMint() public {
        vm.expectEmit(true, true, false, false);
        emit CredentialMinted(0, user1, block.timestamp, 0);

        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server Access",
            "",
            "",
            0
        );

        assertEq(tokenId, 0);
        assertEq(nft.ownerOf(tokenId), user1);
        assertEq(nft.balanceOf(user1), 1);
    }

    function testMintWithExpiration() public {
        uint256 expiresAt = block.timestamp + 30 days;

        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Temporary Access",
            "",
            "",
            expiresAt
        );

        assertFalse(nft.isExpired(tokenId));

        // Warp time past expiration
        vm.warp(expiresAt + 1);
        assertTrue(nft.isExpired(tokenId));
    }

    function testMintOnlyOwner() public {
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user1));

        nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test",
            "",
            "",
            0
        );
    }

    function testMintWithEmptyUserEncrypted() public {
        // Empty userEncrypted is allowed (it's optional)
        uint256 tokenId = nft.mint(
            user1,
            "", // Empty user encrypted data is fine
            sampleDecryptMessage,
            "Test",
            "",
            "",
            0
        );

        assertEq(tokenId, 0);
        assertEq(nft.ownerOf(tokenId), user1);
    }

    function testBatchMint() public {
        address[] memory recipients = new address[](3);
        recipients[0] = user1;
        recipients[1] = user2;
        recipients[2] = user1;

        bytes[] memory userEncryptedArray = new bytes[](3);
        userEncryptedArray[0] = sampleUserEncrypted;
        userEncryptedArray[1] = sampleUserEncrypted;
        userEncryptedArray[2] = sampleUserEncrypted;

        string[] memory decryptMessages = new string[](3);
        decryptMessages[0] = sampleDecryptMessage;
        decryptMessages[1] = sampleDecryptMessage;
        decryptMessages[2] = sampleDecryptMessage;

        string[] memory descriptions = new string[](3);
        descriptions[0] = "Server 1";
        descriptions[1] = "Server 2";
        descriptions[2] = "Server 3";

        string[] memory imageUris = new string[](3);
        imageUris[0] = "";
        imageUris[1] = "";
        imageUris[2] = "";

        string[] memory animationUrls = new string[](3);
        animationUrls[0] = "";
        animationUrls[1] = "";
        animationUrls[2] = "";

        uint256[] memory expirations = new uint256[](3);
        expirations[0] = 0;
        expirations[1] = 0;
        expirations[2] = 0;

        uint256[] memory tokenIds = nft.mintBatch(
            recipients,
            userEncryptedArray,
            decryptMessages,
            descriptions,
            imageUris,
            animationUrls,
            expirations
        );

        assertEq(tokenIds.length, 3);
        assertEq(nft.ownerOf(0), user1);
        assertEq(nft.ownerOf(1), user2);
        assertEq(nft.ownerOf(2), user1);
        assertEq(nft.balanceOf(user1), 2);
        assertEq(nft.balanceOf(user2), 1);
    }

    function testGetAccessData() public {
        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "",
            "",
            0
        );

        (
            bytes memory userEncrypted,
            string memory decryptMessage,
            uint256 issuedAt,
            uint256 expiresAt
        ) = nft.getAccessData(tokenId);

        assertEq(userEncrypted, sampleUserEncrypted);
        assertEq(decryptMessage, sampleDecryptMessage);
        assertEq(issuedAt, block.timestamp);
        assertEq(expiresAt, 0);
    }

    function testUpdateUserEncrypted() public {
        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "",
            "",
            0
        );

        bytes memory newUserEncrypted = hex"042222222222222222222222222222222222222222222222222222222222222222";

        vm.expectEmit(true, false, false, false);
        emit CredentialUpdated(tokenId);

        nft.updateUserEncrypted(tokenId, newUserEncrypted);

        (bytes memory userEncrypted, , , ) = nft.getAccessData(tokenId);

        assertEq(userEncrypted, newUserEncrypted);
    }

    function testUpdateExpiration() public {
        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "",
            "",
            0
        );

        uint256 newExpiration = block.timestamp + 7 days;
        nft.updateExpiration(tokenId, newExpiration);

        (, , , uint256 expiresAt) = nft.getAccessData(tokenId);
        assertEq(expiresAt, newExpiration);
    }

    function testTokenURI() public {
        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Production Server Access",
            "ipfs://QmCustomImage",
            "",
            0
        );

        string memory uri = nft.tokenURI(tokenId);

        // Should be a base64-encoded JSON data URI
        assertTrue(bytes(uri).length > 0);
        assertTrue(_startsWith(uri, "data:application/json;base64,"));
    }

    function testTokenURIWithDefaultImage() public {
        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "", // No custom image
            "", // No custom animation URL
            0
        );

        string memory uri = nft.tokenURI(tokenId);
        assertTrue(bytes(uri).length > 0);
    }

    function testEnumerable() public {
        // Mint several tokens to user1
        nft.mint(user1, sampleUserEncrypted, sampleDecryptMessage, "Server 1", "", "", 0);
        nft.mint(user1, sampleUserEncrypted, sampleDecryptMessage, "Server 2", "", "", 0);
        nft.mint(user2, sampleUserEncrypted, sampleDecryptMessage, "Server 3", "", "", 0);
        nft.mint(user1, sampleUserEncrypted, sampleDecryptMessage, "Server 4", "", "", 0);

        assertEq(nft.totalSupply(), 4);
        assertEq(nft.balanceOf(user1), 3);
        assertEq(nft.balanceOf(user2), 1);

        // Test tokenOfOwnerByIndex
        assertEq(nft.tokenOfOwnerByIndex(user1, 0), 0);
        assertEq(nft.tokenOfOwnerByIndex(user1, 1), 1);
        assertEq(nft.tokenOfOwnerByIndex(user1, 2), 3);
        assertEq(nft.tokenOfOwnerByIndex(user2, 0), 2);
    }

    function testTransfer() public {
        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "",
            "",
            0
        );

        vm.prank(user1);
        nft.transferFrom(user1, user2, tokenId);

        assertEq(nft.ownerOf(tokenId), user2);
        assertEq(nft.balanceOf(user1), 0);
        assertEq(nft.balanceOf(user2), 1);
    }

    function testSetSigningPage() public {
        string memory newSigningPage = "PGh0bWw+TmV3IFBhZ2U8L2h0bWw+";
        nft.setSigningPage(newSigningPage);
        // No direct getter, but should not revert
    }

    function testSetDefaultImageUri() public {
        string memory newUri = "ipfs://QmNewDefaultImage";
        nft.setDefaultImageUri(newUri);
        // Verify by minting and checking URI contains new default
    }

    function testPerTokenAnimationUrl() public {
        // Use a different signing page for this specific token (must be longer than default which is 88 chars)
        string memory customSigningPage = "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PHRpdGxlPkN1c3RvbSBTaWduaW5nIFBhZ2U8L3RpdGxlPjwvaGVhZD48Ym9keT48aDE+Q3VzdG9tIFBhZ2UgV2l0aCBNdWNoIE1vcmUgQ29udGVudDwvaDE+PC9ib2R5PjwvaHRtbD4=";

        // First mint with empty (uses default)
        uint256 tokenIdDefault = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server Default",
            "",
            "", // Empty = use default
            0
        );

        // Then mint with custom animation URL
        uint256 tokenIdCustom = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server Custom",
            "",
            customSigningPage, // Per-token animation URL
            0
        );

        string memory uriDefault = nft.tokenURI(tokenIdDefault);
        string memory uriCustom = nft.tokenURI(tokenIdCustom);

        // Both URIs should be valid
        assertTrue(bytes(uriDefault).length > 0);
        assertTrue(bytes(uriCustom).length > 0);

        // The custom one should be longer since it has a longer animation URL
        assertTrue(bytes(uriCustom).length > bytes(uriDefault).length);
    }

    function testAnimationUrlFallbackToDefault() public {
        // Mint with empty animation URL to use contract default
        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "",
            "", // Empty = use contract default
            0
        );

        string memory uri = nft.tokenURI(tokenId);
        assertTrue(bytes(uri).length > 0);
        assertTrue(_startsWith(uri, "data:application/json;base64,"));
    }

    function testUpdateAnimationUrl() public {
        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "",
            "",
            0
        );

        string memory uriBefore = nft.tokenURI(tokenId);

        // Update to a custom animation URL (must be longer than default)
        string memory customSigningPage = "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PHRpdGxlPlVwZGF0ZWQgU2lnbmluZyBQYWdlPC90aXRsZT48L2hlYWQ+PGJvZHk+PGgxPlVwZGF0ZWQgUGFnZSBXaXRoIE11Y2ggTW9yZSBDb250ZW50PC9oMT48L2JvZHk+PC9odG1sPg==";

        vm.expectEmit(true, false, false, false);
        emit CredentialUpdated(tokenId);

        nft.updateAnimationUrl(tokenId, customSigningPage);

        string memory uriAfter = nft.tokenURI(tokenId);

        assertTrue(bytes(uriAfter).length > bytes(uriBefore).length);
    }

    function testUpdateAnimationUrlToEmpty() public {
        string memory customSigningPage = "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PHRpdGxlPkN1c3RvbSBTaWduaW5nIFBhZ2U8L3RpdGxlPjwvaGVhZD48Ym9keT48aDE+Q3VzdG9tIFBhZ2UgV2l0aCBNdWNoIE1vcmUgQ29udGVudDwvaDE+PC9ib2R5PjwvaHRtbD4=";

        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "",
            customSigningPage,
            0
        );

        string memory uriBefore = nft.tokenURI(tokenId);

        // Update to empty (revert to contract default)
        nft.updateAnimationUrl(tokenId, "");

        string memory uriAfter = nft.tokenURI(tokenId);

        assertTrue(bytes(uriAfter).length < bytes(uriBefore).length);
    }

    function testUpdateAnimationUrlOnlyOwner() public {
        uint256 tokenId = nft.mint(
            user1,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "",
            "",
            0
        );

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user1));

        nft.updateAnimationUrl(tokenId, "PGh0bWw+PC9odG1sPg==");
    }

    // Helper function to check string prefix
    function _startsWith(string memory str, string memory prefix) internal pure returns (bool) {
        bytes memory strBytes = bytes(str);
        bytes memory prefixBytes = bytes(prefix);

        if (strBytes.length < prefixBytes.length) {
            return false;
        }

        for (uint256 i = 0; i < prefixBytes.length; i++) {
            if (strBytes[i] != prefixBytes[i]) {
                return false;
            }
        }

        return true;
    }
}
