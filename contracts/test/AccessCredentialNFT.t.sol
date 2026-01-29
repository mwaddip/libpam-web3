// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/AccessCredentialNFT.sol";

contract AccessCredentialNFTTest is Test {
    AccessCredentialNFT public nft;
    address public owner;
    address public user1;
    address public user2;

    // Sample encrypted data (in real usage, these would be ECIES ciphertexts)
    bytes public sampleServerEncrypted = hex"04abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
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
            sampleServerEncrypted,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server Access",
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
            sampleServerEncrypted,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Temporary Access",
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
            sampleServerEncrypted,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test",
            "",
            0
        );
    }

    function testMintInvalidAccessData() public {
        vm.expectRevert(AccessCredentialNFT.InvalidAccessData.selector);

        nft.mint(
            user1,
            "", // Empty server encrypted data
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test",
            "",
            0
        );
    }

    function testBatchMint() public {
        address[] memory recipients = new address[](3);
        recipients[0] = user1;
        recipients[1] = user2;
        recipients[2] = user1;

        bytes[] memory serverEncryptedArray = new bytes[](3);
        serverEncryptedArray[0] = sampleServerEncrypted;
        serverEncryptedArray[1] = sampleServerEncrypted;
        serverEncryptedArray[2] = sampleServerEncrypted;

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

        uint256[] memory expirations = new uint256[](3);
        expirations[0] = 0;
        expirations[1] = 0;
        expirations[2] = 0;

        uint256[] memory tokenIds = nft.mintBatch(
            recipients,
            serverEncryptedArray,
            userEncryptedArray,
            decryptMessages,
            descriptions,
            imageUris,
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
            sampleServerEncrypted,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "",
            0
        );

        (
            bytes memory serverEncrypted,
            bytes memory userEncrypted,
            string memory decryptMessage,
            uint256 issuedAt,
            uint256 expiresAt
        ) = nft.getAccessData(tokenId);

        assertEq(serverEncrypted, sampleServerEncrypted);
        assertEq(userEncrypted, sampleUserEncrypted);
        assertEq(decryptMessage, sampleDecryptMessage);
        assertEq(issuedAt, block.timestamp);
        assertEq(expiresAt, 0);
    }

    function testUpdateAccessData() public {
        uint256 tokenId = nft.mint(
            user1,
            sampleServerEncrypted,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "",
            0
        );

        bytes memory newServerEncrypted = hex"041111111111111111111111111111111111111111111111111111111111111111";
        bytes memory newUserEncrypted = hex"042222222222222222222222222222222222222222222222222222222222222222";

        vm.expectEmit(true, false, false, false);
        emit CredentialUpdated(tokenId);

        nft.updateAccessData(tokenId, newServerEncrypted, newUserEncrypted);

        (bytes memory serverEncrypted, bytes memory userEncrypted, , , ) = nft.getAccessData(tokenId);

        assertEq(serverEncrypted, newServerEncrypted);
        assertEq(userEncrypted, newUserEncrypted);
    }

    function testUpdateExpiration() public {
        uint256 tokenId = nft.mint(
            user1,
            sampleServerEncrypted,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "",
            0
        );

        uint256 newExpiration = block.timestamp + 7 days;
        nft.updateExpiration(tokenId, newExpiration);

        (, , , , uint256 expiresAt) = nft.getAccessData(tokenId);
        assertEq(expiresAt, newExpiration);
    }

    function testTokenURI() public {
        uint256 tokenId = nft.mint(
            user1,
            sampleServerEncrypted,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Production Server Access",
            "ipfs://QmCustomImage",
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
            sampleServerEncrypted,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
            "", // No custom image
            0
        );

        string memory uri = nft.tokenURI(tokenId);
        assertTrue(bytes(uri).length > 0);
    }

    function testEnumerable() public {
        // Mint several tokens to user1
        nft.mint(user1, sampleServerEncrypted, sampleUserEncrypted, sampleDecryptMessage, "Server 1", "", 0);
        nft.mint(user1, sampleServerEncrypted, sampleUserEncrypted, sampleDecryptMessage, "Server 2", "", 0);
        nft.mint(user2, sampleServerEncrypted, sampleUserEncrypted, sampleDecryptMessage, "Server 3", "", 0);
        nft.mint(user1, sampleServerEncrypted, sampleUserEncrypted, sampleDecryptMessage, "Server 4", "", 0);

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
            sampleServerEncrypted,
            sampleUserEncrypted,
            sampleDecryptMessage,
            "Test Server",
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
