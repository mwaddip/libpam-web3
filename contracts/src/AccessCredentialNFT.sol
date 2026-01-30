// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @title AccessCredentialNFT
 * @notice ERC-721 NFT contract for Web3-based Linux authentication credentials
 * @dev Each NFT grants access to specific servers. Authentication is based on:
 *      1. Wallet ownership (user signs challenge)
 *      2. NFT ownership (token ID matches GECOS entry in /etc/passwd)
 *      Connection details can be encrypted for the user in userEncrypted field.
 */
contract AccessCredentialNFT is ERC721, ERC721Enumerable, Ownable {
    using Strings for uint256;

    /// @notice Counter for token IDs
    uint256 private _nextTokenId;

    /// @notice Access metadata for each token
    struct AccessData {
        /// @notice Connection details encrypted with signature-derived key (AES-GCM)
        /// Contains hostname/connection info that only the NFT holder can decrypt
        bytes userEncrypted;
        /// @notice Deterministic message for re-signing to derive decryption key
        /// Format: "libpam-web3:<checksumAddress>:<nonce>"
        string decryptMessage;
        /// @notice Human-readable description (e.g., "Production Server Access")
        string description;
        /// @notice Optional image URI (IPFS or HTTPS)
        string imageUri;
        /// @notice Per-token animation URL (base64-encoded HTML, falls back to contract-wide default if empty)
        string animationUrlBase64;
        /// @notice Timestamp when the credential was issued
        uint256 issuedAt;
        /// @notice Optional expiration timestamp (0 = no expiration)
        uint256 expiresAt;
    }

    /// @notice Mapping from token ID to access data
    mapping(uint256 => AccessData) private _accessData;

    /// @notice Base64-encoded signing page HTML (shared across all tokens)
    string private _signingPageBase64;

    /// @notice Default image URI for credentials without custom images
    string private _defaultImageUri;

    /// @notice Emitted when a new credential is minted
    event CredentialMinted(
        uint256 indexed tokenId,
        address indexed recipient,
        uint256 issuedAt,
        uint256 expiresAt
    );

    /// @notice Emitted when a credential's access data is updated
    event CredentialUpdated(uint256 indexed tokenId);

    /// @notice Emitted when the signing page is updated
    event SigningPageUpdated();

    /// @notice Error when trying to use an expired credential
    error CredentialExpired(uint256 tokenId, uint256 expiresAt);

    constructor(
        string memory name,
        string memory symbol,
        string memory signingPageBase64,
        string memory defaultImageUri
    ) ERC721(name, symbol) Ownable(msg.sender) {
        _signingPageBase64 = signingPageBase64;
        _defaultImageUri = defaultImageUri;
    }

    /**
     * @notice Mint a new access credential NFT
     * @param to Recipient address (the user who will use this credential)
     * @param userEncrypted Connection details encrypted with signature-derived key (optional)
     * @param decryptMessage Deterministic message for re-signing to derive decryption key
     * @param description Human-readable description
     * @param imageUri Custom image URI (pass empty string to use default)
     * @param animationUrlBase64 Per-token signing page HTML (base64, pass empty string for contract default)
     * @param expiresAt Expiration timestamp (pass 0 for no expiration)
     * @return tokenId The ID of the newly minted token
     */
    function mint(
        address to,
        bytes calldata userEncrypted,
        string calldata decryptMessage,
        string calldata description,
        string calldata imageUri,
        string calldata animationUrlBase64,
        uint256 expiresAt
    ) external onlyOwner returns (uint256 tokenId) {
        tokenId = _nextTokenId++;

        _accessData[tokenId] = AccessData({
            userEncrypted: userEncrypted,
            decryptMessage: decryptMessage,
            description: description,
            imageUri: imageUri,
            animationUrlBase64: animationUrlBase64,
            issuedAt: block.timestamp,
            expiresAt: expiresAt
        });

        _safeMint(to, tokenId);

        emit CredentialMinted(tokenId, to, block.timestamp, expiresAt);
    }

    /**
     * @notice Batch mint multiple credentials
     * @param recipients Array of recipient addresses
     * @param userEncryptedArray Array of user-encrypted connection details (optional per token)
     * @param decryptMessages Array of deterministic messages for decryption
     * @param descriptions Array of descriptions
     * @param imageUris Array of image URIs
     * @param animationUrlBase64s Array of per-token signing pages (base64, empty string for contract default)
     * @param expirations Array of expiration timestamps
     * @return tokenIds Array of minted token IDs
     */
    function mintBatch(
        address[] calldata recipients,
        bytes[] calldata userEncryptedArray,
        string[] calldata decryptMessages,
        string[] calldata descriptions,
        string[] calldata imageUris,
        string[] calldata animationUrlBase64s,
        uint256[] calldata expirations
    ) external onlyOwner returns (uint256[] memory tokenIds) {
        uint256 length = recipients.length;
        require(
            userEncryptedArray.length == length &&
            decryptMessages.length == length &&
            descriptions.length == length &&
            imageUris.length == length &&
            animationUrlBase64s.length == length &&
            expirations.length == length,
            "Array length mismatch"
        );

        tokenIds = new uint256[](length);

        for (uint256 i = 0; i < length; i++) {
            uint256 tokenId = _nextTokenId++;
            tokenIds[i] = tokenId;

            _accessData[tokenId] = AccessData({
                userEncrypted: userEncryptedArray[i],
                decryptMessage: decryptMessages[i],
                description: descriptions[i],
                imageUri: imageUris[i],
                animationUrlBase64: animationUrlBase64s[i],
                issuedAt: block.timestamp,
                expiresAt: expirations[i]
            });

            _safeMint(recipients[i], tokenId);

            emit CredentialMinted(tokenId, recipients[i], block.timestamp, expirations[i]);
        }
    }

    /**
     * @notice Update the user-encrypted data for an existing credential
     * @dev Only callable by owner. Useful for updating connection details.
     * @param tokenId The token to update
     * @param newUserEncrypted New user-encrypted connection details
     */
    function updateUserEncrypted(
        uint256 tokenId,
        bytes calldata newUserEncrypted
    ) external onlyOwner {
        require(_ownerOf(tokenId) != address(0), "Token does not exist");
        _accessData[tokenId].userEncrypted = newUserEncrypted;
        emit CredentialUpdated(tokenId);
    }

    /**
     * @notice Update the expiration for a credential
     * @param tokenId The token to update
     * @param newExpiration New expiration timestamp (0 = no expiration)
     */
    function updateExpiration(
        uint256 tokenId,
        uint256 newExpiration
    ) external onlyOwner {
        require(_ownerOf(tokenId) != address(0), "Token does not exist");
        _accessData[tokenId].expiresAt = newExpiration;
        emit CredentialUpdated(tokenId);
    }

    /**
     * @notice Update the animation URL (signing page) for an existing token
     * @param tokenId The token to update
     * @param newAnimationUrlBase64 New base64-encoded signing page HTML (empty string to use contract default)
     */
    function updateAnimationUrl(
        uint256 tokenId,
        string calldata newAnimationUrlBase64
    ) external onlyOwner {
        require(_ownerOf(tokenId) != address(0), "Token does not exist");
        _accessData[tokenId].animationUrlBase64 = newAnimationUrlBase64;
        emit CredentialUpdated(tokenId);
    }

    /**
     * @notice Update the signing page HTML (base64 encoded)
     * @param newSigningPageBase64 New base64-encoded signing page
     */
    function setSigningPage(string calldata newSigningPageBase64) external onlyOwner {
        _signingPageBase64 = newSigningPageBase64;
        emit SigningPageUpdated();
    }

    /**
     * @notice Update the default image URI
     * @param newDefaultImageUri New default image URI
     */
    function setDefaultImageUri(string calldata newDefaultImageUri) external onlyOwner {
        _defaultImageUri = newDefaultImageUri;
    }

    /**
     * @notice Get the access data for a token
     * @param tokenId The token ID
     * @return userEncrypted The user-encrypted connection details
     * @return decryptMessage The deterministic message for decryption
     * @return issuedAt When the credential was issued
     * @return expiresAt When the credential expires (0 = never)
     */
    function getAccessData(uint256 tokenId) external view returns (
        bytes memory userEncrypted,
        string memory decryptMessage,
        uint256 issuedAt,
        uint256 expiresAt
    ) {
        require(_ownerOf(tokenId) != address(0), "Token does not exist");
        AccessData storage data = _accessData[tokenId];
        return (
            data.userEncrypted,
            data.decryptMessage,
            data.issuedAt,
            data.expiresAt
        );
    }

    /**
     * @notice Check if a credential is expired
     * @param tokenId The token ID to check
     * @return True if expired, false otherwise
     */
    function isExpired(uint256 tokenId) public view returns (bool) {
        require(_ownerOf(tokenId) != address(0), "Token does not exist");
        uint256 expiresAt = _accessData[tokenId].expiresAt;
        return expiresAt != 0 && block.timestamp > expiresAt;
    }

    /**
     * @notice Get the token URI with full on-chain metadata
     * @param tokenId The token ID
     * @return Base64-encoded JSON metadata
     */
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(_ownerOf(tokenId) != address(0), "Token does not exist");

        AccessData storage data = _accessData[tokenId];

        string memory imageUri = bytes(data.imageUri).length > 0
            ? data.imageUri
            : _defaultImageUri;

        // Use per-token animation URL, falling back to contract-wide default
        string memory animationUrl = bytes(data.animationUrlBase64).length > 0
            ? data.animationUrlBase64
            : _signingPageBase64;

        // Build the access object
        string memory accessJson = string(abi.encodePacked(
            '{"user_encrypted":"0x',
            _bytesToHex(data.userEncrypted),
            '","decrypt_message":"',
            data.decryptMessage,
            '"}'
        ));

        // Build attributes array
        string memory attributes = string(abi.encodePacked(
            '[{"trait_type":"Type","value":"Server Access"},',
            '{"trait_type":"Issued","display_type":"date","value":', data.issuedAt.toString(), '}',
            data.expiresAt > 0
                ? string(abi.encodePacked(',{"trait_type":"Expires","display_type":"date","value":', data.expiresAt.toString(), '}'))
                : '',
            ']'
        ));

        // Build the full metadata JSON
        string memory json = string(abi.encodePacked(
            '{"name":"Access Credential #', tokenId.toString(),
            '","description":"', data.description,
            '","image":"', imageUri,
            '","animation_url":"data:text/html;base64,', animationUrl,
            '","attributes":', attributes,
            ',"access":', accessJson,
            '}'
        ));

        return string(abi.encodePacked(
            "data:application/json;base64,",
            Base64.encode(bytes(json))
        ));
    }

    /**
     * @notice Convert bytes to hex string (without 0x prefix)
     */
    function _bytesToHex(bytes memory data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory hexString = new bytes(data.length * 2);

        for (uint256 i = 0; i < data.length; i++) {
            hexString[i * 2] = hexChars[uint8(data[i] >> 4)];
            hexString[i * 2 + 1] = hexChars[uint8(data[i] & 0x0f)];
        }

        return string(hexString);
    }

    // Required overrides for ERC721Enumerable

    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal override(ERC721, ERC721Enumerable) returns (address) {
        return super._update(to, tokenId, auth);
    }

    function _increaseBalance(
        address account,
        uint128 value
    ) internal override(ERC721, ERC721Enumerable) {
        super._increaseBalance(account, value);
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC721, ERC721Enumerable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
