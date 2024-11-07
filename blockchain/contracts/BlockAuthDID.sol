// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";

contract BlockAuthDID is Ownable, Pausable, AccessControl, EIP712 {
    // Define roles
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant USER_ROLE = keccak256("USER_ROLE");

    // Struct to store the identity details with an IPFS hash for privacy
    struct Identity {
        string ipfsHash;    // IPFS hash pointing to the user's personal information
        bytes publicKey;    // User's public key for identity verification
        bytes32 did;        // Decentralized Identifier (DID)
        bool isRegistered;  // Check if user is registered
    }

    // Mapping to store user identities (indexed by their address)
    mapping(address => Identity) public identities;

    // Events to emit for registering identities and verifying signatures
    event IdentityRegistered(address indexed user, bytes32 indexed did);
    event SignatureVerified(address indexed user, bool success);
    event InvalidSignature(address indexed user, string message);
    event IdentityUpdated(address indexed user);
    event ContractPaused(address indexed user);
    event ContractUnpaused(address indexed user);

    constructor() EIP712("BlockAuthDID", "1") {
        // Grant the deployer the ADMIN role by default
        _setupRole(ADMIN_ROLE, msg.sender);
        _setupRole(USER_ROLE, msg.sender);
    }

    // Register a user's public key, personal information (via IPFS), and generate a DID
    function registerUser(
        string memory _ipfsHash,
        bytes memory _publicKey
    ) public whenNotPaused {
        // Ensure the user is not already registered
        require(!identities[msg.sender].isRegistered, "User already registered");

        // Ensure the public key has valid length (Ethereum public key is 65 bytes)
        require(_publicKey.length == 65, "Invalid public key length");

        // Generate DID using msg.sender, publicKey, timestamp, and contract address for uniqueness
        bytes32 did = keccak256(abi.encodePacked(msg.sender, _publicKey, block.timestamp, address(this)));

        // Store the identity in the mapping with IPFS hash and public key
        identities[msg.sender] = Identity({
            ipfsHash: _ipfsHash,
            publicKey: _publicKey,
            did: did,
            isRegistered: true
        });

        // Emit the IdentityRegistered event
        emit IdentityRegistered(msg.sender, did);
    }

    // Update the identity information (e.g., change IPFS hash, name, address)
    function updateIdentity(
        string memory _ipfsHash
    ) public whenNotPaused {
        // Ensure the user is already registered
        require(identities[msg.sender].isRegistered, "User not registered");

        // Update the IPFS hash (could also allow other updates as needed)
        identities[msg.sender].ipfsHash = _ipfsHash;

        // Emit the IdentityUpdated event
        emit IdentityUpdated(msg.sender);
    }

    // Verify the signature of a message, checking if it matches the user's registered identity
    function verifySignature(bytes32 _message, bytes memory _signature) public view returns (bool) {
        // Ensure the user is registered
        require(identities[msg.sender].isRegistered, "User not registered");

        // Hash the message to get its digest
        bytes32 messageHash = keccak256(abi.encodePacked(_message));

        // Prepend the Ethereum signed message prefix to the hash
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));

        // Recover the signer address from the signature
        address signer = recoverSigner(ethSignedMessageHash, _signature);

        // Check if the signer is registered and has a valid public key
        bool success = identities[signer].isRegistered && identities[signer].publicKey.length != 0;

        // Emit event based on verification result
        if (success) {
            emit SignatureVerified(msg.sender, true);
        } else {
            emit InvalidSignature(msg.sender, "Invalid signature or unregistered signer");
        }

        return success;
    }

    // Helper function to recover the signer address from the signature
    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    // Helper function to split the signature into r, s, and v components
    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Correct the v value if it's below 27 (Ethereum signature format)
        if (v < 27) {
            v += 27;
        }

        return (r, s, v);
    }

    // Admin functions to pause and unpause the contract
    function pause() public onlyOwner {
        _pause();
        emit ContractPaused(msg.sender);
    }

    function unpause() public onlyOwner {
        _unpause();
        emit ContractUnpaused(msg.sender);
    }
// Admin function to grant the ADMIN_ROLE to all accounts
function grantAllAdminRole(address[] memory accounts) public onlyOwner {
    for (uint256 i = 0; i < accounts.length; i++) {
        grantRole(ADMIN_ROLE, accounts[i]);
    }

    emit AdminRoleGranted(accounts);
}
// Admin function to grant the USER_ROLE to a specific account
function grantUserRole(address account) public onlyAdmin {
    require(hasRole(ADMIN_ROLE, msg.sender), "Only admin can grant user role");

    // Create a new identity for the user
    identities[account] = Identity({
        ipfsHash: "",
        publicKey: "",
        did: keccak256(abi.encodePacked(account, block.timestamp, address(this))),
        isRegistered: false
    });

    grantRole(USER_ROLE, account);
    emit UserRoleGranted(account);
}

// Helper function to check if the sender is an admin
function isAdmin(address account) public view returns (bool) {
    return hasRole(ADMIN_ROLE, account);
}
    function grantUserRole(address account) public {
        require(hasRole(ADMIN_ROLE, msg.sender), "Only admin can grant user role");
        grantRole(USER_ROLE, account);
    }

    // Function to check if the sender is an admin
    function isAdmin(address account) public view returns (bool) {
        return hasRole(ADMIN_ROLE, account);
    }

    // Event-based logging for role assignments
    event AdminRoleGranted(address indexed account);
    event UserRoleGranted(address indexed account);
}
