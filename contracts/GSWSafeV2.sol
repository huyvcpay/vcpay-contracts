// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GSWSafeV2 {
    // ==================== STATE ====================

    mapping(address => bool) public isOwner;
    mapping(address => uint256) private ownerIndex; // 1-based index into owners[]
    address[] private owners;

    uint256 public ownerCount;
    uint256 public threshold;
    uint256 public nonce;
    uint256 private _status;

    uint256 private immutable _CACHED_CHAIN_ID;
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private constant MAX_DEADLINE_DURATION = 30 days;

    bytes32 public constant TX_TYPEHASH = keccak256(
        "Execute(address to,uint256 value,bytes data,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant ADMIN_TYPEHASH = keccak256(
        "Admin(bytes32 action,address target,uint256 value,uint256 nonce)"
    );

    // ==================== EVENTS ====================

    event Executed(address indexed to, uint256 value, uint256 indexed nonce, bool success);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);
    event NonceCancelled(uint256 indexed nonce);
    event Received(address indexed sender, uint256 value);

    // ==================== ERRORS ====================

    error InvalidThreshold();
    error InvalidOwner();
    error DuplicateOwner();
    error NotOwner();
    error InvalidSignatureLength();
    error InvalidSignatureS();
    error InvalidSignatureV();
    error InvalidSignature();
    error SignaturesNotSorted();
    error ExecutionFailed();
    error ZeroAddress();
    error Expired();
    error DeadlineTooLong();
    error InsufficientBalance();
    error ReentrancyGuard();
    error SelfCallNotAllowed();

    // ==================== CONSTRUCTOR ====================

    constructor(address[] memory _owners, uint256 _threshold) {
        uint256 len = _owners.length;
        for (uint256 i = 0; i < len;) {
            address owner = _owners[i];
            if (owner == address(0)) revert InvalidOwner();
            if (isOwner[owner]) revert DuplicateOwner();
            isOwner[owner] = true;
            owners.push(owner);
            ownerIndex[owner] = owners.length; // 1-based
            emit OwnerAdded(owner);
            unchecked { ++i; }
        }

        ownerCount = len;

        if (_threshold == 0 || _threshold > len) revert InvalidThreshold();

        threshold = _threshold;
        _status = _NOT_ENTERED;

        emit ThresholdChanged(0, _threshold);

        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator();
    }

    // ==================== MODIFIERS ====================

    modifier nonReentrant() {
        if (_status == _ENTERED) revert ReentrancyGuard();
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    // ==================== EXECUTE ====================

    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        bytes calldata signatures
    ) external nonReentrant returns (bool success, bytes memory returnData) {
        if (block.timestamp > deadline) revert Expired();
        if (deadline > block.timestamp + MAX_DEADLINE_DURATION) revert DeadlineTooLong();
        if (to == address(this)) revert SelfCallNotAllowed();
        if (value > 0 && address(this).balance < value) revert InsufficientBalance();

        uint256 currentNonce = nonce;

        bytes32 structHash = keccak256(abi.encode(
            TX_TYPEHASH, to, value, keccak256(data), currentNonce, deadline
        ));
        bytes32 hash = _hashTypedData(structHash);

        _validateSignatures(hash, signatures);

        nonce = currentNonce + 1;

        (success, returnData) = to.call{value: value}(data);
        emit Executed(to, value, currentNonce, success);
    }

    function executeStrict(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        bytes calldata signatures
    ) external nonReentrant returns (bytes memory returnData) {
        if (block.timestamp > deadline) revert Expired();
        if (deadline > block.timestamp + MAX_DEADLINE_DURATION) revert DeadlineTooLong();
        if (to == address(this)) revert SelfCallNotAllowed();
        if (value > 0 && address(this).balance < value) revert InsufficientBalance();

        uint256 currentNonce = nonce;

        bytes32 structHash = keccak256(abi.encode(
            TX_TYPEHASH, to, value, keccak256(data), currentNonce, deadline
        ));
        bytes32 hash = _hashTypedData(structHash);

        _validateSignatures(hash, signatures);

        nonce = currentNonce + 1;

        bool success;
        (success, returnData) = to.call{value: value}(data);

        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    revert(add(returnData, 32), mload(returnData))
                }
            }
            revert ExecutionFailed();
        }

        emit Executed(to, value, currentNonce, true);
    }

    // ==================== ADMIN ====================
    function addOwner(address owner, uint256 newThreshold, bytes calldata signatures) external nonReentrant {
        if (owner == address(0)) revert InvalidOwner();
        if (isOwner[owner]) revert DuplicateOwner();

        uint256 newCount = ownerCount + 1;
        if (newThreshold == 0 || newThreshold > newCount) revert InvalidThreshold();

        uint256 currentNonce = nonce;
        bytes32 structHash = keccak256(abi.encode(
            ADMIN_TYPEHASH, keccak256(bytes("addOwner")), owner, newThreshold, currentNonce
        ));
        bytes32 hash = _hashTypedData(structHash);

        _validateSignatures(hash, signatures);

        nonce = currentNonce + 1;

        isOwner[owner] = true;
        owners.push(owner);
        ownerIndex[owner] = owners.length;
        ownerCount = newCount;
        emit OwnerAdded(owner);

        if (newThreshold != threshold) {
            emit ThresholdChanged(threshold, newThreshold);
            threshold = newThreshold;
        }
    }

    function removeOwner(address owner, uint256 newThreshold, bytes calldata signatures) external nonReentrant {
        if (!isOwner[owner]) revert NotOwner();

        uint256 newCount = ownerCount - 1;
        if (newThreshold == 0 || newThreshold > newCount) revert InvalidThreshold();

        uint256 currentNonce = nonce;
        bytes32 structHash = keccak256(abi.encode(
            ADMIN_TYPEHASH, keccak256(bytes("removeOwner")), owner, newThreshold, currentNonce
        ));
        bytes32 hash = _hashTypedData(structHash);

        _validateSignatures(hash, signatures);

        nonce = currentNonce + 1;

        // swap & pop
        uint256 idx = ownerIndex[owner];
        if (idx == 0) revert NotOwner();
        uint256 lastIdx = owners.length;
        address lastOwner = owners[lastIdx - 1];

        if (idx != lastIdx) {
            owners[idx - 1] = lastOwner;
            ownerIndex[lastOwner] = idx;
        }
        owners.pop();
        ownerIndex[owner] = 0;

        isOwner[owner] = false;
        ownerCount = newCount;
        emit OwnerRemoved(owner);

        if (newThreshold != threshold) {
            emit ThresholdChanged(threshold, newThreshold);
            threshold = newThreshold;
        }
    }

    function setThreshold(uint256 newThreshold, bytes calldata signatures) external nonReentrant {
        if (newThreshold == 0 || newThreshold > ownerCount) revert InvalidThreshold();

        uint256 currentNonce = nonce;
        bytes32 structHash = keccak256(abi.encode(
            ADMIN_TYPEHASH, keccak256(bytes("setThreshold")), address(0), newThreshold, currentNonce
        ));
        bytes32 hash = _hashTypedData(structHash);

        _validateSignatures(hash, signatures);

        nonce = currentNonce + 1;

        emit ThresholdChanged(threshold, newThreshold);
        threshold = newThreshold;
    }

    function cancelNonce(bytes calldata signatures) external nonReentrant {
        uint256 currentNonce = nonce;
        bytes32 structHash = keccak256(abi.encode(
            ADMIN_TYPEHASH, keccak256(bytes("cancelNonce")), address(0), uint256(0), currentNonce
        ));
        bytes32 hash = _hashTypedData(structHash);

        _validateSignatures(hash, signatures);

        nonce = currentNonce + 1;
        emit NonceCancelled(currentNonce);
    }

    // ==================== SIGNATURE VALIDATION ====================

    function _validateSignatures(bytes32 hash, bytes calldata signatures) internal view {
        uint256 _threshold = threshold;
        if (signatures.length != _threshold * 65) revert InvalidSignatureLength();

        address prev = address(0);
        for (uint256 i = 0; i < _threshold;) {
            bytes calldata sig = signatures[i * 65:(i + 1) * 65];
            address signer = _recover(hash, sig);
            if (!isOwner[signer]) revert NotOwner();
            if (signer <= prev) revert SignaturesNotSorted();
            prev = signer;
            unchecked { ++i; }
        }
    }

    function _recover(bytes32 hash, bytes calldata sig) internal pure returns (address signer) {
        if (sig.length != 65) revert InvalidSignatureLength();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignatureS();
        }

        if (v != 27 && v != 28) {
            revert InvalidSignatureV();
        }

        signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
    }

    // ==================== DOMAIN SEPARATOR ====================

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("GSWSafe"),
            keccak256("2"),
            block.chainid,
            address(this)
        ));
    }

    function domainSeparator() public view returns (bytes32) {
        if (block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        }
        return _buildDomainSeparator();
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    // ==================== VIEW ====================

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 deadline
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            TX_TYPEHASH, to, value, keccak256(data), nonce, deadline
        ));
        return _hashTypedData(structHash);
    }

    function getAdminHash(
        string calldata action,
        address target,
        uint256 value
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            ADMIN_TYPEHASH, keccak256(bytes(action)), target, value, nonce
        ));
        return _hashTypedData(structHash);
    }

    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    // ==================== ERC-165 ====================

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || // IERC165
            interfaceId == 0x150b7a02 || // IERC721Receiver
            interfaceId == 0x4e2312e0;   // IERC1155Receiver
    }

    // ==================== RECEIVERS ====================

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return 0x150b7a02;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return 0xf23a6e61;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external pure returns (bytes4) {
        return 0xbc197c81;
    }
}
