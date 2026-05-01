// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Minimal {
  function balanceOf(address account) external view returns (uint256);
  function transfer(address to, uint256 amount) external returns (bool);
}

interface IERC721Minimal {
  function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

interface IERC1155Minimal {
  function balanceOf(
    address account,
    uint256 id
  ) external view returns (uint256);
  function safeBatchTransferFrom(
    address from,
    address to,
    uint256[] calldata ids,
    uint256[] calldata amounts,
    bytes calldata data
  ) external;
}

contract GSWSafeV3 {
  // ==================== STATE ====================

  mapping(address => bool) public isOwner;
  mapping(address => uint256) private ownerIndex; // 1-based index into owners[]
  address[] private owners;

  uint256 public ownerCount;
  uint256 public threshold;
  uint256 public nonce;
  uint256 private _status;

  // Backup wallet state
  mapping(address => address) public backupWallet; // owner → backup address
  mapping(address => address) public backupFor; // backup → owner (reverse lookup)
  mapping(address => uint256) public inactivityBlocks; // owner → required inactivity window (blocks)
  mapping(address => uint256) public lastActiveBlock; // owner → last block where owner signed

  // Migration asset descriptors
  struct ERC721Asset {
    address token;
    uint256 tokenId;
  }
  struct ERC1155Asset {
    address token;
    uint256[] ids; // contract fetches balanceOf at execution time
  }

  // Delegation state
  struct Delegation {
    address owner; // which owner this delegate acts for
    uint256 nonce; // valid only for this exact nonce
    uint256 expiry; // unix timestamp deadline
    uint256 setAt; // contract nonce when this delegation was created (zombie guard)
  }
  mapping(address => Delegation) public delegationOf; // delegate → Delegation
  mapping(address => mapping(uint256 => address)) private _delegateForNonce; // owner → nonce → delegate
  // Tracks the contract nonce at which an owner most recently became an owner.
  // Used to invalidate delegations created during a prior tenure (zombie delegation guard).
  mapping(address => uint256) public ownerSinceNonce; // owner → nonce of their current tenure start

  uint256 private immutable _CACHED_CHAIN_ID;
  bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;

  uint256 private constant _NOT_ENTERED = 1;
  uint256 private constant _ENTERED = 2;
  uint256 private constant MAX_DEADLINE_DURATION = 30 days;
  // Cap on inactivityBlocks to prevent arithmetic overflow in the backup activation check.
  // type(uint64).max blocks at BSC's ~0.75s/block ≈ 440 billion years — effectively unlimited.
  uint256 private constant MAX_INACTIVITY_BLOCKS = type(uint64).max;
  // Deployer-supplied minimum inactivity window. Recommended: 3_456_000 on BSC (~0.75s blocks, 30 days).
  uint256 public immutable MIN_INACTIVITY_BLOCKS;

  bytes32 public constant TX_TYPEHASH =
    keccak256(
      'Execute(address to,uint256 value,bytes data,uint256 nonce,uint256 deadline)'
    );
  bytes32 public constant ADD_OWNER_TYPEHASH =
    keccak256('AddOwner(address owner,uint256 newThreshold,uint256 nonce)');
  bytes32 public constant REMOVE_OWNER_TYPEHASH =
    keccak256('RemoveOwner(address owner,uint256 newThreshold,uint256 nonce)');
  bytes32 public constant SET_THRESHOLD_TYPEHASH =
    keccak256('SetThreshold(uint256 newThreshold,uint256 nonce)');
  bytes32 public constant CANCEL_NONCE_TYPEHASH =
    keccak256('CancelNonce(uint256 nonce)');
  bytes32 public constant ERC721_ASSET_TYPEHASH =
    keccak256('ERC721Asset(address token,uint256 tokenId)');
  bytes32 public constant ERC1155_ASSET_TYPEHASH =
    keccak256('ERC1155Asset(address token,uint256[] ids)');
  // Referenced types appended alphabetically per EIP-712 spec.
  bytes32 public constant MIGRATE_TYPEHASH =
    keccak256(
      'Migrate(address to,address[] erc20s,ERC721Asset[] erc721s,ERC1155Asset[] erc1155s,uint256 nonce,uint256 deadline)'
      'ERC1155Asset(address token,uint256[] ids)'
      'ERC721Asset(address token,uint256 tokenId)'
    );

  // ==================== EVENTS ====================

  event Executed(
    address indexed to,
    uint256 value,
    uint256 indexed nonce,
    bool success
  );
  event Migrated(address indexed to, uint256 amount, uint256 indexed nonce);
  event OwnerAdded(address indexed owner);
  event OwnerRemoved(address indexed owner);
  event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);
  event NonceCancelled(uint256 indexed nonce);
  event Received(address indexed sender, uint256 value);
  event BackupSet(
    address indexed owner,
    address indexed backup,
    uint256 inactivityBlocks
  );
  event BackupRemoved(address indexed owner, address indexed backup);
  event BackupActivated(
    address indexed replacedOwner,
    address indexed newOwner
  );
  event DelegateSet(
    address indexed owner,
    address indexed delegate,
    uint256 nonce,
    uint256 expiry
  );
  event DelegateRevoked(address indexed owner, address indexed delegate);
  event DelegateUsed(
    address indexed owner,
    address indexed delegate,
    uint256 indexed nonce
  );
  /// @dev Emitted when an owner is removed or replaced, signalling that all their
  ///      outstanding delegations are now void (state is orphaned but harmless).
  event DelegatesVoided(address indexed owner);

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
  error InvalidBackup();
  error NoBackupSet();
  error InvalidDelegation();
  error DelegationExpired();
  error NoDelegationSet();
  error DelegationNonceMismatch();
  error InvalidInactivityBlocks();

  // ==================== CONSTRUCTOR ====================

  constructor(
    address[] memory _owners,
    uint256 _threshold,
    uint256 _minInactivityBlocks
  ) {
    if (_minInactivityBlocks == 0) revert InvalidInactivityBlocks();
    MIN_INACTIVITY_BLOCKS = _minInactivityBlocks;
    uint256 len = _owners.length;
    for (uint256 i = 0; i < len; ) {
      address owner = _owners[i];
      if (owner == address(0)) revert InvalidOwner();
      if (isOwner[owner]) revert DuplicateOwner();
      isOwner[owner] = true;
      owners.push(owner);
      ownerIndex[owner] = owners.length; // 1-based
      lastActiveBlock[owner] = block.number;
      ownerSinceNonce[owner] = 0; // initial owners have been owners since nonce 0
      emit OwnerAdded(owner);
      unchecked {
        ++i;
      }
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
  )
    external
    payable
    nonReentrant
    returns (bool success, bytes memory returnData)
  {
    if (block.timestamp > deadline) revert Expired();
    if (deadline > block.timestamp + MAX_DEADLINE_DURATION)
      revert DeadlineTooLong();
    if (to == address(this)) revert SelfCallNotAllowed();
    if (value > 0 && address(this).balance < value)
      revert InsufficientBalance();

    uint256 currentNonce = nonce;

    bytes32 structHash = keccak256(
      abi.encode(
        TX_TYPEHASH,
        to,
        value,
        keccak256(data),
        currentNonce,
        deadline
      )
    );
    bytes32 hash = _hashTypedData(structHash);

    _validateSignatures(hash, signatures, currentNonce);

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
  ) external payable nonReentrant returns (bytes memory returnData) {
    if (block.timestamp > deadline) revert Expired();
    if (deadline > block.timestamp + MAX_DEADLINE_DURATION)
      revert DeadlineTooLong();
    if (to == address(this)) revert SelfCallNotAllowed();
    if (value > 0 && address(this).balance < value)
      revert InsufficientBalance();

    uint256 currentNonce = nonce;

    bytes32 structHash = keccak256(
      abi.encode(
        TX_TYPEHASH,
        to,
        value,
        keccak256(data),
        currentNonce,
        deadline
      )
    );
    bytes32 hash = _hashTypedData(structHash);

    _validateSignatures(hash, signatures, currentNonce);

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
  function addOwner(
    address owner,
    uint256 newThreshold,
    bytes calldata signatures
  ) external nonReentrant {
    if (owner == address(0)) revert InvalidOwner();
    if (isOwner[owner]) revert DuplicateOwner();

    // Prevent adding an address that is an active backup for a current owner
    address backupPrincipal = backupFor[owner];
    if (backupPrincipal != address(0) && isOwner[backupPrincipal])
      revert InvalidOwner();
    if (backupPrincipal != address(0)) {
      // Stale entry (principal was removed) — clean up
      backupFor[owner] = address(0);
    }

    // Prevent adding an address that holds an active (non-expired) delegation from a current owner
    Delegation storage existingDelegation = delegationOf[owner];
    if (existingDelegation.owner != address(0)) {
      bool isActiveDelegation = isOwner[existingDelegation.owner] &&
        existingDelegation.nonce >= nonce;
      if (isActiveDelegation) revert InvalidOwner();
      // Stale entry (principal was removed, or delegation nonce has passed) — clean up
      delete _delegateForNonce[existingDelegation.owner][
        existingDelegation.nonce
      ];
      delete delegationOf[owner];
    }

    uint256 newCount = ownerCount + 1;
    if (newThreshold == 0 || newThreshold > newCount) revert InvalidThreshold();

    uint256 currentNonce = nonce;
    bytes32 structHash = keccak256(
      abi.encode(ADD_OWNER_TYPEHASH, owner, newThreshold, currentNonce)
    );
    bytes32 hash = _hashTypedData(structHash);

    _validateSignatures(hash, signatures, currentNonce);

    nonce = currentNonce + 1;

    isOwner[owner] = true;
    owners.push(owner);
    ownerIndex[owner] = owners.length;
    lastActiveBlock[owner] = block.number;
    ownerSinceNonce[owner] = nonce; // record tenure start nonce for zombie delegation guard
    ownerCount = newCount;
    emit OwnerAdded(owner);

    if (newThreshold != threshold) {
      emit ThresholdChanged(threshold, newThreshold);
      threshold = newThreshold;
    }
  }

  function removeOwner(
    address owner,
    uint256 newThreshold,
    bytes calldata signatures
  ) external nonReentrant {
    if (!isOwner[owner]) revert NotOwner();

    uint256 newCount = ownerCount - 1;
    if (newThreshold == 0 || newThreshold > newCount) revert InvalidThreshold();

    uint256 currentNonce = nonce;
    bytes32 structHash = keccak256(
      abi.encode(REMOVE_OWNER_TYPEHASH, owner, newThreshold, currentNonce)
    );
    bytes32 hash = _hashTypedData(structHash);

    _validateSignatures(hash, signatures, currentNonce);

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
    lastActiveBlock[owner] = 0;

    // Clean up any backup state for the removed owner
    address backup = backupWallet[owner];
    if (backup != address(0)) {
      backupFor[backup] = address(0);
      backupWallet[owner] = address(0);
      inactivityBlocks[owner] = 0;
      emit BackupRemoved(owner, backup);
    }

    ownerCount = newCount;
    emit OwnerRemoved(owner);
    emit DelegatesVoided(owner);

    if (newThreshold != threshold) {
      emit ThresholdChanged(threshold, newThreshold);
      threshold = newThreshold;
    }
  }

  function setThreshold(
    uint256 newThreshold,
    bytes calldata signatures
  ) external nonReentrant {
    if (newThreshold == 0 || newThreshold > ownerCount)
      revert InvalidThreshold();

    uint256 currentNonce = nonce;
    bytes32 structHash = keccak256(
      abi.encode(SET_THRESHOLD_TYPEHASH, newThreshold, currentNonce)
    );
    bytes32 hash = _hashTypedData(structHash);

    _validateSignatures(hash, signatures, currentNonce);

    nonce = currentNonce + 1;

    emit ThresholdChanged(threshold, newThreshold);
    threshold = newThreshold;
  }

  function cancelNonce(bytes calldata signatures) external nonReentrant {
    uint256 currentNonce = nonce;
    bytes32 structHash = keccak256(
      abi.encode(CANCEL_NONCE_TYPEHASH, currentNonce)
    );
    bytes32 hash = _hashTypedData(structHash);

    _validateSignatures(hash, signatures, currentNonce);

    nonce = currentNonce + 1;
    emit NonceCancelled(currentNonce);
  }

  // ==================== MIGRATE ====================

  /// @notice Transfer all specified assets from this safe to `to`.
  ///         Signers commit to the destination and nonce only — not the asset list.
  ///         The asset list is caller-supplied, which is safe because funds can only
  ///         flow to the signer-approved `to` address.
  ///         - Native BNB: always transferred in full (no list entry needed).
  ///         - ERC-20: pass token addresses; full balance of each is transferred.
  ///         - ERC-721: pass (token, tokenId) pairs.
  ///         - ERC-1155: pass (token, ids[]); balances are fetched at execution time.
  function migrate(
    address to,
    uint256 deadline,
    address[] calldata erc20s,
    ERC721Asset[] calldata erc721s,
    ERC1155Asset[] calldata erc1155s,
    bytes calldata signatures
  ) external nonReentrant {
    if (to == address(0)) revert ZeroAddress();
    if (to == address(this)) revert SelfCallNotAllowed();
    if (block.timestamp > deadline) revert Expired();
    if (deadline > block.timestamp + MAX_DEADLINE_DURATION)
      revert DeadlineTooLong();

    uint256 currentNonce = nonce;
    bytes32 structHash = keccak256(
      abi.encode(
        MIGRATE_TYPEHASH,
        to,
        _hashAddressArray(erc20s),
        _hashERC721Assets(erc721s),
        _hashERC1155Assets(erc1155s),
        currentNonce,
        deadline
      )
    );
    bytes32 hash = _hashTypedData(structHash);

    _validateSignatures(hash, signatures, currentNonce);

    nonce = currentNonce + 1;

    // Native BNB — best-effort: if `to` cannot receive BNB (no receive/fallback),
    // skip rather than bricking all ERC-20/721/1155 transfers in the same call.
    uint256 bnbAmount = address(this).balance;
    uint256 bnbSent;
    if (bnbAmount > 0) {
      (bool ok, ) = to.call{value: bnbAmount, gas: 2300}('');
      if (ok) {
        bnbSent = bnbAmount;
      }
      // If BNB send failed, `to` likely cannot receive native tokens.
      // Remaining ERC-20/721/1155 transfers proceed. Drain BNB separately via execute().
    }

    // ERC-20 tokens — transfer full balance of each
    uint256 len = erc20s.length;
    for (uint256 i = 0; i < len; ) {
      uint256 bal = IERC20Minimal(erc20s[i]).balanceOf(address(this));
      if (bal > 0) {
        _safeERC20Transfer(erc20s[i], to, bal);
      }
      unchecked {
        ++i;
      }
    }

    // ERC-721 NFTs
    len = erc721s.length;
    for (uint256 i = 0; i < len; ) {
      IERC721Minimal(erc721s[i].token).safeTransferFrom(
        address(this),
        to,
        erc721s[i].tokenId
      );
      unchecked {
        ++i;
      }
    }

    // ERC-1155 tokens — fetch live balances then batch-transfer per contract
    len = erc1155s.length;
    for (uint256 i = 0; i < len; ) {
      ERC1155Asset calldata asset = erc1155s[i];
      uint256 idsLen = asset.ids.length;
      if (idsLen > 0) {
        uint256[] memory amounts = new uint256[](idsLen);
        for (uint256 j = 0; j < idsLen; ) {
          amounts[j] = IERC1155Minimal(asset.token).balanceOf(
            address(this),
            asset.ids[j]
          );
          unchecked {
            ++j;
          }
        }
        IERC1155Minimal(asset.token).safeBatchTransferFrom(
          address(this),
          to,
          asset.ids,
          amounts,
          ''
        );
      }
      unchecked {
        ++i;
      }
    }

    emit Migrated(to, bnbSent, currentNonce);
  }

  // ==================== BACKUP WALLET ====================

  /// @notice Register a backup wallet that can replace you as owner after `_inactivityBlocks`
  ///         blocks of on-chain inactivity. Callable directly by the owner (no multisig needed).
  function setBackup(address backup, uint256 _inactivityBlocks) external {
    if (!isOwner[msg.sender]) revert NotOwner();
    if (backup == address(0)) revert ZeroAddress();
    if (isOwner[backup]) revert InvalidBackup(); // backup cannot already be an owner
    if (
      _inactivityBlocks < MIN_INACTIVITY_BLOCKS ||
      _inactivityBlocks > MAX_INACTIVITY_BLOCKS
    ) revert InvalidBackup();

    // backup cannot be an active delegate; stale entries (principal removed or nonce expired) are cleaned up
    Delegation storage existingDel = delegationOf[backup];
    if (existingDel.owner != address(0)) {
      bool isActiveDelegation = isOwner[existingDel.owner] &&
        existingDel.nonce >= nonce;
      if (isActiveDelegation) revert InvalidBackup();
      // Stale delegation — clean up
      delete _delegateForNonce[existingDel.owner][existingDel.nonce];
      delete delegationOf[backup];
    }
    address currentOccupant = backupFor[backup];
    if (currentOccupant != address(0) && currentOccupant != msg.sender)
      revert InvalidBackup(); // already another owner's backup

    // Clear old backup reverse-mapping if replacing
    address oldBackup = backupWallet[msg.sender];
    if (oldBackup != address(0) && oldBackup != backup) {
      backupFor[oldBackup] = address(0);
      emit BackupRemoved(msg.sender, oldBackup);
    }

    backupWallet[msg.sender] = backup;
    backupFor[backup] = msg.sender;
    inactivityBlocks[msg.sender] = _inactivityBlocks;
    lastActiveBlock[msg.sender] = block.number;

    emit BackupSet(msg.sender, backup, _inactivityBlocks);
  }

  /// @notice Remove your backup wallet. Callable directly by the owner.
  function removeBackup() external {
    if (!isOwner[msg.sender]) revert NotOwner();
    address backup = backupWallet[msg.sender];
    if (backup == address(0)) revert NoBackupSet();

    backupFor[backup] = address(0);
    backupWallet[msg.sender] = address(0);
    inactivityBlocks[msg.sender] = 0;
    lastActiveBlock[msg.sender] = block.number;

    emit BackupRemoved(msg.sender, backup);
  }

  // ==================== DELEGATION ====================

  /// @notice Delegate signing power for a single nonce to another wallet, with a time limit.
  ///         The delegate signs the same EIP-712 hash as the owner would.
  ///         Callable directly by the owner (no multisig needed).
  ///         NOTE: signing via a delegate does NOT reset the owner's inactivity clock.
  function setDelegate(
    address delegate,
    uint256 _nonce,
    uint256 expiry
  ) external {
    if (!isOwner[msg.sender]) revert NotOwner();
    if (delegate == address(0)) revert ZeroAddress();
    if (isOwner[delegate]) revert InvalidDelegation(); // delegate cannot be an owner
    if (backupFor[delegate] != address(0)) revert InvalidDelegation(); // delegate cannot be an active backup
    if (_nonce < nonce) revert InvalidDelegation(); // cannot delegate a past nonce
    if (expiry <= block.timestamp) revert Expired();
    if (expiry > block.timestamp + MAX_DEADLINE_DURATION)
      revert DeadlineTooLong();

    // One delegate address can only serve one owner at a time.
    // Exception: if the previous owner was removed, the stale entry is cleared and overwritten.
    Delegation storage existing = delegationOf[delegate];
    if (existing.owner != address(0) && existing.owner != msg.sender) {
      // Allow overwrite only if the previous owner was removed, or their delegation
      // nonce has already been passed (expired by nonce progression).
      if (isOwner[existing.owner] && existing.nonce >= nonce)
        revert InvalidDelegation();
      // Clean up the stale nonce pointer for the previous principal
      delete _delegateForNonce[existing.owner][existing.nonce];
    }

    // If this delegate was already assigned to a different nonce by the same owner,
    // clear that stale _delegateForNonce pointer before overwriting delegationOf.
    if (existing.owner == msg.sender && existing.nonce != _nonce) {
      delete _delegateForNonce[msg.sender][existing.nonce];
    }

    // Clear any prior delegate the caller set for this same nonce
    address oldDelegate = _delegateForNonce[msg.sender][_nonce];
    if (oldDelegate != address(0) && oldDelegate != delegate) {
      delete delegationOf[oldDelegate];
      emit DelegateRevoked(msg.sender, oldDelegate);
    }

    delegationOf[delegate] = Delegation({
      owner: msg.sender,
      nonce: _nonce,
      expiry: expiry,
      setAt: nonce
    });
    _delegateForNonce[msg.sender][_nonce] = delegate;
    lastActiveBlock[msg.sender] = block.number;

    emit DelegateSet(msg.sender, delegate, _nonce, expiry);
  }

  /// @notice Revoke a previously set delegation. Callable directly by the owner.
  function revokeDelegate(address delegate) external {
    if (!isOwner[msg.sender]) revert NotOwner();
    Delegation storage d = delegationOf[delegate];
    if (d.owner != msg.sender) revert NoDelegationSet();

    delete _delegateForNonce[msg.sender][d.nonce];
    delete delegationOf[delegate];
    lastActiveBlock[msg.sender] = block.number;

    emit DelegateRevoked(msg.sender, delegate);
  }

  /// @notice Returns the active delegate for a given owner and nonce (address(0) if none).
  function getDelegateForNonce(
    address owner,
    uint256 _nonce
  ) external view returns (address) {
    return _delegateForNonce[owner][_nonce];
  }

  /// @notice Prove liveness on-chain, resetting the inactivity clock.
  ///         Useful for owners whose signatures are not always required to meet the threshold,
  ///         preventing their backup from activating unintentionally.
  function ping() external {
    if (!isOwner[msg.sender]) revert NotOwner();
    lastActiveBlock[msg.sender] = block.number;
  }

  /// @notice Permissionless backup activation sweep. Iterates current owners
  ///         and, for each owner whose registered backup has passed its
  ///         inactivity window, swaps the backup into the owner set atomically.
  ///         No multisig signatures required, no multisig nonce consumed.
  ///         Intended to be called by a keeper bot when inactivity is met —
  ///         anyone can trigger; eligibility is enforced on-chain per-entry.
  ///         No-op (no revert) when nothing is eligible.
  function refreshBackup() external nonReentrant {
    uint256 currentBlock = block.number;
    uint256 i = 0;
    uint256 len = owners.length;
    while (i < len) {
      address owner = owners[i];
      address backup = backupWallet[owner];
      if (
        backup != address(0) &&
        currentBlock >= lastActiveBlock[owner] + inactivityBlocks[owner]
      ) {
        _activateBackup(owner, backup);
        // After swap, owners[i] = backup (len unchanged). Move on; we never
        // re-visit the freshly-installed owner (they have no backup).
      }
      unchecked {
        ++i;
      }
    }
  }

  /// @notice Backup wallet refuses the backup role. Clears the backup
  ///         registration so this wallet is no longer eligible to take over
  ///         via refreshBackup(). Only callable by the backup wallet itself.
  /// @dev    After a backup has been activated, `backupFor[msg.sender]` is 0
  ///         (cleared by _activateBackup), so this function will revert with
  ///         NoBackupSet — protecting against accidental post-activation use.
  function declineBackup() external {
    address principal = backupFor[msg.sender];
    if (principal == address(0)) revert NoBackupSet();

    backupFor[msg.sender] = address(0);
    backupWallet[principal] = address(0);
    inactivityBlocks[principal] = 0;

    emit BackupRemoved(principal, msg.sender);
  }

  /// @dev Replaces `oldOwner` with `newOwner` in the owners set. Only called
  ///      from refreshBackup(); consumes no multisig nonce.
  function _activateBackup(address oldOwner, address newOwner) internal {
    // Swap in owners array (reuse the same slot)
    uint256 idx = ownerIndex[oldOwner];
    owners[idx - 1] = newOwner;
    ownerIndex[newOwner] = idx;
    ownerIndex[oldOwner] = 0;

    isOwner[oldOwner] = false;
    isOwner[newOwner] = true;

    // Clear backup state
    backupWallet[oldOwner] = address(0);
    backupFor[newOwner] = address(0);
    inactivityBlocks[oldOwner] = 0;
    lastActiveBlock[oldOwner] = 0;
    lastActiveBlock[newOwner] = block.number;
    // refreshBackup() does not consume the multisig nonce, so newOwner's
    // tenure starts at the current contract nonce (not nonce+1).
    ownerSinceNonce[newOwner] = nonce;

    emit OwnerRemoved(oldOwner);
    emit OwnerAdded(newOwner);
    emit BackupActivated(oldOwner, newOwner);
    emit DelegatesVoided(oldOwner);
  }

  // ==================== SIGNATURE VALIDATION ====================

  function _validateSignatures(
    bytes32 hash,
    bytes calldata signatures,
    uint256 currentNonce
  ) internal {
    uint256 _threshold = threshold;
    if (signatures.length != _threshold * 65) revert InvalidSignatureLength();

    address prev = address(0);
    for (uint256 i = 0; i < _threshold; ) {
      bytes calldata sig = signatures[i * 65:(i + 1) * 65];
      address signer = _recover(hash, sig);
      address effective;

      if (isOwner[signer]) {
        // Direct owner signature — update inactivity clock
        effective = signer;
        lastActiveBlock[signer] = block.number;
      } else {
        // Delegate signing on behalf of an owner for this specific nonce.
        // NOTE: does NOT update lastActiveBlock — delegate signing ≠ owner activity.
        // Backup wallets CANNOT sign multisig txs directly; they must first
        // take over ownership via refreshBackup() (which is permissionless).
        address dOwner = delegationOf[signer].owner;
        uint256 dNonce = delegationOf[signer].nonce;
        uint256 dExpiry = delegationOf[signer].expiry;
        uint256 dSetAt = delegationOf[signer].setAt;
        if (dOwner == address(0) || !isOwner[dOwner]) revert NotOwner();
        if (dNonce != currentNonce) revert DelegationNonceMismatch();
        if (block.timestamp > dExpiry) revert DelegationExpired();
        // Zombie guard: reject delegations created before the owner's current tenure.
        // Prevents a delegation set during a prior tenure from reviving after re-addition.
        if (dSetAt < ownerSinceNonce[dOwner]) revert InvalidDelegation();
        effective = dOwner;
        // Auto-clear after single use
        delete _delegateForNonce[dOwner][dNonce];
        delete delegationOf[signer];
        emit DelegateUsed(dOwner, signer, currentNonce);
      }

      // Sorting enforced by effective (principal) address — callers must order
      // delegate signatures by their principal's address, not their own.
      if (effective <= prev) revert SignaturesNotSorted();
      prev = effective;
      unchecked {
        ++i;
      }
    }
  }

  // ==================== EIP-712 HASH HELPERS ====================

  /// @dev EIP-712 encoding of address[]: keccak256(pad32(a1) || pad32(a2) || ...)
  ///      abi.encodePacked on address[] gives 20-byte elements (wrong); we must pad each to 32.
  function _hashAddressArray(
    address[] calldata arr
  ) internal pure returns (bytes32 result) {
    uint256 len = arr.length;
    bytes32[] memory words = new bytes32[](len);
    for (uint256 i = 0; i < len; ) {
      words[i] = bytes32(uint256(uint160(arr[i])));
      unchecked {
        ++i;
      }
    }
    assembly {
      result := keccak256(add(words, 32), mul(len, 32))
    }
  }

  /// @dev EIP-712 encoding of a single ERC721Asset struct.
  function _hashERC721Asset(
    ERC721Asset calldata asset
  ) internal pure returns (bytes32) {
    return
      keccak256(abi.encode(ERC721_ASSET_TYPEHASH, asset.token, asset.tokenId));
  }

  /// @dev EIP-712 encoding of ERC721Asset[]: keccak256(enc(a1) || enc(a2) || ...)
  function _hashERC721Assets(
    ERC721Asset[] calldata arr
  ) internal pure returns (bytes32 result) {
    uint256 len = arr.length;
    bytes32[] memory items = new bytes32[](len);
    for (uint256 i = 0; i < len; ) {
      items[i] = _hashERC721Asset(arr[i]);
      unchecked {
        ++i;
      }
    }
    assembly {
      result := keccak256(add(items, 32), mul(len, 32))
    }
  }

  /// @dev EIP-712 encoding of uint256[]: keccak256(v1 || v2 || ...)
  ///      uint256 elements are natively 32 bytes, so bytes32(v) is identity — no padding needed.
  ///      Uses an explicit loop rather than abi.encodePacked(arr) to avoid potential compiler
  ///      restrictions on calldata dynamic arrays inside structs.
  function _hashUint256Array(
    uint256[] calldata arr
  ) internal pure returns (bytes32 result) {
    uint256 len = arr.length;
    bytes32[] memory words = new bytes32[](len);
    for (uint256 i = 0; i < len; ) {
      words[i] = bytes32(arr[i]);
      unchecked {
        ++i;
      }
    }
    assembly {
      result := keccak256(add(words, 32), mul(len, 32))
    }
  }

  /// @dev EIP-712 encoding of a single ERC1155Asset struct.
  function _hashERC1155Asset(
    ERC1155Asset calldata asset
  ) internal pure returns (bytes32) {
    return
      keccak256(
        abi.encode(
          ERC1155_ASSET_TYPEHASH,
          asset.token,
          _hashUint256Array(asset.ids)
        )
      );
  }

  /// @dev EIP-712 encoding of ERC1155Asset[]: keccak256(enc(a1) || enc(a2) || ...)
  function _hashERC1155Assets(
    ERC1155Asset[] calldata arr
  ) internal pure returns (bytes32 result) {
    uint256 len = arr.length;
    bytes32[] memory items = new bytes32[](len);
    for (uint256 i = 0; i < len; ) {
      items[i] = _hashERC1155Asset(arr[i]);
      unchecked {
        ++i;
      }
    }
    assembly {
      result := keccak256(add(items, 32), mul(len, 32))
    }
  }

  /// @dev Safe ERC-20 transfer that handles non-standard tokens (e.g. USDT) which return
  ///      void instead of bool. Reverts if the call fails or explicitly returns false.
  function _safeERC20Transfer(
    address token,
    address to,
    uint256 amount
  ) internal {
    (bool ok, bytes memory ret) = token.call(
      abi.encodeWithSelector(IERC20Minimal.transfer.selector, to, amount)
    );
    if (!ok || (ret.length > 0 && !abi.decode(ret, (bool))))
      revert ExecutionFailed();
  }

  function _recover(
    bytes32 hash,
    bytes calldata sig
  ) internal pure returns (address signer) {
    if (sig.length != 65) revert InvalidSignatureLength();

    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
      r := calldataload(sig.offset)
      s := calldataload(add(sig.offset, 32))
      v := byte(0, calldataload(add(sig.offset, 64)))
    }

    if (
      uint256(s) >
      0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    ) {
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
    return
      keccak256(
        abi.encode(
          keccak256(
            'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
          ),
          keccak256('GSWSafe'),
          keccak256('3'),
          block.chainid,
          address(this)
        )
      );
  }

  function domainSeparator() public view returns (bytes32) {
    if (block.chainid == _CACHED_CHAIN_ID) {
      return _CACHED_DOMAIN_SEPARATOR;
    }
    return _buildDomainSeparator();
  }

  function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
    return
      keccak256(abi.encodePacked('\x19\x01', domainSeparator(), structHash));
  }

  // ==================== VIEW ====================

  function getTransactionHash(
    address to,
    uint256 value,
    bytes calldata data,
    uint256 deadline
  ) external view returns (bytes32) {
    bytes32 structHash = keccak256(
      abi.encode(TX_TYPEHASH, to, value, keccak256(data), nonce, deadline)
    );
    return _hashTypedData(structHash);
  }

  function getAddOwnerHash(
    address owner,
    uint256 newThreshold
  ) external view returns (bytes32) {
    return
      _hashTypedData(
        keccak256(abi.encode(ADD_OWNER_TYPEHASH, owner, newThreshold, nonce))
      );
  }

  function getRemoveOwnerHash(
    address owner,
    uint256 newThreshold
  ) external view returns (bytes32) {
    return
      _hashTypedData(
        keccak256(abi.encode(REMOVE_OWNER_TYPEHASH, owner, newThreshold, nonce))
      );
  }

  function getSetThresholdHash(
    uint256 newThreshold
  ) external view returns (bytes32) {
    return
      _hashTypedData(
        keccak256(abi.encode(SET_THRESHOLD_TYPEHASH, newThreshold, nonce))
      );
  }

  function getCancelNonceHash() external view returns (bytes32) {
    return _hashTypedData(keccak256(abi.encode(CANCEL_NONCE_TYPEHASH, nonce)));
  }

  function getMigrateHash(
    address to,
    uint256 deadline,
    address[] calldata erc20s,
    ERC721Asset[] calldata erc721s,
    ERC1155Asset[] calldata erc1155s
  ) external view returns (bytes32) {
    return
      _hashTypedData(
        keccak256(
          abi.encode(
            MIGRATE_TYPEHASH,
            to,
            _hashAddressArray(erc20s),
            _hashERC721Assets(erc721s),
            _hashERC1155Assets(erc1155s),
            nonce,
            deadline
          )
        )
      );
  }

  function getOwners() external view returns (address[] memory) {
    return owners;
  }

  // ==================== ERC-165 ====================

  function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
    return
      interfaceId == 0x01ffc9a7 || // IERC165
      interfaceId == 0x150b7a02 || // IERC721Receiver
      interfaceId == 0x4e2312e0; // IERC1155Receiver
  }

  // ==================== RECEIVERS ====================

  receive() external payable {
    emit Received(msg.sender, msg.value);
  }

  function onERC721Received(
    address,
    address,
    uint256,
    bytes calldata
  ) external pure returns (bytes4) {
    return 0x150b7a02;
  }

  function onERC1155Received(
    address,
    address,
    uint256,
    uint256,
    bytes calldata
  ) external pure returns (bytes4) {
    return 0xf23a6e61;
  }

  function onERC1155BatchReceived(
    address,
    address,
    uint256[] calldata,
    uint256[] calldata,
    bytes calldata
  ) external pure returns (bytes4) {
    return 0xbc197c81;
  }
}
