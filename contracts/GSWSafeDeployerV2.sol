// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import './GSWSafeV3.sol';

interface IERC20 {
  function transferFrom(
    address from,
    address to,
    uint256 amount
  ) external returns (bool);
}

contract GSWSafeDeployerV2 {
  /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

  error NotAdmin();
  error NotSuperAdmin();
  error ZeroAddress();
  error InvalidInactivityBlocks();
  error WrongPayment();
  error SafeAlreadyDeployed(address predicted);
  error TransferFailed();
  error SalesPaused();
  error SalesNotPaused();
  error ReentrancyGuard();
  error InvalidSignature();
  error InvalidSignatureLength();
  error InvalidSignatureS();
  error InvalidSignatureV();
  error Expired();
  error DeadlineTooLong();

  /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

  event SafeDeployed(
    address indexed safe,
    address indexed buyer,
    address currency,
    uint256 amount
  );

  event SafeDeployedByAdmin(
    address indexed safe,
    address indexed admin,
    uint256 userNonce
  );

  event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

  event FundsReceiverChanged(
    address indexed oldReceiver,
    address indexed newReceiver
  );

  event Paused(address indexed account);
  event Unpaused(address indexed account);

  /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

  uint256 private constant MAX_DEADLINE_DURATION = 30 days;

  bytes32 public constant VOUCHER_TYPEHASH =
    keccak256(
      'DeployVoucher(address buyer,bytes32 safeConfigHash,address currency,uint256 amount,uint256 userNonce,uint256 deadline)'
    );

  /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

  address public immutable superAdmin;
  uint256 public immutable minInactivityBlocks;
  uint256 private immutable _CACHED_CHAIN_ID;
  bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;

  address public admin;
  address public fundsReceiver;

  /// reentrancy lock
  uint256 private _locked = 1;

  /// pause flag
  bool public paused;

  /*//////////////////////////////////////////////////////////////
                                CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

  constructor(
    address _superAdmin,
    address _admin,
    address _fundsReceiver,
    uint256 _minInactivityBlocks
  ) {
    if (_superAdmin == address(0)) revert ZeroAddress();
    if (_admin == address(0)) revert ZeroAddress();
    if (_fundsReceiver == address(0)) revert ZeroAddress();
    if (_minInactivityBlocks == 0) revert InvalidInactivityBlocks();

    superAdmin = _superAdmin;
    admin = _admin;
    fundsReceiver = _fundsReceiver;
    minInactivityBlocks = _minInactivityBlocks;

    _CACHED_CHAIN_ID = block.chainid;
    _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator();
  }

  /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

  modifier onlyAdmin() {
    if (msg.sender != admin) revert NotAdmin();
    _;
  }

  modifier onlySuperAdmin() {
    if (msg.sender != superAdmin) revert NotSuperAdmin();
    _;
  }

  modifier whenNotPaused() {
    if (paused) revert SalesPaused();
    _;
  }

  modifier whenPaused() {
    if (!paused) revert SalesNotPaused();
    _;
  }

  modifier nonReentrant() {
    if (_locked == 2) revert ReentrancyGuard();
    _locked = 2;
    _;
    _locked = 1;
  }

  /*//////////////////////////////////////////////////////////////
                                ADMIN
    //////////////////////////////////////////////////////////////*/

  function withdrawETH() external whenPaused onlyAdmin {
    uint256 balance = address(this).balance;
    if (balance == 0) revert TransferFailed();
    (bool sent, ) = fundsReceiver.call{value: balance, gas: 2300}('');
    if (!sent) revert TransferFailed();
  }

  function setFundsReceiver(
    address newReceiver
  ) external whenPaused onlySuperAdmin {
    if (newReceiver == address(0)) revert ZeroAddress();
    address oldReceiver = fundsReceiver;
    fundsReceiver = newReceiver;
    emit FundsReceiverChanged(oldReceiver, newReceiver);
  }

  /*//////////////////////////////////////////////////////////////
                            SUPER ADMIN
    //////////////////////////////////////////////////////////////*/

  function setAdmin(address newAdmin) external whenPaused onlySuperAdmin {
    if (newAdmin == address(0)) revert ZeroAddress();
    address oldAdmin = admin;
    admin = newAdmin;
    emit AdminChanged(oldAdmin, newAdmin);
  }

  /*//////////////////////////////////////////////////////////////
                            PAUSE
    //////////////////////////////////////////////////////////////*/

  function pause() external onlySuperAdmin {
    if (paused) revert SalesPaused();
    paused = true;
    emit Paused(msg.sender);
  }

  function unpause() external onlySuperAdmin {
    if (!paused) revert SalesNotPaused();
    paused = false;
    emit Unpaused(msg.sender);
  }

  /*//////////////////////////////////////////////////////////////
                                DEPLOY
    //////////////////////////////////////////////////////////////*/

  /**
   * @notice Deploy a new GSWSafeV3 with an admin-signed voucher.
   * @param owners          Safe owner addresses.
   * @param threshold       Signature threshold for the safe.
   * @param userNonce       Caller-chosen nonce (part of CREATE2 salt + voucher).
   * @param currency        address(0) for native ETH, otherwise ERC-20.
   * @param amount          Price to pay (in smallest unit).
   * @param deadline        Voucher expiry timestamp.
   * @param adminSignature  EIP-712 signature from the deployer admin.
   */
  function deploySafe(
    address[] calldata owners,
    uint256 threshold,
    uint256 userNonce,
    address currency,
    uint256 amount,
    uint256 deadline,
    bytes calldata adminSignature
  ) external payable nonReentrant whenNotPaused returns (address safe) {
    if (block.timestamp > deadline) revert Expired();
    if (deadline > block.timestamp + MAX_DEADLINE_DURATION)
      revert DeadlineTooLong();

    // Verify admin voucher
    _verifyVoucher(
      owners,
      threshold,
      currency,
      amount,
      userNonce,
      deadline,
      adminSignature
    );

    // Check not already deployed
    {
      address predicted = predictSafeAddress(
        owners,
        threshold,
        msg.sender,
        userNonce
      );
      if (predicted.code.length != 0) revert SafeAlreadyDeployed(predicted);
    }

    // Collect payment
    if (amount > 0) {
      _collectPayment(currency, amount);
    } else {
      if (msg.value != 0) revert WrongPayment();
    }

    // Deploy
    bytes32 salt = _deriveSalt(msg.sender, owners, threshold, userNonce);
    safe = address(
      new GSWSafeV3{salt: salt}(owners, threshold, minInactivityBlocks)
    );

    emit SafeDeployed(safe, msg.sender, currency, amount);
  }

  /**
   * @notice Deploy a new GSWSafeV3 without charging any fee. Only callable by admin.
   */
  function deploySafeAdmin(
    address[] calldata owners,
    uint256 threshold,
    uint256 userNonce
  ) external onlyAdmin nonReentrant whenNotPaused returns (address safe) {
    address predicted = predictSafeAddress(
      owners,
      threshold,
      msg.sender,
      userNonce
    );
    if (predicted.code.length != 0) revert SafeAlreadyDeployed(predicted);

    bytes32 salt = _deriveSalt(msg.sender, owners, threshold, userNonce);
    safe = address(
      new GSWSafeV3{salt: salt}(owners, threshold, minInactivityBlocks)
    );

    emit SafeDeployedByAdmin(safe, msg.sender, userNonce);
  }

  /*//////////////////////////////////////////////////////////////
                          VOUCHER VERIFICATION
    //////////////////////////////////////////////////////////////*/

  function _verifyVoucher(
    address[] calldata owners,
    uint256 threshold,
    address currency,
    uint256 amount,
    uint256 userNonce,
    uint256 deadline,
    bytes calldata adminSignature
  ) internal view {
    bytes32 safeConfigHash = keccak256(abi.encode(owners, threshold));
    bytes32 structHash = keccak256(
      abi.encode(
        VOUCHER_TYPEHASH,
        msg.sender,
        safeConfigHash,
        currency,
        amount,
        userNonce,
        deadline
      )
    );
    address signer = _recover(_hashTypedData(structHash), adminSignature);
    if (signer != admin) revert InvalidSignature();
  }

  /*//////////////////////////////////////////////////////////////
                                PAYMENT
    //////////////////////////////////////////////////////////////*/

  function _collectPayment(address currency, uint256 amount) internal {
    address receiver = fundsReceiver;
    if (currency == address(0)) {
      if (msg.value != amount) revert WrongPayment();
      (bool sent, ) = receiver.call{value: amount, gas: 2300}('');
      if (!sent) revert TransferFailed();
    } else {
      if (msg.value != 0) revert WrongPayment();
      (bool success, bytes memory ret) = currency.call(
        abi.encodeWithSelector(
          IERC20.transferFrom.selector,
          msg.sender,
          receiver,
          amount
        )
      );
      if (!success || (ret.length > 0 && !abi.decode(ret, (bool))))
        revert TransferFailed();
    }
  }

  /*//////////////////////////////////////////////////////////////
                        EIP-712 / SIGNATURE
    //////////////////////////////////////////////////////////////*/

  function _buildDomainSeparator() private view returns (bytes32) {
    return
      keccak256(
        abi.encode(
          keccak256(
            'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
          ),
          keccak256('GSWSafeDeployer'),
          keccak256('1'),
          block.chainid,
          address(this)
        )
      );
  }

  function domainSeparator() public view returns (bytes32) {
    if (block.chainid == _CACHED_CHAIN_ID) return _CACHED_DOMAIN_SEPARATOR;
    return _buildDomainSeparator();
  }

  function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
    return
      keccak256(abi.encodePacked('\x19\x01', domainSeparator(), structHash));
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

    if (v != 27 && v != 28) revert InvalidSignatureV();

    signer = ecrecover(hash, v, r, s);
    if (signer == address(0)) revert InvalidSignature();
  }

  /*//////////////////////////////////////////////////////////////
                                VIEW
    //////////////////////////////////////////////////////////////*/

  /**
   * @notice Compute the EIP-712 hash for a deploy voucher (for admin to sign off-chain).
   */
  function getVoucherHash(
    address buyer,
    address[] calldata owners,
    uint256 threshold,
    address currency,
    uint256 amount,
    uint256 userNonce,
    uint256 deadline
  ) external view returns (bytes32) {
    bytes32 safeConfigHash = keccak256(abi.encode(owners, threshold));
    bytes32 structHash = keccak256(
      abi.encode(
        VOUCHER_TYPEHASH,
        buyer,
        safeConfigHash,
        currency,
        amount,
        userNonce,
        deadline
      )
    );
    return _hashTypedData(structHash);
  }

  /*//////////////////////////////////////////////////////////////
                        ADDRESS PREDICTION
    //////////////////////////////////////////////////////////////*/

  function predictSafeAddress(
    address[] calldata owners,
    uint256 threshold,
    address deployer,
    uint256 userNonce
  ) public view returns (address) {
    bytes32 salt = _deriveSalt(deployer, owners, threshold, userNonce);

    bytes memory initCode = abi.encodePacked(
      type(GSWSafeV3).creationCode,
      abi.encode(owners, threshold, minInactivityBlocks)
    );

    bytes32 hash = keccak256(
      abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(initCode))
    );

    return address(uint160(uint256(hash)));
  }

  function _deriveSalt(
    address deployer,
    address[] calldata owners,
    uint256 threshold,
    uint256 userNonce
  ) internal pure returns (bytes32) {
    return keccak256(abi.encode(deployer, owners, threshold, userNonce));
  }
}
