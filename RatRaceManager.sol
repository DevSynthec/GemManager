// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract GemManager is ReentrancyGuard {
    using ECDSA for bytes32;

    address public backendHashKey;
    uint256 public immutable ethPerGem;
    address public gameFeeWallet;
    address public claimerWallet;
    address public masterWallet;
    address public marketingWallet;

    uint256 public gameFeePercent;
    mapping(uint256 => bool) public usedNonces;
    uint256 public maxWithdrawalPerDay;
    uint256 public claimerMultiplier;

    struct WithdrawalInfo {
        uint256 withdrawnInCurrentPeriod;
        uint256 lastPeriodStart;
    }

    mapping(address => WithdrawalInfo) public withdrawalInfo;

    bytes32 public constant PURCHASE_TYPEHASH = keccak256("Purchase(address user,uint256 gemCount,uint256 nonce,bool deposit)");
    bytes32 public constant DOMAIN_SEPARATOR = 0x345437aa448a600dcf0666f07c22d486a78c2b0d137f777d8db1aebe38f255fd;

    event GemsPurchased(address indexed buyer, uint256 gemCount, uint256 amountInETH);
    event EtherClaimed(address indexed claimer, uint256 gemCount, uint256 amountInETH);
    event GemsFundedByMarketing(address indexed marketingWallet, uint256 amountInETH, uint256 gemCount);



    constructor(
        address _backendHashKey, 
        uint256 _ethPerGem, 
        address _claimerWallet,
        address _gameFeeWallet,
        address _masterWallet,
        address _marketingWallet,
        uint256 _claimerMultiplier,
        uint256 _maxWithdrawalPerDay,
        uint256 _gameFeePercent
    ) {
        require(_backendHashKey != address(0), "Invalid backend key");
        require(_ethPerGem > 0, "Price per gem must be greater than 0");
        require(_claimerWallet != address(0), "Invalid claimer wallet address");
        require(_gameFeeWallet != address(0), "Invalid game fee wallet address");
        require(_masterWallet != address(0), "Invalid master wallet address");
        require(_marketingWallet != address(0), "Invalid marketing wallet address");
        require(_claimerMultiplier > 0, "Claimer multiplier must be greater than 0");
        require(_maxWithdrawalPerDay > 0, "Max withdrawal per day must be greater than 0");
        require(_gameFeePercent > 0, "Game fee percent must be greater than 0");

        backendHashKey = _backendHashKey;
        ethPerGem = _ethPerGem;
        gameFeeWallet = _gameFeeWallet;
        claimerWallet = _claimerWallet;
        masterWallet = _masterWallet;
        marketingWallet = _marketingWallet;
        claimerMultiplier = _claimerMultiplier;
        maxWithdrawalPerDay = _maxWithdrawalPerDay;
        gameFeePercent = _gameFeePercent;
        // Calcul dynamique du DOMAIN_SEPARATOR
    }

    function setMaxWithdrawalPerDay(uint256 _newLimit) external {
        require(msg.sender == masterWallet, "Unauthorized");
        require(_newLimit > 0, "Limit must be greater than 0");
        maxWithdrawalPerDay = _newLimit;
    }

    function setClaimerMultiplier(uint256 _newMultiplier) external {
        require(msg.sender == masterWallet, "Unauthorized");
        require(_newMultiplier > 0, "Multiplier must be greater than 0");
        claimerMultiplier = _newMultiplier;
    }

    function setGameFeePercent(uint256 _newGameFeePercent) external {
        require(msg.sender == masterWallet, "Unauthorized");
        require(_newGameFeePercent > 0, "Game fee percent must be greater than 0");
        gameFeePercent = _newGameFeePercent;
    }

    function deposit(
        bytes memory _signature, 
        uint256 gemCount, 
        uint256 nonce
    ) external payable nonReentrant {
        address user = _verifySignature(_signature, msg.sender, gemCount, nonce, true);
        require(user == msg.sender, "Invalid user in signature");
    require(gemCount > 0, "gemCount must be greater than zero");
        require(!usedNonces[nonce], "Nonce already used");
        usedNonces[nonce] = true;

        uint256 totalCostInETH = gemCount * ethPerGem;
        uint256 gameFee = (totalCostInETH * gameFeePercent) / 1000000;

        require(msg.value >= totalCostInETH + gameFee, "Insufficient ETH sent");

        emit GemsPurchased(msg.sender, gemCount, totalCostInETH);

        require(payable(gameFeeWallet).send(gameFee), "Transfer to game fee wallet failed");

        if (msg.value > totalCostInETH + gameFee) {
            require(payable(msg.sender).send(msg.value - (totalCostInETH + gameFee)), "Refund failed");
        }
    }

    function withdraw(
        bytes memory _signature, 
        uint256 gemCount, 
        uint256 nonce
    ) external nonReentrant {
        address user = _verifySignature(_signature, msg.sender, gemCount, nonce, false);
        require(user == msg.sender, "Invalid user in signature");
        require(!usedNonces[nonce], "Nonce already used");
        require(gemCount > 0, "gemCount must be greater than zero");
        usedNonces[nonce] = true;

        uint256 amountInETH = gemCount * ethPerGem;
        require(address(this).balance >= amountInETH, "Insufficient contract balance for claim");

        _updateDailyLimit(user, amountInETH);

        emit EtherClaimed(msg.sender, gemCount, amountInETH);

        require(payable(msg.sender).send(amountInETH), "Transfer of ETH failed");
    }

    function marketingDepositGems(uint256 gemCount) external payable {
        require(msg.sender == marketingWallet, "Only marketing wallet can add funds");
        require(gemCount > 0, "Gem count must be greater than 0");

        uint256 requiredEthAmount = gemCount * ethPerGem;
        require(msg.value == requiredEthAmount, "Incorrect ETH amount sent");

        emit GemsFundedByMarketing(msg.sender, msg.value, gemCount);
    }

    function _verifySignature(
        bytes memory _signature, 
        address _user, 
        uint256 _gemCount, 
        uint256 _nonce, 
        bool _deposit
    ) internal view returns (address) {
        bytes32 structHash = keccak256(abi.encode(PURCHASE_TYPEHASH, _user, _gemCount, _nonce, _deposit));
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = hash.recover(_signature);
        require(signer == backendHashKey, "Invalid signature");

        return _user;
    }

    function _updateDailyLimit(address user, uint256 amountInETH) internal {
    WithdrawalInfo storage info = withdrawalInfo[user];

    uint256 currentPeriodStart = block.timestamp - (block.timestamp % 1 days);

    if (info.lastPeriodStart < currentPeriodStart) {
        info.withdrawnInCurrentPeriod = 0;
        info.lastPeriodStart = currentPeriodStart;
    }

    uint256 effectiveLimit = (user == claimerWallet) 
        ? maxWithdrawalPerDay * claimerMultiplier 
        : maxWithdrawalPerDay;

    require(
        info.withdrawnInCurrentPeriod + amountInETH <= effectiveLimit,
        "Daily withdrawal limit exceeded"
    );

    require(address(this).balance >= amountInETH, "Insufficient contract balance");

    info.withdrawnInCurrentPeriod += amountInETH;
}

    receive() external payable {}
}
