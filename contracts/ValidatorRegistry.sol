// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title ValidatorRegistry — Proof of Authority validator management
/// @notice Implements an application-layer PoA mechanism.
///         The contract owner registers trusted gateway/validator addresses.
///         All storage contracts check this registry before accepting commits.
///         This models a consortium IoT network where gateways are known entities.
contract ValidatorRegistry {

    address public owner;
    mapping(address => bool)   public validators;
    mapping(address => string) public validatorNames;   // human-readable labels
    address[] private _validatorList;

    event ValidatorAdded(address indexed validator, string name);
    event ValidatorRemoved(address indexed validator);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "PoA: caller is not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        // Auto-register deployer as first validator (IoT gateway 0)
        _addValidator(msg.sender, "Gateway-0 (deployer)");
    }

    // ── Validator management ──────────────────────────────────────

    function addValidator(address v, string calldata name) external onlyOwner {
        _addValidator(v, name);
    }

    function _addValidator(address v, string memory name) internal {
        require(v != address(0), "PoA: zero address");
        if (!validators[v]) {
            validators[v] = true;
            validatorNames[v] = name;
            _validatorList.push(v);
            emit ValidatorAdded(v, name);
        }
    }

    function removeValidator(address v) external onlyOwner {
        require(validators[v], "PoA: not a validator");
        validators[v] = false;
        emit ValidatorRemoved(v);
    }

    function isValidator(address v) external view returns (bool) {
        return validators[v];
    }

    function getValidators() external view returns (address[] memory) {
        return _validatorList;
    }

    function validatorCount() external view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < _validatorList.length; i++) {
            if (validators[_validatorList[i]]) count++;
        }
        return count;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "PoA: zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
