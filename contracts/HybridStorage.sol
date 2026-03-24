// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./ValidatorRegistry.sol";

/// @title HybridStorage (PoA-enabled) — M5: Proposed Novel Hybrid Protocol
/// @notice Extended with Proof of Authority: only registered validators
///         (trusted IoT gateways) may commit batches to the ledger.
///         PoA models consortium IoT deployment where gateways are known entities.
contract HybridStorage {

    ValidatorRegistry public immutable registry;

    struct HybridBatch {
        bytes32 merkleRoot;
        bytes   blsAggSig;
        bytes   blsAggPubKey;
        uint256 aggregateSum;
        uint256 batchSize;
        uint256 deviceCount;
        uint256 arrivalRate;
        bool    urgentFlush;
        uint256 timestamp;
        address validator;      // PoA: which registered gateway committed this
    }

    HybridBatch[] public batches;

    event HybridBatchCommitted(
        uint256 indexed batchId,
        bytes32 indexed merkleRoot,
        uint256 aggregateSum,
        uint256 batchSize,
        bool    urgentFlush,
        address indexed validator,
        uint256 timestamp
    );

    /// @dev PoA guard — reverts if caller is not a registered validator
    modifier onlyValidator() {
        require(registry.isValidator(msg.sender),
            "PoA: caller is not an authorized validator");
        _;
    }

    constructor(address registryAddress) {
        registry = ValidatorRegistry(registryAddress);
    }

    /// @notice Commit a full hybrid batch: {R, Sigma, S} in one transaction.
    ///         Caller MUST be a registered validator in ValidatorRegistry.
    function commitHybridBatch(
        bytes32 merkleRoot,
        bytes calldata blsAggSig,
        bytes calldata blsAggPubKey,
        uint256 aggregateSum,
        uint256 batchSize,
        uint256 deviceCount,
        uint256 arrivalRate,
        bool    urgentFlush
    ) external onlyValidator {
        require(blsAggSig.length == 48,    "BLS sig must be 48 bytes (G1)");
        require(blsAggPubKey.length == 96, "BLS pubkey must be 96 bytes (G2)");

        uint256 batchId = batches.length;
        batches.push(HybridBatch({
            merkleRoot:    merkleRoot,
            blsAggSig:     blsAggSig,
            blsAggPubKey:  blsAggPubKey,
            aggregateSum:  aggregateSum,
            batchSize:     batchSize,
            deviceCount:   deviceCount,
            arrivalRate:   arrivalRate,
            urgentFlush:   urgentFlush,
            timestamp:     block.timestamp,
            validator:     msg.sender
        }));

        emit HybridBatchCommitted(
            batchId, merkleRoot, aggregateSum,
            batchSize, urgentFlush, msg.sender, block.timestamp
        );
    }

    function verifyInclusion(
        uint256 batchId,
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256[] calldata indices
    ) external view returns (bool) {
        require(batchId < batches.length, "Invalid batchId");
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = indices[i] == 0
                ? keccak256(abi.encodePacked(proof[i], computed))
                : keccak256(abi.encodePacked(computed, proof[i]));
        }
        return computed == batches[batchId].merkleRoot;
    }

    function batchCount() external view returns (uint256) {
        return batches.length;
    }
}
