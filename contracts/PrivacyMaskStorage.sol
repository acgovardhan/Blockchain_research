// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title PrivacyMaskStorage — M4: Bonawitz-style secure aggregation
/// @notice Individual sensor values are never stored. Only the aggregate sum
///         is on-chain. Individual values cannot be recovered from the sum alone.
contract PrivacyMaskStorage {
    struct MaskedBatch {
        bytes32 merkleRoot;
        uint256 aggregateSum;    // sum recovered after masks cancel
        uint256 deviceCount;
        uint256 batchSize;
        uint256 timestamp;
        address aggregator;
    }
    MaskedBatch[] public batches;

    event MaskedBatchCommitted(uint256 indexed batchId, bytes32 indexed merkleRoot,
                                uint256 aggregateSum, uint256 deviceCount, uint256 timestamp);

    function commitMaskedBatch(bytes32 merkleRoot, uint256 aggregateSum,
                                uint256 deviceCount, uint256 batchSize) external {
        uint256 batchId = batches.length;
        batches.push(MaskedBatch({
            merkleRoot:   merkleRoot,
            aggregateSum: aggregateSum,
            deviceCount:  deviceCount,
            batchSize:    batchSize,
            timestamp:    block.timestamp,
            aggregator:   msg.sender
        }));
        emit MaskedBatchCommitted(batchId, merkleRoot, aggregateSum, deviceCount, block.timestamp);
    }

    function getAggregateSum(uint256 batchId) external view returns (uint256) {
        return batches[batchId].aggregateSum;
    }

    function batchCount() external view returns (uint256) { return batches.length; }
}
