// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title BLSStorage — M3: Fixed batching + BLS12-381 aggregate signature compression
/// @notice BLS verification via EIP-2537 precompile — gas estimated in Python
///         since Ganache does not natively execute EIP-2537.
contract BLSStorage {
    struct BLSBatch {
        bytes32 merkleRoot;
        bytes   aggSignature;    // G1 point, 48 bytes
        bytes   aggPubKey;       // G2 point, 96 bytes
        uint256 deviceCount;
        uint256 batchSize;
        uint256 timestamp;
        address submitter;
    }
    BLSBatch[] public batches;

    event BLSBatchStored(uint256 indexed batchId, bytes32 indexed merkleRoot,
                          uint256 deviceCount, uint256 timestamp);

    function storeBLSBatch(bytes32 merkleRoot, bytes calldata aggSignature,
                            bytes calldata aggPubKey, uint256 deviceCount,
                            uint256 batchSize) external {
        require(aggSignature.length == 48, "BLS G1 sig must be 48 bytes");
        require(aggPubKey.length == 96,    "BLS G2 key must be 96 bytes");
        uint256 batchId = batches.length;
        batches.push(BLSBatch({
            merkleRoot:   merkleRoot,
            aggSignature: aggSignature,
            aggPubKey:    aggPubKey,
            deviceCount:  deviceCount,
            batchSize:    batchSize,
            timestamp:    block.timestamp,
            submitter:    msg.sender
        }));
        emit BLSBatchStored(batchId, merkleRoot, deviceCount, block.timestamp);
    }

    // Placeholder — actual EIP-2537 pairing check would go here in production
    function verifyBLS(uint256) external pure returns (bool) { return true; }

    function batchCount() external view returns (uint256) { return batches.length; }
}
