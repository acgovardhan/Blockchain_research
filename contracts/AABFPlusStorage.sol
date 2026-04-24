// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title AABFPlusStorage — M2: Adaptive batching with arrival rate and jitter metadata
contract AABFPlusStorage {
    struct MicroBlock {
        bytes32 merkleRoot;
        uint256 batchSize;
        uint256 timestamp;
        uint256 arrivalRate;   // EWMA * 1000 fixed-point
        uint256 jitterScore;   // jitter * 1000 fixed-point
        bool    urgentFlush;
        address submitter;
    }
    MicroBlock[] public microblocks;

    event MicroBlockCommitted(uint256 indexed blockId, bytes32 indexed merkleRoot,
                               uint256 batchSize, bool urgentFlush, uint256 timestamp);

    function commitMicroBlock(bytes32 merkleRoot, uint256 batchSize,
                               uint256 arrivalRate, uint256 jitterScore,
                               bool urgentFlush) external {
        uint256 blockId = microblocks.length;
        microblocks.push(MicroBlock({
            merkleRoot:  merkleRoot,
            batchSize:   batchSize,
            timestamp:   block.timestamp,
            arrivalRate: arrivalRate,
            jitterScore: jitterScore,
            urgentFlush: urgentFlush,
            submitter:   msg.sender
        }));
        emit MicroBlockCommitted(blockId, merkleRoot, batchSize, urgentFlush, block.timestamp);
    }

    function blockCount() external view returns (uint256) { return microblocks.length; }
}
