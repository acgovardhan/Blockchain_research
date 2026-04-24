// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title MerkleStorage — M1: Fixed-window batching + Merkle root anchoring (Tierion/Factom style)
contract MerkleStorage {
    struct Batch {
        bytes32 merkleRoot;
        uint256 batchSize;
        uint256 timestamp;
        address submitter;
    }
    Batch[] public batches;

    event BatchAnchored(uint256 indexed batchId, bytes32 indexed merkleRoot,
                        uint256 batchSize, uint256 timestamp);

    function anchorBatch(bytes32 merkleRoot, uint256 batchSize) external {
        uint256 batchId = batches.length;
        batches.push(Batch({
            merkleRoot: merkleRoot,
            batchSize:  batchSize,
            timestamp:  block.timestamp,
            submitter:  msg.sender
        }));
        emit BatchAnchored(batchId, merkleRoot, batchSize, block.timestamp);
    }

    function verifyProof(uint256 batchId, bytes32 leaf,
                         bytes32[] calldata proof, uint256[] calldata indices)
        external view returns (bool)
    {
        require(batchId < batches.length, "Invalid batchId");
        require(proof.length == indices.length, "Length mismatch");
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = indices[i] == 0
                ? keccak256(abi.encodePacked(proof[i], computed))
                : keccak256(abi.encodePacked(computed, proof[i]));
        }
        return computed == batches[batchId].merkleRoot;
    }

    function batchCount() external view returns (uint256) { return batches.length; }
}
