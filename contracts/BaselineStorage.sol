// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title BaselineStorage — M0: One transaction per IoT reading (no optimization)
contract BaselineStorage {
    struct Reading {
        address device;
        bytes32 dataHash;
        uint256 timestamp;
        uint256 nonce;
    }
    mapping(address => Reading[]) public readings;
    uint256 public totalReadings;

    event ReadingStored(address indexed device, bytes32 indexed dataHash,
                        uint256 timestamp, uint256 nonce);

    function storeReading(bytes32 dataHash, uint256 nonce) external {
        readings[msg.sender].push(Reading({
            device:    msg.sender,
            dataHash:  dataHash,
            timestamp: block.timestamp,
            nonce:     nonce
        }));
        totalReadings++;
        emit ReadingStored(msg.sender, dataHash, block.timestamp, nonce);
    }

    function getReading(address device, uint256 index)
        external view returns (bytes32 dataHash, uint256 timestamp, uint256 nonce)
    {
        Reading storage r = readings[device][index];
        return (r.dataHash, r.timestamp, r.nonce);
    }

    function readingCount(address device) external view returns (uint256) {
        return readings[device].length;
    }
}
