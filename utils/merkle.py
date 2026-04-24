"""utils/merkle.py — Deterministic Merkle tree for IoT batch hashing"""
import hashlib, struct
from typing import List, Tuple

def _hash_pair(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(a + b).digest()

def build_merkle_tree(leaves: List[bytes]) -> Tuple[bytes, list]:
    if not leaves:
        return b'\x00' * 32, []
    level = [hashlib.sha256(l).digest() for l in leaves]
    levels = [level[:]]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_hash_pair(level[i], level[i+1]) for i in range(0, len(level), 2)]
        levels.append(level[:])
    return level[0], levels

def get_merkle_root(leaves: List[bytes]) -> bytes:
    root, _ = build_merkle_tree(leaves)
    return root

def get_proof(leaves: List[bytes], index: int) -> Tuple[List[bytes], List[int]]:
    _, levels = build_merkle_tree(leaves)
    proof, sides = [], []
    cur = index
    for level in levels[:-1]:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        if cur % 2 == 0:
            proof.append(level[cur + 1])
            sides.append(1)
        else:
            proof.append(level[cur - 1])
            sides.append(0)
        cur //= 2
    return proof, sides

def leaves_from_readings(readings: List[dict]) -> List[bytes]:
    result = []
    for r in readings:
        raw = (str(r.get("device_id", "")).encode()
               + struct.pack(">Q", int(r.get("timestamp", 0)))
               + str(r.get("data_hash", "")).encode())
        result.append(raw)
    return result
