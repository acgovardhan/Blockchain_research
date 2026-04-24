"""utils/bonawitz_masking.py — Bonawitz-style pairwise additive masking"""
import hashlib, os, time
from typing import List, Tuple, Dict

FIELD_PRIME = (1 << 61) - 1   # Mersenne prime M61

def _generate_pairwise_masks(devices: List[int], seed: bytes) -> Dict[int, int]:
    masks = {d: 0 for d in devices}
    for i, di in enumerate(devices):
        for dj in devices[i+1:]:
            h = hashlib.sha256(
                seed + di.to_bytes(4,'big') + dj.to_bytes(4,'big')
            ).digest()
            s = int.from_bytes(h[:8], 'big') % FIELD_PRIME
            masks[di] = (masks[di] + s) % FIELD_PRIME
            masks[dj] = (masks[dj] - s) % FIELD_PRIME
    return masks

def run_secure_aggregation(device_readings: Dict[int, int],
                            aggregate_seed: bytes = None):
    if aggregate_seed is None:
        aggregate_seed = os.urandom(32)
    device_ids = sorted(device_readings.keys())
    t0 = time.perf_counter()
    masks = _generate_pairwise_masks(device_ids, aggregate_seed)
    masked_values = [(device_readings[d] + masks[d]) % FIELD_PRIME
                     for d in device_ids]
    device_time = time.perf_counter() - t0
    t1 = time.perf_counter()
    agg_sum = sum(masked_values) % FIELD_PRIME
    agg_time = time.perf_counter() - t1
    true_sum = sum(device_readings.values()) % FIELD_PRIME
    assert agg_sum == true_sum, f"Masking check failed: {agg_sum} != {true_sum}"
    return agg_sum, masked_values, device_time, agg_time
