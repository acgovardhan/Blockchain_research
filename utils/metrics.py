"""utils/metrics.py — Shared metric helpers (used by legacy scripts 02-07)"""
import csv, time, json, hashlib
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List

ENERGY_ECDSA_SIGN_MJ = 0.50
ENERGY_BLS_SIGN_MJ   = 2.10
ENERGY_HASH_PER_BYTE = 0.001
ENERGY_TX_PER_BYTE   = 0.012
ENERGY_MASK_OP_MJ    = 0.08

@dataclass
class BatchMetrics:
    method:              str
    batch_id:            int
    batch_size:          int
    tx_hash:             str
    gas_used:            int
    gas_price_wei:       int
    gas_cost_wei:        int
    latency_ms:          float
    bandwidth_bytes:     int
    offchain_compute_ms: float
    energy_device_mj:    float
    energy_aggr_mj:      float
    num_devices:         int
    urgent_flush:        bool
    arrival_rate:        float
    timestamp_unix:      float = field(default_factory=time.time)
    notes:               str   = ""

class MetricsRecorder:
    FIELDNAMES = list(BatchMetrics.__dataclass_fields__.keys())
    def __init__(self, method: str):
        from config import RESULTS_DIR
        self.method  = method
        self.outfile = RESULTS_DIR / f"metrics_{method}.csv"
        self._rows: List[BatchMetrics] = []
        if not self.outfile.exists():
            with open(self.outfile, 'w', newline='') as f:
                csv.DictWriter(f, fieldnames=self.FIELDNAMES).writeheader()

    def record(self, m: BatchMetrics):
        self._rows.append(m)
        with open(self.outfile, 'a', newline='') as f:
            csv.DictWriter(f, fieldnames=self.FIELDNAMES).writerow(asdict(m))

    def save_summary(self):
        if not self._rows: return {}
        import statistics
        lats = [r.latency_ms for r in self._rows]
        lats_sorted = sorted(lats)
        p95 = lats_sorted[int(0.95*len(lats_sorted))]
        total_r = sum(r.batch_size for r in self._rows)
        s = {
            "method": self.method,
            "total_batches": len(self._rows),
            "total_readings": total_r,
            "avg_gas_per_reading": sum(r.gas_used for r in self._rows)/max(1,total_r),
            "avg_latency_ms": statistics.mean(lats),
            "p95_latency_ms": p95,
            "avg_bandwidth_per_reading": sum(r.bandwidth_bytes for r in self._rows)/max(1,total_r),
            "avg_energy_per_reading": sum(r.energy_device_mj+r.energy_aggr_mj for r in self._rows)/max(1,total_r),
            "avg_batch_size": total_r/len(self._rows),
            "urgent_flush_count": sum(1 for r in self._rows if r.urgent_flush),
        }
        from config import RESULTS_DIR
        out = RESULTS_DIR / f"summary_{self.method}.json"
        with open(out,'w') as f: json.dump(s, f, indent=2)
        return s

def reading_to_hash(r: dict) -> bytes:
    payload = json.dumps({k: str(v) for k,v in sorted(r.items())
                          if k != 'data_hash'}, sort_keys=True).encode()
    return hashlib.sha256(payload).digest()

def hash_to_int(h: bytes, max_val: int = 10_000) -> int:
    return int.from_bytes(h[:4], 'big') % max_val

def count_calldata_bytes(tx) -> int:
    raw = tx.get('input', tx.get('data', '0x'))
    hexstr = raw[2:] if raw.startswith('0x') else raw
    return len(hexstr) // 2

def estimate_device_energy(n_devices, use_bls=False, use_masking=False,
                            data_bytes_per_device=64):
    sign  = (ENERGY_BLS_SIGN_MJ if use_bls else ENERGY_ECDSA_SIGN_MJ) * n_devices
    hsh   = ENERGY_HASH_PER_BYTE * data_bytes_per_device * n_devices
    tx    = ENERGY_TX_PER_BYTE   * data_bytes_per_device * n_devices
    mask  = (ENERGY_MASK_OP_MJ*(n_devices-1))*n_devices if use_masking else 0
    return sign + hsh + tx + mask

def estimate_aggregator_energy(n_readings, build_merkle=True,
                                use_bls_agg=False, use_masking=False):
    m = ENERGY_HASH_PER_BYTE*32*n_readings*2 if build_merkle else 0
    b = ENERGY_BLS_SIGN_MJ*n_readings if use_bls_agg else 0
    k = ENERGY_MASK_OP_MJ*n_readings  if use_masking  else 0
    return m + b + k
