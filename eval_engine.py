"""
eval_engine.py — FIXED VERSION
======================================================================
FIXES APPLIED:
  1. BLS is now pure-simulation (no py_ecc calls) — 1000x faster
  2. Correct byte sizes: sig=48 bytes (G1), pubkey=96 bytes (G2)
  3. M2/M5 progress bar now row-based (not batch-count-estimate)
  4. M3/M5 no longer call [:96].ljust(96) — functions return right sizes
  5. Checkpoint logic unchanged
"""

import time, math, hashlib, struct, json, csv, pickle, os
from pathlib import Path
from collections import deque
from dataclasses import dataclass, asdict, field
from typing import List, Optional
from datetime import datetime, timedelta

try:
    from web3 import Web3
    WEB3_OK = True
except ImportError:
    WEB3_OK = False

# ── BLS: ALWAYS use fast simulation ───────────────────────────
# py_ecc is pure-Python elliptic curve math and takes ~1-2s per call.
# For bulk evaluation this is catastrophic (20+ hours for 500k rows).
# Our simulation uses SHA-256 XOR which is cryptographically equivalent
# for the purpose of measuring gas/latency/bandwidth on Ganache.
# Ganache does NOT verify BLS math — it only checks byte lengths.
BLS_OK = False  # Force simulation — DO NOT SET TO TRUE for bulk eval

# ── Constants ──────────────────────────────────────────────────
GANACHE_URL        = "http://127.0.0.1:7545"
NUM_DEVICES        = 20
FIXED_BATCH_SIZE   = 20
FIELD_PRIME        = (1 << 61) - 1
AABF_LAMBDA_BASE   = 10.0
AABF_ALPHA         = 0.3
AABF_JITTER_THRESH = 0.40
AABF_MIN_BATCH     = 5
AABF_MAX_BATCH     = 50
HIGH_SEVERITY      = {
    'c&c', 'attack', 'ddos', 'dos', 'okiru', 'mirai',
    'ransomware', 'backdoor', 'injection', 'xss', 'mitm',
    'password'
    # NOTE: 'scanning' intentionally removed — PortScan is high-volume
    # but NOT time-critical. Including it caused all readings to be urgent.
}
GAS_BLS_VERIFY     = 89_000
ENERGY_ECDSA_MJ    = 0.50
ENERGY_BLS_MJ      = 2.10
ENERGY_HASH_MJ     = 0.001
ENERGY_TX_MJ       = 0.012
ENERGY_MASK_MJ     = 0.08
CHECKPOINT_INTERVAL = 50

# ── Data record ────────────────────────────────────────────────
@dataclass
class BatchRecord:
    method:           str
    dataset:          str
    batch_id:         int
    batch_size:       int
    tx_hash:          str
    gas_used:         int
    latency_ms:       float
    bandwidth_bytes:  int
    offchain_ms:      float
    energy_device_mj: float
    energy_aggr_mj:   float
    num_devices:      int
    urgent_flush:     bool
    arrival_rate:     float
    notes:            str = ""

FIELDS = list(BatchRecord.__dataclass_fields__.keys())


# ══════════════════════════════════════════════════════════════
# CHECKPOINT MANAGER
# ══════════════════════════════════════════════════════════════
class CheckpointManager:
    def __init__(self, method: str, dataset: str, ckpt_dir: Path):
        ckpt_dir.mkdir(parents=True, exist_ok=True)
        self.path = ckpt_dir / f"ckpt_{method}_{dataset}.json"

    def save(self, batch_id: int, records_written: int, elapsed_s: float):
        data = {
            "batch_id": batch_id,
            "records_written": records_written,
            "elapsed_s": elapsed_s,
            "saved_at": datetime.now().isoformat(),
        }
        with open(self.path, 'w') as f:
            json.dump(data, f, indent=2)

    def load(self) -> Optional[dict]:
        if self.path.exists():
            with open(self.path) as f:
                return json.load(f)
        return None

    def clear(self):
        if self.path.exists():
            self.path.unlink()


# ══════════════════════════════════════════════════════════════
# RESULTS WRITER
# ══════════════════════════════════════════════════════════════
class ResultsWriter:
    def __init__(self, method: str, dataset: str,
                 results_dir: Path, resume_from: int = 0):
        results_dir.mkdir(parents=True, exist_ok=True)
        self.path = results_dir / f"metrics_{method}_{dataset}.csv"
        self.rows: List[BatchRecord] = []
        self.resume_from = resume_from

        if resume_from == 0:
            with open(self.path, 'w', newline='') as f:
                csv.DictWriter(f, fieldnames=FIELDS).writeheader()
            print(f"  [writer] Starting fresh → {self.path.name}")
        else:
            if self.path.exists():
                existing = list(csv.DictReader(open(self.path)))
                print(f"  [writer] Resuming from batch {resume_from}. "
                      f"Found {len(existing)} existing rows → {self.path.name}")

    def write(self, rec: BatchRecord):
        self.rows.append(rec)
        with open(self.path, 'a', newline='') as f:
            csv.DictWriter(f, fieldnames=FIELDS).writerow(asdict(rec))

    def summary(self):
        all_rows = []
        if self.path.exists():
            for row in csv.DictReader(open(self.path)):
                all_rows.append(row)
        if not all_rows:
            return {}
        gases    = [float(r['gas_used'])        for r in all_rows]
        lats     = [float(r['latency_ms'])       for r in all_rows]
        bws      = [float(r['bandwidth_bytes'])  for r in all_rows]
        batches  = [int(r['batch_size'])         for r in all_rows]
        energies = [float(r['energy_device_mj']) + float(r['energy_aggr_mj'])
                    for r in all_rows]
        total_r  = sum(batches)
        lats_s   = sorted(lats)
        p95      = lats_s[int(0.95 * len(lats_s))]
        urgent   = sum(1 for r in all_rows if r['urgent_flush'] == 'True')
        return {
            "method":             all_rows[0]['method'],
            "dataset":            all_rows[0]['dataset'],
            "total_batches":      len(all_rows),
            "total_readings":     total_r,
            "avg_gas":            sum(gases) / len(gases),
            "avg_gas_reading":    sum(gases) / max(1, total_r),
            "avg_latency_ms":     sum(lats) / len(lats),
            "p95_latency_ms":     p95,
            "avg_bw_reading":     sum(bws) / max(1, total_r),
            "avg_energy_reading": sum(energies) / max(1, total_r),
            "avg_batch_size":     total_r / len(all_rows),
            "urgent_flushes":     urgent,
        }


# ══════════════════════════════════════════════════════════════
# BLOCKCHAIN CONNECTOR
# ══════════════════════════════════════════════════════════════
class BlockchainConn:
    def __init__(self, addresses, abis):
        self.addresses = addresses
        self.abis = abis
        self._connect()

    def _connect(self):
        self.w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
        self.accounts = self.w3.eth.accounts
        assert self.w3.is_connected(), \
            f"Cannot connect to Ganache at {GANACHE_URL}"

    def contract(self, name):
        return self.w3.eth.contract(
            address=self.addresses[name],
            abi=self.abis[name]
        )

    def send(self, func, sender, gas=500_000, retries=3):
        for attempt in range(retries):
            try:
                t0 = time.perf_counter()
                tx = func.transact({"from": sender, "gas": gas})
                rx = self.w3.eth.wait_for_transaction_receipt(tx)
                ms = (time.perf_counter() - t0) * 1000
                bw = len(self.w3.eth.get_transaction(tx)["input"]) // 2
                return rx, ms, bw, tx.hex()
            except Exception as e:
                if attempt < retries - 1:
                    print(f"\n  [retry {attempt+1}] {e} — reconnecting...")
                    time.sleep(2)
                    try:
                        self._connect()
                    except Exception:
                        pass
                else:
                    raise


# ══════════════════════════════════════════════════════════════
# CRYPTO UTILITIES
# ══════════════════════════════════════════════════════════════
def reading_to_hash(r: dict) -> bytes:
    payload = json.dumps(
        {k: str(v) for k, v in sorted(r.items()) if k != 'data_hash'},
        sort_keys=True
    ).encode()
    return hashlib.sha256(payload).digest()

def hash_to_int(h: bytes, max_val=10_000) -> int:
    return int.from_bytes(h[:4], 'big') % max_val

def build_merkle(leaves: List[bytes]) -> bytes:
    if not leaves:
        return b'\x00' * 32
    level = [hashlib.sha256(l).digest() for l in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i+1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0]

def leaves_from_batch(batch):
    out = []
    for r in batch:
        raw = (str(r.get('device_id', 0)).encode()
               + struct.pack(">Q", int(r.get('timestamp', 0)))
               + r.get('data_hash', '').encode())
        out.append(raw)
    return out

def _pairwise_masks(device_ids, seed):
    masks = {d: 0 for d in device_ids}
    for i, di in enumerate(device_ids):
        for dj in device_ids[i+1:]:
            h = hashlib.sha256(
                seed + di.to_bytes(4, 'big') + dj.to_bytes(4, 'big')
            ).digest()
            s = int.from_bytes(h[:8], 'big') % FIELD_PRIME
            masks[di] = (masks[di] + s) % FIELD_PRIME
            masks[dj] = (masks[dj] - s) % FIELD_PRIME
    return masks

def secure_aggregate(device_readings: dict, seed: bytes):
    ids    = sorted(device_readings.keys())
    masks  = _pairwise_masks(ids, seed)
    masked = [(device_readings[d] + masks[d]) % FIELD_PRIME for d in ids]
    total  = sum(masked) % FIELD_PRIME
    return total, masked


# ══════════════════════════════════════════════════════════════
# BLS SIMULATION — FAST, CORRECT BYTE SIZES
# ══════════════════════════════════════════════════════════════
# Contracts require: aggSignature=48 bytes (G1), aggPubKey=96 bytes (G2)
# py_ecc G2ProofOfPossession produces: Sign→96 bytes, SkToPk→48 bytes
# i.e. sizes are SWAPPED from what the contracts expect.
# Solution: use fast SHA-256 XOR simulation with correct sizes.
# Ganache stores bytes and emits events — it does NOT verify BLS math.
# Gas estimates for real BLS verification are added analytically (GAS_BLS_VERIFY).

def _bls_keygen(device_id: int):
    """Returns (sk: int, pk: bytes[96]) — simulated G2 public key"""
    seed = hashlib.sha256(f"device_{device_id:04d}".encode()).digest()
    sk   = int.from_bytes(seed, 'big') | 1   # ensure non-zero
    # 96-byte simulated G2 public key (3 × SHA-256)
    pk   = (hashlib.sha256(seed + b'\x00').digest() +
            hashlib.sha256(seed + b'\x01').digest() +
            hashlib.sha256(seed + b'\x02').digest())  # 96 bytes
    return sk, pk

# Pre-compute device keys once at module load
DEVICE_KEYS = [_bls_keygen(i) for i in range(NUM_DEVICES)]

def bls_sign(sk: int, msg: bytes) -> bytes:
    """Simulated BLS G1 signature — 48 bytes"""
    seed = sk.to_bytes(32, 'big') + msg
    return (hashlib.sha256(seed + b'\x00').digest() +
            hashlib.sha256(seed + b'\x01').digest()[:16])  # 32+16 = 48 bytes

def bls_aggregate(sigs: List[bytes]) -> bytes:
    """XOR aggregate of G1 signatures — returns exactly 48 bytes"""
    if not sigs:
        return b'\x00' * 48
    agg = bytearray(48)
    for s in sigs:
        b = s if len(s) >= 48 else s.ljust(48, b'\x00')
        for j in range(48):
            agg[j] ^= b[j]
    return bytes(agg)

def bls_agg_pk(pks: List[bytes]) -> bytes:
    """XOR aggregate of G2 public keys — returns exactly 96 bytes"""
    if not pks:
        return b'\x00' * 96
    agg = bytearray(96)
    for pk in pks:
        b = pk if len(pk) >= 96 else pk.ljust(96, b'\x00')
        for j in range(96):
            agg[j] ^= b[j]
    return bytes(agg)

def device_energy(n, use_bls=False, use_mask=False, data_bytes=64):
    sign = (ENERGY_BLS_MJ if use_bls else ENERGY_ECDSA_MJ) * n
    hsh  = ENERGY_HASH_MJ * data_bytes * n
    tx   = ENERGY_TX_MJ   * data_bytes * n
    mask = (ENERGY_MASK_MJ * (n - 1)) * n if use_mask else 0
    return sign + hsh + tx + mask

def aggr_energy(n, merkle=True, bls_agg=False, masking=False):
    m = ENERGY_HASH_MJ * 32 * n * 2 if merkle  else 0
    b = ENERGY_BLS_MJ  * n          if bls_agg else 0
    k = ENERGY_MASK_MJ * n          if masking  else 0
    return m + b + k


# ══════════════════════════════════════════════════════════════
# PROGRESS PRINTER
# ══════════════════════════════════════════════════════════════
def print_progress(label, done, total, start_time, extra_label=""):
    now      = time.time()
    elapsed  = now - start_time
    rate     = done / max(elapsed, 1)
    remaining = (total - done) / max(rate, 1e-9)
    eta      = datetime.now() + timedelta(seconds=remaining)
    bar_fill = int(30 * done / max(total, 1))
    bar      = "#" * bar_fill + "-" * (30 - bar_fill)
    print(f"\r  [{bar}] {done}/{total} {label} | "
          f"Elapsed: {timedelta(seconds=int(elapsed))} | "
          f"ETA: {eta.strftime('%H:%M')} {extra_label}",
          end="", flush=True)


# ══════════════════════════════════════════════════════════════
# METHOD IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════

def run_m0(readings, bc, dataset, results_dir, ckpt_dir):
    """M0: Baseline — one transaction per reading."""
    method   = "M0_Baseline"
    ckpt_mgr = CheckpointManager(method, dataset, ckpt_dir)
    ckpt     = ckpt_mgr.load()
    resume   = ckpt['batch_id'] + 1 if ckpt else 0
    writer   = ResultsWriter(method, dataset, results_dir, resume)
    contract = bc.contract("BaselineStorage")

    total   = len(readings)
    start_t = time.time()

    print(f"\n  [M0] Baseline on {dataset} | {total:,} readings")
    if resume > 0:
        print(f"  [M0] Resuming from reading {resume}")

    for idx in range(resume, total):
        r      = readings[idx]
        sender = bc.accounts[r['device_id'] % len(bc.accounts)]
        dhash  = bytes.fromhex(r['data_hash'])

        try:
            rx, ms, bw, txh = bc.send(
                contract.functions.storeReading(dhash, idx),
                sender, gas=100_000)
            writer.write(BatchRecord(
                method=method, dataset=dataset,
                batch_id=idx, batch_size=1,
                tx_hash=txh, gas_used=rx['gasUsed'],
                latency_ms=ms, bandwidth_bytes=bw,
                offchain_ms=0,
                energy_device_mj=device_energy(1),
                energy_aggr_mj=0, num_devices=1,
                urgent_flush=r.get('is_urgent', False),
                arrival_rate=0))
        except Exception as e:
            print(f"\n  M0 error at idx {idx}: {e}")

        if (idx + 1) % CHECKPOINT_INTERVAL == 0:
            ckpt_mgr.save(idx, idx - resume + 1, time.time() - start_t)
            print_progress("readings", idx + 1, total, start_t)

    print()
    ckpt_mgr.clear()
    return writer.summary()


def run_m1(readings, bc, dataset, results_dir, ckpt_dir):
    """M1: Fixed-window Merkle anchoring."""
    method   = "M1_MerkleOnly"
    ckpt_mgr = CheckpointManager(method, dataset, ckpt_dir)
    ckpt     = ckpt_mgr.load()
    resume   = ckpt['batch_id'] + 1 if ckpt else 0
    contract = bc.contract("MerkleStorage")
    agg      = bc.accounts[0]

    batches = [readings[i:i + FIXED_BATCH_SIZE]
               for i in range(0, len(readings), FIXED_BATCH_SIZE)]
    total   = len(batches)
    writer  = ResultsWriter(method, dataset, results_dir, resume)
    start_t = time.time()

    print(f"\n  [M1] Merkle-Only on {dataset} | "
          f"{len(readings):,} readings → {total:,} batches")
    if resume > 0:
        print(f"  [M1] Resuming from batch {resume}")

    for bid in range(resume, total):
        batch  = batches[bid]
        t0     = time.perf_counter()
        leaves = leaves_from_batch(batch)
        root   = build_merkle(leaves)
        comp   = (time.perf_counter() - t0) * 1000

        try:
            rx, ms, bw, txh = bc.send(
                contract.functions.anchorBatch(root, len(batch)),
                agg, gas=200_000)
            writer.write(BatchRecord(
                method=method, dataset=dataset,
                batch_id=bid, batch_size=len(batch),
                tx_hash=txh, gas_used=rx['gasUsed'],
                latency_ms=ms, bandwidth_bytes=bw,
                offchain_ms=comp,
                energy_device_mj=device_energy(len(batch)),
                energy_aggr_mj=aggr_energy(len(batch), merkle=True),
                num_devices=len({r['device_id'] for r in batch}),
                urgent_flush=False, arrival_rate=0))
        except Exception as e:
            print(f"\n  M1 error batch {bid}: {e}")

        if (bid + 1) % CHECKPOINT_INTERVAL == 0:
            ckpt_mgr.save(bid, bid - resume + 1, time.time() - start_t)
            print_progress("batches", bid + 1, total, start_t)

    print()
    ckpt_mgr.clear()
    return writer.summary()


def run_m2(readings, bc, dataset, results_dir, ckpt_dir):
    """M2: AABF+ adaptive batching."""
    method    = "M2_AABF_Plus"
    ckpt_mgr  = CheckpointManager(method, dataset, ckpt_dir)
    ckpt      = ckpt_mgr.load()
    resume    = ckpt['batch_id'] + 1 if ckpt else 0
    contract  = bc.contract("AABFPlusStorage")
    agg       = bc.accounts[0]
    writer    = ResultsWriter(method, dataset, results_dir, resume)

    ewma_rate = AABF_LAMBDA_BASE
    last_ts   = None
    iats      = deque(maxlen=50)
    buffer    = []
    bid       = 0
    rows_done = 0
    start_t   = time.time()
    total_rows = len(readings)

    print(f"\n  [M2] AABF+ on {dataset} | {total_rows:,} readings")

    def flush(buf, urgent, rate, jitter_fp):
        nonlocal bid
        if bid < resume:
            bid += 1
            return
        t0     = time.perf_counter()
        leaves = leaves_from_batch(buf)
        root   = build_merkle(leaves)
        comp   = (time.perf_counter() - t0) * 1000
        try:
            rx, ms, bw, txh = bc.send(
                contract.functions.commitMicroBlock(
                    root, len(buf), int(rate * 1000), jitter_fp, urgent),
                agg, gas=250_000)
            writer.write(BatchRecord(
                method=method, dataset=dataset,
                batch_id=bid, batch_size=len(buf),
                tx_hash=txh, gas_used=rx['gasUsed'],
                latency_ms=ms, bandwidth_bytes=bw, offchain_ms=comp,
                energy_device_mj=device_energy(len(buf)),
                energy_aggr_mj=aggr_energy(len(buf), merkle=True),
                num_devices=len({r['device_id'] for r in buf}),
                urgent_flush=urgent, arrival_rate=rate))
        except Exception as e:
            print(f"\n  M2 error batch {bid}: {e}")
        bid += 1
        if bid % CHECKPOINT_INTERVAL == 0:
            ckpt_mgr.save(bid - 1, bid - resume, time.time() - start_t)
            print_progress("rows", rows_done, total_rows, start_t,
                           f"| batches={bid}")

    for r in readings:
        rows_done += 1
        buffer.append(r)
        ts     = r['timestamp']
        jitter = 0.0
        if last_ts is not None:
            iat = max(ts - last_ts, 1e-6)
            iats.append(iat)
            ewma_rate = AABF_ALPHA * (1 / iat) + (1 - AABF_ALPHA) * ewma_rate
            if len(iats) >= 3:
                m = sum(iats) / len(iats)
                v = sum((x - m) ** 2 for x in iats) / len(iats)
                jitter = math.sqrt(v) / (m + 1e-9)
        last_ts = ts
        W = int((AABF_MIN_BATCH + AABF_MAX_BATCH) / 2
                * AABF_LAMBDA_BASE / max(ewma_rate, 0.1))
        W = max(AABF_MIN_BATCH, min(AABF_MAX_BATCH, W))
        urgent = r.get('is_urgent', False)
        if len(buffer) >= W or jitter > AABF_JITTER_THRESH or urgent:
            flush(buffer[:], urgent or jitter > AABF_JITTER_THRESH,
                  ewma_rate, int(jitter * 1000))
            buffer.clear()

    if buffer:
        flush(buffer[:], False, ewma_rate, 0)
    print()
    ckpt_mgr.clear()
    return writer.summary()


def run_m3(readings, bc, dataset, results_dir, ckpt_dir):
    """M3: BLS aggregate signatures (simulated)."""
    method   = "M3_BLS_Only"
    ckpt_mgr = CheckpointManager(method, dataset, ckpt_dir)
    ckpt     = ckpt_mgr.load()
    resume   = ckpt['batch_id'] + 1 if ckpt else 0
    contract = bc.contract("BLSStorage")
    agg      = bc.accounts[0]
    batches  = [readings[i:i + FIXED_BATCH_SIZE]
                for i in range(0, len(readings), FIXED_BATCH_SIZE)]
    total    = len(batches)
    writer   = ResultsWriter(method, dataset, results_dir, resume)
    start_t  = time.time()

    print(f"\n  [M3] BLS-Only on {dataset} | "
          f"{len(readings):,} readings → {total:,} batches")
    if resume > 0:
        print(f"  [M3] Resuming from batch {resume}")

    for bid in range(resume, total):
        batch  = batches[bid]
        t0     = time.perf_counter()
        leaves = leaves_from_batch(batch)
        root   = build_merkle(leaves)
        devs   = {r['device_id']: DEVICE_KEYS[r['device_id'] % NUM_DEVICES]
                  for r in batch}
        sigs, pks = [], []
        for sk, pk in devs.values():
            sigs.append(bls_sign(sk, root))
            pks.append(pk)

        # FIX: bls_aggregate returns 48 bytes, bls_agg_pk returns 96 bytes
        agg_sig = bls_aggregate(sigs)   # 48 bytes — matches contract requirement
        agg_pk  = bls_agg_pk(pks)       # 96 bytes — matches contract requirement
        comp    = (time.perf_counter() - t0) * 1000

        try:
            rx, ms, bw, txh = bc.send(
                contract.functions.storeBLSBatch(
                    root, agg_sig, agg_pk, len(devs), len(batch)),
                agg, gas=300_000)
            writer.write(BatchRecord(
                method=method, dataset=dataset,
                batch_id=bid, batch_size=len(batch),
                tx_hash=txh, gas_used=rx['gasUsed'] + GAS_BLS_VERIFY,
                latency_ms=ms, bandwidth_bytes=bw, offchain_ms=comp,
                energy_device_mj=device_energy(len(devs), use_bls=True),
                energy_aggr_mj=aggr_energy(len(batch), merkle=True, bls_agg=True),
                num_devices=len(devs), urgent_flush=False, arrival_rate=0,
                notes=f"StorageGas={rx['gasUsed']},BLSEst={GAS_BLS_VERIFY}"))
        except Exception as e:
            print(f"\n  M3 error batch {bid}: {e}")

        if (bid + 1) % CHECKPOINT_INTERVAL == 0:
            ckpt_mgr.save(bid, bid - resume + 1, time.time() - start_t)
            print_progress("batches", bid + 1, total, start_t)

    print()
    ckpt_mgr.clear()
    return writer.summary()


def run_m4(readings, bc, dataset, results_dir, ckpt_dir):
    """M4: Bonawitz privacy masking."""
    method   = "M4_Privacy_Mask"
    ckpt_mgr = CheckpointManager(method, dataset, ckpt_dir)
    ckpt     = ckpt_mgr.load()
    resume   = ckpt['batch_id'] + 1 if ckpt else 0
    contract = bc.contract("PrivacyMaskStorage")
    agg      = bc.accounts[0]
    batches  = [readings[i:i + FIXED_BATCH_SIZE]
                for i in range(0, len(readings), FIXED_BATCH_SIZE)]
    total    = len(batches)
    writer   = ResultsWriter(method, dataset, results_dir, resume)
    start_t  = time.time()

    print(f"\n  [M4] Privacy-Mask on {dataset} | "
          f"{len(readings):,} readings → {total:,} batches")
    if resume > 0:
        print(f"  [M4] Resuming from batch {resume}")

    for bid in range(resume, total):
        batch    = batches[bid]
        t0       = time.perf_counter()
        dev_vals = {}
        for r in batch:
            d = r['device_id']
            dev_vals[d] = dev_vals.get(d, 0) + r['sensor_val']
        seed    = hashlib.sha256(struct.pack(">I", bid) + b"m4seed").digest()
        agg_sum, masked = secure_aggregate(dev_vals, seed)
        leaves  = [struct.pack(">II", d, mv % (2 ** 32))
                   for d, mv in zip(sorted(dev_vals), masked)]
        root    = build_merkle(leaves)
        comp    = (time.perf_counter() - t0) * 1000

        try:
            rx, ms, bw, txh = bc.send(
                contract.functions.commitMaskedBatch(
                    root, int(agg_sum) % (2 ** 256), len(dev_vals), len(batch)),
                agg, gas=200_000)
            writer.write(BatchRecord(
                method=method, dataset=dataset,
                batch_id=bid, batch_size=len(batch),
                tx_hash=txh, gas_used=rx['gasUsed'],
                latency_ms=ms, bandwidth_bytes=bw, offchain_ms=comp,
                energy_device_mj=device_energy(len(dev_vals), use_mask=True),
                energy_aggr_mj=aggr_energy(len(batch), merkle=True, masking=True),
                num_devices=len(dev_vals), urgent_flush=False, arrival_rate=0))
        except Exception as e:
            print(f"\n  M4 error batch {bid}: {e}")

        if (bid + 1) % CHECKPOINT_INTERVAL == 0:
            ckpt_mgr.save(bid, bid - resume + 1, time.time() - start_t)
            print_progress("batches", bid + 1, total, start_t)

    print()
    ckpt_mgr.clear()
    return writer.summary()


def run_m5(readings, bc, dataset, results_dir, ckpt_dir):
    """M5: Hybrid — adaptive + masking + BLS + Merkle (PROPOSED PROTOCOL)."""
    method   = "M5_Hybrid"
    ckpt_mgr = CheckpointManager(method, dataset, ckpt_dir)
    ckpt     = ckpt_mgr.load()
    resume   = ckpt['batch_id'] + 1 if ckpt else 0
    contract = bc.contract("HybridStorage")
    agg_acc  = bc.accounts[0]
    writer   = ResultsWriter(method, dataset, results_dir, resume)

    ewma_rate  = AABF_LAMBDA_BASE
    last_ts    = None
    iats       = deque(maxlen=50)
    buffer     = []
    bid        = 0
    rows_done  = 0
    start_t    = time.time()
    total_rows = len(readings)

    print(f"\n  [M5] Hybrid on {dataset} | {total_rows:,} readings")

    def flush_hybrid(buf, urgent, rate):
        nonlocal bid
        if bid < resume:
            bid += 1
            return
        dev_vals = {}
        for r in buf:
            d = r['device_id']
            dev_vals[d] = dev_vals.get(d, 0) + r['sensor_val']
        seed    = hashlib.sha256(struct.pack(">I", bid) + b"m5seed").digest()
        agg_sum, masked = secure_aggregate(dev_vals, seed)
        batch_msg = hashlib.sha256(seed + struct.pack(">I", bid)).digest()

        sigs, pks = [], []
        for d in sorted(dev_vals):
            sk, pk = DEVICE_KEYS[d % NUM_DEVICES]
            sigs.append(bls_sign(sk, batch_msg))
            pks.append(pk)

        # FIX: bls_aggregate returns 48 bytes, bls_agg_pk returns 96 bytes
        agg_sig = bls_aggregate(sigs)   # 48 bytes
        agg_pk  = bls_agg_pk(pks)       # 96 bytes

        leaves = [struct.pack(">II", d, mv % (2 ** 32))
                  for d, mv in zip(sorted(dev_vals), masked)]
        root   = build_merkle(leaves)

        try:
            rx, ms, bw, txh = bc.send(
                contract.functions.commitHybridBatch(
                    root, agg_sig, agg_pk,
                    int(agg_sum) % (2 ** 256), len(buf), len(dev_vals),
                    int(rate * 1000), urgent),
                agg_acc, gas=500_000)
            writer.write(BatchRecord(
                method=method, dataset=dataset,
                batch_id=bid, batch_size=len(buf),
                tx_hash=txh, gas_used=rx['gasUsed'] + GAS_BLS_VERIFY,
                latency_ms=ms, bandwidth_bytes=bw, offchain_ms=0,
                energy_device_mj=device_energy(len(dev_vals), True, True),
                energy_aggr_mj=aggr_energy(len(buf), True, True, True),
                num_devices=len(dev_vals), urgent_flush=urgent,
                arrival_rate=rate,
                notes=f"StorageGas={rx['gasUsed']},BLSEst={GAS_BLS_VERIFY}"))
        except Exception as e:
            print(f"\n  M5 error batch {bid}: {e}")
        bid += 1
        if bid % CHECKPOINT_INTERVAL == 0:
            ckpt_mgr.save(bid - 1, bid - resume, time.time() - start_t)
            print_progress("rows", rows_done, total_rows, start_t,
                           f"| batches={bid}")

    for r in readings:
        rows_done += 1
        buffer.append(r)
        ts     = r['timestamp']
        jitter = 0.0
        if last_ts is not None:
            iat = max(ts - last_ts, 1e-6)
            iats.append(iat)
            ewma_rate = AABF_ALPHA * (1 / iat) + (1 - AABF_ALPHA) * ewma_rate
            if len(iats) >= 3:
                m = sum(iats) / len(iats)
                v = sum((x - m) ** 2 for x in iats) / len(iats)
                jitter = math.sqrt(v) / (m + 1e-9)
        last_ts = ts
        W = int((AABF_MIN_BATCH + AABF_MAX_BATCH) / 2
                * AABF_LAMBDA_BASE / max(ewma_rate, 0.1))
        W = max(AABF_MIN_BATCH, min(AABF_MAX_BATCH, W))
        urgent = r.get('is_urgent', False)
        if len(buffer) >= W or jitter > AABF_JITTER_THRESH or urgent:
            flush_hybrid(buffer[:], urgent, ewma_rate)
            buffer.clear()

    if buffer:
        flush_hybrid(buffer[:], False, ewma_rate)
    print()
    ckpt_mgr.clear()
    return writer.summary()


# ── Summary helpers ────────────────────────────────────────────
def print_summary_table(summaries, dataset):
    print(f"\n{'=' * 82}")
    print(f"  RESULTS SUMMARY — {dataset}")
    print(f"{'=' * 82}")
    fmt = "  {:<18} {:>10} {:>10} {:>10} {:>10} {:>8}"
    print(fmt.format("Method", "Gas/Rdg", "Lat(ms)", "BW(B/rdg)", "Energy(mJ)", "AvgBatch"))
    print(f"  {'-' * 78}")
    for s in summaries:
        if not s: continue
        print(fmt.format(
            s.get('method', '?')[:18],
            f"{s.get('avg_gas_reading', 0):,.0f}",
            f"{s.get('avg_latency_ms', 0):.2f}",
            f"{s.get('avg_bw_reading', 0):.1f}",
            f"{s.get('avg_energy_reading', 0):.4f}",
            f"{s.get('avg_batch_size', 0):.1f}",
        ))
    print(f"{'=' * 82}\n")

def save_summary_csv(summaries, dataset, results_dir):
    out  = results_dir / f"summary_ALL_{dataset}.csv"
    keys = ["method", "dataset", "total_batches", "total_readings",
            "avg_gas", "avg_gas_reading", "avg_latency_ms", "p95_latency_ms",
            "avg_bw_reading", "avg_energy_reading", "avg_batch_size", "urgent_flushes"]
    with open(out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for s in summaries:
            if s:
                w.writerow({k: s.get(k, '') for k in keys})
    print(f"  [summary] → {out}")
    return out
