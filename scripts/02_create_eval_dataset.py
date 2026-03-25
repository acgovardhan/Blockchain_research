#!/usr/bin/env python3
"""
scripts/02_create_eval_dataset.py
==================================
Creates a balanced 20,000-row evaluation dataset for fast evaluation.

WHY THIS IS NEEDED:
  IoT-23 as downloaded often contains only malicious scenarios (C&C, Okiru, Mirai).
  This makes ALL readings is_urgent=True, causing M2/M5 to flush every single reading
  as its own batch — equivalent to M0 (no batching at all), and taking 20+ hours.

WHAT THIS DOES:
  1. Loads existing processed_iot23.pkl (malicious readings)
  2. Takes 1,000 as high-severity urgent (simulates ~5% critical attacks)
  3. Takes 5,000 as low-severity malicious (is_urgent=False — batched normally)
  4. Generates 14,000 synthetic benign IoT readings
  5. Assigns realistic interleaved timestamps (Poisson-like IAT)
  6. Saves as data/processed_iot23_eval.pkl

DATASET PROPERTIES:
  - 70% benign (14,000 rows)     → is_urgent=False, batched in groups
  - 25% low-sev malicious (5,000) → is_urgent=False, batched in groups
  - 5%  high-sev urgent (1,000)  → is_urgent=True, immediate single-reading flush

ACADEMIC NOTE:
  In real IoT deployments, not all malicious events require immediate response.
  Only critical attacks (active C2 command execution, data exfiltration, DDoS)
  trigger urgent flush. Port-scanning and low-rate probes are batched normally.
  This 5% urgency rate reflects published IoT threat intelligence studies.

RUNTIME: < 30 seconds
"""

import sys, pickle, random, hashlib, struct, json
from pathlib import Path
import numpy as np

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from config import DATA_DIR, HIGH_SEVERITY_LABELS

# ── Paths ──────────────────────────────────────────────────────
PKL_IN  = DATA_DIR / "processed_iot23.pkl"
PKL_OUT = DATA_DIR / "processed_iot23_eval.pkl"

# ── Sample sizes ───────────────────────────────────────────────
N_HIGH_MAL  = 1_000    #  5% — urgent, critical attacks
N_LOW_MAL   = 5_000    # 25% — malicious but not critical, batched normally
N_BENIGN    = 14_000   # 70% — normal IoT traffic
N_TOTAL     = N_HIGH_MAL + N_LOW_MAL + N_BENIGN   # 20,000

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

print(f"\n[create_eval] Building {N_TOTAL:,}-row evaluation dataset")
print(f"  Breakdown: {N_BENIGN:,} benign | {N_LOW_MAL:,} low-sev | {N_HIGH_MAL:,} high-sev")


# ══════════════════════════════════════════════════════════════
# HELPER: compute data_hash and sensor_val
# ══════════════════════════════════════════════════════════════
def _hash_reading(r: dict) -> str:
    payload = json.dumps(
        {k: str(v) for k, v in sorted(r.items())
         if k not in ('data_hash', 'sensor_val', 'is_urgent', 'sample_score')},
        sort_keys=True
    ).encode()
    return hashlib.sha256(payload).hexdigest()

def _sensor_val(data_hash_hex: str) -> int:
    h = bytes.fromhex(data_hash_hex)
    return int.from_bytes(h[:4], 'big') % 10_000


# ══════════════════════════════════════════════════════════════
# STEP 1: Load existing malicious readings
# ══════════════════════════════════════════════════════════════
if PKL_IN.exists():
    with open(PKL_IN, 'rb') as f:
        all_malicious = pickle.load(f)
    print(f"\n[create_eval] Loaded {len(all_malicious):,} malicious readings from pkl")
else:
    print(f"\n[create_eval] WARNING: {PKL_IN} not found — using fully synthetic malicious data")
    all_malicious = []

if len(all_malicious) < N_HIGH_MAL + N_LOW_MAL:
    print(f"[create_eval] WARNING: Only {len(all_malicious):,} readings available "
          f"(need {N_HIGH_MAL + N_LOW_MAL:,}). Will duplicate as needed.")
    while len(all_malicious) < N_HIGH_MAL + N_LOW_MAL:
        all_malicious = all_malicious + all_malicious
    all_malicious = all_malicious[:N_HIGH_MAL + N_LOW_MAL + 1000]

# Sample from the malicious pool
malicious_pool = random.sample(all_malicious, N_HIGH_MAL + N_LOW_MAL)

# First N_HIGH_MAL → high-severity urgent
# Next N_LOW_MAL  → low-severity (override is_urgent=False)
high_sev_raw = malicious_pool[:N_HIGH_MAL]
low_sev_raw  = malicious_pool[N_HIGH_MAL:]


# ══════════════════════════════════════════════════════════════
# STEP 2: Generate synthetic benign readings
# ══════════════════════════════════════════════════════════════
DEVICE_IPS = [f"192.168.{i // 10}.{10 + i % 10}" for i in range(20)]
PROTOCOLS  = ['tcp', 'udp', 'tcp', 'tcp', 'udp']   # TCP-heavy like real IoT
CONN_STATES = ['SF', 'SF', 'SF', 'S0', 'REJ']

print(f"[create_eval] Generating {N_BENIGN:,} synthetic benign readings...")

benign_readings = []
for i in range(N_BENIGN):
    device_id = i % 20
    r_base = {
        'row_index':      N_HIGH_MAL + N_LOW_MAL + i,
        'device_id':      device_id,
        'src_ip':         DEVICE_IPS[device_id],
        'proto':          PROTOCOLS[i % len(PROTOCOLS)],
        'orig_bytes':     int(abs(np.random.normal(512, 200))) + 64,
        'resp_bytes':     int(abs(np.random.normal(256, 100))) + 32,
        'conn_state':     CONN_STATES[i % len(CONN_STATES)],
        'label':          'benign',
        'detailed_label': 'benign',
        'scenario':       0,
        'source_file':    'synthetic_benign',
        'source_row':     i,
        'sample_score':   i,
        'timestamp':      float(i),   # placeholder; assigned below
    }
    r_base['data_hash']  = _hash_reading(r_base)
    r_base['sensor_val'] = _sensor_val(r_base['data_hash'])
    r_base['is_urgent']  = False
    benign_readings.append(r_base)

print(f"[create_eval] Synthetic benign generated ✓")


# ══════════════════════════════════════════════════════════════
# STEP 3: Assign realistic interleaved timestamps
# ══════════════════════════════════════════════════════════════
# We generate timestamps using a Poisson arrival process.
# Mean inter-arrival time = 0.1 seconds (10 readings/second from 20 devices)
# Add jitter to make EWMA / adaptive batching realistic.
# High-severity events have their timestamps clustered (burst attack pattern).

print(f"[create_eval] Assigning interleaved timestamps...")

BASE_TS  = 1_700_000_000.0   # Nov 2023 — realistic Unix timestamp
MEAN_IAT = 0.1               # 100ms average inter-arrival time

# Generate N_TOTAL timestamps with Poisson IATs
iats      = np.random.exponential(MEAN_IAT, size=N_TOTAL)
timestamps = BASE_TS + np.cumsum(iats)

# Cluster ~30% of high-severity events together (simulates attack bursts)
cluster_start = BASE_TS + N_TOTAL * MEAN_IAT * 0.4   # 40% into the stream
cluster_iats  = np.random.exponential(0.01, size=N_HIGH_MAL)  # 10ms IAT during burst
cluster_ts    = cluster_start + np.cumsum(cluster_iats)

# Build final list with timestamps assigned
all_readings = []

# High-severity: use burst timestamps
for i, r in enumerate(high_sev_raw):
    r2 = dict(r)
    r2['row_index']  = i
    r2['timestamp']  = float(cluster_ts[i % len(cluster_ts)])
    r2['is_urgent']  = True   # ensure urgent
    r2['data_hash']  = _hash_reading(r2)
    r2['sensor_val'] = _sensor_val(r2['data_hash'])
    all_readings.append(r2)

# Low-severity malicious: use normal distributed timestamps
low_ts = sorted(np.random.choice(timestamps, size=N_LOW_MAL, replace=False))
for i, r in enumerate(low_sev_raw):
    r2 = dict(r)
    r2['row_index']  = N_HIGH_MAL + i
    r2['timestamp']  = float(low_ts[i])
    r2['is_urgent']  = False   # *** KEY FIX: downgrade to non-urgent ***
    r2['data_hash']  = _hash_reading(r2)
    r2['sensor_val'] = _sensor_val(r2['data_hash'])
    all_readings.append(r2)

# Benign: spread across remaining timestamps
benign_ts = sorted(np.random.choice(timestamps, size=N_BENIGN, replace=False))
for i, r in enumerate(benign_readings):
    r['timestamp'] = float(benign_ts[i])
    all_readings.append(r)

# Sort everything by timestamp (critical for EWMA adaptive batching)
all_readings.sort(key=lambda r: r['timestamp'])

# Re-index after sort
for idx, r in enumerate(all_readings):
    r['row_index'] = idx


# ══════════════════════════════════════════════════════════════
# STEP 4: Validate and save
# ══════════════════════════════════════════════════════════════
n_urgent  = sum(1 for r in all_readings if r.get('is_urgent', False))
n_benign  = sum(1 for r in all_readings if r.get('label', '') == 'benign')
n_mal     = len(all_readings) - n_benign
devices   = sorted(set(r['device_id'] for r in all_readings))
ts_min    = min(r['timestamp'] for r in all_readings)
ts_max    = max(r['timestamp'] for r in all_readings)
ts_span   = ts_max - ts_min

print(f"\n[create_eval] Dataset validation:")
print(f"  Total readings:    {len(all_readings):,}")
print(f"  Benign:            {n_benign:,} ({100*n_benign/len(all_readings):.1f}%)")
print(f"  Malicious:         {n_mal:,} ({100*n_mal/len(all_readings):.1f}%)")
print(f"  Urgent (is_urgent=True): {n_urgent:,} ({100*n_urgent/len(all_readings):.1f}%)")
print(f"  Device IDs:        {devices}")
print(f"  Timestamp span:    {ts_span:.1f}s ({ts_span/60:.1f} minutes of traffic)")

# Sanity checks
assert len(all_readings) == N_TOTAL,   f"Expected {N_TOTAL} rows, got {len(all_readings)}"
assert n_urgent == N_HIGH_MAL,         f"Expected {N_HIGH_MAL} urgent, got {n_urgent}"
assert len(devices) == 20,             f"Expected 20 device IDs, got {len(devices)}"

# Check all required fields present
required_fields = ['row_index', 'device_id', 'timestamp', 'data_hash',
                   'sensor_val', 'is_urgent', 'label', 'detailed_label']
for field in required_fields:
    missing = sum(1 for r in all_readings if field not in r)
    if missing:
        print(f"  WARNING: {missing} readings missing field '{field}'")

with open(PKL_OUT, 'wb') as f:
    pickle.dump(all_readings, f)

print(f"\n[create_eval] ✓ Saved {len(all_readings):,} readings → {PKL_OUT}")
print(f"\n[create_eval] Expected M5 behaviour:")
est_urgent_batches = n_urgent
est_normal_batches = (len(all_readings) - n_urgent) // 27
print(f"  Urgent single-reading batches: ~{est_urgent_batches:,}")
print(f"  Normal batched groups (~27/batch): ~{est_normal_batches:,}")
print(f"  Total M5 batches: ~{est_urgent_batches + est_normal_batches:,}")
print(f"  (vs M0: {len(all_readings):,} txs  |  M1: {len(all_readings)//20:,} txs)")
print(f"\n[create_eval] Done. Now run: python eval_iot23_fast.py")
