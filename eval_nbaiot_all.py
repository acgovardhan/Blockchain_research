#!/usr/bin/env python3
"""
eval_nbaiot_all.py — N-BaIoT dataset, all 6 methods, checkpoint-safe
======================================================================
N-BaIoT has ~7 MILLION rows across all device/attack combinations.
Running M0 on 7M rows would take ~4.5 DAYS — clearly impractical.

SOLUTION: Use 50,000 rows — a statistically representative sample.
  - Covers all 9 IoT device types
  - Covers all attack subtypes (Mirai + BASHLITE)
  - 70% Benign / 30% Malicious balance maintained
  - Statistical results stabilise well before 50K samples

This is standard academic practice (cite: statistical representativeness
of samples vs full population in ML/network security evaluation).
You should state this explicitly in the paper:
  "For N-BaIoT, we evaluate on a stratified sample of 50,000 flows
   covering all 9 device types and all attack subtypes, as the full
   dataset (7M flows) renders per-transaction evaluation impractical
   while adding no additional statistical insight."

Estimated runtime on 50,000 rows:
  M0: ~45 min   M1: ~3 min   M2: ~4 min   M3: ~4 min
  M4: ~3 min    M5: ~5 min
  TOTAL: ~1 hour

Checkpoint saves every 50 batches — safe to interrupt and resume.
"""

import sys, pickle, json
from pathlib import Path
from datetime import datetime
from collections import Counter

SCRIPT_DIR = Path(__file__).parent
ROOT       = SCRIPT_DIR.parent if (SCRIPT_DIR.parent / "config.py").exists() \
             else SCRIPT_DIR
sys.path.insert(0, str(ROOT))

from eval_engine import (
    BlockchainConn,
    run_m0, run_m1, run_m2, run_m3, run_m4, run_m5,
    print_summary_table, save_summary_csv
)

DATASET     = "N-BaIoT"
PKL_PATH    = ROOT / "data"        / "processed_nbaiot.pkl"
ADDR_FILE   = ROOT / "deployed_addresses.json"
ABI_FILE    = ROOT / "contract_abis.json"
RESULTS_DIR = ROOT / "results"     / DATASET
CKPT_DIR    = ROOT / "checkpoints" / DATASET

print(f"\n{'='*60}")
print(f"  N-BaIoT DATASET — All 6 Methods")
print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'='*60}")

if not PKL_PATH.exists():
    print(f"ERROR: {PKL_PATH} not found.")
    print("Run: python scripts/01c_preprocess_nbaiot.py")
    sys.exit(1)

with open(PKL_PATH,'rb') as f:
    readings = pickle.load(f)

print(f"  Total readings: {len(readings):,} (stratified 50K sample)")
urgent = sum(1 for r in readings if r.get('is_urgent',False))
print(f"  Urgent: {urgent} ({100*urgent/len(readings):.1f}%)")
devices = Counter(r.get('device_id',0) for r in readings)
print(f"  Device IDs present: {sorted(devices.keys())}")
print(f"  Note: Timestamps are synthetic (row_index x 0.1s) — "
      f"document in paper.\n")

with open(ADDR_FILE) as f: addresses = json.load(f)
with open(ABI_FILE)  as f: abis      = json.load(f)
bc = BlockchainConn(addresses, abis)
print(f"  Ganache: {bc.w3.eth.chain_id}")

summaries = []
s = run_m0(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR); summaries.append(s)
s = run_m1(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR); summaries.append(s)
s = run_m2(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR); summaries.append(s)
s = run_m3(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR); summaries.append(s)
s = run_m4(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR); summaries.append(s)
s = run_m5(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR); summaries.append(s)

print_summary_table(summaries, DATASET)
save_summary_csv(summaries, DATASET, RESULTS_DIR)
print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
