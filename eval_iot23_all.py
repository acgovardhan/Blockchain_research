#!/usr/bin/env python3
"""
eval_iot23_all.py — Full IoT-23 dataset, all 6 methods, checkpoint-safe
========================================================================
Estimated runtime on full IoT-23 (~156,000 rows):
  M0: ~2.5 hours   M1: ~8 min   M2: ~10 min   M3: ~10 min
  M4: ~8 min       M5: ~12 min
  TOTAL: ~3.5 hours

OVERNIGHT USAGE:
  Start before sleeping:   python eval_iot23_all.py
  Check in the morning:    results/IoT23/summary_ALL_IoT23.csv

If interrupted (power cut, crash), just re-run the same command.
Checkpoints are saved every 50 batches — progress is not lost.
"""

import sys, pickle, json
from pathlib import Path
from datetime import datetime

SCRIPT_DIR = Path(__file__).parent
ROOT       = SCRIPT_DIR.parent if (SCRIPT_DIR.parent / "config.py").exists() \
             else SCRIPT_DIR
sys.path.insert(0, str(ROOT))

from eval_engine import (
    BlockchainConn,
    run_m0, run_m1, run_m2, run_m3, run_m4, run_m5,
    print_summary_table, save_summary_csv
)

DATASET      = "IoT23"
PKL_PATH     = ROOT / "data"        / "processed_iot23.pkl"
ADDR_FILE    = ROOT / "deployed_addresses.json"
ABI_FILE     = ROOT / "contract_abis.json"
RESULTS_DIR  = ROOT / "results"     / DATASET
CKPT_DIR     = ROOT / "checkpoints" / DATASET

print(f"\n{'='*60}")
print(f"  IoT-23 FULL DATASET — All 6 Methods")
print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'='*60}")

if not PKL_PATH.exists():
    print(f"ERROR: {PKL_PATH} not found.")
    print("Run: python scripts/01_preprocess_iot23.py")
    sys.exit(1)

with open(PKL_PATH,'rb') as f:
    readings = pickle.load(f)

print(f"  Total readings loaded: {len(readings):,}")
urgent = sum(1 for r in readings if r.get('is_urgent',False))
print(f"  Urgent readings: {urgent} ({100*urgent/len(readings):.1f}%)")

with open(ADDR_FILE) as f: addresses = json.load(f)
with open(ABI_FILE)  as f: abis      = json.load(f)
bc = BlockchainConn(addresses, abis)
print(f"  Ganache: {bc.w3.eth.chain_id} | Validator: {bc.accounts[0][:10]}...")

summaries = []

# ── M0: run overnight — the slow one ──────────────────────────
print("\n  NOTE: M0 will take ~2.5 hours. Leave running overnight.")
s = run_m0(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)

# ── M1–M5: fast, should finish in ~1 hour total ───────────────
s = run_m1(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)

s = run_m2(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)

s = run_m3(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)

s = run_m4(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)

s = run_m5(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)

print_summary_table(summaries, DATASET)
save_summary_csv(summaries, DATASET, RESULTS_DIR)

print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  Results: {RESULTS_DIR}\n")
