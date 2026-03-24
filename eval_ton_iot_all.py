#!/usr/bin/env python3
"""
eval_ton_iot_all.py — Full TON_IoT dataset, all 6 methods, checkpoint-safe
===========================================================================
Estimated runtime on full TON_IoT (~460,000 rows):
  M0: ~7 hours     M1: ~25 min   M2: ~30 min   M3: ~25 min
  M4: ~25 min      M5: ~35 min
  TOTAL: ~9.5 hours

OVERNIGHT USAGE:
  Start before sleeping:   python eval_ton_iot_all.py
  Check next morning:      results/TON_IoT/summary_ALL_TON_IoT.csv

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

DATASET     = "TON_IoT"
PKL_PATH    = ROOT / "data"        / "processed_ton_iot.pkl"
ADDR_FILE   = ROOT / "deployed_addresses.json"
ABI_FILE    = ROOT / "contract_abis.json"
RESULTS_DIR = ROOT / "results"     / DATASET
CKPT_DIR    = ROOT / "checkpoints" / DATASET

print(f"\n{'='*60}")
print(f"  TON_IoT FULL DATASET — All 6 Methods")
print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'='*60}")

if not PKL_PATH.exists():
    print(f"ERROR: {PKL_PATH} not found.")
    print("Run: python scripts/01b_preprocess_ton_iot.py")
    sys.exit(1)

with open(PKL_PATH,'rb') as f:
    readings = pickle.load(f)

print(f"  Total readings: {len(readings):,}")
urgent = sum(1 for r in readings if r.get('is_urgent',False))
print(f"  Urgent: {urgent} ({100*urgent/len(readings):.1f}%)")
attacks = Counter(r.get('detailed_label','?')
                  for r in readings if r.get('label','')=='Malicious')
print(f"  Attack types: {dict(attacks.most_common(5))}")

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
