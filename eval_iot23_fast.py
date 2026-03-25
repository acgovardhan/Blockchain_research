#!/usr/bin/env python3
"""
eval_iot23_fast.py — Fast IoT-23 Evaluation (20,000 rows, all 6 methods)
=========================================================================
Estimated runtime: 20–35 minutes total

PRE-REQUISITES (run once in order):
  1. python scripts/00_deploy_contracts.py     (deploy to Ganache)
  2. python scripts/01_preprocess_iot23.py     (create processed_iot23.pkl)
  3. python scripts/02_create_eval_dataset.py  (create 20k balanced dataset)
  4. python eval_iot23_fast.py                 (THIS SCRIPT)

ESTIMATED TIMES (20,000 rows):
  M0 Baseline:       ~8–12 min  (20,000 individual transactions)
  M1 MerkleOnly:     ~1–2 min   (1,000 batches)
  M2 AABF+:          ~3–5 min   (~1,500 adaptive batches)
  M3 BLS-Only:       ~1–2 min   (1,000 batches)
  M4 Privacy-Mask:   ~1–2 min   (1,000 batches)
  M5 Hybrid:         ~3–5 min   (~1,500 adaptive batches)
  TOTAL:             ~20–30 min

OUTPUTS:
  results/IoT23/metrics_M{0-5}_*.csv   — per-batch metrics
  results/IoT23/summary_ALL_IoT23.csv  — summary table
  
  Then run: python generate_figures_all.py
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
# Use balanced eval dataset if available, else fall back to full pkl
EVAL_PKL     = ROOT / "data" / "processed_iot23_eval.pkl"
FALLBACK_PKL = ROOT / "data" / "processed_iot23.pkl"
ADDR_FILE    = ROOT / "deployed_addresses.json"
ABI_FILE     = ROOT / "contract_abis.json"
RESULTS_DIR  = ROOT / "results"     / DATASET
CKPT_DIR     = ROOT / "checkpoints" / DATASET

print(f"\n{'=' * 60}")
print(f"  IoT-23 FAST EVALUATION — All 6 Methods")
print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'=' * 60}")

# ── Load dataset ───────────────────────────────────────────────
if EVAL_PKL.exists():
    pkl_path = EVAL_PKL
    print(f"\n  Using balanced eval dataset: {EVAL_PKL.name}")
elif FALLBACK_PKL.exists():
    pkl_path = FALLBACK_PKL
    print(f"\n  WARNING: Balanced dataset not found.")
    print(f"  Using full pkl: {FALLBACK_PKL.name}")
    print(f"  STRONGLY RECOMMENDED: Run scripts/02_create_eval_dataset.py first!")
    print(f"  (Without it, M2/M5 may take 20+ hours due to all-urgent data)")
else:
    print(f"\n  ERROR: No dataset found.")
    print(f"  Run: python scripts/01_preprocess_iot23.py")
    print(f"  Then: python scripts/02_create_eval_dataset.py")
    sys.exit(1)

with open(pkl_path, 'rb') as f:
    readings = pickle.load(f)

print(f"\n  Total readings loaded: {len(readings):,}")
urgent  = sum(1 for r in readings if r.get('is_urgent', False))
benign  = sum(1 for r in readings if r.get('label', '') == 'benign')
mal     = len(readings) - benign
print(f"  Benign:          {benign:,} ({100*benign/len(readings):.1f}%)")
print(f"  Malicious:       {mal:,} ({100*mal/len(readings):.1f}%)")
print(f"  Urgent readings: {urgent:,} ({100*urgent/len(readings):.1f}%)")

if urgent > len(readings) * 0.20:
    print(f"\n  ⚠  WARNING: {100*urgent/len(readings):.0f}% of readings are urgent.")
    print(f"     M2/M5 will flush each urgent reading individually.")
    print(f"     This will significantly increase M2/M5 runtime.")
    print(f"     Run scripts/02_create_eval_dataset.py for a balanced dataset.")
    ans = input("  Continue anyway? [y/N]: ").strip().lower()
    if ans != 'y':
        print("  Aborted. Run: python scripts/02_create_eval_dataset.py")
        sys.exit(0)

# ── Connect to blockchain ──────────────────────────────────────
if not ADDR_FILE.exists():
    print(f"\n  ERROR: {ADDR_FILE} not found.")
    print(f"  Run: python scripts/00_deploy_contracts.py")
    sys.exit(1)

with open(ADDR_FILE) as f:
    addresses = json.load(f)
with open(ABI_FILE) as f:
    abis = json.load(f)

bc = BlockchainConn(addresses, abis)
print(f"\n  Ganache: chain_id={bc.w3.eth.chain_id} | "
      f"Validator: {bc.accounts[0][:10]}... | "
      f"Accounts: {len(bc.accounts)}")

print(f"\n{'=' * 60}")
print(f"  Starting evaluation — estimated 20–35 minutes")
print(f"  Progress is checkpointed every 50 batches.")
print(f"  Safe to Ctrl+C and re-run — will resume from checkpoint.")
print(f"{'=' * 60}")

summaries = []

# ── M0: Baseline ───────────────────────────────────────────────
print(f"\n  [INFO] M0 sends 1 tx per reading — will take ~8-12 min for 20k rows")
s = run_m0(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)
if s:
    print(f"  ✓ M0 complete: {s['total_readings']:,} readings, "
          f"avg gas/reading: {s['avg_gas_reading']:,.0f}")

# ── M1: Merkle-Only ────────────────────────────────────────────
s = run_m1(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)
if s:
    print(f"  ✓ M1 complete: {s['total_batches']:,} batches, "
          f"avg gas/reading: {s['avg_gas_reading']:,.0f}")

# ── M2: AABF+ ─────────────────────────────────────────────────
s = run_m2(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)
if s:
    print(f"  ✓ M2 complete: {s['total_batches']:,} batches, "
          f"avg batch size: {s['avg_batch_size']:.1f}, "
          f"urgent: {s['urgent_flushes']}")

# ── M3: BLS-Only ───────────────────────────────────────────────
s = run_m3(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)
if s:
    print(f"  ✓ M3 complete: {s['total_batches']:,} batches, "
          f"avg gas/reading: {s['avg_gas_reading']:,.0f}")

# ── M4: Privacy-Mask ──────────────────────────────────────────
s = run_m4(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)
if s:
    print(f"  ✓ M4 complete: {s['total_batches']:,} batches, "
          f"avg gas/reading: {s['avg_gas_reading']:,.0f}")

# ── M5: Hybrid (Proposed) ─────────────────────────────────────
s = run_m5(readings, bc, DATASET, RESULTS_DIR, CKPT_DIR)
summaries.append(s)
if s:
    print(f"  ✓ M5 complete: {s['total_batches']:,} batches, "
          f"avg batch size: {s['avg_batch_size']:.1f}, "
          f"urgent: {s['urgent_flushes']}")

# ── Results ────────────────────────────────────────────────────
print_summary_table(summaries, DATASET)
out = save_summary_csv(summaries, DATASET, RESULTS_DIR)

print(f"\n{'=' * 60}")
print(f"  EVALUATION COMPLETE")
print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  Results:  {RESULTS_DIR}")
print(f"  Summary:  {out}")
print(f"\n  Next: python generate_figures_all.py")
print(f"{'=' * 60}\n")
