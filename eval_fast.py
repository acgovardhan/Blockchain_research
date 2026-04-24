#!/usr/bin/env python3
"""
eval_fast.py — Universal evaluation runner

- Loads *_eval.pkl first, falls back to base processed_*.pkl
- If --rows exceeds dataset size, automatically caps to actual size
- eval_engine.py is unchanged
"""
import sys, pickle, json, argparse
from pathlib import Path
from datetime import datetime

SCRIPT_DIR = Path(__file__).parent
ROOT = SCRIPT_DIR.parent if (SCRIPT_DIR.parent / "config.py").exists() else SCRIPT_DIR
sys.path.insert(0, str(ROOT))

from eval_engine import (
    BlockchainConn, run_m0, run_m1, run_m2, run_m3, run_m4, run_m5,
    print_summary_table, save_summary_csv,
    FORCE_FLUSH_LABELS, HIGH_SEVERITY_LABELS, is_high_severity,
)

parser = argparse.ArgumentParser(description="IoT-Blockchain Evaluation")
parser.add_argument("--dataset",  choices=["IoT23", "TON_IoT", "N-BaIoT"], default="IoT23")
parser.add_argument("--rows",     type=int, default=None,
                    help="Max rows to use (automatically capped to dataset size)")
parser.add_argument("--skip",     nargs="+", default=[],
                    choices=["M0","M1","M2","M3","M4","M5"])
parser.add_argument("--methods",  nargs="+", default=None,
                    choices=["M0","M1","M2","M3","M4","M5"])
args = parser.parse_args()

DATASET        = args.dataset
REQUESTED_ROWS = args.rows
IS_TEST        = REQUESTED_ROWS is not None and REQUESTED_ROWS <= 5000

# NOTE: pkl names must match exactly what preprocess + create_eval write
PKL_MAP = {
    "IoT23": [
        ROOT / "data" / "processed_iot23_eval.pkl",
        ROOT / "data" / "processed_iot23.pkl",
    ],
    "TON_IoT": [
        ROOT / "data" / "processed_ton_iot_eval.pkl",
        ROOT / "data" / "processed_ton_iot.pkl",
    ],
    "N-BaIoT": [
        ROOT / "data" / "processed_nbaiot_eval.pkl",
        ROOT / "data" / "processed_nbaiot.pkl",
    ],
}

ADDR_FILE   = ROOT / "deployed_addresses.json"
ABI_FILE    = ROOT / "contract_abis.json"
RESULTS_DIR = ROOT / "results" / DATASET
CKPT_DIR    = ROOT / "checkpoints" / DATASET

# ── Find PKL ──────────────────────────────────────────────────
pkl_path = None
for candidate in PKL_MAP[DATASET]:
    if candidate.exists():
        pkl_path = candidate
        break

if pkl_path is None:
    print(f"\nERROR: No preprocessed data found for {DATASET}.")
    fix = {
        "IoT23":   "python scripts/preprocess_iot23.py\n  python scripts/create_eval_iot23.py",
        "TON_IoT": "python scripts/preprocess_ton_iot.py\n  python scripts/create_eval_ton_iot.py",
        "N-BaIoT": "python scripts/preprocess_nbaiot.py\n  python scripts/create_eval_nbaiot.py",
    }
    print(f"Run:\n  {fix[DATASET]}")
    sys.exit(1)

# ── Load & cap rows ───────────────────────────────────────────
print(f"\n{'='*64}")
print(f"  {DATASET} Evaluation")
print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'='*64}")

with open(pkl_path, "rb") as f:
    all_readings = pickle.load(f)

if not isinstance(all_readings, list):
    raise TypeError(f"Expected list in {pkl_path}, got {type(all_readings).__name__}")

actual_rows = len(all_readings)

# Cap --rows to actual dataset size — never crash, never silently use less
if REQUESTED_ROWS is None:
    use_rows = actual_rows
else:
    use_rows = min(REQUESTED_ROWS, actual_rows)

readings = all_readings[:use_rows]

print(f"\n  PKL file:  {pkl_path.name}")
print(f"  Available: {actual_rows:,} readings")
if REQUESTED_ROWS is not None and REQUESTED_ROWS > actual_rows:
    print(f"  Requested: {REQUESTED_ROWS:,}  →  capped to {actual_rows:,}")
print(f"  Using:     {len(readings):,} readings")

# ── Dataset stats ─────────────────────────────────────────────
benign = sum(1 for r in readings if str(r.get("label", "")).lower() == "benign")
force  = sum(1 for r in readings if any(
    s in str(r.get("detailed_label", "")).lower() for s in FORCE_FLUSH_LABELS
))
high   = sum(1 for r in readings if is_high_severity(r))

print(f"  Benign:          {benign:,} ({100*benign/max(1,len(readings)):.1f}%)")
print(f"  Malicious:       {len(readings)-benign:,} ({100*(len(readings)-benign)/max(1,len(readings)):.1f}%)")
print(f"  Force-flush:     {force:,} ({100*force/max(1,len(readings)):.1f}%)")
print(f"  High-severity:   {high:,} ({100*high/max(1,len(readings)):.1f}%)")

if force > len(readings) * 0.5:
    print(f"\n  WARNING: {100*force/len(readings):.0f}% of readings are force-flush.")
    print(f"  M2/M5 avg_batch will be close to 1.0 — this is expected.")

# ── Blockchain ────────────────────────────────────────────────
if not ADDR_FILE.exists():
    print("\nERROR: deployed_addresses.json not found.")
    print("Run: python scripts/deploy_contracts.py")
    sys.exit(1)

with open(ADDR_FILE) as f: addresses = json.load(f)
with open(ABI_FILE)  as f: abis      = json.load(f)

bc = BlockchainConn(addresses, abis)
print(f"\n  Ganache: chain_id={bc.w3.eth.chain_id} | "
      f"PoA validator: {bc.accounts[0][:12]}... | "
      f"Accounts: {len(bc.accounts)}")

try:
    registry  = bc.contract("ValidatorRegistry")
    is_val    = registry.functions.isValidator(bc.accounts[0]).call()
    val_count = registry.functions.validatorCount().call()
    print(f"  PoA: accounts[0] is validator = {is_val} | Total = {val_count}")
    if not is_val:
        print("  ERROR: accounts[0] is NOT a registered validator!")
        print("  Re-run: python scripts/deploy_contracts.py")
        sys.exit(1)
except Exception as e:
    print(f"  PoA check skipped: {e}")

# ── Select methods ────────────────────────────────────────────
all_methods = ["M0", "M1", "M2", "M3", "M4", "M5"]
run_methods = args.methods if args.methods else [m for m in all_methods if m not in args.skip]

print(f"\n  Methods to run: {run_methods}")
if IS_TEST:
    m0_est = max(1, len(readings) // 35)
    print(f"  Est. test time: ~{m0_est + len(run_methods) * 3}s")

print(f"\n{'='*64}")
print("  NOTE: Only M5 uses PoA (onlyValidator). M0–M4 are open baselines.")
print(f"{'='*64}\n")

# ── Run ───────────────────────────────────────────────────────
summaries = []
fn_map = {
    "M0": run_m0, "M1": run_m1, "M2": run_m2,
    "M3": run_m3, "M4": run_m4, "M5": run_m5,
}

for m in run_methods:
    # pass max_rows=None — readings is already sliced above
    s = fn_map[m](readings, bc, DATASET, RESULTS_DIR, CKPT_DIR, max_rows=None)
    summaries.append(s)
    if s:
        extra = (
            f"avg_batch={s.get('avg_batch_size', 0):.1f}, urgent={s.get('urgent_flushes', 0)}"
            if m in ("M2", "M5")
            else f"gas/rdg={s.get('avg_gas_reading', 0):,.0f}"
        )
        print(f"  {m} complete: {extra}")

# ── Summary ───────────────────────────────────────────────────
if summaries:
    print_summary_table(summaries, DATASET)
    save_summary_csv(summaries, DATASET, RESULTS_DIR)
    print(f"\n{'='*64}")
    print(f"  COMPLETE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Results:  {RESULTS_DIR}")
    if IS_TEST:
        print(f"\n  Test passed! Full run:")
        print(f"  python eval_fast.py --dataset {DATASET}")
    else:
        print("\n  Next: python generate_figures_all.py")
    print(f"{'='*64}\n")