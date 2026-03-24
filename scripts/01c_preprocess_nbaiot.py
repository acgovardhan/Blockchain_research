#!/usr/bin/env python3
"""
scripts/01c_preprocess_nbaiot.py
Preprocesses the N-BaIoT dataset (50,000 stratified rows).
Place all downloaded CSV files in: data/nbaiot/
Download: https://www.kaggle.com/datasets/mkashifn/nbaiot-dataset
"""
import sys, pickle, glob
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import DATA_DIR, EVAL_ROWS_NBAIOT, HIGH_SEVERITY_LABELS
from utils.metrics import reading_to_hash, hash_to_int

import pandas as pd
import numpy as np

NBAIOT_DIR = DATA_DIR / "nbaiot"
OUTPUT_PKL = DATA_DIR / "processed_nbaiot.pkl"
EVAL_ROWS  = EVAL_ROWS_NBAIOT   # 50,000

if not NBAIOT_DIR.exists() or not list(NBAIOT_DIR.glob("*.csv")):
    print(f"ERROR: No CSV files found in {NBAIOT_DIR}")
    print("Download from: https://www.kaggle.com/datasets/mkashifn/nbaiot-dataset")
    print("Create folder data/nbaiot/ and place ALL CSV files inside it (flat, no sub-folders).")
    sys.exit(1)

files = sorted(NBAIOT_DIR.glob("*.csv"))
print(f"[N-BaIoT] Merging {len(files)} CSV files from {NBAIOT_DIR} ...")

frames = []
for fpath in files:
    try:
        tmp   = pd.read_csv(fpath, low_memory=False)
        fname = fpath.stem.lower().replace('-','_')
        if 'benign' in fname:
            tmp['label']       = 'Benign'
            tmp['attack_type'] = 'benign'
        else:
            tmp['label']       = 'Malicious'
            parts = fname.split('_')
            tmp['attack_type'] = '_'.join(parts[1:]) if len(parts) > 1 else fname
        dev_name = fname.split('.')[0] if '.' in fname else fname.split('_')[0]
        tmp['device_id_raw'] = abs(hash(dev_name)) % 20
        frames.append(tmp)
        print(f"  Loaded {len(tmp):,} rows from {fpath.name}")
    except Exception as e:
        print(f"  Skipping {fpath.name}: {e}")

df = pd.concat(frames, ignore_index=True)
print(f"[N-BaIoT] Merged total: {len(df):,} rows")

# Synthetic timestamps (N-BaIoT has no real timestamps)
df['timestamp'] = df.index.astype(float) * 0.1
df['src_ip']    = '192.168.1.' + df['device_id_raw'].astype(str)

# Use sum of first 5 numeric features as sensor proxy
numeric_cols = df.select_dtypes(include=[np.number]).columns
numeric_cols = [c for c in numeric_cols if c not in ['device_id_raw']][:5]
if numeric_cols:
    df['sensor_proxy'] = df[numeric_cols].sum(axis=1).abs()
else:
    df['sensor_proxy'] = df.index.astype(float)

# Rebalance 70/30 — take exactly EVAL_ROWS total
benign    = df[df['label'] == 'Benign']
malicious = df[df['label'] == 'Malicious']
n_b = min(len(benign),    int(EVAL_ROWS * 0.70))
n_m = min(len(malicious), int(EVAL_ROWS * 0.30))
df  = pd.concat([
    benign.sample(n=n_b,    random_state=42),
    malicious.sample(n=n_m, random_state=42)
]).sample(frac=1, random_state=42).reset_index(drop=True)
print(f"[N-BaIoT] Sample: {n_b:,} Benign + {n_m:,} Malicious = {len(df):,} rows")
print("[N-BaIoT] Note: timestamps are SYNTHETIC. M2/M5 adaptive batching")
print("          will use even arrival rates. Document this in the paper.")

readings = []
for idx, row in df.iterrows():
    attack = str(row.get('attack_type','-')).strip().lower()
    r = {
        'row_index': idx,
        'device_id': int(row.get('device_id_raw', idx % 20)),
        'timestamp': float(row['timestamp']),
        'src_ip':    str(row.get('src_ip','192.168.1.0')),
        'proto':     'tcp',
        'orig_bytes':int(abs(row.get('sensor_proxy',0)) % 65536),
        'resp_bytes':0,
        'conn_state':'SF',
        'label':     str(row['label']),
        'detailed_label': attack,
    }
    r['data_hash']  = reading_to_hash(r).hex()
    r['sensor_val'] = hash_to_int(bytes.fromhex(r['data_hash']), max_val=10_000)
    r['is_urgent']  = any(s in attack for s in HIGH_SEVERITY_LABELS)
    readings.append(r)

with open(OUTPUT_PKL,'wb') as f:
    pickle.dump(readings, f)

urgent = sum(1 for r in readings if r['is_urgent'])
print(f"[N-BaIoT] Saved {len(readings):,} readings -> {OUTPUT_PKL}")
print(f"[N-BaIoT] Urgent: {urgent:,} ({100*urgent/len(readings):.1f}%)")
print("[N-BaIoT] Ready. Run: python eval_nbaiot_all.py")
