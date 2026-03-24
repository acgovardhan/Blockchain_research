#!/usr/bin/env python3
"""
scripts/01b_preprocess_ton_iot.py
Preprocesses the TON_IoT network dataset.
Place your downloaded file at: data/ton_iot_network.csv
Download: https://www.kaggle.com/datasets/arnobbhowmik/ton-iot-network-dataset
"""
import sys, pickle
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import DATA_DIR, EVAL_ROWS_TON, HIGH_SEVERITY_LABELS
from utils.metrics import reading_to_hash, hash_to_int

import pandas as pd

INPUT_CSV  = DATA_DIR / "ton_iot_network.csv"
OUTPUT_PKL = DATA_DIR / "processed_ton_iot.pkl"
EVAL_ROWS  = EVAL_ROWS_TON   # None = use all rows

if not INPUT_CSV.exists():
    print(f"ERROR: {INPUT_CSV} not found.")
    print("Download from: https://www.kaggle.com/datasets/arnobbhowmik/ton-iot-network-dataset")
    print("Extract zip, find Train_Test_Network_dataset.csv")
    print("Rename to ton_iot_network.csv and place in the data/ folder.")
    sys.exit(1)

print(f"[TON_IoT] Loading {INPUT_CSV} ...")
df = pd.read_csv(INPUT_CSV, low_memory=False)
df.columns = [c.strip().lower() for c in df.columns]
print(f"[TON_IoT] Loaded {len(df):,} rows | Columns: {list(df.columns[:8])}")

# Column rename
rename = {'ts':'timestamp','src_ip':'src_ip','dst_ip':'dst_ip',
          'proto':'proto','src_bytes':'orig_bytes','dst_bytes':'resp_bytes',
          'conn_state':'conn_state','label':'label_int','type':'attack_type'}
df = df.rename(columns={k:v for k,v in rename.items() if k in df.columns})

# Convert integer label to string
if 'label_int' in df.columns:
    df['label'] = df['label_int'].map({0:'Benign',1:'Malicious'}).fillna('Benign')
elif 'label' in df.columns:
    df['label'] = df['label'].astype(str).str.strip()
else:
    df['label'] = 'Benign'

if 'attack_type' not in df.columns:
    df['attack_type'] = '-'

if 'timestamp' not in df.columns:
    df['timestamp'] = df.index.astype(float)
else:
    df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce').fillna(0)

if 'src_ip' not in df.columns:
    df['src_ip'] = 'device_' + (df.index % 20).astype(str)

for col in ['orig_bytes','resp_bytes']:
    if col in df.columns:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)

df = df.dropna(subset=['timestamp','src_ip'])

# Rebalance 70/30
benign    = df[df['label'].str.lower() == 'benign']
malicious = df[df['label'].str.lower() != 'benign']
total     = len(df) if EVAL_ROWS is None else EVAL_ROWS
n_b = min(len(benign),    int(total * 0.70))
n_m = min(len(malicious), int(total * 0.30))
df  = pd.concat([
    benign.sample(n=n_b,    random_state=42),
    malicious.sample(n=n_m, random_state=42)
]).sample(frac=1, random_state=42).reset_index(drop=True)
print(f"[TON_IoT] Rebalanced: {n_b:,} Benign + {n_m:,} Malicious = {len(df):,} total")

unique_ips = sorted(df['src_ip'].unique())
ip_to_id   = {ip: i % 20 for i, ip in enumerate(unique_ips)}
df['device_id'] = df['src_ip'].map(ip_to_id)

readings = []
for idx, row in df.iterrows():
    attack = str(row.get('attack_type','-')).strip().lower()
    r = {
        'row_index': idx, 'device_id': int(row['device_id']),
        'timestamp': float(row['timestamp']),
        'src_ip':    str(row['src_ip']),
        'proto':     str(row.get('proto','tcp')),
        'orig_bytes':int(row.get('orig_bytes',0)),
        'resp_bytes':int(row.get('resp_bytes',0)),
        'conn_state':str(row.get('conn_state','')),
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
print(f"[TON_IoT] Saved {len(readings):,} readings -> {OUTPUT_PKL}")
print(f"[TON_IoT] Urgent: {urgent:,} ({100*urgent/len(readings):.1f}%)  <- should be under 20%")
print("[TON_IoT] Ready. Run: python eval_ton_iot_all.py")
