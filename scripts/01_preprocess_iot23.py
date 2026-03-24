#!/usr/bin/env python3
"""
scripts/01_preprocess_iot23.py

Memory-safe, reproducible IoT-23 preprocessing.

What it does:
- Reads all IoT-23 files in chunks
- Counts benign/malicious rows per scenario
- Builds a deterministic stratified sample
- Saves:
    data/processed_iot23.pkl
    data/processed_iot23_manifest.csv
    results/iot23_dataset_table.txt

For reproducibility:
- File order is deterministic (natural sort)
- Sampling is deterministic (fixed seed + hash-based selection)
- A manifest CSV is written so the exact sample can be audited later
"""

import sys
import re
import math
import pickle
import heapq
from pathlib import Path
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from config import DATA_DIR, EVAL_ROWS_IOT23, HIGH_SEVERITY_LABELS
from utils.metrics import reading_to_hash, hash_to_int

# ----------------------------
# Settings
# ----------------------------
SCENARIOS_DIR = DATA_DIR / "iot23_scenarios"
OUTPUT_PKL = DATA_DIR / "processed_iot23.pkl"
OUTPUT_MANIFEST = DATA_DIR / "processed_iot23_manifest.csv"
RESULTS_DIR = ROOT / "results"
PAPER_TABLE = RESULTS_DIR / "iot23_dataset_table.txt"

SEED = 42
SAMPLE_SIZE = EVAL_ROWS_IOT23 if EVAL_ROWS_IOT23 else 500_000
BENIGN_FRAC = 0.70
MALICIOUS_FRAC = 0.30
CHUNK_SIZE = 100_000

VALID_LABELS = {"benign", "malicious"}

# ----------------------------
# Helpers
# ----------------------------
def natural_key(path: Path):
    parts = re.split(r"(\d+)", path.name)
    return [int(p) if p.isdigit() else p.lower() for p in parts]


def iter_file_chunks(path: Path, chunk_size: int = CHUNK_SIZE):
    """
    Yield pandas chunks for either CSV files or Zeek-style tab-separated files.
    """
    suffix = path.suffix.lower()

    if suffix == ".csv":
        reader = pd.read_csv(
            path,
            chunksize=chunk_size,
            low_memory=False,
            encoding_errors="replace",
            on_bad_lines="skip",
        )
        for chunk in reader:
            yield chunk
        return

    # Fallback for .labeled / .log style Zeek files
    col_names = None
    skip_rows = 0
    with open(path, "r", errors="replace") as f:
        for li, line in enumerate(f):
            if line.startswith("#fields"):
                raw = line.strip().replace("#fields", "").strip()
                col_names = [c.strip() for c in raw.split("\t") if c.strip()]
                skip_rows = li + 1
                break
            elif not line.startswith("#") and line.strip():
                break

    if col_names:
        reader = pd.read_csv(
            path,
            sep="\t",
            skiprows=skip_rows,
            names=col_names,
            header=None,
            chunksize=chunk_size,
            low_memory=False,
            encoding_errors="replace",
            on_bad_lines="skip",
        )
    else:
        reader = pd.read_csv(
            path,
            sep="\t",
            comment="#",
            header=None,
            chunksize=chunk_size,
            low_memory=False,
            encoding_errors="replace",
            on_bad_lines="skip",
        )

    for chunk in reader:
        yield chunk


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [
        str(c).strip().lower().replace(" ", "_").replace(".", "_").replace("-", "_")
        for c in df.columns
    ]

    rename_map = {}
    if "ts" in df.columns and "timestamp" not in df.columns:
        rename_map["ts"] = "timestamp"
    if "id_orig_h" in df.columns and "src_ip" not in df.columns:
        rename_map["id_orig_h"] = "src_ip"
    if "id_orig_p" in df.columns and "src_port" not in df.columns:
        rename_map["id_orig_p"] = "src_port"
    if "id_resp_h" in df.columns and "dst_ip" not in df.columns:
        rename_map["id_resp_h"] = "dst_ip"
    if "id_resp_p" in df.columns and "dst_port" not in df.columns:
        rename_map["id_resp_p"] = "dst_port"

    if rename_map:
        df = df.rename(columns=rename_map)

    return df


def prepare_chunk(df: pd.DataFrame, base_row: int, file_stem: str) -> pd.DataFrame:
    """
    Standardize columns, add defaults, and filter to benign/malicious rows.
    """
    if df.empty:
        return df

    df = normalize_columns(df)
    n = len(df)

    # Deterministic row number within the file/chunk stream
    df["source_row"] = np.arange(base_row, base_row + n, dtype=np.int64)
    df["source_file"] = file_stem

    if "detailed_label" not in df.columns:
        df["detailed_label"] = "-"

    if "timestamp" not in df.columns:
        df["timestamp"] = df["source_row"].astype(float)

    if "src_ip" not in df.columns:
        df["src_ip"] = [f"device_{i % 20}" for i in range(n)]

    if "proto" not in df.columns:
        df["proto"] = "tcp"

    if "orig_bytes" not in df.columns:
        df["orig_bytes"] = 0

    if "resp_bytes" not in df.columns:
        df["resp_bytes"] = 0

    if "conn_state" not in df.columns:
        df["conn_state"] = ""

    if "label" not in df.columns:
        # Fallback only if label is missing
        df["label"] = np.where(
            df["detailed_label"].astype(str).str.contains("benign", case=False, na=False),
            "benign",
            "malicious",
        )

    # Normalize values
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce").fillna(0)
    df["src_ip"] = df["src_ip"].astype(str).str.strip()
    df["proto"] = df["proto"].astype(str).str.strip().str.lower()
    df["conn_state"] = df["conn_state"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df["detailed_label"] = df["detailed_label"].astype(str).str.strip().str.lower()

    for col in ["orig_bytes", "resp_bytes"]:
        df[col] = pd.to_numeric(
            df[col].astype(str).str.strip().replace("-", "0"),
            errors="coerce",
        ).fillna(0).astype(np.int64)

    df = df[df["label"].isin(VALID_LABELS)].copy()
    return df


def distribute_quotas(total_target: int, counts_by_scenario: dict) -> dict:
    """
    Distribute a total target across scenarios proportionally to available counts.
    Deterministic and stable.
    """
    counts_by_scenario = {k: int(v) for k, v in counts_by_scenario.items() if v > 0}
    if total_target <= 0 or not counts_by_scenario:
        return {k: 0 for k in counts_by_scenario}

    available = sum(counts_by_scenario.values())
    target = min(total_target, available)

    quotas = {k: 0 for k in counts_by_scenario}
    remainders = []
    assigned = 0

    for sc, cnt in counts_by_scenario.items():
        exact = target * cnt / available
        q = min(cnt, int(math.floor(exact)))
        quotas[sc] = q
        assigned += q
        remainders.append((exact - q, sc))

    remaining = target - assigned

    # Largest remainder method
    for _, sc in sorted(remainders, key=lambda x: x[0], reverse=True):
        if remaining <= 0:
            break
        if quotas[sc] < counts_by_scenario[sc]:
            quotas[sc] += 1
            remaining -= 1

    # Final fill, if any leftover remains because of cap constraints
    if remaining > 0:
        for sc, cnt in sorted(counts_by_scenario.items(), key=lambda kv: kv[1] - quotas[kv[0]], reverse=True):
            spare = cnt - quotas[sc]
            if spare <= 0:
                continue
            take = min(spare, remaining)
            quotas[sc] += take
            remaining -= take
            if remaining == 0:
                break

    return quotas


# ----------------------------
# Main
# ----------------------------
if not SCENARIOS_DIR.exists():
    print(f"ERROR: {SCENARIOS_DIR} not found.")
    print("Create this folder and place the IoT-23 files inside it.")
    sys.exit(1)

csv_files = sorted(
    list(SCENARIOS_DIR.glob("*.csv")) +
    list(SCENARIOS_DIR.glob("*.labeled")) +
    list(SCENARIOS_DIR.glob("*.log")),
    key=natural_key
)

if not csv_files:
    print(f"ERROR: No data files found in {SCENARIOS_DIR}")
    sys.exit(1)

print(f"\n[IoT-23] Found {len(csv_files)} file(s) in {SCENARIOS_DIR}")
print(f"[IoT-23] Target sample: {SAMPLE_SIZE:,} rows")
print(f"[IoT-23] Chunk size: {CHUNK_SIZE:,}\n")

# First pass: count benign/malicious rows per scenario
scenario_label_counts = {
    "benign": Counter(),
    "malicious": Counter(),
}
total_raw_rows = 0
total_valid_rows = 0

for scenario_id, fpath in enumerate(csv_files, 1):
    file_raw = 0
    file_valid = 0

    for chunk in iter_file_chunks(fpath):
        chunk = normalize_columns(chunk)
        if chunk.empty:
            continue

        file_raw += len(chunk)

        # Add defaults and normalize labels
        if "detailed_label" not in chunk.columns:
            chunk["detailed_label"] = "-"

        if "label" not in chunk.columns:
            chunk["label"] = np.where(
                chunk["detailed_label"].astype(str).str.contains("benign", case=False, na=False),
                "benign",
                "malicious",
            )

        chunk["label"] = chunk["label"].astype(str).str.strip().str.lower()
        chunk = chunk[chunk["label"].isin(VALID_LABELS)]

        if chunk.empty:
            continue

        vc = chunk["label"].value_counts()
        for lab, cnt in vc.items():
            scenario_label_counts[lab][scenario_id] += int(cnt)
            file_valid += int(cnt)

    total_raw_rows += file_raw
    total_valid_rows += file_valid
    print(f"  [count] {fpath.name:45s} raw={file_raw:>12,}  valid={file_valid:>12,}")

benign_available = sum(scenario_label_counts["benign"].values())
mal_available = sum(scenario_label_counts["malicious"].values())

desired_benign = int(SAMPLE_SIZE * BENIGN_FRAC)
desired_malicious = SAMPLE_SIZE - desired_benign

target_benign = min(desired_benign, benign_available)
target_malicious = min(desired_malicious, mal_available)

# If one class is short, let the other class fill the remainder
remaining = SAMPLE_SIZE - (target_benign + target_malicious)
if remaining > 0:
    benign_spare = benign_available - target_benign
    mal_spare = mal_available - target_malicious
    if benign_spare > mal_spare:
        add = min(remaining, benign_spare)
        target_benign += add
        remaining -= add
    if remaining > 0 and mal_spare > 0:
        add = min(remaining, mal_spare)
        target_malicious += add
        remaining -= add

benign_quotas = distribute_quotas(target_benign, scenario_label_counts["benign"])
malicious_quotas = distribute_quotas(target_malicious, scenario_label_counts["malicious"])

print("\n[IoT-23] Full dataset counts")
print(f"  Total raw rows:    {total_raw_rows:,}")
print(f"  Valid labeled rows:{total_valid_rows:,}")
print(f"  Benign:            {benign_available:,}")
print(f"  Malicious:         {mal_available:,}")
print(f"  Target benign:     {target_benign:,}")
print(f"  Target malicious:  {target_malicious:,}")

print("\n[IoT-23] Scenario quotas (benign)")
for sc in sorted(benign_quotas):
    print(f"  scenario {sc:02d}: {benign_quotas[sc]:,}")

print("\n[IoT-23] Scenario quotas (malicious)")
for sc in sorted(malicious_quotas):
    print(f"  scenario {sc:02d}: {malicious_quotas[sc]:,}")

# Second pass: deterministic top-k by hash inside each (scenario, label) bucket
heaps = defaultdict(list)

for scenario_id, fpath in enumerate(csv_files, 1):
    base_row = 0
    for chunk in iter_file_chunks(fpath):
        chunk = prepare_chunk(chunk, base_row=base_row, file_stem=fpath.stem)
        base_row += len(chunk)  # keep deterministic source_row space in sync with file order

        if chunk.empty:
            continue

        # Standardize needed columns
        n = len(chunk)

        # Build a deterministic hash input frame
        score_frame = pd.DataFrame({
            "seed": np.full(n, SEED, dtype=np.int64),
            "scenario": np.full(n, scenario_id, dtype=np.int64),
            "source_file": np.full(n, fpath.stem, dtype=object),
            "source_row": chunk["source_row"].to_numpy(dtype=np.int64),
            "timestamp": pd.to_numeric(chunk["timestamp"], errors="coerce").fillna(0).to_numpy(),
            "src_ip": chunk["src_ip"].astype(str).to_numpy(),
            "proto": chunk["proto"].astype(str).to_numpy(),
            "orig_bytes": chunk["orig_bytes"].to_numpy(dtype=np.int64),
            "resp_bytes": chunk["resp_bytes"].to_numpy(dtype=np.int64),
            "conn_state": chunk["conn_state"].astype(str).to_numpy(),
            "label": chunk["label"].astype(str).to_numpy(),
            "detailed_label": chunk["detailed_label"].astype(str).to_numpy(),
        })

        scores = pd.util.hash_pandas_object(score_frame, index=False).astype("uint64").to_numpy()

        # Arrays for fast row extraction
        source_rows = chunk["source_row"].to_numpy(dtype=np.int64)
        timestamps = pd.to_numeric(chunk["timestamp"], errors="coerce").fillna(0).to_numpy()
        src_ips = chunk["src_ip"].astype(str).to_numpy()
        protos = chunk["proto"].astype(str).to_numpy()
        orig_bytes = chunk["orig_bytes"].to_numpy(dtype=np.int64)
        resp_bytes = chunk["resp_bytes"].to_numpy(dtype=np.int64)
        conn_states = chunk["conn_state"].astype(str).to_numpy()
        labels = chunk["label"].astype(str).to_numpy()
        detailed_labels = chunk["detailed_label"].astype(str).to_numpy()

        for j in range(n):
            label = labels[j]
            quota = benign_quotas.get(scenario_id, 0) if label == "benign" else malicious_quotas.get(scenario_id, 0)
            if quota <= 0:
                continue

            score = int(scores[j])
            record = (
                fpath.stem,                 # source_file
                int(source_rows[j]),        # source_row
                int(scenario_id),           # scenario
                float(timestamps[j]),       # timestamp
                str(src_ips[j]),            # src_ip
                str(protos[j]),             # proto
                int(orig_bytes[j]),         # orig_bytes
                int(resp_bytes[j]),         # resp_bytes
                str(conn_states[j]),        # conn_state
                str(labels[j]),             # label
                str(detailed_labels[j]),    # detailed_label
                np.uint64(score).item(),    # sample_score
            )

            heap_key = (-score, int(source_rows[j]), record)
            heap = heaps[(scenario_id, label)]

            if len(heap) < quota:
                heapq.heappush(heap, heap_key)
            else:
                # Replace the worst item in the heap if the new one is better (smaller score)
                if heap_key[0] > heap[0][0]:
                    heapq.heapreplace(heap, heap_key)

# Build final sample from heaps
selected_records = []
for (_, _), heap in heaps.items():
    selected_records.extend(item[2] for item in heap)

if not selected_records:
    print("ERROR: No rows were selected for the sample.")
    sys.exit(1)

FINAL_COLUMNS = [
    "source_file",
    "source_row",
    "scenario",
    "timestamp",
    "src_ip",
    "proto",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "label",
    "detailed_label",
    "sample_score",
]

sample_df = pd.DataFrame(selected_records, columns=FINAL_COLUMNS)

# Deterministic final ordering
sample_df = sample_df.sort_values(
    by=["sample_score", "source_file", "source_row"],
    ascending=[True, True, True],
    kind="mergesort",
).reset_index(drop=True)

# Device ID mapping, stable across runs
unique_ips = sorted(sample_df["src_ip"].astype(str).unique())
ip_to_id = {ip: i % 20 for i, ip in enumerate(unique_ips)}
sample_df["device_id"] = sample_df["src_ip"].map(ip_to_id).astype(int)

# Add urgency flag for manifest + stats
sample_df["is_urgent"] = sample_df["detailed_label"].astype(str).apply(
    lambda d: any(s in d for s in HIGH_SEVERITY_LABELS)
)

print(f"\n[IoT-23] Sample built")
print(f"  Total sample rows: {len(sample_df):,}")
print(f"  Benign rows:       {(sample_df['label'] == 'benign').sum():,}")
print(f"  Malicious rows:    {(sample_df['label'] == 'malicious').sum():,}")
print(f"  Scenarios covered: {sample_df['scenario'].nunique()} / {len(csv_files)}")
print(f"  Device IDs:        {sorted(sample_df['device_id'].unique())}")

# Convert into the list-of-dicts format your downstream code expects
print("\n[IoT-23] Building reading objects...")
readings = []
for idx, row in enumerate(sample_df.itertuples(index=False), 0):
    detail = str(row.detailed_label).strip().lower()

    r = {
        "row_index": idx,
        "device_id": int(row.device_id),
        "timestamp": float(row.timestamp),
        "src_ip": str(row.src_ip),
        "proto": str(row.proto),
        "orig_bytes": int(row.orig_bytes),
        "resp_bytes": int(row.resp_bytes),
        "conn_state": str(row.conn_state),
        "label": str(row.label),
        "detailed_label": detail,
        "scenario": int(row.scenario),
        "source_file": str(row.source_file),
        "source_row": int(row.source_row),
        "sample_score": int(row.sample_score),
    }

    r["data_hash"] = reading_to_hash(r).hex()
    r["sensor_val"] = hash_to_int(bytes.fromhex(r["data_hash"]), max_val=10_000)
    r["is_urgent"] = any(s in detail for s in HIGH_SEVERITY_LABELS)

    readings.append(r)

urgent = sum(1 for r in readings if r["is_urgent"])
ts_vals = [r["timestamp"] for r in readings]

# Save outputs
with open(OUTPUT_PKL, "wb") as f:
    pickle.dump(readings, f)

# Save a provenance manifest for reproducibility
manifest_cols = [
    "row_index",
    "device_id",
    "source_file",
    "source_row",
    "scenario",
    "timestamp",
    "src_ip",
    "proto",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "label",
    "detailed_label",
    "sample_score",
    "is_urgent",
]
sample_df_export = sample_df.copy()
sample_df_export["row_index"] = np.arange(len(sample_df_export), dtype=np.int64)
sample_df_export["is_urgent"] = sample_df_export["is_urgent"].astype(bool)
sample_df_export[manifest_cols].to_csv(OUTPUT_MANIFEST, index=False)

RESULTS_DIR.mkdir(exist_ok=True)
with open(PAPER_TABLE, "w", encoding="utf-8") as f:
    f.write("IoT-23 Dataset Statistics  (copy into paper Table I)\n")
    f.write("=" * 62 + "\n\n")
    f.write(f"Full dataset raw rows:    {total_raw_rows:>12,}\n")
    f.write(f"Valid labeled rows:       {total_valid_rows:>12,}\n")
    f.write(f"Benign rows:              {benign_available:>12,}\n")
    f.write(f"Malicious rows:           {mal_available:>12,}\n")
    f.write(f"Total files/scenarios:    {len(csv_files):>12,}\n\n")
    f.write(f"Evaluation sample:        {len(readings):>12,} rows\n")
    f.write(f"Sample benign:            {(sample_df['label'] == 'benign').sum():>12,}\n")
    f.write(f"Sample malicious:         {(sample_df['label'] == 'malicious').sum():>12,}\n")
    f.write(f"Scenarios in sample:      {sample_df['scenario'].nunique():>12,} / {len(csv_files)}\n")
    f.write(f"Random seed:              {SEED} (fixed - reproducible)\n")
    f.write(f"Chunk size:               {CHUNK_SIZE:,}\n\n")
    f.write("Per-file breakdown:\n")
    f.write("-" * 62 + "\n")
    for scenario_id, fpath in enumerate(csv_files, 1):
        sub = sample_df[sample_df["source_file"] == fpath.stem]
        b = (sub["label"] == "benign").sum()
        m = (sub["label"] == "malicious").sum()
        f.write(f"  {fpath.stem:42s}  {len(sub):>8,}  (B:{b:,} M:{m:,})\n")

print(f"\n[IoT-23] SAMPLE STATISTICS")
print(f"  Readings saved:    {len(readings):,}")
print(f"  Urgent:            {urgent:,}  ({100 * urgent / len(readings):.1f}%)")
print(f"  Scenarios covered: {sample_df['scenario'].nunique()}")
print(f"  Device IDs:        {sorted(set(r['device_id'] for r in readings))}")
print(f"  Timestamp span:    {min(ts_vals):.0f} to {max(ts_vals):.0f}")
print(f"  Saved -> {OUTPUT_PKL}")
print(f"  Manifest -> {OUTPUT_MANIFEST}")
print(f"  Paper table -> {PAPER_TABLE}")

print(f"\n[IoT-23] Done. Run:  python eval_iot23_all.py")