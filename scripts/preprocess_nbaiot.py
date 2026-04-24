#!/usr/bin/env python3
"""
Lightweight N-BaIoT preprocessing for eval_engine.py
Input:  data/NBA_IoT/nbaiot_250k.csv
Output: data/processed_nbaiot.pkl
"""
from __future__ import annotations
import hashlib, json, pickle, sys
from pathlib import Path
from typing import Any, Dict, List
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from config import DATA_DIR, HIGH_SEVERITY_LABELS

DATA_DIR = Path(DATA_DIR)
INPUT    = DATA_DIR / "NBA_IoT" / "nbaiot_250k.csv"
OUTPUT   = DATA_DIR / "processed_nbaiot.pkl"

NUM_DEVICES = 20
CHUNK_SIZE  = 100_000
BASE_TS     = 1_700_000_000.0
TS_STEP     = 0.1
BENIGN_KEYS = {"0", "benign", "normal", "false"}


def clean_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    s = str(v).strip()
    return default if s.lower() in {"nan", "none", "null"} else s

def clean_int(v: Any, default: int = 0) -> int:
    try:
        s = clean_str(v, "")
        if s in {"", "-", "(empty)", "na", "n/a"}:
            return default
        return int(float(s))
    except Exception:
        return default

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [
        str(c).strip().lower().replace(".", "_").replace("-", "_").replace(" ", "_")
        for c in df.columns
    ]
    return df

def stable_int(text: str, mod: int) -> int:
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8], "big") % mod

def infer_label(raw_label: Any, detailed_label: str) -> str:
    v = clean_str(raw_label, "").lower()
    if v in BENIGN_KEYS:
        return "benign"
    return "benign" if "benign" in detailed_label else "malicious"

def make_hash(row: Dict[str, Any]) -> str:
    payload = json.dumps(
        {k: str(v) for k, v in sorted(row.items()) if k != "data_hash"},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def sensor_val_from_hash(data_hash_hex: str) -> int:
    return int.from_bytes(bytes.fromhex(data_hash_hex)[:4], "big") % 10_000

def build_reading(raw: Dict[str, Any], row_index: int, source_row: int, source_file: str) -> Dict[str, Any]:
    detailed_label = clean_str(raw.get("detailed_label") or raw.get("label") or source_file).lower()
    label = infer_label(raw.get("label"), detailed_label)

    if label == "benign":
        detailed_label = "benign"
    elif not detailed_label or detailed_label in {"-", "none", "nan"}:
        detailed_label = "malicious"

    device_id = stable_int(source_file, NUM_DEVICES)
    timestamp = BASE_TS + source_row * TS_STEP

    reading: Dict[str, Any] = {
        "row_index":      int(row_index),
        "source_row":     int(source_row),
        "device_id":      int(device_id),
        "timestamp":      float(timestamp),
        "label":          label,
        "detailed_label": detailed_label,
        "source_file":    source_file,
        "scenario":       "nbaiot",
    }
    reading["is_urgent"]  = any(tag in reading["detailed_label"] for tag in HIGH_SEVERITY_LABELS)
    reading["data_hash"]  = make_hash(reading)
    reading["sensor_val"] = sensor_val_from_hash(reading["data_hash"])
    return reading


def main() -> int:
    if not INPUT.exists():
        raise FileNotFoundError(f"Input CSV not found: {INPUT}")

    print(f"[N-BaIoT] Loading: {INPUT}")
    rows: List[Dict[str, Any]] = []
    total_seen = 0

    for chunk_id, chunk in enumerate(
        pd.read_csv(INPUT, chunksize=CHUNK_SIZE, low_memory=False,
                    encoding_errors="replace", on_bad_lines="skip"), 1
    ):
        if chunk.empty:
            continue
        chunk = normalize_columns(chunk)
        if "source_file"    not in chunk.columns: chunk["source_file"]    = INPUT.name
        if "label"          not in chunk.columns: chunk["label"]          = "malicious"
        if "detailed_label" not in chunk.columns: chunk["detailed_label"] = chunk["label"]

        n    = len(chunk)
        base = total_seen
        total_seen += n

        for i, raw in enumerate(chunk.to_dict(orient="records")):
            rows.append(build_reading(
                raw, row_index=len(rows), source_row=base + i,
                source_file=clean_str(raw.get("source_file", INPUT.name)),
            ))

        print(f"  [chunk {chunk_id:02d}] rows={n:,}  total={len(rows):,}")

    if not rows:
        raise RuntimeError("No N-BaIoT rows were loaded.")

    for idx, r in enumerate(rows):
        r["row_index"]  = idx
        r["data_hash"]  = make_hash(r)
        r["sensor_val"] = sensor_val_from_hash(r["data_hash"])
        r["is_urgent"]  = any(tag in str(r.get("detailed_label", "")).lower() for tag in HIGH_SEVERITY_LABELS)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "wb") as f:
        pickle.dump(rows, f, protocol=pickle.HIGHEST_PROTOCOL)

    benign  = sum(1 for r in rows if r["label"] == "benign")
    urgent  = sum(1 for r in rows if r["is_urgent"])
    devices = sorted({r["device_id"] for r in rows})
    print(f"\n[N-BaIoT] rows={len(rows):,}  benign={benign:,}  urgent={urgent:,}")
    print(f"[N-BaIoT] device_ids={devices}")
    print(f"[N-BaIoT] Saved -> {OUTPUT}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())