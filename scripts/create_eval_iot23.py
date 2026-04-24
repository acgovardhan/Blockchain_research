#!/usr/bin/env python3
"""
Build processed_iot23_eval.pkl from processed_iot23.pkl.
Converts ALL rows — no sampling, no row limit.
Run once after preprocess_iot23.py.
"""
from __future__ import annotations
import hashlib, json, pickle, sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from config import DATA_DIR  # type: ignore

PKL_IN  = Path(DATA_DIR) / "processed_iot23.pkl"
PKL_OUT = Path(DATA_DIR) / "processed_iot23_eval.pkl"

HIGH_SEVERITY_LABELS = {
    "c&c", "ddos", "dos", "okiru", "mirai", "ransomware",
    "backdoor", "injection", "xss", "mitm", "password",
}


# ── helpers ───────────────────────────────────────────────────
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

def clean_float(v: Any, default: float = 0.0) -> float:
    try:
        s = clean_str(v, "")
        if s in {"", "-", "(empty)", "na", "n/a"}:
            return default
        return float(s)
    except Exception:
        return default

def payload_hash(r: Dict[str, Any]) -> str:
    payload = json.dumps(
        {k: str(v) for k, v in sorted(r.items()) if k != "data_hash"},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def sensor_val_from_hash(data_hash_hex: str) -> int:
    return int.from_bytes(bytes.fromhex(data_hash_hex)[:4], "big") % 10_000


# ── normalize ─────────────────────────────────────────────────
def normalize_row(r: Dict[str, Any]) -> Dict[str, Any]:
    x = dict(r)

    x["row_index"]      = clean_int(x.get("row_index", 0))
    x["source_row"]     = clean_int(x.get("source_row", x["row_index"]))
    x["device_id"]      = clean_int(x.get("device_id", 0))
    x["timestamp"]      = clean_float(x.get("timestamp", x.get("ts", 0.0)))
    x["src_ip"]         = clean_str(x.get("src_ip", ""))
    x["proto"]          = clean_str(x.get("proto", "tcp")).lower()
    x["orig_bytes"]     = clean_int(x.get("orig_bytes", 0))
    x["resp_bytes"]     = clean_int(x.get("resp_bytes", 0))
    x["conn_state"]     = clean_str(x.get("conn_state", ""))
    x["label"]          = clean_str(x.get("label", "benign")).lower()
    x["detailed_label"] = clean_str(x.get("detailed_label", x["label"])).lower()
    x["source_file"]    = clean_str(x.get("source_file", ""))
    x["scenario"]       = clean_str(x.get("scenario", "iot-23"))

    # enforce coarse label
    if x["label"] not in {"benign", "malicious"}:
        x["label"] = "benign" if "benign" in x["detailed_label"] else "malicious"
    if x["label"] == "benign":
        x["detailed_label"] = "benign"
    elif not x["detailed_label"] or x["detailed_label"] in {"-", "none", "nan"}:
        x["detailed_label"] = "malicious"

    x["is_urgent"] = bool(x.get("is_urgent", False)) or any(
        tag in x["detailed_label"] for tag in HIGH_SEVERITY_LABELS
    )

    # always (re)compute hash and sensor_val for consistency
    x["data_hash"]  = payload_hash(x)
    x["sensor_val"] = sensor_val_from_hash(x["data_hash"])
    return x


def main() -> int:
    print(f"\n[create_eval IoT-23]  {PKL_IN}  ->  {PKL_OUT}")
    if not PKL_IN.exists():
        print("ERROR: processed_iot23.pkl not found.")
        print("Run: python scripts/preprocess_iot23.py")
        return 1

    with open(PKL_IN, "rb") as f:
        source = pickle.load(f)

    if not isinstance(source, list):
        raise TypeError(f"Expected list in pkl, got {type(source).__name__}")

    rows: List[Dict[str, Any]] = [normalize_row(r) for r in source]
    print(f"[create_eval IoT-23] {len(rows):,} rows normalized")

    rows.sort(key=lambda r: (float(r.get("timestamp", 0.0)), int(r.get("source_row", 0))))

    # final reindex + stable hash/sensor_val after sort
    for idx, r in enumerate(rows):
        r["row_index"]  = idx
        r["data_hash"]  = payload_hash(r)
        r["sensor_val"] = sensor_val_from_hash(r["data_hash"])
        r["is_urgent"]  = bool(r.get("is_urgent", False)) or any(
            tag in str(r.get("detailed_label", "")).lower() for tag in HIGH_SEVERITY_LABELS
        )

    PKL_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(PKL_OUT, "wb") as f:
        pickle.dump(rows, f, protocol=pickle.HIGHEST_PROTOCOL)

    benign = sum(1 for r in rows if str(r.get("label", "")) == "benign")
    urgent = sum(1 for r in rows if bool(r.get("is_urgent", False)))
    print(f"[create_eval IoT-23] rows={len(rows):,}  benign={benign:,}  urgent={urgent:,}")
    print(f"[create_eval IoT-23] Saved -> {PKL_OUT}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())