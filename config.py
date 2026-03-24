# config.py — Central settings for IoT-Blockchain evaluation
import os, json, pathlib

# ── Ganache ───────────────────────────────────────────────────
GANACHE_URL = "http://127.0.0.1:7545"
CHAIN_ID    = 1337

# ── Row limits per dataset ────────────────────────────────────
# None = no limit (use full dataset)
EVAL_ROWS_IOT23  = None     # ~156,000 rows (~3.5 hrs total)
EVAL_ROWS_TON    = None     # ~460,000 rows (~9.5 hrs total)
EVAL_ROWS_NBAIOT = 50_000   # 7M rows -> use representative 50K sample

# Generic alias imported by preprocess scripts
# Each preprocess script overrides this with its dataset-specific value
EVAL_ROWS = None             # default: no limit

# ── Batching ──────────────────────────────────────────────────
NUM_DEVICES      = 20
FIXED_BATCH_SIZE = 20

# ── Adaptive batching ─────────────────────────────────────────
AABF_LAMBDA_BASE   = 10.0
AABF_ALPHA         = 0.3
AABF_JITTER_THRESH = 0.40   # raised from 0.15 — prevents premature flush
AABF_MIN_BATCH     = 5
AABF_MAX_BATCH     = 50

# ── High-severity attack labels (trigger urgent flush) ────────
# PortScan is NOT here — it is high-volume but not time-critical
HIGH_SEVERITY_LABELS = {
    'c&c', 'attack', 'ddos', 'dos', 'okiru', 'mirai',
    'ransomware', 'backdoor', 'injection', 'xss', 'mitm',
    'password', 'scanning'
}

# ── Energy model constants (mJ) ───────────────────────────────
ENERGY_ECDSA_SIGN_MJ = 0.50
ENERGY_BLS_SIGN_MJ   = 2.10
ENERGY_HASH_PER_BYTE = 0.001
ENERGY_TX_PER_BYTE   = 0.012
ENERGY_MASK_OP_MJ    = 0.08

# ── Gas estimates ─────────────────────────────────────────────
GAS_BLS_VERIFY   = 89_000   # EIP-2537: 43000 + 23000*2
GAS_ECDSA_VERIFY = 3_000

# ── Checkpoint (overnight run safety) ────────────────────────
CHECKPOINT_INTERVAL = 50    # save progress every 50 batches

# ── Paths ─────────────────────────────────────────────────────
BASE_DIR       = pathlib.Path(__file__).parent
DATA_DIR       = BASE_DIR / "data"
RESULTS_DIR    = BASE_DIR / "results"
CONTRACT_DIR   = BASE_DIR / "contracts"
ADDR_FILE      = BASE_DIR / "deployed_addresses.json"
CHECKPOINT_DIR = BASE_DIR / "checkpoints"

RESULTS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)
CHECKPOINT_DIR.mkdir(exist_ok=True)

# ── Dataset paths ─────────────────────────────────────────────
DATASETS = {
    "IoT23":   DATA_DIR / "iot23_full.csv",
    "TON_IoT": DATA_DIR / "ton_iot_network.csv",
    "N-BaIoT": DATA_DIR / "nbaiot",           # folder containing all CSVs
}
PROCESSED = {
    "IoT23":   DATA_DIR / "processed_iot23.pkl",
    "TON_IoT": DATA_DIR / "processed_ton_iot.pkl",
    "N-BaIoT": DATA_DIR / "processed_nbaiot.pkl",
}

def load_addresses():
    if not ADDR_FILE.exists():
        raise FileNotFoundError(
            "deployed_addresses.json not found. "
            "Run: python scripts/00_deploy_contracts.py"
        )
    with open(ADDR_FILE) as f:
        return json.load(f)

def save_addresses(addr_dict):
    with open(ADDR_FILE, "w") as f:
        json.dump(addr_dict, f, indent=2)
    print(f"[config] Saved addresses -> {ADDR_FILE}")
