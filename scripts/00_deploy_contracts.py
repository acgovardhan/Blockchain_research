#!/usr/bin/env python3
# scripts/00_deploy_contracts.py  — Updated with PoA ValidatorRegistry
# ============================================================
# Run FIRST. Deploys ValidatorRegistry + all 6 storage contracts.
# Registers Ganache accounts 0-4 as authorized PoA validators.
# ============================================================

import sys
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import GANACHE_URL, CONTRACT_DIR, save_addresses

from web3 import Web3
from solcx import compile_source, install_solc, get_installed_solc_versions, set_solc_version

w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
assert w3.is_connected(), f"Cannot connect to Ganache at {GANACHE_URL}"
print(f"[deploy] Connected  |  Chain ID: {w3.eth.chain_id}")

deployer = w3.eth.accounts[0]
SOLC_VER = "0.8.19"

if SOLC_VER not in [str(v) for v in get_installed_solc_versions()]:
    print(f"[deploy] Installing solc {SOLC_VER}...")
    install_solc(SOLC_VER)

set_solc_version(SOLC_VER)

BASE_DIR = Path(__file__).parent.parent
ADDR_FILE = BASE_DIR / "deployed_addresses.json"
ABI_FILE = BASE_DIR / "contract_abis.json"


def remove_duplicate_spdx(source: str) -> str:
    """Keep only the first SPDX line in a combined Solidity source."""
    seen_spdx = False
    cleaned_lines = []

    for line in source.splitlines():
        if line.strip().startswith("// SPDX-License-Identifier:"):
            if seen_spdx:
                continue
            seen_spdx = True
        cleaned_lines.append(line)

    return "\n".join(cleaned_lines)


def compile_contract(name: str):
    """Compile a single contract file."""
    sol_file = CONTRACT_DIR / f"{name}.sol"
    with open(sol_file, encoding="utf-8") as f:
        source = f.read()

    compiled = compile_source(
        source,
        output_values=["abi", "bin"],
        solc_version=SOLC_VER
    )

    key = next(k for k in compiled if k.endswith(f":{name}"))
    return compiled[key]["abi"], compiled[key]["bin"]


def deploy(name, abi, bytecode, *args):
    print(f"[deploy] Deploying {name} ...")
    t0 = time.time()
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Contract.constructor(*args).transact({"from": deployer, "gas": 3_000_000})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    elapsed = time.time() - t0
    addr = receipt["contractAddress"]
    gas = receipt["gasUsed"]
    print(f"[deploy] ✓ {name}: {addr}  (gas={gas:,}  {elapsed:.2f}s)")
    return addr, gas


deployed = {}
abis = {}

# ── 1. Deploy ValidatorRegistry FIRST ────────────────────────
abi, bin_ = compile_contract("ValidatorRegistry")
addr, _ = deploy("ValidatorRegistry", abi, bin_)
deployed["ValidatorRegistry"] = addr
abis["ValidatorRegistry"] = abi
registry_contract = w3.eth.contract(address=addr, abi=abi)

# ── 2. Register 5 Ganache accounts as PoA validators ─────────
print("\n[deploy] Registering PoA validators ...")
for i, account in enumerate(w3.eth.accounts[:5]):
    if i == 0:
        print(f"[deploy]   Account 0 ({account}): auto-registered as Gateway-0")
        continue

    tx = registry_contract.functions.addValidator(
        account, f"Gateway-{i}"
    ).transact({"from": deployer, "gas": 100_000})
    w3.eth.wait_for_transaction_receipt(tx)
    print(f"[deploy]   Registered Gateway-{i}: {account}")

count = registry_contract.functions.validatorCount().call()
print(f"[deploy] Total validators registered: {count}")

# ── 3. Deploy standalone contracts (no PoA dependency) ───────
STANDALONE = [
    "BaselineStorage",
    "MerkleStorage",
    "AABFPlusStorage",
    "BLSStorage",
    "PrivacyMaskStorage",
]

for name in STANDALONE:
    abi, bin_ = compile_contract(name)
    addr, _ = deploy(name, abi, bin_)
    deployed[name] = addr
    abis[name] = abi

# ── 4. Deploy HybridStorage with ValidatorRegistry address ───
# HybridStorage imports ValidatorRegistry — compile together
with open(CONTRACT_DIR / "HybridStorage.sol", encoding="utf-8") as f:
    hybrid_src = f.read()

with open(CONTRACT_DIR / "ValidatorRegistry.sol", encoding="utf-8") as f:
    registry_src = f.read()

# Inline compile with dependency
combined = registry_src + "\n\n" + hybrid_src.replace(
    'import "./ValidatorRegistry.sol";', ''
)

combined = remove_duplicate_spdx(combined)

compiled = compile_source(
    combined,
    output_values=["abi", "bin"],
    solc_version=SOLC_VER
)

hybrid_key = next(k for k in compiled if k.endswith(":HybridStorage"))
hybrid_abi = compiled[hybrid_key]["abi"]
hybrid_bin = compiled[hybrid_key]["bin"]

addr, _ = deploy("HybridStorage", hybrid_abi, hybrid_bin, deployed["ValidatorRegistry"])
deployed["HybridStorage"] = addr
abis["HybridStorage"] = hybrid_abi

# ── 5. Save ───────────────────────────────────────────────────
save_addresses(deployed)
with open(ABI_FILE, "w", encoding="utf-8") as f:
    json.dump(abis, f, indent=2)

print("\n[deploy] ══════════════════════════════════════════════")
print("[deploy] All contracts deployed successfully")
print(f"[deploy] ValidatorRegistry: {deployed['ValidatorRegistry']}")
print(f"[deploy] HybridStorage:     {deployed['HybridStorage']}")
print("[deploy] Addresses → deployed_addresses.json")
print("[deploy] ABIs      → contract_abis.json")
print("[deploy] PoA validators: accounts 0–4 registered")