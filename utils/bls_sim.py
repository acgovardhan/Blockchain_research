"""utils/bls_sim.py — BLS12-381 signature simulation"""
import os, time, hashlib
from typing import List, Tuple

try:
    from py_ecc.bls import G2ProofOfPossession as bls
    _OK = True
except ImportError:
    _OK = False

def generate_keypair(seed: bytes = None):
    if seed is None: seed = os.urandom(32)
    seed = seed[:32].ljust(32, b'\x00')
    if _OK:
        sk = int.from_bytes(seed, 'big') % (
            0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001)
        if sk == 0: sk = 1
        return sk, bls.SkToPk(sk)
    sk = int.from_bytes(seed, 'big')
    pk = (hashlib.sha256(seed).digest() * 2 + seed)[:48]
    return sk, pk

def generate_device_keys(n: int):
    keys = []
    for i in range(n):
        seed = hashlib.sha256(f"device_{i:04d}".encode()).digest()
        sk, pk = generate_keypair(seed)
        keys.append({"device_id": i, "sk": sk, "pk": pk})
    return keys

def sign_message(sk: int, message: bytes):
    t0 = time.perf_counter()
    if _OK:
        sig = bls.Sign(sk, message)
    else:
        h = hashlib.sha256(sk.to_bytes(32, 'big') + message).digest()
        sig = (h * 3)[:96]
    return sig, time.perf_counter() - t0

def aggregate_signatures(sigs: List[bytes]):
    t0 = time.perf_counter()
    if _OK and sigs:
        agg = bls.Aggregate(sigs)
    else:
        agg = bytearray(96)
        for s in sigs:
            for j in range(min(len(s), 96)): agg[j] ^= s[j]
        agg = bytes(agg)
    return agg, time.perf_counter() - t0

def aggregate_pubkeys(pks: List[bytes]) -> bytes:
    if _OK and pks:
        return bls._AggregatePKs(pks)
    agg = bytearray(48)
    for pk in pks:
        for j in range(min(len(pk), 48)): agg[j] ^= pk[j]
    return bytes(agg)

def generate_pop(sk: int, pk: bytes) -> bytes:
    if _OK: return bls.Sign(sk, pk)
    h = hashlib.sha256(sk.to_bytes(32, 'big') + pk).digest()
    return (h * 3)[:96]

def verify_pop(pk: bytes, pop: bytes) -> bool:
    if _OK: return bls.Verify(pk, pk, pop)
    return True

def estimate_bls_gas(n: int, use_eip2537: bool = True) -> int:
    if use_eip2537:
        return 21_000 + 43_000 + 23_000*2 + (96+48)*16 + 22_100*3
    return 21_000 + 3_000*n + 22_100*n
