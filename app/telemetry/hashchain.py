import hashlib
import json

def compute_hash(prev_hash: str | None, payload: dict) -> str:
    """
    Computes a SHA-256 hash of the previous hash + the JSON payload.
    This creates a tamper-evident chain: if any record is modified,
    all subsequent hashes will be invalid.
    """
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if prev_hash:
        body = prev_hash.encode() + body
    return hashlib.sha256(body).hexdigest()