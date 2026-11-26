import hashlib
import hmac

SIGNATURE_ALG = "HMAC-SHA256"


def derive_key_id(signing_key: str) -> str:
    """Derive a non-secret 8-char key identifier from the active signing key."""
    digest = hashlib.sha256(signing_key.encode("utf-8")).hexdigest()
    return f"hmac-{digest[:8]}"


def sign_bundle_manifest(
    *,
    manifest_sha256: str,
    chain_head_hash: str,
    signing_key: str,
) -> dict[str, str]:
    """Sign a compiled evidence bundle's manifest and chain head using HMAC-SHA256."""
    payload = f"{manifest_sha256}:{chain_head_hash}".encode()
    sig_hex = hmac.new(signing_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return {
        "signature_alg": SIGNATURE_ALG,
        "signature_key_id": derive_key_id(signing_key),
        "signature_hex": sig_hex,
    }


def verify_bundle_signature(
    *,
    manifest_sha256: str,
    chain_head_hash: str,
    signature_hex: str,
    signing_key: str,
) -> bool:
    """Verify an evidence bundle HMAC-SHA256 signature in constant time."""
    expected = sign_bundle_manifest(
        manifest_sha256=manifest_sha256,
        chain_head_hash=chain_head_hash,
        signing_key=signing_key,
    )["signature_hex"]
    return hmac.compare_digest(signature_hex.strip().lower(), expected.lower())
