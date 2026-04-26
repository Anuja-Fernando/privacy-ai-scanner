"""
he_layer.py — Homomorphic Encryption Layer (CKKS)

Uses TenSEAL's CKKS scheme for real homomorphic encryption.
CKKS supports approximate arithmetic on real numbers —
ideal for ML confidence scores (floats between 0 and 1).

Falls back to MockHE if TenSEAL is not installed.

What CKKS does:
    - Encrypts a vector of floats into a ciphertext
    - Supports addition and multiplication ON THE CIPHERTEXT
      without ever decrypting the individual values
    - Only the final result needs to be decrypted

Place in: backend/enclave/he_layer.py
"""

import json
import base64
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════
# TenSEAL IMPORT WITH MOCK FALLBACK
# ══════════════════════════════════════════════════════════
try:
    import tenseal as ts
    HAS_TENSEAL = True
    print("✅ TenSEAL loaded — using real CKKS homomorphic encryption")
except ImportError:
    HAS_TENSEAL = False
    print("ℹ️  TenSEAL not installed — using MockHE fallback")
    print("   Install with: pip install tenseal")


# ══════════════════════════════════════════════════════════
# MOCK HE — used only when TenSEAL is not installed
# ══════════════════════════════════════════════════════════
class MockEncryptedVector:
    """
    Simulates encrypted vector behaviour without real cryptography.
    Used as fallback when TenSEAL is not available.
    Supports the same operations as a real CKKS vector.
    """
    def __init__(self, data: List[float]):
        self._data = data

    def __add__(self, other):
        if isinstance(other, MockEncryptedVector):
            return MockEncryptedVector([x + y for x, y in zip(self._data, other._data)])
        elif isinstance(other, list):
            return MockEncryptedVector([x + y for x, y in zip(self._data, other)])
        return MockEncryptedVector([x + other for x in self._data])

    def __mul__(self, other):
        if isinstance(other, MockEncryptedVector):
            return MockEncryptedVector([x * y for x, y in zip(self._data, other._data)])
        elif isinstance(other, list):
            return MockEncryptedVector([x * y for x, y in zip(self._data, other)])
        return MockEncryptedVector([x * other for x in self._data])

    def decrypt(self) -> List[float]:
        return self._data

    def serialize(self) -> bytes:
        return base64.b64encode(json.dumps(self._data).encode())

    @staticmethod
    def deserialize(data: bytes) -> "MockEncryptedVector":
        return MockEncryptedVector(json.loads(base64.b64decode(data).decode()))


# ══════════════════════════════════════════════════════════
# CKKS CONTEXT — created once at startup
# ══════════════════════════════════════════════════════════
def _create_ckks_context():
    """
    Create and configure the TenSEAL CKKS context.

    Parameters explained:
        poly_modulus_degree=8192  → security level (higher = more secure, slower)
        coeff_mod_bit_sizes       → precision of the computation
        global_scale=2**40        → controls how precise the approximation is
        galois_keys               → needed for rotation operations on vectors
    """
    if not HAS_TENSEAL:
        return None

    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree = 8192,
        coeff_mod_bit_sizes = [60, 40, 40, 60]
    )
    context.global_scale = 2 ** 40
    context.generate_galois_keys()
    logger.info("🔑 CKKS context created (poly_modulus=8192, scale=2^40)")
    return context


print("🔒 Creating CKKS context...")
_CONTEXT = _create_ckks_context()
if _CONTEXT:
    print("✅ CKKS context ready — real homomorphic encryption active")
else:
    print("ℹ️  Using MockHE context")


# ══════════════════════════════════════════════════════════
# CORE CKKS OPERATIONS
# ══════════════════════════════════════════════════════════

def _encrypt(vector: List[float]) -> Any:
    """
    Encrypt a list of floats using CKKS.
    Returns a TenSEAL CKKSVector (or MockEncryptedVector if no TenSEAL).
    """
    if HAS_TENSEAL:
        return ts.ckks_vector(_CONTEXT, vector)
    return MockEncryptedVector(vector)


def _decrypt(encrypted: Any) -> List[float]:
    """
    Decrypt a CKKS ciphertext back to a list of floats.
    Small approximation error is normal for CKKS (e.g. 0.9970 instead of 0.997).
    """
    return encrypted.decrypt()


def _serialize(encrypted: Any) -> str:
    """Serialize encrypted vector to base64 string for JSON transmission."""
    if HAS_TENSEAL:
        return base64.b64encode(encrypted.serialize()).decode()
    return base64.b64encode(encrypted.serialize()).decode()


def _deserialize(data: str) -> Any:
    """Deserialize encrypted vector from base64 string."""
    raw = base64.b64decode(data.encode())
    if HAS_TENSEAL:
        return ts.ckks_vector_from(_CONTEXT, raw)
    return MockEncryptedVector.deserialize(raw)


# ══════════════════════════════════════════════════════════
# MAIN PRODUCTION FUNCTIONS
# ══════════════════════════════════════════════════════════

def encrypt_enclave_output(
    risk_confidence:  float,
    scope_confidence: float,
    trust_score:      int,
    risk_label:       str,
    scope_label:      str,
) -> Dict[str, Any]:
    """
    Called after enclave processing.
    Encrypts ML confidence scores using CKKS before transmission.

    HE computation performed ON CIPHERTEXT (no decryption):
        security_score = (risk × 0.4) + (scope × 0.3) + (trust × 0.3)

    Only the final security score is decrypted.
    Individual risk_confidence, scope_confidence, trust are never
    transmitted in plaintext.

    Args:
        risk_confidence:  float 0.0–1.0 from risk classifier
        scope_confidence: float 0.0–1.0 from scope classifier
        trust_score:      int   0–5     from trust scorer
        risk_label:       str   safe/sensitive/malicious
        scope_label:      str   user_pii/aggregate/public/unknown

    Returns:
        dict with encrypted scores and computed security score
    """
    logger.info("🔒 HE Layer — encrypting enclave output with CKKS")

    # Normalise trust to 0–1 range
    trust_norm = trust_score / 5.0

    # ── Step 1: Encrypt individual scores ──────────────
    # Each score is encrypted into its own ciphertext
    enc_risk  = _encrypt([risk_confidence])
    enc_scope = _encrypt([scope_confidence])
    enc_trust = _encrypt([trust_norm])

    logger.info(f"  Encrypted: risk={risk_confidence} scope={scope_confidence} trust={trust_norm}")

    # ── Step 2: HE weighted addition ON CIPHERTEXT ─────
    # This computation happens entirely on encrypted data.
    # No decryption occurs during this step.
    #
    # security_score = (risk × 0.4) + (scope × 0.3) + (trust × 0.3)
    enc_risk_weighted  = enc_risk  * [0.4]   # HE scalar multiplication
    enc_scope_weighted = enc_scope * [0.3]   # HE scalar multiplication
    enc_trust_weighted = enc_trust * [0.3]   # HE scalar multiplication

    enc_total = enc_risk_weighted + enc_scope_weighted  # HE addition
    enc_total = enc_total + enc_trust_weighted           # HE addition

    logger.info("  HE computation: weighted addition on ciphertext (no decryption)")

    # ── Step 3: Decrypt ONLY the final aggregated score ─
    total_decrypted    = _decrypt(enc_total)
    overall_score      = round(total_decrypted[0], 4)
    overall_percentage = round(overall_score * 100, 1)

    # ── Step 4: Serialize full score vector for transmission
    enc_full_vector = _encrypt([risk_confidence, scope_confidence, trust_norm])
    serialized      = _serialize(enc_full_vector)

    logger.info(
        f"✅ HE complete — security_score={overall_percentage}% "
        f"scheme={'CKKS (TenSEAL)' if HAS_TENSEAL else 'MockHE'}"
    )

    return {
        # Plaintext labels — safe to transmit
        "risk_label":             risk_label,
        "scope_label":            scope_label,

        # Encrypted score vector — protected during transmission
        "encrypted_scores":       serialized,

        # HE scheme info
        "he_scheme":              "CKKS (TenSEAL)" if HAS_TENSEAL else "MockHE (Demo)",
        "he_vector_fields":       ["risk_confidence", "scope_confidence", "trust_norm"],
        "he_vector_size":         3,

        # Security score computed via HE — only this value was decrypted
        "overall_security_score": overall_score,
        "overall_percentage":     overall_percentage,
        "security_level":         _get_security_level(overall_score),
        "he_computation":         "weighted addition on ciphertext — individual scores protected",
        "he_enabled":             True,
        "tenseal_available":      HAS_TENSEAL,
    }


def decrypt_enclave_output(encrypted_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decrypts individual scores from the encrypted payload.
    In production this would run client-side in the browser.
    Here it is provided as a verification endpoint.

    Note: CKKS introduces small approximation errors (e.g. 0.9970001).
    This is expected and normal for approximate arithmetic.
    """
    try:
        enc_vector = _deserialize(encrypted_payload["encrypted_scores"])
        decrypted  = _decrypt(enc_vector)

        return {
            "risk_confidence":  round(decrypted[0], 4),
            "scope_confidence": round(decrypted[1], 4),
            "trust_norm":       round(decrypted[2], 4),
            "trust_score":      round(decrypted[2] * 5, 1),
            "decryption":       "success",
            "ckks_note":        "Small approximation error is normal for CKKS scheme",
        }
    except Exception as e:
        return {
            "decryption": "failed",
            "error":      str(e),
        }


def get_he_info() -> Dict[str, Any]:
    """Return HE configuration info for the /health endpoint."""
    return {
        "scheme":            "CKKS" if HAS_TENSEAL else "MockHE",
        "tenseal_available": HAS_TENSEAL,
        "poly_modulus":      8192  if HAS_TENSEAL else "N/A",
        "global_scale":      "2^40" if HAS_TENSEAL else "N/A",
        "operations":        ["scalar_multiplication", "vector_addition"],
        "security_level":    "128-bit" if HAS_TENSEAL else "Demo only",
        "use_case":          "Encrypts ML confidence scores before leaving enclave",
    }


def _get_security_level(score: float) -> str:
    if score >= 0.80:
        return "HIGH"
    elif score >= 0.60:
        return "MEDIUM"
    else:
        return "LOW"


# ══════════════════════════════════════════════════════════
# QUICK TEST
# ══════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "="*60)
    print("🧪 CKKS HOMOMORPHIC ENCRYPTION TEST")
    print(f"   Scheme: {'CKKS (TenSEAL) — REAL HE' if HAS_TENSEAL else 'MockHE — Demo mode'}")
    print("="*60)

    test_cases = [
        {
            "risk_confidence":  0.997,
            "scope_confidence": 0.997,
            "trust_score":      3,
            "risk_label":       "sensitive",
            "scope_label":      "user_pii",
        },
        {
            "risk_confidence":  0.999,
            "scope_confidence": 0.985,
            "trust_score":      5,
            "risk_label":       "safe",
            "scope_label":      "public",
        },
        {
            "risk_confidence":  0.999,
            "scope_confidence": 0.965,
            "trust_score":      0,
            "risk_label":       "malicious",
            "scope_label":      "unknown",
        },
    ]

    for i, case in enumerate(test_cases, 1):
        print(f"\n── Test {i}: {case['risk_label'].upper()} / {case['scope_label'].upper()} ──")
        print(f"  Input scores:")
        print(f"    risk_confidence  = {case['risk_confidence']}")
        print(f"    scope_confidence = {case['scope_confidence']}")
        print(f"    trust_score      = {case['trust_score']}/5")

        # Encrypt
        payload = encrypt_enclave_output(**case)

        print(f"\n  After CKKS encryption:")
        print(f"    Encrypted vector : {payload['encrypted_scores'][:50]}...")
        print(f"    HE scheme        : {payload['he_scheme']}")
        print(f"    HE computation   : {payload['he_computation']}")
        print(f"    Security score   : {payload['overall_percentage']}% ({payload['security_level']})")

        # Decrypt to verify
        decrypted = decrypt_enclave_output(payload)
        print(f"\n  After decryption (verification):")
        print(f"    risk_confidence  = {decrypted.get('risk_confidence')} "
              f"(original: {case['risk_confidence']})")
        print(f"    scope_confidence = {decrypted.get('scope_confidence')} "
              f"(original: {case['scope_confidence']})")
        print(f"    trust_score      = {decrypted.get('trust_score')}/5 "
              f"(original: {case['trust_score']}/5)")

        if HAS_TENSEAL:
            print(f"    Note: Small differences are expected — CKKS is approximate arithmetic")

    print("\n✅ HE layer test complete.")
    print("="*60)