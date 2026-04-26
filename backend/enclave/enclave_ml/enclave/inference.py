"""
enclave/inference.py

Loads both trained DistilBERT models and exposes two functions:
    - infer_risk(text)  → safe | sensitive | malicious
    - infer_scope(text) → user_pii | aggregate | public | unknown
    - infer_anomaly(text) → anomaly | normal
    - infer_phishing(text) → phishing | legitimate

Used by the enclave controller at Phase 2 (risk check) and Phase 5 (scope check).
"""

import os
import torch
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from anomaly_detector import detect_anomaly
from phishing_detector import detect_phishing, get_phishing_risk_factors

# ══════════════════════════════════════════════════════════
# CONFIGURATION — update paths if your folder structure differs
# ══════════════════════════════════════════════════════════
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

RISK_MODEL_PATH  = os.path.join(MODELS_DIR, "risk_classifier")
SCOPE_MODEL_PATH = os.path.join(MODELS_DIR, "scope_classifier")

# ══════════════════════════════════════════════════════════
# LABEL DEFINITIONS
# ══════════════════════════════════════════════════════════
RISK_LABELS  = ["safe", "sensitive", "malicious"]
SCOPE_LABELS = ["user_pii", "aggregate", "public", "unknown"]

# ══════════════════════════════════════════════════════════
# MODEL LOADING — loaded once at startup, reused for all requests
# ══════════════════════════════════════════════════════════
print("🔄 Loading risk classifier...")
try:
    _risk_pipeline = pipeline(
        "text-classification",
        model     = RISK_MODEL_PATH,
        tokenizer = RISK_MODEL_PATH,
        device    = 0 if torch.cuda.is_available() else -1,
    )
except Exception as e:
    print(f"Error loading risk model: {e}")
    print("Falling back to default risk model...")
    _risk_pipeline = pipeline(
        "text-classification",
        model     = "distilbert-base-uncased-finetuned-sst-2-english",
        tokenizer = "distilbert-base-uncased-finetuned-sst-2-english",
        device    = 0 if torch.cuda.is_available() else -1,
    )
print("✅ Risk classifier loaded.")

print("🔄 Loading scope classifier...")
try:
    _scope_pipeline = pipeline(
        "text-classification",
        model     = SCOPE_MODEL_PATH,
        tokenizer = SCOPE_MODEL_PATH,
        device    = 0 if torch.cuda.is_available() else -1,
    )
except Exception as e:
    print(f"Error loading scope model: {e}")
    print("Falling back to default scope model...")
    _scope_pipeline = pipeline(
        "text-classification",
        model     = "distilbert-base-uncased-finetuned-sst-2-english",
        tokenizer = "distilbert-base-uncased-finetuned-sst-2-english",
        device    = 0 if torch.cuda.is_available() else -1,
    )
print("✅ Scope classifier loaded.")
print("✅ Both models ready.\n")

# ══════════════════════════════════════════════════════════
# PUBLIC FUNCTIONS
# ══════════════════════════════════════════════════════════

def infer_risk(text: str) -> dict:
    """
    Classify the risk level of a text query.

    Args:
        text (str): The input query from the user.

    Returns:
        dict: {
            "label":      "safe" | "sensitive" | "malicious",
            "confidence": float (0.0 to 1.0),
            "scores":     {"safe": float, "sensitive": float, "malicious": float}
        }

    Example:
        >>> result = infer_risk("DROP TABLE users;")
        >>> result["label"]       # "malicious"
        >>> result["confidence"]  # 0.999
    """
    if not text or not text.strip():
        return {
            "label":      "unknown",
            "confidence": 0.0,
            "scores":     {lbl: 0.0 for lbl in RISK_LABELS}
        }

    # get top result
    result = _risk_pipeline(text, truncation=True, max_length=128)[0]
    label      = result["label"]
    confidence = round(result["score"], 4)

    # get all scores
    all_results = _risk_pipeline(
        text,
        truncation=True,
        max_length=128,
        top_k=None
    )
    scores = {r["label"]: round(r["score"], 4) for r in all_results}

    return {
        "label":      label,
        "confidence": confidence,
        "scores":     scores
    }


def infer_scope(text: str) -> dict:
    """
    Classify the data scope of a text query.

    Args:
        text (str): The input query from the user.

    Returns:
        dict: {
            "label":      "user_pii" | "aggregate" | "public" | "unknown",
            "confidence": float (0.0 to 1.0),
            "scores":     {"user_pii": float, "aggregate": float, "public": float, "unknown": float}
        }

    Example:
        >>> result = infer_scope("What is the patient's blood type?")
        >>> result["label"]       # "user_pii"
        >>> result["confidence"]  # 0.996
    """
    if not text or not text.strip():
        return {
            "label":      "unknown",
            "confidence": 0.0,
            "scores":     {lbl: 0.0 for lbl in SCOPE_LABELS}
        }

    # get top result
    result = _scope_pipeline(text, truncation=True, max_length=128)[0]
    label      = result["label"]
    confidence = round(result["score"], 4)

    # get all scores
    all_results = _scope_pipeline(
        text,
        truncation=True,
        max_length=128,
        top_k=None
    )
    scores = {r["label"]: round(r["score"], 4) for r in all_results}

    return {
        "label":      label,
        "confidence": confidence,
        "scores":     scores
    }


def infer_anomaly(text: str) -> dict:
    """
    Detect anomalous patterns in user query using autoencoder.

    Args:
        text (str): The input query from the user.

    Returns:
        dict: {
            "is_anomaly": bool,
            "anomaly_score": float (0.0 to 1.0),
            "reconstruction_error": float,
            "threshold": float
        }
    """
    return detect_anomaly(text)


def infer_phishing(text: str) -> dict:
    """
    Detect phishing/malicious intent using BERT + heuristics.

    Args:
        text (str): The input query from the user.

    Returns:
        dict: {
            "is_phishing": bool,
            "phishing_score": float (0.0 to 1.0),
            "heuristic_score": float,
            "bert_score": float,
            "matched_patterns": list,
            "bert_label": str,
            "confidence": float
        }
    """
    return detect_phishing(text)


def infer_all(text: str) -> dict:
    """
    Run all ML classifications in one call.
    Comprehensive analysis for the enclave controller.

    Args:
        text (str): The input query from the user.

    Returns:
        dict: {
            "risk": {"label": str, "confidence": float, "scores": dict},
            "scope": {"label": str, "confidence": float, "scores": dict},
            "anomaly": {"is_anomaly": bool, "anomaly_score": float, "reconstruction_error": float, "threshold": float},
            "phishing": {"is_phishing": bool, "phishing_score": float, "heuristic_score": float, "bert_score": float, "matched_patterns": list, "bert_label": str, "confidence": float}
        }

    Example:
        >>> result = infer_all("Click here to update your bank account immediately")
        >>> result["risk"]["label"]        # "malicious"
        >>> result["phishing"]["is_phishing"] # True
        >>> result["anomaly"]["is_anomaly"] # True
    """
    return {
        "risk":     infer_risk(text),
        "scope":    infer_scope(text),
        "anomaly":  infer_anomaly(text),
        "phishing": infer_phishing(text)
    }


def infer_both(text: str) -> dict:
    """
    Run both risk and scope classification in one call.
    Convenience function for the enclave controller.

    Args:
        text (str): The input query from the user.

    Returns:
        dict: {
            "risk":  {"label": str, "confidence": float, "scores": dict},
            "scope": {"label": str, "confidence": float, "scores": dict}
        }

    Example:
        >>> result = infer_both("Show me the patient's blood pressure readings.")
        >>> result["risk"]["label"]   # "sensitive"
        >>> result["scope"]["label"]  # "user_pii"
    """
    return {
        "risk":  infer_risk(text),
        "scope": infer_scope(text),
    }


# ══════════════════════════════════════════════════════════
# QUICK TEST — runs when script is executed directly
# ══════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("🧪 INFERENCE TEST")
    print("=" * 60)

    test_cases = [
        # (text, expected_risk, expected_scope)
        ("What is the capital of France?",                "safe",      "unknown"),
        ("How do I make pasta?",                          "safe",      "unknown"),
        ("Average customer satisfaction score is 4.2.",   "sensitive", "aggregate"),
        ("Tell me more.",                                 "malicious", "unknown"),
    ]

    RISK_ICONS  = {"safe": "✅", "sensitive": "⚠️ ", "malicious": "🚨"}
    SCOPE_ICONS = {"user_pii": "🔐", "aggregate": "📊", "public": "🌍", "unknown": "❓"}

    all_correct = True
    for text, exp_risk, exp_scope in test_cases:
        result     = infer_both(text)
        risk_label = result["risk"]["label"]
        risk_conf  = round(result["risk"]["confidence"] * 100, 1)
        scope_label= result["scope"]["label"]
        scope_conf = round(result["scope"]["confidence"] * 100, 1)

        risk_icon  = RISK_ICONS.get(risk_label, "❓")
        scope_icon = SCOPE_ICONS.get(scope_label, "❓")

        risk_ok  = "✓" if risk_label  == exp_risk  else "✗"
        scope_ok = "✓" if scope_label == exp_scope else "✗"

        if risk_label != exp_risk or scope_label != exp_scope:
            all_correct = False

        print(f"{risk_icon} RISK  [{risk_label.upper():10}] {risk_conf:5.1f}% {risk_ok}  "
              f"{scope_icon} SCOPE [{scope_label.upper():10}] {scope_conf:5.1f}% {scope_ok}  "
              f"→ {text[:55]}")

    print("\n" + "=" * 60)
    if all_correct:
        print("✅ All predictions correct. Models are ready for enclave integration.")
    else:
        print("⚠️  Some predictions differ from expected. Review mismatches above.")
    print("=" * 60)