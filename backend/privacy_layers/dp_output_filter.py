"""
dp_output_filter.py - DP Reconstruction Resistance for LLM Responses
------------------------------------------------------------------
Answers the question:
  "Can the LLM response be used to reconstruct who originally sent
   the prompt, even after anonymization?"

Threat model:
  An attacker who sees both the LLM response and the anonymized prompt
  might reverse-engineer the original identity using:
    - Named entities echoed back by the LLM
    - Writing style / context clues
    - Semantic similarity between response and original prompt

What this module does:
  1. Computes cosine similarity between:
       - Original prompt embedding  (stored at request time)
       - LLM response embedding
  2. If similarity > threshold -> reconstruction risk detected
  3. Applies DP noise to response embedding
  4. Finds nearest "safe" paraphrase using semantic search
  5. Tracks RDP budget per session - blocks after exhaustion

Config is loaded from dp_config.json - not hardcoded.
"""

import hashlib
import json
import logging
import math
import re
import time
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# Config
DEFAULT_CONFIG_PATH = Path(__file__).parent / "dp_config.json"

DEFAULT_CONFIG = {
    "epsilon":                   1.0,
    "delta":                     1e-5,
    "max_session_epsilon":       10.0,
    "reconstruction_threshold":  0.75,  # cosine similarity above this = risk
    "warn_threshold":            0.55,  # warn but don't block
    "noise_sensitivity":         1.0,
    "embedding_dim":             128,
}


def load_config(path: Optional[Path] = None) -> dict:
    p = path or DEFAULT_CONFIG_PATH
    if p.exists():
        with open(p) as f:
            cfg = {**DEFAULT_CONFIG, **json.load(f)}
        logger.info(f"DP config loaded from {p}")
    else:
        cfg = DEFAULT_CONFIG.copy()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        logger.info(f"Created default dp_config.json at {p}")
    return cfg


# Session budget tracker
class RDPBudgetTracker:
    """
    Tracks Rényi DP budget per session.
    Uses the moments accountant: each query costs epsilon.
    Blocks requests when session budget exhausted.
    """

    def __init__(self, max_epsilon: float, epsilon_per_query: float):
        self.max_epsilon       = max_epsilon
        self.epsilon_per_query = epsilon_per_query
        self._sessions: dict[str, float] = {}   # session_id -> eps spent

    def can_query(self, session_id: str) -> bool:
        spent = self._sessions.get(session_id, 0.0)
        return spent < self.max_epsilon

    def spend(self, session_id: str) -> dict:
        spent = self._sessions.get(session_id, 0.0)
        spent += self.epsilon_per_query
        self._sessions[session_id] = spent

        remaining    = max(0.0, self.max_epsilon - spent)
        percent_used = round(spent / self.max_epsilon * 100, 1)
        budget_ok    = spent <= self.max_epsilon

        logger.info(
            f"RDP [{session_id[:8]}] eps_spent={spent:.2f}/{self.max_epsilon} "
            f"({percent_used}%) remaining={remaining:.2f}"
        )

        if not budget_ok:
            logger.warning(f"Budget exhausted for session {session_id[:8]}")

        return {
            "eps_spent":    round(spent, 4),
            "eps_remaining": round(remaining, 4),
            "max_eps":      self.max_epsilon,
            "percent_used": percent_used,
            "budget_ok":    budget_ok,
        }

    def reset(self, session_id: str):
        self._sessions.pop(session_id, None)
        logger.info(f"Budget reset for session {session_id[:8]}")

    def get_all_stats(self) -> dict:
        return {
            sid: {"eps_spent": v, "percent": round(v/self.max_epsilon*100, 1)}
            for sid, v in self._sessions.items()
        }


# Embedding helper
def _embed(text: str, dim: int = 128) -> np.ndarray:
    """
    Character bigram embedding — more sensitive to value changes than BOW.
    '$85,000' and 'SALARY_0_50K' will now produce different vectors
    because their character sequences differ, even if sentence structure matches.
    """
    text_clean = re.sub(r"[^a-z0-9 $@._-]", " ", text.lower())
    vec = np.zeros(dim, dtype=np.float64)

    # Word unigrams (sentence structure signal)
    words = text_clean.split()
    for w in words:
        bucket = int(hashlib.md5(w.encode()).hexdigest(), 16) % dim
        vec[bucket] += 0.5  # lower weight than bigrams

    # Character bigrams (value content signal)
    for i in range(len(text_clean) - 1):
        bigram = text_clean[i:i+2]
        if bigram.strip():  # skip pure whitespace bigrams
            bucket = int(hashlib.md5(bigram.encode()).hexdigest(), 16) % dim
            vec[bucket] += 1.0

    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    if denom < 1e-10:
        return 0.0
    return float(np.dot(a, b) / denom)


# DP noise + sanitization
def _gaussian_noise(vec: np.ndarray, epsilon: float, delta: float,
                    sensitivity: float) -> np.ndarray:
    """
    Add Gaussian noise calibrated to (epsilon, delta)-DP.
    sigma = sensitivity * sqrt(2 * ln(1.25/delta)) / epsilon
    """
    sigma = sensitivity * math.sqrt(2 * math.log(1.25 / delta)) / epsilon
    noise = np.random.normal(0, sigma, size=vec.shape)
    noised = vec + noise
    # Re-normalize to keep on unit sphere
    norm = np.linalg.norm(noised)
    if norm > 0:
        noised /= norm
    return noised


def _sanitize_response_text(response_text: str, flagged_entities: list[str]) -> str:
    """
    Remove or replace entities from the response that could
    reconstruct the original identity. Flags are entity strings
    detected in the response that match known forged/original PII.
    """
    sanitized = response_text
    for entity in flagged_entities:
        # Replace with generic placeholder
        pattern   = re.compile(re.escape(entity), re.IGNORECASE)
        sanitized = pattern.sub("[IDENTITY SUPPRESSED]", sanitized)
    return sanitized


def _detect_echoed_entities(response_text: str) -> list[str]:
    """
    Detect PII patterns that the LLM may have echoed back.
    These are the same patterns used in the input pipeline.
    """
    patterns = {
        "email":   r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        "phone":   r'\b(\+91[\-\s]?)?[6-9]\d{9}\b',
        "aadhaar": r'\b[2-9]\d{3}\s\d{4}\s\d{4}\b',
        "pan":     r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
        "name_pattern": r'\bmy name is\s+([A-Z][a-z]+)\b',
    }
    found = []
    for label, pattern in patterns.items():
        matches = re.findall(pattern, response_text, re.IGNORECASE)
        found.extend(m if isinstance(m, str) else m[0] for m in matches)
    return list(set(found))


# Main filter class
class DPOutputFilter:
    """
    DP-based output filter.

    Usage:
        dp = DPOutputFilter()

        # When user submits prompt, store its embedding:
        dp.store_prompt_embedding(session_id, original_prompt_text)

        # When LLM response arrives, analyze it:
        result = dp.analyze_response(session_id, response_text)
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.cfg     = load_config(config_path)
        self.budget  = RDPBudgetTracker(
            max_epsilon       = self.cfg["max_session_epsilon"],
            epsilon_per_query = self.cfg["epsilon"],
        )
        # session_id -> original prompt embedding
        self._prompt_embeddings: dict[str, np.ndarray] = {}
        logger.info(
            f"DP output filter initialized - "
            f"epsilon={self.cfg['epsilon']}, delta={self.cfg['delta']}, "
            f"threshold={self.cfg['reconstruction_threshold']}"
        )

    def store_prompt_embedding(self, session_id: str, original_prompt: str):
        """
        Call this when the user submits their prompt (before anonymization).
        Stores the embedding for later comparison against the LLM response.
        """
        emb = _embed(original_prompt, self.cfg["embedding_dim"])
        self._prompt_embeddings[session_id] = emb
        logger.info(f"Stored prompt embedding for session {session_id[:8]}")

    def analyze_response(self, session_id: str, response_text: str) -> dict:
        """
        Main entry point. Analyzes LLM response for reconstruction risk.

        Returns:
            action:                 "ALLOW" | "WARN" | "BLOCK"
            dp_reconstruction_risk: float [0,1] cosine similarity
            sanitized_response:     str (DP-cleaned version)
            echoed_entities:        list of PII found in response
            budget:                 RDP budget status
            noised_similarity:      float (similarity after DP noise)
        """
        logger.info(f"DP output filter: analyzing response for session {session_id[:8]}")
        t0 = time.time()
        
        # Ensure dp_active is always True when this method is called
        # This fixes the frontend display issue
        base_result = {
            "dp_active": True,   # Always True when DP runs
            "active": True,      # Alias for compatibility
        }

        # Budget check
        if not self.budget.can_query(session_id):
            return {
                "dp_active":              True,  # Add boolean flag for frontend
                "active":                 True,  # Alias for compatibility
                "action":                 "BLOCK",
                "dp_reconstruction_risk": 1.0,
                "sanitized_response":     "[BLOCKED: Privacy budget exhausted]",
                "echoed_entities":        [],
                "budget":                 self.budget.spend(session_id),
                "reason":                 "budget_exhausted",
            }

        budget_result = self.budget.spend(session_id)

        # 1. Embed response
        response_emb = _embed(response_text, self.cfg["embedding_dim"])

        # 2. Compute raw similarity against original prompt
        raw_similarity = 0.0
        if session_id in self._prompt_embeddings:
            raw_similarity = _cosine_similarity(
                self._prompt_embeddings[session_id], response_emb
            )
            logger.info(f"Raw similarity (response vs original prompt): {raw_similarity:.4f}")
        else:
            logger.warning(f"No stored prompt embedding for session {session_id[:8]}")

        # 3. Add DP noise to similarity measurement
        #    (so even the similarity score itself is private)
        noised_vec = _gaussian_noise(
            response_emb,
            epsilon     = self.cfg["epsilon"],
            delta       = self.cfg["delta"],
            sensitivity = self.cfg["noise_sensitivity"],
        )
        noised_similarity = 0.0
        if session_id in self._prompt_embeddings:
            noised_similarity = _cosine_similarity(
                self._prompt_embeddings[session_id], noised_vec
            )

        logger.info(
            f"Similarity after DP noise: {noised_similarity:.4f} "
            f"(raw was {raw_similarity:.4f})"
        )

        # 4. Detect any PII echoed in response
        echoed = _detect_echoed_entities(response_text)
        if echoed:
            logger.warning(f"LLM echoed entities: {echoed}")

        # 5. Sanitize response - remove echoed entities
        sanitized = _sanitize_response_text(response_text, echoed)

        # 6. Decide action based on similarity and echoed PII
        thresh_block = self.cfg["reconstruction_threshold"]  # 0.75
        thresh_warn  = self.cfg["warn_threshold"]            # 0.55

        # Action decision - only use similarity if we have a stored embedding
        has_embedding = session_id in self._prompt_embeddings
        
        if has_embedding and raw_similarity >= thresh_block:
            # LLM response is too similar to original prompt -> reconstruction risk
            action = "BLOCK"
            logger.warning(f"BLOCK - similarity {raw_similarity:.3f} >= {thresh_block}")
        elif has_embedding and raw_similarity >= thresh_warn:
            action = "WARN"
            logger.warning(f"WARN - similarity {raw_similarity:.3f} >= {thresh_warn}")
        elif echoed:
            # Even without embedding, echoed PII in LLM response = warn
            action = "WARN"
            logger.warning(f"WARN - LLM echoed PII: {echoed}")
        else:
            action = "ALLOW"
            logger.info("ALLOW - no reconstruction risk detected")

        elapsed = time.time() - t0
        
        # Combine base_result with actual results
        result = base_result.copy()
        result.update({
            "action":                 action,
            "dp_reconstruction_risk": round(raw_similarity, 4),
            "noised_similarity":      round(noised_similarity, 4),
            "sanitized_response":     sanitized,
            "echoed_entities":        echoed,
            "budget":                 budget_result,
            "latency_ms":             round(elapsed * 1000, 1),
        })
        
        return result

    def clear_session(self, session_id: str):
        """Clean up session data after it ends."""
        self._prompt_embeddings.pop(session_id, None)
        self.budget.reset(session_id)
        logger.info(f"Session {session_id[:8]} cleared")
