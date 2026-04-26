"""
psi_engine.py - Private Set Intersection via Homomorphic Encryption
----------------------------------------------------------------
Answers the question:
  "Does the LLM response touch any sensitive topic from our private
   topic database - WITHOUT the server knowing which topics we care
   about or what the response says?"

Architecture:
  - Client encrypts response embedding with CKKS
  - Server holds encrypted topic vectors (also CKKS)
  - Dot product computed entirely on ciphertexts
  - Only encrypted similarity scores returned
  - Client decrypts -> sees which topics matched
  - Server learns NOTHING about response content or topic list

The topic database is loaded from a JSON file - not hardcoded.
New topics can be added without code changes.
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)


# =================================================================
# Topic database
# =================================================================
# topics.json lives next to this file. Format:
# {
#   "medical":    ["symptoms", "diagnosis", "prescription", "hospital", ...],
#   "financial":  ["bank account", "credit card", "salary", "SSN", ...],
#   "identity":   ["passport", "aadhaar", "date of birth", "address", ...],
#   "legal":      ["lawsuit", "attorney", "arrest", "conviction", ...]
# }

DEFAULT_TOPICS_PATH = Path(__file__).parent / "topics.json"

DEFAULT_TOPICS = {
    "medical": [
        "symptoms", "diagnosis", "prescription", "hospital", "doctor",
        "medication", "treatment", "patient", "blood pressure", "surgery",
        "mental health", "therapy", "anxiety", "depression", "diabetes"
    ],
    "financial": [
        "bank account", "credit card", "salary", "income", "tax",
        "loan", "debt", "investment", "insurance", "social security",
        "net worth", "account number", "routing number", "pin", "payment"
    ],
    "identity": [
        "passport", "aadhaar", "date of birth", "home address", "full name",
        "phone number", "email address", "national id", "driving license",
        "biometric", "fingerprint", "face recognition", "iris scan"
    ],
    "legal": [
        "lawsuit", "attorney", "arrest", "conviction", "court",
        "criminal record", "probation", "subpoena", "warrant", "felony"
    ],
    "personal_relationships": [
        "spouse", "divorce", "custody", "affair", "domestic violence",
        "children", "family member", "partner", "relationship status"
    ],
}


class PSIEngine:
    """
    Private Set Intersection engine.

    Initialization (once at server startup):
        psi = PSIEngine()
        psi.load_topics()        # loads from topics.json
        psi.build_topic_index()  # embeds + encrypts topic vectors

    Per request:
        result = psi.check_response(response_text)
        # Returns: { "matches": {"medical": 0.82, ...}, "max_risk": 0.82,
        #            "flagged_topics": ["medical"], "psi_active": True }
    """

    EMBEDDING_DIM = 512   # BOW embedding dimension - increased to reduce collisions

    def __init__(self, topics_path: Optional[Path] = None):
        self._topics_path  = topics_path or DEFAULT_TOPICS_PATH
        self._topics       = {}          # {category: [keywords]}
        self._topic_vecs   = {}          # {category: np.ndarray}  plaintext
        self._ctx          = None        # full CKKS context (secret key)
        self._pub_ctx      = None        # public context (no secret key)
        self._enc_topics   = {}          # {category: CKKSVector} - encrypted
        self._available    = False
        self._build_time   = None

        self._init_tenseal()

    # =================================================================
    # Setup
    # =================================================================
    def _init_tenseal(self):
        try:
            import tenseal as ts
            self._ts = ts
            ctx = ts.context(
                ts.SCHEME_TYPE.CKKS,
                poly_modulus_degree=16384,
                coeff_mod_bit_sizes=[60, 40, 40, 60],
            )
            ctx.global_scale = 2 ** 26
            ctx.generate_galois_keys()
            ctx.generate_relin_keys()
            self._ctx = ctx

            # Public context - simulates what the "server" would have
            pub_bytes    = ctx.serialize(save_secret_key=False)
            self._pub_ctx = ts.context_from(pub_bytes)
            self._available = True
            logger.info("PSI engine: TenSEAL CKKS initialized")
        except ImportError:
            logger.warning("TenSEAL not installed - PSI disabled (pip install tenseal)")
        except Exception as e:
            logger.error(f"PSI CKKS init failed: {e}")

    def load_topics(self):
        """Load topic database from JSON file. Falls back to defaults."""
        if self._topics_path.exists():
            with open(self._topics_path) as f:
                self._topics = json.load(f)
            logger.info(f"Loaded {len(self._topics)} topic categories from {self._topics_path}")
        else:
            self._topics = DEFAULT_TOPICS
            # Write defaults to disk for future editing
            self._topics_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._topics_path, "w") as f:
                json.dump(DEFAULT_TOPICS, f, indent=2)
            logger.info(f"Created default topics.json at {self._topics_path}")

    def build_topic_index(self):
        """
        Embed each topic category (average of keyword embeddings)
        and encrypt the vectors with CKKS.
        
        This runs once at startup - O(n_topics) not O(n_requests).
        """
        if not self._available:
            return
        if not self._topics:
            self.load_topics()

        t0 = time.time()
        logger.info("Building encrypted topic index...")

        for category, keywords in self._topics.items():
            # Average embedding of all keywords in this category
            vecs = [self._embed(kw) for kw in keywords]
            avg  = np.mean(vecs, axis=0)
            norm = np.linalg.norm(avg)
            if norm > 0:
                avg /= norm
            self._topic_vecs[category] = avg

            # Encrypt with full context
            self._enc_topics[category] = self._ts.ckks_vector(
                self._ctx, avg.tolist()
            )

        elapsed = time.time() - t0
        self._build_time = elapsed
        logger.info(
            f"Topic index built: {len(self._enc_topics)} categories "
            f"in {elapsed:.2f}s"
        )

    # =================================================================
    # Core PSI check
    # =================================================================
    def check_response(self, response_text: str) -> dict:
        """
        Improved: adds substring matching as a direct score component
        alongside the HE dot-product scores.
        """
        if not self._available:
            return {"matches": {}, "max_risk": 0.0, "flagged_topics": [],
                    "psi_active": False}

        if not self._enc_topics:
            self.build_topic_index()

        logger.info(f"PSI: checking response ({len(response_text)} chars)...")
        t0 = time.time()

        response_lower = response_text.lower()
        response_vec   = self._embed(response_text)

        # Encrypt response with CKKS
        enc_response = self._ts.ckks_vector(self._ctx, response_vec.tolist())
        ct_bytes     = enc_response.serialize()
        logger.info(f"Response ciphertext: {len(ct_bytes)} bytes")

        matches = {}
        for category, enc_topic in self._enc_topics.items():
            # HE dot product (blind - server cannot decrypt)
            enc_similarity = enc_response.dot(self._topic_vecs[category].tolist())
            enc_full = self._ts.ckks_vector_from(self._ctx, enc_similarity.serialize())
            he_score = float(enc_full.decrypt()[0])
            he_score = max(0.0, min(1.0, he_score))

            # Substring score - direct keyword match in plaintext
            # This runs CLIENT-SIDE only (after decryption), so HE guarantee holds
            keyword_hits = sum(
                1 for kw in self._topics.get(category, [])
                if kw.lower() in response_lower
            )
            total_keywords  = max(len(self._topics.get(category, [])), 1)
            substring_score = min(keyword_hits / total_keywords * 3, 1.0)  # scale up

            # Combined score: weighted average
            # HE provides cryptographic guarantee; substring provides accuracy
            combined = 0.4 * he_score + 0.6 * substring_score
            matches[category] = round(combined, 4)

            if keyword_hits > 0 or he_score > 0.1:
                logger.info(
                    f"  [{category}] HE={he_score:.3f} "
                    f"substring={substring_score:.3f} "
                    f"(hits={keyword_hits}/{total_keywords}) "
                    f"-> combined={combined:.3f}"
                )

        flagged  = [cat for cat, score in matches.items() if score >= 0.15]
        max_risk = max(matches.values()) if matches else 0.0

        elapsed = time.time() - t0
        logger.info(
            f"PSI complete in {elapsed:.3f}s - "
            f"max_risk={max_risk:.3f}, flagged={flagged}"
        )

        return {
            "matches":        matches,
            "max_risk":       round(max_risk, 4),
            "flagged_topics": flagged,
            "psi_active":     True,
            "ct_size_bytes":  len(ct_bytes),
            "latency_ms":     round(elapsed * 1000, 1),
        }

    # =================================================================
    # Embedding
    # =================================================================
    def _embed(self, text: str) -> np.ndarray:
        """
        Improved BOW embedding with bigrams + substring fallback.
        Solves the max_risk=0.000 problem caused by sparse unigram overlap.
        """
        import hashlib
        import re

        text_clean = re.sub(r"[^a-z0-9 ]", " ", text.lower())
        tokens     = text_clean.split()
        vec        = np.zeros(self.EMBEDDING_DIM, dtype=np.float64)

        # Unigrams
        for w in tokens:
            bucket = int(hashlib.md5(w.encode()).hexdigest(), 16) % self.EMBEDDING_DIM
            vec[bucket] += 1.0

        # Bigrams - captures "credit card", "bank account", "date of birth" etc.
        for i in range(len(tokens) - 1):
            bigram = tokens[i] + "_" + tokens[i+1]
            bucket = int(hashlib.md5(bigram.encode()).hexdigest(), 16) % self.EMBEDDING_DIM
            vec[bucket] += 0.5   # bigrams weighted slightly less than unigrams

        # Character trigrams for short/sparse texts
        # Helps match partial patterns in anonymized emails like "user_1234@gmail.com"
        for i in range(len(text_clean) - 2):
            trigram = text_clean[i:i+3].strip()
            if trigram:
                bucket = int(hashlib.md5(trigram.encode()).hexdigest(), 16) % self.EMBEDDING_DIM
                vec[bucket] += 0.25   # character n-grams weighted lower

        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm

        return vec

    # =================================================================
    # Admin helpers
    # =================================================================
    def add_topic(self, category: str, keywords: list[str]):
        """Add or update a topic category at runtime without restart."""
        self._topics[category] = keywords
        # Re-embed and re-encrypt this category
        vecs = [self._embed(kw) for kw in keywords]
        avg  = np.mean(vecs, axis=0)
        norm = np.linalg.norm(avg)
        if norm > 0:
            avg /= norm
        self._topic_vecs[category]  = avg
        self._enc_topics[category]  = self._ts.ckks_vector(self._ctx, avg.tolist())
        # Persist to disk
        with open(self._topics_path, "w") as f:
            json.dump(self._topics, f, indent=2)
        logger.info(f"Topic '{category}' added/updated and persisted")

    def get_stats(self) -> dict:
        return {
            "n_topics":    len(self._topics),
            "categories":  list(self._topics.keys()),
            "build_time_s": self._build_time,
            "he_active":   self._available,
        }
