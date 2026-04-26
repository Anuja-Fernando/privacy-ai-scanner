import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from inference import infer_risk, infer_scope, infer_anomaly, infer_phishing, infer_all
from policy_engine import policy_engine, DataSensitivityLevel

from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import logging
import hashlib
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════
# PII REGEX DETECTOR
# ══════════════════════════════════════════════════════════

PII_PATTERNS = {
    "email":       r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    "phone_india": r'\b(\+91[\-\s]?)?[6-9]\d{9}\b',
    "phone_us":    r'\b\(?\d{3}\)?[\-\s]\d{3}[\-\s]\d{4}\b',
    "aadhaar":     r'\b[2-9]\d{3}\s\d{4}\s\d{4}\b',
    "pan":         r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
    "credit_card": r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
    "ssn":         r'\b\d{3}-\d{2}-\d{4}\b',
    "dob":         r'\b(born|dob|date of birth)\b',
    "address":     r'\b(i live at|my address is|residing at)\b',
    "name_signal": r'\b(my name is|i am called|call me)\s+[A-Z][a-z]+',
    # FIX 2 — salary pattern now captures full amount incl. commas
    "salary":      r'\$[\d,]+(?:\.\d+)?',
}

# Salary bucketing labels
SALARY_BUCKETS = [
    (25_000,   "$0–25k"),
    (50_000,   "$25k–50k"),
    (100_000,  "$50k–100k"),
    (200_000,  "$100k–200k"),
    (float("inf"), "$200k+"),
]

def _bucket_salary(amount: int) -> str:
    for cap, label in SALARY_BUCKETS:
        if amount <= cap:
            return label
    return "$200k+"

def detect_pii_override(text: str) -> Dict[str, Any]:
    detected = []
    for pii_type, pattern in PII_PATTERNS.items():
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pii_type)
    has_pii = len(detected) > 0
    return {
        "has_pii":       has_pii,
        "detected":      detected,
        "override_risk": "sensitive" if has_pii else None,
    }


# ══════════════════════════════════════════════════════════
# PHASE 1 — TRUST SCORER
# ══════════════════════════════════════════════════════════
class TrustScorer:
    def __init__(self):
        self.trust_factors = {
            "mfa_verified":       2,
            "session_fresh":      1,
            "verified_extension": 1,
            "low_anomaly":        1,
        }
        self.max_trust_score = 5

    def compute_trust_score(self, jwt_claims, request_metadata):
        logger.info("🔍 Phase 1 — Computing trust score...")
        trust_score     = 0
        trust_breakdown = {}

        mfa_score = self._check_mfa_verification(jwt_claims)
        trust_score += mfa_score
        trust_breakdown["mfa_verified"] = mfa_score
        logger.info(f"🔐 MFA score: {mfa_score}")

        session_score = self._check_session_age(jwt_claims)
        trust_score += session_score
        trust_breakdown["session_fresh"] = session_score
        logger.info(f"⏰ Session score: {session_score}")

        extension_score = self._check_extension_verification(jwt_claims, request_metadata)
        trust_score += extension_score
        trust_breakdown["verified_extension"] = extension_score
        logger.info(f"🔗 Extension score: {extension_score}")

        anomaly_score = self._check_anomaly_score(jwt_claims, request_metadata)
        trust_score += anomaly_score
        trust_breakdown["low_anomaly"] = anomaly_score
        logger.info(f"📊 Anomaly score: {anomaly_score}")

        trust_score = min(trust_score, self.max_trust_score)
        logger.info(f"🎯 Trust score: {trust_score}/{self.max_trust_score}")

        return {
            "trust_score": trust_score,
            "max_score":   self.max_trust_score,
            "breakdown":   trust_breakdown,
            "computed_at": datetime.utcnow().isoformat(),
            "phase":       "trust_computation",
        }

    def _check_mfa_verification(self, jwt_claims):
        mfa_verified = jwt_claims.get("mfa_verified", False)
        mfa_time     = jwt_claims.get("mfa_verified_at")
        if mfa_verified and mfa_time:
            try:
                mfa_dt = datetime.fromisoformat(mfa_time.replace("Z", "+00:00"))
                if datetime.utcnow() - mfa_dt.replace(tzinfo=None) < timedelta(hours=24):
                    logger.info("✅ MFA verified within 24 hours")
                    return self.trust_factors["mfa_verified"]
                logger.info("⚠️  MFA verification expired")
            except Exception:
                logger.info("⚠️  Invalid MFA timestamp")
        else:
            logger.info("❌ No MFA verification found")
        return 0

    def _check_session_age(self, jwt_claims):
        session_start = jwt_claims.get("auth_time") or jwt_claims.get("iat")
        if session_start:
            try:
                session_dt  = datetime.fromtimestamp(session_start)
                session_age = datetime.utcnow() - session_dt
                if session_age < timedelta(hours=1):
                    logger.info("✅ Fresh session (<1 hour)")
                    return self.trust_factors["session_fresh"]
                elif session_age < timedelta(hours=24):
                    logger.info("⚠️  Session is moderate age (1-24 hours)")
                else:
                    logger.info("❌ Session is old (>24 hours)")
            except Exception:
                logger.info("⚠️  Invalid session timestamp")
        return 0

    def _check_extension_verification(self, jwt_claims, request_metadata):
        extension_id        = jwt_claims.get("extension_id")
        verified_extensions = ["njbpnodfjkoahlomcnbmghohfpdkcbki"]
        if extension_id and extension_id in verified_extensions:
            logger.info(f"✅ Verified extension: {extension_id}")
            return self.trust_factors["verified_extension"]
        logger.info("❌ No valid extension ID")
        return 0

    def _check_anomaly_score(self, jwt_claims, request_metadata):
        anomaly    = 0
        ip_address = request_metadata.get("ip_address")
        known_ips  = jwt_claims.get("known_ips", [])
        if ip_address and ip_address in known_ips:
            logger.info("✅ Known IP address")
            anomaly += 1
        else:
            logger.info(f"⚠️  New IP: {ip_address}")

        if jwt_claims.get("request_count_24h", 0) < 100:
            logger.info("✅ Normal request frequency")
            anomaly += 1

        req_loc   = request_metadata.get("location")
        known_loc = jwt_claims.get("location")
        if req_loc and known_loc and req_loc == known_loc:
            logger.info("✅ Known location")
            anomaly += 1

        return self.trust_factors["low_anomaly"] if anomaly >= 2 else 0


# ══════════════════════════════════════════════════════════
# ENCLAVE CONTROLLER — 7-PHASE PIPELINE
# ══════════════════════════════════════════════════════════
class EnclaveController:
    """
    FIXED phase order (was scrambled before):
    Phase 1   → Trust scoring
    Phase 2   → PII override check (regex)
    Phase 2b  → Risk classification (ML)
    Phase 2c  → Advanced ML analysis (anomaly + phishing)
    Phase 2d  → HE/PSI on ORIGINAL text  ← runs ONCE here only
    Phase 3   → Policy gate
    Phase 4   → Privacy processing (anonymize)
    Phase 4b  → DP output filter  ← BLOCK now propagates correctly
    Phase 5   → Scope classification
    Phase 3a  → Policy security (GDPR/DPDP)
    Phase 6   → Response filtering
    Phase 7   → Audit logging
    """

    TRUST_THRESHOLDS = {
        "safe":      0,
        "sensitive": 2,
        "malicious": 99,
    }

    def __init__(self):
        self.trust_scorer     = TrustScorer()
        self.psi_engine       = None
        self.dp_filter        = None
        self.processing_stats = {
            "total_requests":        0,
            "successful_processing": 0,
            "failed_processing":     0,
            "blocked_malicious":     0,
            "blocked_low_trust":     0,
            "blocked_dp":            0,
            "trust_scores":          {},
            "pii_overrides":         0,
            "he_checks":             0,
            "dp_checks":             0,
        }

    def set_engines(self, psi_engine, dp_filter):
        self.psi_engine = psi_engine
        self.dp_filter  = dp_filter
        logger.info("✅ PSI + DP engines registered in enclave controller")

    # ──────────────────────────────────────────────────────
    # MAIN ENTRY POINT
    # ──────────────────────────────────────────────────────
    def process_ml_inference(self, packaged_request: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"🔒 Enclave received: {packaged_request.get('operation')}")
        self.processing_stats["total_requests"] += 1

        try:
            text             = packaged_request.get("text", "")
            operation        = packaged_request.get("operation", "")
            user_claims      = packaged_request.get("user_claims", {})
            request_metadata = packaged_request.get("request_metadata", {})
            session_id       = packaged_request.get("session_id", "")

            logger.info(f"📝 Text   : {text[:60]}...")
            logger.info(f"👤 User   : {user_claims.get('sub', 'unknown')}")
            logger.info(f"🔧 Op     : {operation}")

            # ── Phase 1: Trust Scoring ──────────────────────
            trust_result = self._phase1_trust(user_claims, request_metadata)
            trust_score  = trust_result["trust_score"]

            # ── Phase 2: PII Override Check ─────────────────
            pii_check   = self._phase2_pii_override(text)

            # ── Phase 2b: Risk Classification (ML) ──────────
            risk_result = self._phase2b_risk(text, pii_check)
            risk_label  = risk_result["label"]
            risk_conf   = risk_result["confidence"]

            # ── Phase 2c: Advanced ML Analysis ──────────────
            ml_analysis       = self._phase2c_advanced_ml(text)
            anomaly_detected  = ml_analysis["anomaly"]["is_anomaly"]
            phishing_detected = ml_analysis["phishing"]["is_phishing"]

            # ── Phase 2d: HE PSI on ORIGINAL text ───────────
            # FIX 4 — runs ONCE here only (was incorrectly run twice before)
            he_result = self._phase2d_he_psi(text)

            # ── Phase 3: Policy Gate ─────────────────────────
            gate_result = self._phase3_policy_gate(
                trust_score, risk_label, risk_conf,
                anomaly_detected, phishing_detected,
                he_result=he_result
            )
            if gate_result["action"] == "block":
                self.processing_stats["failed_processing"] += 1
                if risk_label == "malicious":
                    self.processing_stats["blocked_malicious"] += 1
                else:
                    self.processing_stats["blocked_low_trust"] += 1
                return self._blocked_response(gate_result, trust_result, risk_result)

            # ── Phase 4: Privacy Processing ──────────────────
            anonymized_text = self._phase4_privacy_processing(text)

            # Store anonymized prompt embedding for DP similarity baseline
            # FIX: Store AFTER anonymization so DP compares response vs anonymized prompt
            if self.dp_filter and session_id:
                self.dp_filter.store_prompt_embedding(session_id, anonymized_text)

            # ── Phase 4b: DP Output Filter ───────────────────
            # FIX 1 — BLOCK from DP now returns early and stops the pipeline
            logger.info(f"DEBUG: About to call DP filter with session_id={session_id}")
            dp_result = self._phase4b_dp_filter(
                anonymized_text, session_id, risk_label, risk_conf
            )
            logger.info(f"DEBUG dp_filter result: {dp_result}")

            if dp_result.get("action") == "BLOCK":
                self.processing_stats["failed_processing"] += 1
                self.processing_stats["blocked_dp"] += 1
                logger.warning("🚨 DP BLOCK — stopping pipeline, request rejected")
                return self._dp_blocked_response(dp_result, trust_result, risk_result)

            # ── Phase 5: Scope Classification ────────────────
            scope_result = self._phase5_scope(anonymized_text)
            scope_label  = scope_result["label"]

            # ── Phase 3a: Policy Security (GDPR/DPDP) ────────
            # FIX 7 — moved AFTER scope (needs scope_label) and AFTER DP
            policy_result = self._phase3a_policy_security(
                scope_label, user_claims, operation,
                risk_label, trust_score, text
            )
            if not policy_result["allowed"]:
                self.processing_stats["failed_processing"] += 1
                return self._policy_blocked_response(
                    policy_result, trust_result, risk_result, scope_result
                )

            # ── Phase 6: Response Filtering ──────────────────
            filtered_output = self._phase6_response_filter(
                anonymized_text, scope_label, trust_score
            )

            # ── Phase 7: Audit Logging ────────────────────────
            audit_log = self._phase7_audit(
                text, user_claims, trust_result,
                risk_result, scope_result, gate_result,
                ml_analysis.get("comprehensive", {}),
                he_result, dp_result=dp_result
            )

            self.processing_stats["successful_processing"] += 1
            logger.info("✅ All phases completed successfully")

            return {
                "status":   "success",
                "result":   filtered_output,
                "metadata": {
                    "phase":         "complete",
                    "trust_score":   trust_result,
                    "risk_result":   risk_result,
                    "scope_result":  scope_result,
                    "gate_decision": gate_result,
                    "policy_result": policy_result,
                    "audit_id":      audit_log["audit_id"],
                    "processed_by":  "enclave",
                    "privacy_level": self._get_privacy_level(
                        policy_result.get("sensitivity_level", "standard")
                    ),
                    "user_id":    user_claims.get("sub", "anonymous"),
                    "advanced_ml": ml_analysis.get("comprehensive", {}),
                    "pii_check":   pii_check,
                    "pii_detected": pii_check.get("detected", []),
                    # FIX 3 & 5 — unified key: always use "active", never "psi_active"/"dp_active"
                    "he": {
                        "active":         he_result.get("active", False),
                        "flagged_topics": he_result.get("flagged_topics", []),
                        "max_risk":       he_result.get("max_risk", 0),
                        "ct_size_bytes":  he_result.get("ct_size_bytes", 0),
                        "note": "HE ran on original text — detects sensitive topics in user input",
                    },
                    "dp": {
                        "note":                "DP ran on anonymized text",
                        "active":              dp_result.get("active", False),
                        "action":              dp_result.get("action", "N/A"),
                        "reconstruction_risk": dp_result.get("dp_reconstruction_risk", 0),
                        "noised_similarity":   dp_result.get("noised_similarity", 0),
                        "budget":              dp_result.get("budget", {}),
                        "echoed_entities":     dp_result.get("echoed_entities", []),
                    },
                    "timestamp":  datetime.utcnow().isoformat(),
                },
                "stats": self.processing_stats,
            }

        except Exception as e:
            self.processing_stats["failed_processing"] += 1
            logger.error(f"❌ Enclave error: {str(e)}", exc_info=True)
            return {
                "status": "error",
                "error":  f"Enclave processing error: {str(e)}",
                "stats":  self.processing_stats,
            }

    # ──────────────────────────────────────────────────────
    # PHASE 1 — TRUST SCORING
    # ──────────────────────────────────────────────────────
    def _phase1_trust(self, user_claims, request_metadata):
        logger.info("── Phase 1: Trust Scoring ──")
        result    = self.trust_scorer.compute_trust_score(user_claims, request_metadata)
        score_key = f"{result['trust_score']}/5"
        self.processing_stats["trust_scores"][score_key] = \
            self.processing_stats["trust_scores"].get(score_key, 0) + 1
        return result

    # ──────────────────────────────────────────────────────
    # PHASE 2 — PII OVERRIDE
    # ──────────────────────────────────────────────────────
    def _phase2_pii_override(self, text: str) -> Dict[str, Any]:
        logger.info("── Phase 2: PII Override Check ──")
        result = detect_pii_override(text)
        if result["has_pii"]:
            logger.info(f"🔴 PII detected by regex: {result['detected']} → forcing risk=sensitive")
            self.processing_stats["pii_overrides"] += 1
        else:
            logger.info("✅ No direct PII patterns detected")
        return result

    # ──────────────────────────────────────────────────────
    # PHASE 2B — RISK CLASSIFICATION (ML)
    # ──────────────────────────────────────────────────────
    def _phase2b_risk(self, text: str, pii_check: Dict) -> Dict[str, Any]:
        logger.info("── Phase 2b: Risk Classification (ML) ──")
        result = infer_risk(text)
        label  = result["label"]
        conf   = result["confidence"]

        if pii_check["has_pii"] and label == "safe":
            logger.info(
                f"⚠️  ML said {label.upper()} ({conf*100:.1f}%) "
                f"but PII detected → overriding to SENSITIVE"
            )
            result["label"]          = "sensitive"
            result["original_label"] = label
            result["overridden_by"]  = "pii_regex"
        else:
            icons = {"safe": "✅", "sensitive": "⚠️ ", "malicious": "🚨"}
            logger.info(f"{icons.get(label,'?')} Risk: {label.upper()} ({conf*100:.1f}%)")

        return result

    # ──────────────────────────────────────────────────────
    # PHASE 2C — ADVANCED ML ANALYSIS
    # ──────────────────────────────────────────────────────
    def _phase2c_advanced_ml(self, text: str) -> Dict[str, Any]:
        logger.info("── Phase 2c: Advanced ML Analysis ──")
        ml_results      = infer_all(text)
        anomaly_result  = ml_results["anomaly"]
        phishing_result = ml_results["phishing"]

        anomaly_icon  = "🔴" if anomaly_result["is_anomaly"] else "✅"
        phishing_icon = "🎣" if phishing_result["is_phishing"] else "✅"
        logger.info(f"{anomaly_icon} Anomaly: {anomaly_result['anomaly_score']:.3f} (threshold: {anomaly_result['threshold']})")
        logger.info(f"{phishing_icon} Phishing: {phishing_result['phishing_score']:.3f}")

        if phishing_result["matched_patterns"]:
            logger.info(f"      Patterns: {', '.join(phishing_result['matched_patterns'][:3])}")

        return {
            "anomaly":       anomaly_result,
            "phishing":      phishing_result,
            "comprehensive": ml_results,
        }

    # ──────────────────────────────────────────────────────
    # PHASE 2D — HE / PSI CHECK
    # FIX 4 — called ONCE (on original text). Removed second
    # call on anonymized text that was causing duplicate logs.
    # FIX 5 — result["active"] is now always set (was "psi_active")
    # ──────────────────────────────────────────────────────
    def _phase2d_he_psi(self, text: str) -> Dict[str, Any]:
        logger.info("── Phase 2d: HE Private Set Intersection ──")

        if self.psi_engine is None:
            logger.warning("⚠️  PSI engine not set — skipping HE check")
            return {"active": False, "max_risk": 0.0, "flagged_topics": [], "ct_size_bytes": 0}

        self.processing_stats["he_checks"] += 1
        result = self.psi_engine.check_response(text)

        # FIX 5 — normalize to "active" regardless of what psi_engine returns
        result["active"] = result.get("psi_active", result.get("active", False))

        if result["flagged_topics"]:
            logger.info(
                f"🔐 HE PSI: sensitive topics detected — "
                f"{result['flagged_topics']} (max_risk={result['max_risk']:.3f})"
            )
        else:
            logger.info(f"✅ HE PSI: no sensitive topics matched (max_risk={result['max_risk']:.3f})")

        return result

    # ──────────────────────────────────────────────────────
    # PHASE 3 — POLICY GATE
    # ──────────────────────────────────────────────────────
    def _phase3_policy_gate(
        self, trust_score, risk_label, risk_conf,
        anomaly_detected, phishing_detected, he_result
    ) -> Dict[str, Any]:
        logger.info("── Phase 3: Policy Gate ──")

        block_reasons = []
        if risk_label == "malicious":
            block_reasons.append("malicious content")
        if anomaly_detected:
            block_reasons.append("anomalous pattern")
        if phishing_detected:
            block_reasons.append("phishing attempt")
        if he_result.get("max_risk", 0) >= 0.8 and risk_label == "sensitive":
            block_reasons.append(f"HE topic match: {he_result.get('flagged_topics')}")

        if block_reasons:
            logger.info(f"BLOCKED {', '.join(block_reasons)}")
            return {
                "action":     "block",
                "reason":     f"Request blocked: {', '.join(block_reasons)}",
                "risk":       risk_label,
                "trust":      trust_score,
                "he_flagged": he_result.get("flagged_topics", []),
            }

        threshold = self.TRUST_THRESHOLDS.get(risk_label, 0)
        logger.info(f"Policy Gate Check: risk={risk_label}, trust={trust_score}, threshold={threshold}")
        if trust_score < threshold:
            logger.info(f"BLOCKED trust {trust_score} < required {threshold} for {risk_label}")
            return {
                "action":   "block",
                "reason":   f"Insufficient trust ({trust_score}/{threshold}) for {risk_label}",
                "risk":     risk_label,
                "trust":    trust_score,
                "required": threshold,
            }

        logger.info(f"ALLOWED risk={risk_label}, trust={trust_score}/{threshold}")
        return {
            "action": "allow",
            "reason": "Request passed policy gate",
            "risk":   risk_label,
            "trust":  trust_score,
        }

    # ──────────────────────────────────────────────────────
    # PHASE 4 — PRIVACY PROCESSING
    # FIX 2 — salary regex now replaces full amount ($85,000)
    #          not just the dollar sign prefix ($85)
    # FIX 6 — single consistent prefix "anon_" everywhere
    # ──────────────────────────────────────────────────────
    def _phase4_privacy_processing(self, text: str) -> str:
        logger.info("── Phase 4: Privacy Processing ──")
        processed = text

        # FIX 2 — salary bucketing: replace full dollar amount with range label
        def _replace_salary(match):
            raw = match.group(0).replace("$", "").replace(",", "")
            # Guard: skip if it's already been generalized (contains letters)
            if not raw.replace(".", "").isdigit():
                return match.group(0)
            try:
                amount = int(float(raw))
            except ValueError:
                return match.group(0)
            return _bucket_salary(amount)

        processed = re.sub(r'\$[\d,]+(?:\.\d+)?', _replace_salary, processed)

        # Redact emails
        emails_found = re.findall(PII_PATTERNS["email"], processed, re.IGNORECASE)
        if emails_found:
            logger.info(f"🔴 Redacting {len(emails_found)} email address(es)")
            processed = re.sub(PII_PATTERNS["email"], "[EMAIL_REDACTED]", processed, flags=re.IGNORECASE)

        # FIX 6 — use "anon_" consistently (removed "dummy_" → "anon_" replacement
        #          since input should never contain "dummy_" after this fix)
        processed = processed.replace("TechCorp", "ORG_X").replace("DataInc", "ORG_Y")

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        processed = f"[ENCLAVE_{ts}] {processed} [PROCESSED_IN_ENCLAVE]"
        logger.info("🔐 Privacy processing applied")
        return processed

    # ──────────────────────────────────────────────────────
    # PHASE 4B — DP OUTPUT FILTER
    # FIX 1 — caller now checks dp_result["action"] == "BLOCK"
    #          and returns early. The pipeline no longer continues
    #          after a DP BLOCK.
    # FIX 3 — result["active"] normalized here (was "dp_active")
    # ──────────────────────────────────────────────────────
    def _phase4b_dp_filter(
        self, text: str, session_id: str,
        risk_label: str, risk_conf: float
    ) -> Dict[str, Any]:
        logger.info("── Phase 4b: DP Reconstruction Filter ──")

        if self.dp_filter is None:
            logger.warning("⚠️  DP filter not set — skipping")
            return {"active": False, "action": "ALLOW", "sanitized_text": text}

        if not session_id:
            logger.info("ℹ️  No session_id — DP similarity check skipped")
            return {"active": False, "action": "ALLOW", "sanitized_text": text}

        self.processing_stats["dp_checks"] += 1
        result = self.dp_filter.analyze_response(session_id, text)

        # FIX 3 — normalize key: always expose "active" (was "dp_active")
        result["active"] = result.get("dp_active", result.get("active", False))

        action = result.get("action", "ALLOW")
        icons  = {"ALLOW": "✅", "WARN": "⚠️ ", "BLOCK": "🚨"}
        logger.info(
            f"{icons.get(action,'?')} DP: action={action} | "
            f"similarity={result.get('dp_reconstruction_risk',0):.3f} | "
            f"noised={result.get('noised_similarity',0):.3f} | "
            f"budget={result.get('budget',{}).get('percent_used',0)}%"
        )
        if result.get("echoed_entities"):
            logger.warning(f"⚠️  LLM echoed PII: {result['echoed_entities']}")

        return result

    # ──────────────────────────────────────────────────────
    # PHASE 5 — SCOPE CLASSIFICATION
    # ──────────────────────────────────────────────────────
    def _phase5_scope(self, text: str) -> Dict[str, Any]:
        logger.info("── Phase 5: Scope Classification ──")
        result = infer_scope(text)
        label  = result["label"]
        conf   = result["confidence"]
        icons  = {"user_pii": "🔐", "aggregate": "📊", "public": "🌍", "unknown": "❓"}
        logger.info(f"{icons.get(label,'?')} Scope: {label.upper()} ({conf*100:.1f}%)")
        return result

    # ──────────────────────────────────────────────────────
    # PHASE 3A — POLICY SECURITY (GDPR/DPDP)
    # FIX 7 — moved after Phase 5 so scope_label is available
    # ──────────────────────────────────────────────────────
    def _phase3a_policy_security(self, scope_label, user_claims, operation, risk_label, trust_score, text):
        logger.info("Phase 3a: Policy Security (GDPR/DPDP Compliance)")
        user_id           = user_claims.get("sub", "anonymous")
        pii_detected      = scope_label == "user_pii"
        tool_category     = self._determine_tool_category(operation, "CONFIDENTIAL" if pii_detected else "PUBLIC")

        policy_result = policy_engine.evaluate_request(
            user_id=user_id,
            scope_label=scope_label,
            tool_category=tool_category,
            operation=operation,
            risk_label=risk_label,
            trust_score=trust_score,
            text=text,
            pii_detected=pii_detected,
        )

        sensitivity = policy_result["sensitivity_level"]
        if policy_result["allowed"]:
            logger.info(f"Policy check: {sensitivity.upper()} data - ALLOWED")
        else:
            logger.info(f"Policy check: {sensitivity.upper()} data - BLOCKED")
            logger.info(f"Violations: {', '.join(policy_result['policy_violations'])}")

        return policy_result

    def _determine_tool_category(self, operation, sensitivity_level=None):
        if sensitivity_level and sensitivity_level.upper() in ["CONFIDENTIAL", "STRICTLY_CONFIDENTIAL"]:
            return "enclave"
        op = operation.lower()
        if any(w in op for w in ["generate", "summarize", "translate"]):
            return "low_risk"
        if any(w in op for w in ["analyze", "classify", "detect"]):
            return "medium_risk"
        if any(w in op for w in ["personal", "biometric", "location"]):
            return "high_risk"
        if any(w in op for w in ["transfer", "profile", "automated"]):
            return "restricted"
        return "low_risk"

    # ──────────────────────────────────────────────────────
    # PHASE 6 — RESPONSE FILTERING
    # ──────────────────────────────────────────────────────
    def _phase6_response_filter(self, text, scope_label, trust_score):
        logger.info("── Phase 6: Response Filtering ──")
        if scope_label == "user_pii":
            if trust_score >= 3:
                logger.info("🔐 PII data — high trust — returning with PII notice")
                return f"[PII_DATA] {text}"
            else:
                logger.info("🔐 PII data — low trust — redacting")
                return "[REDACTED — PII data requires higher trust level]"
        elif scope_label == "aggregate":
            logger.info("📊 Aggregate data — returning with aggregate notice")
            return f"[AGGREGATE_DATA] {text}"
        elif scope_label == "public":
            logger.info("🌍 Public data — returning without restriction")
            return text
        else:
            logger.info("❓ Unknown scope — returning with caution notice")
            return f"[UNCLASSIFIED] {text}"

    # ──────────────────────────────────────────────────────
    # PHASE 7 — AUDIT LOGGING
    # ──────────────────────────────────────────────────────
    def _phase7_audit(
        self, original_text, user_claims, trust_result,
        risk_result, scope_result, gate_result,
        ml_analysis=None, he_result=None, dp_result=None,
    ) -> Dict[str, Any]:
        logger.info("── Phase 7: Audit Logging ──")
        audit_record = {
            "audit_id":   hashlib.sha256(
                f"{user_claims.get('sub','anon')}{datetime.utcnow().isoformat()}".encode()
            ).hexdigest()[:16],
            "timestamp":  datetime.utcnow().isoformat(),
            "user_id":    user_claims.get("sub", "anonymous"),
            "text_hash":  hashlib.sha256(original_text.encode()).hexdigest()[:16],
            "trust_score": trust_result["trust_score"],
            "risk_label": risk_result["label"],
            "risk_conf":  risk_result["confidence"],
            "scope_label": scope_result["label"],
            "scope_conf": scope_result["confidence"],
            "gate_action": gate_result["action"],
            "gate_reason": gate_result["reason"],
            "he_flagged_topics": (he_result or {}).get("flagged_topics", []),
            "he_max_risk":       (he_result or {}).get("max_risk", 0),
            # FIX 3 — use normalized "action" key
            "dp_action":         (dp_result or {}).get("action", "N/A"),
            "dp_similarity":     (dp_result or {}).get("dp_reconstruction_risk", 0),
            "dp_budget_used":    (dp_result or {}).get("budget", {}).get("percent_used", 0),
            "advanced_ml":       ml_analysis or {},
        }
        logger.info(
            f"📋 Audit ID: {audit_record['audit_id']} | "
            f"risk={audit_record['risk_label']} | "
            f"scope={audit_record['scope_label']} | "
            f"gate={audit_record['gate_action']} | "
            f"he_topics={audit_record['he_flagged_topics']} | "
            f"dp={audit_record['dp_action']}"
        )
        return audit_record

    # ──────────────────────────────────────────────────────
    # RESPONSE HELPERS
    # ──────────────────────────────────────────────────────
    def _blocked_response(self, gate_result, trust_result, risk_result):
        return {
            "status": "blocked",
            "reason": gate_result["reason"],
            "metadata": {
                "phase":         "policy_gate",
                "gate_decision": gate_result,
                "trust_score":   trust_result,
                "risk_result":   risk_result,
                "timestamp":     datetime.utcnow().isoformat(),
            },
            "stats": self.processing_stats,
        }

    def _dp_blocked_response(self, dp_result, trust_result, risk_result):
        return {
            "status": "blocked",
            "reason": "DP reconstruction risk too high — output too similar to original input",
            "metadata": {
                "phase":       "dp_filter",
                "dp_result":   dp_result,
                "trust_score": trust_result,
                "risk_result": risk_result,
                "timestamp":   datetime.utcnow().isoformat(),
            },
            "stats": self.processing_stats,
        }

    def _policy_blocked_response(self, policy_result, trust_result, risk_result, scope_result):
        return {
            "status": "blocked",
            "reason": f"Policy violation: {', '.join(policy_result['policy_violations'])}",
            "metadata": {
                "phase":         "policy_security",
                "policy_result": policy_result,
                "trust_score":   trust_result,
                "risk_result":   risk_result,
                "scope_result":  scope_result,
                "timestamp":     datetime.utcnow().isoformat(),
            },
            "stats": self.processing_stats,
        }

    def _get_privacy_level(self, sensitivity_level: str) -> str:
        return {
            "STRICTLY_CONFIDENTIAL": "maximum",
            "CONFIDENTIAL":          "high",
            "INTERNAL":              "elevated",
            "PUBLIC":                "standard",
        }.get(sensitivity_level.upper(), "standard")

    def get_enclave_status(self) -> Dict[str, Any]:
        return {
            "status":           "active",
            "phases":           "7+HE+DP",
            "ml_models":        ["risk_classifier", "scope_classifier"],
            "he_active":        self.psi_engine is not None,
            "dp_active":        self.dp_filter is not None,
            "processing_stats": self.processing_stats,
            "last_updated":     datetime.utcnow().isoformat(),
        }


# ── Global instance ────────────────────────────────────────
enclave_controller = EnclaveController()