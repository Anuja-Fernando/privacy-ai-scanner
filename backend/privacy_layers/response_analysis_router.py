"""
response_analysis_router.py
------------------------------------------------
FastAPI router - mounts at /analyze/response in your main.py

Add to your main.py:
    from response_analysis_router import router as response_router
    app.include_router(response_router)

Endpoints:
    POST /analyze/response        - main analysis (PSI + DP)
    POST /analyze/store-prompt    - store prompt embedding before LLM call
    GET  /analyze/budget/{sid}    - check session budget
    POST /analyze/reset/{sid}     - reset session
    GET  /analyze/psi/stats       - PSI topic index stats
    POST /analyze/psi/add-topic   - add new topic category at runtime
"""

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel

from psi_engine      import PSIEngine
from dp_output_filter import DPOutputFilter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["Response Analysis"])

# Singletons (initialized once at startup)
# These are module-level so they're shared across all requests.
# Call init_engines() from your main.py lifespan/startup event.

_psi: Optional[PSIEngine]     = None
_dp:  Optional[DPOutputFilter] = None


def init_engines():
    """
    Call this from your FastAPI startup event in main.py:

        from response_analysis_router import init_engines
        @app.on_event("startup")
        async def startup():
            psi_engine, dp_filter = init_engines()
    """
    global _psi, _dp
    logger.info("Initializing PSI + DP engines...")
    _psi = PSIEngine()
    _psi.load_topics()
    _psi.build_topic_index()
    _dp  = DPOutputFilter()
    logger.info("PSI + DP engines ready")
    return _psi, _dp


def get_psi() -> PSIEngine:
    if _psi is None:
        raise HTTPException(503, "PSI engine not initialized")
    return _psi


def get_dp() -> DPOutputFilter:
    if _dp is None:
        raise HTTPException(503, "DP engine not initialized")
    return _dp


# Request / response models
class StorePromptRequest(BaseModel):
    session_id:    Optional[str] = None   # auto-generated if not provided
    original_text: str                    # the ORIGINAL prompt before anonymization


class AnalyzeResponseRequest(BaseModel):
    session_id:    str
    response_text: str


class AddTopicRequest(BaseModel):
    category: str
    keywords: list[str]


# Endpoints
@router.post("/store-prompt")
async def store_prompt(
    req:    StorePromptRequest,
    dp_eng: DPOutputFilter = Depends(get_dp),
):
    """
    Call this when the user submits their prompt.
    Stores the embedding of the ORIGINAL (pre-anonymization) text
    so it can be compared against the LLM response later.

    Returns a session_id that the extension must include in
    the subsequent /analyze/response call.
    """
    session_id = req.session_id or str(uuid.uuid4())
    dp_eng.store_prompt_embedding(session_id, req.original_text)
    return {
        "session_id": session_id,
        "status":     "stored",
        "message":    "Prompt embedding stored. Include session_id in /analyze/response",
    }


@router.post("/response")
async def analyze_response(
    req:    AnalyzeResponseRequest,
    psi_eng: PSIEngine      = Depends(get_psi),
    dp_eng:  DPOutputFilter = Depends(get_dp),
):
    """
    Main analysis endpoint. Called by response_interceptor.js
    when the LLM response is fully loaded in the browser.

    Runs:
        1. PSI (HE) - checks if response touches sensitive topics
        2. DP filter - checks if response could reconstruct original identity

    Returns:
        action:                 "ALLOW" | "WARN" | "BLOCK"
        psi_risk:               float   - max topic match score
        dp_reconstruction_risk: float   - cosine similarity to original
        sanitized_response:     str     - DP-cleaned response
        flagged_topics:         list    - topic categories matched
        echoed_entities:        list    - PII found in response
        budget:                 dict    - RDP budget status
    """
    logger.info(
        f"/analyze/response - session={req.session_id[:8]}, "
        f"response_len={len(req.response_text)}"
    )

    # 1. PSI check (HE)
    psi_result = psi_eng.check_response(req.response_text)

    # 2. DP reconstruction check
    dp_result = dp_eng.analyze_response(req.session_id, req.response_text)

    # 3. Merge decisions (take worst case)
    actions_rank = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
    psi_action   = "BLOCK" if psi_result["max_risk"] >= 0.8 else \
                   "WARN"  if psi_result["max_risk"] >= 0.5 else "ALLOW"
    dp_action    = dp_result["action"]
    final_action = max(psi_action, dp_action, key=lambda a: actions_rank[a])

    logger.info(
        f"Final action: {final_action} "
        f"(PSI={psi_action}, DP={dp_action})"
    )

    return {
        "action":                 final_action,
        "psi_risk":               psi_result["max_risk"],
        "psi_flagged_topics":     psi_result["flagged_topics"],
        "psi_matches":            psi_result["matches"],
        "psi_active":             psi_result["psi_active"],
        "dp_reconstruction_risk": dp_result["dp_reconstruction_risk"],
        "dp_noised_similarity":   dp_result["noised_similarity"],
        "sanitized_response":     dp_result["sanitized_response"],
        "echoed_entities":        dp_result["echoed_entities"],
        "budget":                 dp_result["budget"],
        "he_ct_size_bytes":       psi_result.get("ct_size_bytes", 0),
        "latency_ms": {
            "psi": psi_result.get("latency_ms", 0),
            "dp":  dp_result.get("latency_ms", 0),
        },
    }


@router.get("/budget/{session_id}")
async def get_budget(session_id: str, dp_eng: DPOutputFilter = Depends(get_dp)):
    """Check remaining DP privacy budget for a session."""
    tracker = dp_eng.budget
    spent   = tracker._sessions.get(session_id, 0.0)
    return {
        "session_id":    session_id,
        "eps_spent":     round(spent, 4),
        "eps_remaining": round(max(0, tracker.max_epsilon - spent), 4),
        "max_eps":       tracker.max_epsilon,
        "budget_ok":     spent < tracker.max_epsilon,
        "percent_used":  round(spent / tracker.max_epsilon * 100, 1),
    }


@router.post("/reset/{session_id}")
async def reset_session(session_id: str, dp_eng: DPOutputFilter = Depends(get_dp)):
    """Reset session data and budget (call on tab close or logout)."""
    dp_eng.clear_session(session_id)
    return {"status": "cleared", "session_id": session_id}


@router.get("/psi/stats")
async def psi_stats(psi_eng: PSIEngine = Depends(get_psi)):
    """Returns topic index statistics."""
    return psi_eng.get_stats()


@router.post("/psi/add-topic")
async def add_topic(
    req:    AddTopicRequest,
    psi_eng: PSIEngine = Depends(get_psi),
):
    """Add a new topic category to the PSI engine at runtime."""
    psi_eng.add_topic(req.category, req.keywords)
    return {
        "status":   "added",
        "category": req.category,
        "n_keywords": len(req.keywords),
    }
