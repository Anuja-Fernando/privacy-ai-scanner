"""
main.py — Privacy AI Scanner Backend
Fixed: single engine initialization, engines shared with enclave controller,
       session_id threading through pipeline, DistilBERT loaded once.
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pydantic import BaseModel
import os
import sys
import logging
from dotenv import load_dotenv

# ── Add enclave to path ────────────────────────────────────
ENCLAVE_PATH = r"C:\Users\anuja\OneDrive\Desktop\example\backend\enclave\enclave_ml\enclave"
sys.path.append(ENCLAVE_PATH)

PRIVACY_PATH = r"C:\Users\anuja\OneDrive\Desktop\example\backend\privacy_layers"
sys.path.append(PRIVACY_PATH)

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables that will be initialized in startup
enclave_controller = None
psi_engine = None
dp_filter = None
_infer_risk = None
_infer_scope = None

# ── Security config ────────────────────────────────────────
SECRET_KEY                  = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM                   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ══════════════════════════════════════════════════════════
# APP SETUP
# ══════════════════════════════════════════════════════════
app = FastAPI(
    title       = "Privacy AI Scanner Backend",
    description = "7-phase secure enclave with HE + DP output protection",
    version     = "2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

security = HTTPBearer()

# ══════════════════════════════════════════════════════════
# STARTUP — initialize EVERYTHING once here
# FIX: no more double initialization
# ══════════════════════════════════════════════════════════
@app.on_event("startup")
async def startup_event():
    """
    All heavy initialization happens here — once, at startup.
    Engines are then passed into the enclave controller via set_engines().
    """
    global enclave_controller, psi_engine, dp_filter, _infer_risk, _infer_scope

    # ── Import inference (loads DistilBERT once) ───────────
    logger.info("📦 Loading ML inference models (once)...")
    from inference import infer_risk, infer_scope, infer_all
    _infer_risk  = infer_risk
    _infer_scope = infer_scope
    logger.info("✅ ML models loaded")

    # ── Import enclave controller ──────────────────────────
    from enclave_controller import enclave_controller as _enc
    enclave_controller = _enc

    # ── Initialize PSI engine (HE) ─────────────────────────
    logger.info("🔐 Initializing PSI engine (HE)...")
    from psi_engine import PSIEngine
    psi_engine = PSIEngine()
    psi_engine.load_topics()
    psi_engine.build_topic_index()
    logger.info("✅ PSI engine ready")

    # ── Initialize DP filter ───────────────────────────────
    logger.info("🔊 Initializing DP output filter...")
    from dp_output_filter import DPOutputFilter
    dp_filter = DPOutputFilter()
    logger.info("✅ DP filter ready")

    # ── Give engines to enclave controller ─────────────────
    # FIX: single source of truth — enclave uses same instances
    enclave_controller.set_engines(psi_engine, dp_filter)
    logger.info("✅ Engines registered in enclave controller")

    # ── Initialize response analysis router engines ────────
    from response_analysis_router import init_engines
    init_engines()
    logger.info("✅ Response analysis router initialized")

    logger.info("🚀 All systems ready")


# ── Include response analysis router ──────────────────────
# Import and include AFTER app creation but routes register on startup
from response_analysis_router import router as response_router
app.include_router(response_router)

# ══════════════════════════════════════════════════════════
# PYDANTIC MODELS
# ══════════════════════════════════════════════════════════
class TokenData(BaseModel):
    username: Optional[str] = None
    scopes:   list[str]     = []

class MLInferenceRequest(BaseModel):
    text:       str
    operation:  str           = "ml_inference"
    session_id: Optional[str] = None   # NEW — links to DP prompt embedding

    class Config:
        json_schema_extra = {
            "example": {
                "text":       "my email is test@gmail.com",
                "operation":  "ml_inference",
                "session_id": "uuid-from-store-prompt",
            }
        }

class QuickScanRequest(BaseModel):
    text: str

class StorePromptRequest(BaseModel):
    prompt_text: str
    session_id:  Optional[str] = None

# ══════════════════════════════════════════════════════════
# JWT HELPERS
# ══════════════════════════════════════════════════════════
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire    = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    exc = HTTPException(
        status_code=401, detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not credentials or not credentials.credentials:
        raise exc
    payload = verify_token(credentials.credentials)
    if payload is None:
        raise exc
    return payload

# ══════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.get("/", tags=["Health"])
def root():
    return {
        "service": "Privacy AI Scanner Backend",
        "status":  "running",
        "version": "2.0.0",
        "docs":    "/docs",
    }

@app.get("/health", tags=["Health"])
def health_check():
    enclave_status = enclave_controller.get_enclave_status() if enclave_controller else {"status": "not_initialized"}
    psi_stats = psi_engine.get_stats() if psi_engine else {"status": "not_initialized"}
    return {
        "status":    "healthy",
        "enclave":   enclave_status,
        "psi":       psi_stats,
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.post("/auth/token", tags=["Auth"])
def login_for_access_token():
    token = create_access_token(
        data={
            "sub":               "privacy_user",
            "scopes":            ["ml_inference"],
            "mfa_verified":      True,
            "mfa_verified_at":   datetime.utcnow().isoformat() + "Z",
            "iat":               int(datetime.utcnow().timestamp()),
            "auth_time":         int(datetime.utcnow().timestamp()),
            "extension_id":      "njbpnodfjkoahlomcnbmghohfpdkcbki",
            "known_ips":         ["127.0.0.1"],
            "request_count_24h": 5,
            "location":          "IN",
        },
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": token, "token_type": "bearer"}


@app.post("/ml/inference", tags=["Enclave"])
def ml_inference(
    request:      MLInferenceRequest,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Main endpoint — full pipeline including HE + DP phases.
    Pass session_id (from /analyze/store-prompt) to enable DP similarity check.
    """
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Text field cannot be empty.")

    logger.info(f"📥 Request from: {current_user.get('sub', 'unknown')}")
    logger.info(f"📝 Text: {request.text[:60]}...")

    request_metadata = {
        "ip_address": http_request.client.host if http_request.client else "127.0.0.1",
        "user_agent": http_request.headers.get("user-agent", "Privacy AI Scanner"),
        "location":   current_user.get("location", "unknown"),
    }

    packaged_request = {
        "text":             request.text.strip(),
        "operation":        request.operation,
        "user_claims":      current_user,
        "request_metadata": request_metadata,
        "session_id":       request.session_id or "",   # NEW — passed to DP phase
        "timestamp":        datetime.utcnow().isoformat(),
    }

    enclave_result = enclave_controller.process_ml_inference(packaged_request)
    status         = enclave_result.get("status")

    # ── Blocked ───────────────────────────────────────────
    if status == "blocked":
        metadata = enclave_result.get("metadata", {})
        # reason is at top level for all block types
        block_reason = enclave_result.get("reason", "Request blocked")
        logger.info(f"🚫 Request blocked: {block_reason}")
        return {
            "status":       "blocked",
            "processed_by": "enclave",
            "result":       None,
            "error":        block_reason,
            "metadata":     metadata,
            "stats":        enclave_result.get("stats", {}),
        }

    if status == "error":
        raise HTTPException(status_code=500, detail=enclave_result.get("error"))

    # ── Success ───────────────────────────────────────────
    metadata      = enclave_result.get("metadata", {})
    risk_result   = metadata.get("risk_result", {})
    scope_result  = metadata.get("scope_result", {})
    trust_result  = metadata.get("trust_score", {})
    gate_decision = metadata.get("gate_decision", {})
    he_result     = metadata.get("he", metadata.get("he_result", {}))
    dp_result     = metadata.get("dp", metadata.get("dp_result", {}))
    pii_check     = metadata.get("pii_check", {})

    # DEBUG: Log what keys we actually received
    logger.info(f"DEBUG he_result keys: {list(he_result.keys())} | active={he_result.get('active')} | psi_active={he_result.get('psi_active')}")
    logger.info(f"DEBUG dp_result keys: {list(dp_result.keys())} | active={dp_result.get('active')} | dp_active={dp_result.get('dp_active')}")

    logger.info(
        f"✅ Pipeline complete — "
        f"risk={risk_result.get('label')} "
        f"scope={scope_result.get('label')} "
        f"he_topics={he_result.get('flagged_topics',[])} "
        f"dp_action={dp_result.get('action','N/A')}"
    )

    return {
        "status":       "success",
        "processed_by": "enclave",
        "result":       enclave_result.get("result", ""),
        "metadata": {
            "phase":         "complete",
            "trust_score":   trust_result,
            "risk_result":   risk_result,
            "pii_detected":  pii_check.get("detected", []),   # NEW
            "scope_result":  scope_result,
            "gate_decision": gate_decision,
            "policy_result": metadata.get("policy_result", {}),
            "audit_id":      metadata.get("audit_id"),
            "privacy_level": metadata.get("privacy_level"),
            "advanced_ml":   metadata.get("advanced_ml", {}),
            # NEW — HE + DP surfaced in response for popup.js
            "he": {
                "active":         he_result.get("active", False),
                "flagged_topics": he_result.get("flagged_topics", []),
                "max_risk":       he_result.get("max_risk", 0),
                "ct_size_bytes":  he_result.get("ct_size_bytes", 0),
            },
            "dp": {
                # Normalize both possible key names from DP filter
                "active":              dp_result.get("active", dp_result.get("dp_active", False)),
                "action":              dp_result.get("action", "N/A"),
                "reconstruction_risk": dp_result.get("reconstruction_risk",
                                    dp_result.get("dp_reconstruction_risk", 0)),
                "noised_similarity":   dp_result.get("noised_similarity", 0),
                "budget":              dp_result.get("budget", {}),
                "echoed_entities":     dp_result.get("echoed_entities", []),
                # Add aliases for frontend compatibility
                "dp_active":          dp_result.get("dp_active", dp_result.get("active", False)),
                "dp_reconstruction_risk": dp_result.get("dp_reconstruction_risk",
                                    dp_result.get("reconstruction_risk", 0)),
            },

            "timestamp": datetime.utcnow().isoformat(),
        },
        "stats": enclave_result.get("stats", {}),
    }


@app.post("/scan", tags=["Enclave"])
def quick_scan(request: QuickScanRequest):
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty.")
    from inference import infer_risk, infer_scope
    risk  = infer_risk(request.text)
    scope = infer_scope(request.text)
    return {
        "text":  request.text,
        "risk":  {"label": risk["label"],  "confidence": f"{risk['confidence']*100:.1f}%"},
        "scope": {"label": scope["label"], "confidence": f"{scope['confidence']*100:.1f}%"},
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/enclave/status", tags=["Enclave"])
def enclave_status():
    return enclave_controller.get_enclave_status()


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)