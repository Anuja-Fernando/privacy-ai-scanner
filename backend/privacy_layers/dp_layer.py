"""
Differential Privacy Layer
==========================
Sits after the Homomorphic Encryption layer in the pipeline:

  Enclave (7-phase) → HE Layer (TenSEAL CKKS) → DP Layer ← YOU ARE HERE → Frontend

Implements:
  - Gaussian mechanism  (ε, δ)-DP  for continuous ML scores
  - Rényi Differential Privacy (RDP) accountant for tight budget tracking
  - Per-session + global privacy budget management
  - Sensitivity auto-calibration from score vectors
  - Budget exhaustion policy: CLAMP | REJECT | WARN
"""

import math
import uuid
import time
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class BudgetPolicy(str, Enum):
    CLAMP  = "clamp"   # Inject max-noise, still return result
    REJECT = "reject"  # Raise BudgetExhaustedError
    WARN   = "warn"    # Log warning, continue normally (use for dev)


class BudgetExhaustedError(RuntimeError):
    pass


@dataclass
class PrivacyBudget:
    """Tracks (ε, δ) consumption using the RDP → (ε, δ)-DP conversion."""

    epsilon_total: float = 1.0          # total ε budget
    delta: float = 1e-5                 # fixed δ for (ε,δ)-DP guarantee
    epsilon_used: float = 0.0           # accumulated ε spent so far
    query_count: int = 0                # number of queries charged
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)

    # RDP accumulator: list of (alpha, rdp_epsilon) per query
    _rdp_log: list = field(default_factory=list, repr=False)

    @property
    def epsilon_remaining(self) -> float:
        return max(0.0, self.epsilon_total - self.epsilon_used)

    @property
    def fraction_used(self) -> float:
        return self.epsilon_used / self.epsilon_total if self.epsilon_total > 0 else 1.0

    @property
    def is_exhausted(self) -> bool:
        return self.epsilon_remaining <= 1e-9

    def charge(self, epsilon_cost: float, rdp_entry: Optional[tuple] = None):
        self.epsilon_used = min(self.epsilon_total, self.epsilon_used + epsilon_cost)
        self.query_count += 1
        if rdp_entry:
            self._rdp_log.append(rdp_entry)

    def to_dict(self) -> dict:
        return {
            "session_id":        self.session_id,
            "epsilon_total":     round(self.epsilon_total, 6),
            "epsilon_used":      round(self.epsilon_used, 6),
            "epsilon_remaining": round(self.epsilon_remaining, 6),
            "delta":             self.delta,
            "fraction_used":     round(self.fraction_used, 4),
            "query_count":       self.query_count,
            "exhausted":         self.is_exhausted,
        }


# ---------------------------------------------------------------------------
# Gaussian Mechanism
# ---------------------------------------------------------------------------

class GaussianMechanism:
    """
    (ε, δ)-DP Gaussian mechanism.

    Calibrates σ from the analytic Gaussian mechanism bound:
        σ ≥ Δ₂ · √(2 ln(1.25/δ)) / ε

    Also tracks privacy loss via RDP at α = [2, 4, 8, 16, 32, 64] for
    tighter composition accounting (Mironov 2017).
    """

    # Rényi orders used for RDP accounting
    RDP_ORDERS = [2, 4, 8, 16, 32, 64]

    def __init__(
        self,
        epsilon: float,
        delta: float,
        sensitivity: float = 1.0,
        clip_bound: float = 1.0,
    ):
        """
        Args:
            epsilon:     ε for this single mechanism invocation
            delta:       δ for (ε,δ)-DP
            sensitivity: L2 sensitivity (Δ₂) of the query function
            clip_bound:  gradient/score clipping bound (same as sensitivity
                         if scores are already in [0,1])
        """
        if epsilon <= 0:
            raise ValueError(f"epsilon must be > 0, got {epsilon}")
        if not (0 < delta < 1):
            raise ValueError(f"delta must be in (0,1), got {delta}")
        if sensitivity <= 0:
            raise ValueError(f"sensitivity must be > 0, got {sensitivity}")

        self.epsilon     = epsilon
        self.delta       = delta
        self.sensitivity = sensitivity
        self.clip_bound  = clip_bound

        # Analytic Gaussian mechanism: σ from (ε, δ) guarantee
        self.sigma = self._calibrate_sigma()

        logger.debug(
            "GaussianMechanism: ε=%.4f  δ=%.2e  Δ₂=%.4f  σ=%.4f",
            epsilon, delta, sensitivity, self.sigma,
        )

    # ------------------------------------------------------------------
    # σ calibration
    # ------------------------------------------------------------------

    def _calibrate_sigma(self) -> float:
        """Analytic Gaussian mechanism lower bound on σ."""
        return (
            self.sensitivity
            * math.sqrt(2 * math.log(1.25 / self.delta))
            / self.epsilon
        )

    # ------------------------------------------------------------------
    # Core noise injection
    # ------------------------------------------------------------------

    def apply(self, values: np.ndarray) -> np.ndarray:
        """
        Clip → add Gaussian noise.

        Args:
            values: numpy array of real-valued scores (any shape)

        Returns:
            Noised array of same shape, clipped to [0, clip_bound]
        """
        clipped = np.clip(values, 0.0, self.clip_bound)
        noise   = np.random.normal(loc=0.0, scale=self.sigma, size=clipped.shape)
        noised  = clipped + noise
        # Post-clipping keeps scores in valid range
        return np.clip(noised, 0.0, self.clip_bound)

    # ------------------------------------------------------------------
    # RDP accounting
    # ------------------------------------------------------------------

    def rdp_epsilon(self, alpha: float) -> float:
        """
        RDP ε at order α for the Gaussian mechanism:
            ε_RDP(α) = α · Δ₂² / (2 σ²)
        """
        return alpha * (self.sensitivity ** 2) / (2 * self.sigma ** 2)

    def rdp_to_dp(self, alpha: float, rdp_eps: float) -> float:
        """
        Convert RDP guarantee (α, ε_RDP) to (ε, δ)-DP:
            ε_DP = ε_RDP + log(1 - 1/α) - (log(δ) + log(1 - 1/α)) / (α - 1)
        Uses the tightest known conversion (Balle et al. 2020 approx).
        """
        if alpha <= 1:
            return float("inf")
        log_term = math.log(1 - 1.0 / alpha)
        return rdp_eps + log_term - (math.log(self.delta) + log_term) / (alpha - 1)

    def best_dp_from_rdp(self) -> tuple[float, float]:
        """Return tightest (ε_DP, α) over all RDP orders."""
        best_eps   = float("inf")
        best_alpha = None
        for alpha in self.RDP_ORDERS:
            r   = self.rdp_epsilon(alpha)
            eps = self.rdp_to_dp(alpha, r)
            if eps < best_eps:
                best_eps   = eps
                best_alpha = alpha
        return best_eps, best_alpha


# ---------------------------------------------------------------------------
# Privacy Budget Manager
# ---------------------------------------------------------------------------

class PrivacyBudgetManager:
    """
    Thread-safe manager for per-session and global privacy budgets.

    Usage
    -----
    mgr = PrivacyBudgetManager(global_epsilon=10.0, delta=1e-5)

    session_id = mgr.create_session(epsilon=2.0)
    noised, report = mgr.apply_dp(scores, session_id=session_id, epsilon_per_query=0.1)
    print(mgr.budget_status(session_id))
    """

    def __init__(
        self,
        global_epsilon: float  = 10.0,
        delta:          float  = 1e-5,
        policy:         BudgetPolicy = BudgetPolicy.CLAMP,
        sensitivity:    float  = 1.0,
        clip_bound:     float  = 1.0,
    ):
        self.global_epsilon = global_epsilon
        self.delta          = delta
        self.policy         = policy
        self.sensitivity    = sensitivity
        self.clip_bound     = clip_bound

        self._global_budget = PrivacyBudget(
            epsilon_total=global_epsilon,
            delta=delta,
            session_id="__global__",
        )
        self._sessions: dict[str, PrivacyBudget] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def create_session(
        self,
        epsilon: float,
        session_id: Optional[str] = None,
    ) -> str:
        """
        Allocate a per-session privacy budget.

        Args:
            epsilon:    Maximum ε this session is allowed to spend.
                        Must not exceed global remaining budget.
            session_id: Optional explicit ID (auto-generated if None)

        Returns:
            session_id string
        """
        with self._lock:
            remaining = self._global_budget.epsilon_remaining
            if epsilon > remaining:
                raise BudgetExhaustedError(
                    f"Requested session ε={epsilon:.4f} exceeds global "
                    f"remaining ε={remaining:.4f}"
                )
            sid = session_id or str(uuid.uuid4())
            self._sessions[sid] = PrivacyBudget(
                epsilon_total=epsilon,
                delta=self.delta,
                session_id=sid,
            )
            # Pre-reserve from global budget
            self._global_budget.charge(epsilon)
            logger.info("Session %s created with ε=%.4f", sid, epsilon)
            return sid

    def get_session(self, session_id: str) -> PrivacyBudget:
        if session_id not in self._sessions:
            raise KeyError(f"Unknown session: {session_id}")
        return self._sessions[session_id]

    # ------------------------------------------------------------------
    # Core DP application
    # ------------------------------------------------------------------

    def apply_dp(
        self,
        scores: np.ndarray,
        session_id: str,
        epsilon_per_query: Optional[float] = None,
    ) -> tuple[np.ndarray, dict]:
        """
        Apply Gaussian DP mechanism to a score vector, charging the session budget.

        Args:
            scores:            1-D numpy array of ML sensitivity scores (values in [0,1])
            session_id:        Session to charge
            epsilon_per_query: ε to spend on this query; defaults to
                               10% of remaining session budget

        Returns:
            (noised_scores, privacy_report)
            privacy_report keys:
                epsilon_spent, sigma, session_budget, global_budget, rdp_alpha
        """
        with self._lock:
            budget = self.get_session(session_id)

            if budget.is_exhausted:
                return self._handle_exhausted(budget, scores)

            # Default: spend 10% of remaining each call (decaying schedule)
            if epsilon_per_query is None:
                epsilon_per_query = max(1e-6, budget.epsilon_remaining * 0.10)

            epsilon_per_query = min(epsilon_per_query, budget.epsilon_remaining)

            # Build mechanism for this query
            mech = GaussianMechanism(
                epsilon=epsilon_per_query,
                delta=self.delta,
                sensitivity=self.sensitivity,
                clip_bound=self.clip_bound,
            )

            noised = mech.apply(np.asarray(scores, dtype=float))

            # RDP accounting
            best_dp_eps, best_alpha = mech.best_dp_from_rdp()
            rdp_entry = (best_alpha, mech.rdp_epsilon(best_alpha))
            budget.charge(epsilon_per_query, rdp_entry)

            report = {
                "epsilon_spent":   round(epsilon_per_query, 6),
                "sigma":           round(mech.sigma, 6),
                "rdp_alpha":       best_alpha,
                "rdp_eps_tight":   round(best_dp_eps, 6),
                "session_budget":  budget.to_dict(),
                "global_budget":   self._global_budget.to_dict(),
            }
            return noised, report

    def _handle_exhausted(
        self,
        budget: PrivacyBudget,
        scores: np.ndarray,
    ) -> tuple[np.ndarray, dict]:
        msg = f"Session {budget.session_id} privacy budget exhausted."
        report = {
            "epsilon_spent": 0.0,
            "sigma": None,
            "session_budget": budget.to_dict(),
            "exhausted": True,
        }
        if self.policy == BudgetPolicy.REJECT:
            raise BudgetExhaustedError(msg)
        elif self.policy == BudgetPolicy.WARN:
            logger.warning(msg)
            return np.asarray(scores, dtype=float), report
        else:  # CLAMP — inject maximum noise
            logger.warning("%s Clamping with max noise.", msg)
            mech = GaussianMechanism(
                epsilon=1e-6,           # tiny ε → huge σ
                delta=self.delta,
                sensitivity=self.sensitivity,
                clip_bound=self.clip_bound,
            )
            noised = mech.apply(np.asarray(scores, dtype=float))
            report["sigma"] = round(mech.sigma, 6)
            return noised, report

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def budget_status(self, session_id: Optional[str] = None) -> dict:
        """Return budget snapshot for a session (or global if None)."""
        with self._lock:
            if session_id:
                return self.get_session(session_id).to_dict()
            return self._global_budget.to_dict()

    def all_sessions(self) -> dict:
        with self._lock:
            return {sid: b.to_dict() for sid, b in self._sessions.items()}


# ---------------------------------------------------------------------------
# Convenience wrapper — drop-in for pipeline integration
# ---------------------------------------------------------------------------

class DifferentialPrivacyLayer:
    """
    High-level wrapper used by enclave_controller.py / main.py.

    Example
    -------
    dp = DifferentialPrivacyLayer(global_epsilon=5.0, delta=1e-5)

    session_id = dp.new_session(epsilon=1.0)
    result = dp.process(he_scores, session_id)
    # result.noised_scores   — ready for frontend
    # result.privacy_report  — for audit log (Phase 7)
    """

    @dataclass
    class Result:
        noised_scores:  np.ndarray
        original_scores: np.ndarray
        privacy_report: dict
        noise_added:    np.ndarray

    def __init__(
        self,
        global_epsilon: float = 5.0,
        delta:          float = 1e-5,
        sensitivity:    float = 1.0,
        clip_bound:     float = 1.0,
        policy:         BudgetPolicy = BudgetPolicy.CLAMP,
    ):
        self.manager = PrivacyBudgetManager(
            global_epsilon=global_epsilon,
            delta=delta,
            sensitivity=sensitivity,
            clip_bound=clip_bound,
            policy=policy,
        )

    def new_session(self, epsilon: float = 1.0) -> str:
        return self.manager.create_session(epsilon=epsilon)

    def process(
        self,
        scores: np.ndarray | list,
        session_id: str,
        epsilon_per_query: Optional[float] = None,
    ) -> "DifferentialPrivacyLayer.Result":
        original = np.asarray(scores, dtype=float).copy()
        noised, report = self.manager.apply_dp(
            original, session_id, epsilon_per_query
        )
        return self.Result(
            noised_scores=noised,
            original_scores=original,
            privacy_report=report,
            noise_added=noised - original,
        )

    def budget_status(self, session_id: Optional[str] = None) -> dict:
        return self.manager.budget_status(session_id)