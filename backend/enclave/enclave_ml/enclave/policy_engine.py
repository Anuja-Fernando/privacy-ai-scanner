"""
Policy-Based Security Engine
GDPR/DPDP Compliance with Data Sensitivity & Tool Whitelisting
"""

from enum import Enum
from typing import Dict, List, Any, Optional, Set
import json
import logging
from datetime import datetime, timedelta
import hashlib

logger = logging.getLogger(__name__)

class DataSensitivityLevel(Enum):
    """Data sensitivity levels following GDPR/DPDP standards"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    STRICTLY_CONFIDENTIAL = "strictly_confidential"

class ComplianceFramework(Enum):
    """Compliance frameworks"""
    GDPR = "gdpr"
    DPDP = "dpdp"
    HIPAA = "hipaa"
    SOX = "sox"

class PolicyEngine:
    """
    Policy-Based Security Engine
    - GDPR/DPDP compliance
    - Data sensitivity classification
    - Tool whitelisting
    - Privacy budget management
    """
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path or "policy_config.json"
        self.policies = self._load_policies()
        self.privacy_budgets = {}
        self.audit_log = []
        
        # Default policy mappings
        self.scope_to_sensitivity = {
            "public": DataSensitivityLevel.PUBLIC,
            "aggregate": DataSensitivityLevel.INTERNAL,
            "user_pii": DataSensitivityLevel.CONFIDENTIAL,
            "unknown": DataSensitivityLevel.STRICTLY_CONFIDENTIAL
        }
        
        # Tool categories with risk levels
        self.tool_categories = {
            "enclave": ["secure_processing", "pii_handling", "confidential_compute"],
            "low_risk": ["text_generation", "summarization", "translation"],
            "medium_risk": ["data_analysis", "pattern_recognition", "classification"],
            "high_risk": ["personal_data_processing", "biometric_analysis", "location_tracking"],
            "restricted": ["cross_border_transfer", "profiling", "automated_decision"]
        }
        
    def _load_policies(self) -> Dict[str, Any]:
        """Load policy configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Policy config not found at {self.config_path}, using defaults")
            return self._get_default_policies()
    
    def _get_default_policies(self) -> Dict[str, Any]:
        """Default policy configuration"""
        return {
            "compliance_frameworks": ["GDPR", "DPDP"],
            "data_retention_days": {
                "public": 365,
                "internal": 180,
                "confidential": 90,
                "strictly_confidential": 30
            },
            "privacy_budgets": {
                "public": {"daily_requests": 1000, "monthly_requests": 30000},
                "internal": {"daily_requests": 500, "monthly_requests": 15000},
                "confidential": {"daily_requests": 100, "monthly_requests": 3000},
                "strictly_confidential": {"daily_requests": 10, "monthly_requests": 300}
            },
            "tool_whitelist": {
                "public": ["low_risk", "medium_risk"],
                "internal": ["low_risk"],
                "confidential": ["enclave"],
                "strictly_confidential": ["enclave"]
            },
            "cross_border_restrictions": {
                "confidential": False,
                "strictly_confidential": True
            },
            "audit_requirements": {
                "confidential": True,
                "strictly_confidential": True
            }
        }
    
    def classify_data_sensitivity(self, scope_label: str, text: str = "") -> DataSensitivityLevel:
        """Classify data sensitivity based on scope with keyword fallback"""
        # Keyword-based intent fallback for common queries
        if self._is_general_query(text):
            return DataSensitivityLevel.PUBLIC
        
        # Safe fallback: UNKNOWN -> GENERAL instead of STRICTLY_CONFIDENTIAL
        return self.scope_to_sensitivity.get(scope_label, DataSensitivityLevel.PUBLIC)
    
    def _is_general_query(self, text: str) -> bool:
        """Check if text contains general query keywords"""
        general_keywords = [
            "how", "what", "when", "where", "why", "who", "recipe", 
            "make", "cook", "prepare", "instructions", "steps", "guide",
            "tutorial", "explain", "definition", "meaning", "example"
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in general_keywords)
    
    def check_tool_whitelist(self, tool_category: str, sensitivity: DataSensitivityLevel) -> bool:
        """Check if tool is whitelisted for sensitivity level"""
        allowed_tools = self.policies.get("tool_whitelist", {}).get(sensitivity.value, [])
        return tool_category in allowed_tools
    
    def check_privacy_budget(self, user_id: str, sensitivity: DataSensitivityLevel) -> Dict[str, Any]:
        """Check and update privacy budget"""
        today = datetime.now().strftime("%Y-%m-%d")
        this_month = datetime.now().strftime("%Y-%m")
        
        # Initialize user budget tracking
        if user_id not in self.privacy_budgets:
            self.privacy_budgets[user_id] = {
                "daily": {},
                "monthly": {}
            }
        
        user_budget = self.privacy_budgets[user_id]
        budget_limits = self.policies.get("privacy_budgets", {}).get(sensitivity.value, {})
        
        # Check daily budget
        daily_count = user_budget["daily"].get(today, 0)
        daily_limit = budget_limits.get("daily_requests", 0)
        
        # Check monthly budget
        monthly_count = user_budget["monthly"].get(this_month, 0)
        monthly_limit = budget_limits.get("monthly_requests", 0)
        
        daily_available = daily_limit - daily_count
        monthly_available = monthly_limit - monthly_count
        
        can_proceed = daily_available > 0 and monthly_available > 0
        
        if can_proceed:
            # Update budget usage
            user_budget["daily"][today] = daily_count + 1
            user_budget["monthly"][this_month] = monthly_count + 1
        
        return {
            "can_proceed": can_proceed,
            "daily_available": daily_available,
            "monthly_available": monthly_available,
            "daily_limit": daily_limit,
            "monthly_limit": monthly_limit,
            "sensitivity": sensitivity.value
        }
    
    def check_compliance_requirements(self, sensitivity: DataSensitivityLevel, operation: str) -> Dict[str, Any]:
        """Check compliance requirements based on sensitivity"""
        requirements = {
            "audit_required": False,
            "consent_required": False,
            "data_minimization": False,
            "purpose_limitation": False,
            "cross_border_allowed": True,
            "retention_days": 365
        }
        
        if sensitivity in [DataSensitivityLevel.CONFIDENTIAL, DataSensitivityLevel.STRICTLY_CONFIDENTIAL]:
            requirements.update({
                "audit_required": True,
                "consent_required": True,
                "data_minimization": True,
                "purpose_limitation": True,
                "cross_border_allowed": not self.policies.get("cross_border_restrictions", {}).get(sensitivity.value, False),
                "retention_days": self.policies.get("data_retention_days", {}).get(sensitivity.value, 90)
            })
        
        return requirements
    
    def evaluate_request(self, 
                         user_id: str,
                         scope_label: str,
                         tool_category: str,
                         operation: str = "process",
                         risk_label: str = "unknown",
                         trust_score: int = 0,
                         text: str = "",
                         pii_detected: bool = False) -> Dict[str, Any]:
        """Evaluate request against all policies"""
        
        # Classify sensitivity with keyword fallback
        sensitivity = self.classify_data_sensitivity(scope_label, text)
        
        # PII OVERRIDE: PII detection always overrides to CONFIDENTIAL
        # This is the dominant rule - data sensitivity > risk classification
        if pii_detected:
            sensitivity = DataSensitivityLevel.CONFIDENTIAL
            logger.info(f"PII override: {sensitivity.value}")
        # No intent override for safe queries when PII is present
        logger.info(f"Final sensitivity: {sensitivity.value} (PII-based: {sensitivity.value != DataSensitivityLevel.PUBLIC})")
        
        # Check tool whitelist
        tool_allowed = self.check_tool_whitelist(tool_category, sensitivity)
        
        # Check privacy budget
        budget_result = self.check_privacy_budget(user_id, sensitivity)
        
        # Check compliance requirements
        compliance = self.check_compliance_requirements(sensitivity, operation)
        
        # Overall decision
        allowed = tool_allowed and budget_result["can_proceed"]
        
        # Log the evaluation
        self._log_evaluation(user_id, sensitivity, tool_category, allowed)
        
        return {
            "allowed": allowed,
            "sensitivity_level": sensitivity.value,
            "tool_category": tool_category,
            "tool_whitelisted": tool_allowed,
            "privacy_budget": budget_result,
            "compliance": compliance,
            "policy_violations": self._get_violations(tool_allowed, budget_result, compliance),
            "evaluation_time": datetime.utcnow().isoformat(),
            "intent_override_applied": risk_label == "safe" and trust_score >= 3
        }
    
    def _get_violations(self, tool_allowed: bool, budget_result: Dict, compliance: Dict) -> List[str]:
        """Identify policy violations"""
        violations = []
        
        if not tool_allowed:
            violations.append("Tool not whitelisted for sensitivity level")
        
        if not budget_result["can_proceed"]:
            if budget_result["daily_available"] <= 0:
                violations.append("Daily privacy budget exceeded")
            if budget_result["monthly_available"] <= 0:
                violations.append("Monthly privacy budget exceeded")
        
        if compliance.get("cross_border_allowed") == False:
            violations.append("Cross-border data transfer not allowed")
        
        return violations
    
    def _log_evaluation(self, user_id: str, sensitivity: DataSensitivityLevel, 
                       tool_category: str, allowed: bool):
        """Log policy evaluation for audit"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "sensitivity_level": sensitivity.value,
            "tool_category": tool_category,
            "allowed": allowed,
            "evaluation_id": hashlib.sha256(f"{user_id}{sensitivity.value}{tool_category}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
        }
        
        self.audit_log.append(log_entry)
        
        # Keep only last 10000 entries
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]
    
    def get_user_budget_status(self, user_id: str) -> Dict[str, Any]:
        """Get user's privacy budget status"""
        if user_id not in self.privacy_budgets:
            return {"status": "no_usage", "budgets": {}}
        
        user_budget = self.privacy_budgets[user_id]
        today = datetime.now().strftime("%Y-%m-%d")
        this_month = datetime.now().strftime("%Y-%m")
        
        status = {}
        for sensitivity in DataSensitivityLevel:
            budget_limits = self.policies.get("privacy_budgets", {}).get(sensitivity.value, {})
            daily_used = user_budget["daily"].get(today, 0)
            monthly_used = user_budget["monthly"].get(this_month, 0)
            
            status[sensitivity.value] = {
                "daily": {
                    "used": daily_used,
                    "limit": budget_limits.get("daily_requests", 0),
                    "remaining": budget_limits.get("daily_requests", 0) - daily_used
                },
                "monthly": {
                    "used": monthly_used,
                    "limit": budget_limits.get("monthly_requests", 0),
                    "remaining": budget_limits.get("monthly_requests", 0) - monthly_used
                }
            }
        
        return {"status": "active", "budgets": status}
    
    def update_policy(self, policy_updates: Dict[str, Any]):
        """Update policy configuration"""
        self.policies.update(policy_updates)
        
        # Save to file if path exists
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.policies, f, indent=2)
            logger.info("Policy configuration updated and saved")
        except Exception as e:
            logger.error(f"Failed to save policy updates: {e}")
    
    def get_audit_log(self, user_id: str = None, limit: int = 100) -> List[Dict]:
        """Get audit log entries"""
        if user_id:
            return [entry for entry in self.audit_log if entry.get("user_id") == user_id][-limit:]
        return self.audit_log[-limit:]

# Global policy engine instance
policy_engine = PolicyEngine()
