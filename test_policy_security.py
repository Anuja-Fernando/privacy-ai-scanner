#!/usr/bin/env python3
"""
Test Policy-Based Security Engine
GDPR/DPDP Compliance, Privacy Budgets, Tool Whitelisting
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend', 'enclave', 'enclave_ml', 'enclave'))

from policy_engine import PolicyEngine, DataSensitivityLevel, ComplianceFramework
from enclave_controller import enclave_controller

def test_policy_engine():
    """Test policy engine functionality"""
    print("=" * 60)
    print("Testing Policy-Based Security Engine")
    print("=" * 60)
    
    # Initialize policy engine
    engine = PolicyEngine()
    
    # Test 1: Data sensitivity classification
    print("\n1. Testing Data Sensitivity Classification:")
    test_scopes = ["public", "aggregate", "user_pii", "unknown"]
    for scope in test_scopes:
        sensitivity = engine.classify_data_sensitivity(scope)
        print(f"   Scope: {scope} -> Sensitivity: {sensitivity.value}")
    
    # Test 2: Tool whitelisting
    print("\n2. Testing Tool Whitelisting:")
    test_tools = ["low_risk", "medium_risk", "high_risk", "restricted"]
    for tool in test_tools:
        for sensitivity in DataSensitivityLevel:
            allowed = engine.check_tool_whitelist(tool, sensitivity)
            status = "ALLOWED" if allowed else "BLOCKED"
            print(f"   {sensitivity.value.upper()} + {tool}: {status}")
    
    # Test 3: Privacy budget management
    print("\n3. Testing Privacy Budget Management:")
    user_id = "test_user_123"
    
    # Simulate multiple requests
    for i in range(5):
        result = engine.check_privacy_budget(user_id, DataSensitivityLevel.PUBLIC)
        print(f"   Request {i+1}: Daily remaining: {result['daily_available']}, Monthly remaining: {result['monthly_available']}")
    
    # Test 4: Compliance requirements
    print("\n4. Testing Compliance Requirements:")
    for sensitivity in DataSensitivityLevel:
        requirements = engine.check_compliance_requirements(sensitivity, "process")
        print(f"   {sensitivity.value.upper()}:")
        print(f"     Audit required: {requirements['audit_required']}")
        print(f"     Consent required: {requirements['consent_required']}")
        print(f"     Cross-border allowed: {requirements['cross_border_allowed']}")
        print(f"     Retention days: {requirements['retention_days']}")
    
    # Test 5: Complete policy evaluation
    print("\n5. Testing Complete Policy Evaluation:")
    test_requests = [
        ("user_001", "public", "low_risk", "generate"),
        ("user_002", "user_pii", "low_risk", "summarize"),
        ("user_003", "confidential", "medium_risk", "analyze"),
        ("user_004", "strictly_confidential", "high_risk", "process"),
    ]
    
    for user_id, scope, tool, operation in test_requests:
        result = engine.evaluate_request(user_id, scope, tool, operation)
        status = "ALLOWED" if result["allowed"] else "BLOCKED"
        print(f"   User: {user_id} | Scope: {scope} | Tool: {tool}")
        print(f"   Result: {status}")
        if not result["allowed"]:
            print(f"   Violations: {', '.join(result['policy_violations'])}")
        print()

def test_enclave_policy_integration():
    """Test policy engine integration with enclave controller"""
    print("=" * 60)
    print("Testing Enclave Policy Integration")
    print("=" * 60)
    
    # Test requests with different sensitivity levels
    test_requests = [
        {
            "text": "What is the weather today?",
            "operation": "generate",
            "user_claims": {"sub": "user_public"},
            "expected_sensitivity": "public"
        },
        {
            "text": "My name is John and I live in New York",
            "operation": "summarize", 
            "user_claims": {"sub": "user_pii"},
            "expected_sensitivity": "confidential"
        },
        {
            "text": "Please analyze my medical records",
            "operation": "analyze",
            "user_claims": {"sub": "user_sensitive"},
            "expected_sensitivity": "strictly_confidential"
        }
    ]
    
    for i, request in enumerate(test_requests, 1):
        print(f"\n{i}. Testing: {request['text'][:30]}...")
        print(f"   Operation: {request['operation']}")
        print(f"   Expected sensitivity: {request['expected_sensitivity']}")
        
        # Create packaged request
        packaged_request = {
            "text": request["text"],
            "operation": request["operation"],
            "user_claims": request["user_claims"],
            "request_metadata": {}
        }
        
        # Process through enclave
        result = enclave_controller.process_ml_inference(packaged_request)
        
        if result["status"] == "success":
            print(f"   Result: SUCCESS")
            print(f"   Privacy level: {result['metadata']['privacy_level']}")
        else:
            print(f"   Result: BLOCKED")
            print(f"   Reason: {result['reason']}")

def test_privacy_budget_limits():
    """Test privacy budget enforcement"""
    print("=" * 60)
    print("Testing Privacy Budget Limits")
    print("=" * 60)
    
    engine = PolicyEngine()
    user_id = "budget_test_user"
    
    # Test strict confidentiality budget (very low limits)
    print(f"\nTesting STRICTLY_CONFIDENTIAL data for user: {user_id}")
    print(f"Daily limit: 10 requests")
    
    # Make requests until budget is exhausted
    for i in range(12):
        result = engine.check_privacy_budget(user_id, DataSensitivityLevel.STRICTLY_CONFIDENTIAL)
        if result["can_proceed"]:
            print(f"   Request {i+1}: ALLOWED (Daily remaining: {result['daily_available']})")
        else:
            violations = result.get("policy_violations", ["Budget exceeded"])
            print(f"   Request {i+1}: BLOCKED - {', '.join(violations)}")
    
    # Show budget status
    budget_status = engine.get_user_budget_status(user_id)
    print(f"\nFinal Budget Status:")
    print(f"   Strictly confidential daily: {budget_status['budgets']['strictly_confidential']['daily']['used']}/{budget_status['budgets']['strictly_confidential']['daily']['limit']}")

def test_policy_configuration():
    """Test policy configuration updates"""
    print("=" * 60)
    print("Testing Policy Configuration")
    print("=" * 60)
    
    engine = PolicyEngine()
    
    # Show current policies
    print("\nCurrent Privacy Budget Limits:")
    budgets = engine.policies.get("privacy_budgets", {})
    for sensitivity, limits in budgets.items():
        print(f"   {sensitivity.upper()}: Daily={limits['daily_requests']}, Monthly={limits['monthly_requests']}")
    
    # Test policy update
    print("\nTesting policy update...")
    new_policies = {
        "privacy_budgets": {
            "public": {"daily_requests": 2000, "monthly_requests": 60000},
            "internal": {"daily_requests": 1000, "monthly_requests": 30000}
        }
    }
    
    engine.update_policy(new_policies)
    print("Policy updated successfully!")
    
    # Verify update
    updated_budgets = engine.policies.get("privacy_budgets", {})
    print("\nUpdated Privacy Budget Limits:")
    for sensitivity, limits in updated_budgets.items():
        if sensitivity in ["public", "internal"]:
            print(f"   {sensitivity.upper()}: Daily={limits['daily_requests']}, Monthly={limits['monthly_requests']}")

if __name__ == "__main__":
    try:
        test_policy_engine()
        test_enclave_policy_integration()
        test_privacy_budget_limits()
        test_policy_configuration()
        
        print("\n" + "=" * 60)
        print("Policy-Based Security Tests Complete!")
        print("=" * 60)
        
    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()
