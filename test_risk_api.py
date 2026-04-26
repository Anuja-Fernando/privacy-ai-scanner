# Test your risk model in API context
from backend.enclave.enclave_ml.enclave.inference import infer_risk, infer_scope

# Test cases
test_texts = [
    "What is the capital of France?",
    "My SSN is 123-45-6789", 
    "DROP TABLE users;",
    "Patient John Doe has blood pressure 120/80"
]

print("🧪 Testing Risk Model Integration")
print("=" * 50)

for i, text in enumerate(test_texts, 1):
    print(f"\n{i}. Testing: '{text}'")
    
    # Test risk inference
    risk_result = infer_risk(text)
    print(f"   🚨 Risk: {risk_result['label']} ({risk_result['confidence']:.3f})")
    
    # Test scope inference  
    scope_result = infer_scope(text)
    print(f"   🎯 Scope: {scope_result['label']} ({scope_result['confidence']:.3f})")

print("\n✅ Model integration test complete!")
print("You can now use infer_risk() and infer_scope() in your API")
