# Test the actual inference that the enclave uses
import sys
import os
sys.path.append('backend/enclave/enclave_ml/enclave')

try:
    from inference import infer_risk, infer_scope
    
    # Test with the exact text you mentioned
    test_text = 'where can i buys 200 books'
    
    print('=== TESTING YOUR EXACT INPUT ===')
    print(f'Input: "{test_text}"')
    print()
    
    risk_result = infer_risk(test_text)
    scope_result = infer_scope(test_text)
    
    print('RISK RESULT:')
    print(f'  Label: {risk_result["label"]}')
    print(f'  Confidence: {risk_result["confidence"]}')
    print(f'  All scores: {risk_result["scores"]}')
    print()
    
    print('SCOPE RESULT:')
    print(f'  Label: {scope_result["label"]}')
    print(f'  Confidence: {scope_result["confidence"]}')
    print(f'  All scores: {scope_result["scores"]}')
    
except Exception as e:
    print(f'Error: {e}')
    print('This confirms the models are not loading properly in the current environment')
