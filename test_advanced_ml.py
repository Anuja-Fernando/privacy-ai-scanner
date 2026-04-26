# Test Advanced ML Models - Anomaly & Phishing Detection
import sys
sys.path.append('backend/enclave/enclave_ml/enclave')

try:
    from inference import infer_all, infer_anomaly, infer_phishing
    
    print("🧪 Testing Advanced ML Models")
    print("=" * 50)
    
    test_cases = [
        # Normal queries
        "What is the capital of France?",
        "How do I implement a binary search tree?",
        
        # Anomalous queries
        "x9y2z8w1q7 asdflkj1234 !!!",
        "SELECT * FROM users WHERE 1=1; DROP TABLE users;",
        
        # Phishing queries
        "URGENT: Click here to update your bank account immediately",
        "Your account will be suspended unless you verify your credit card",
        "Congratulations! You won $1,000,000. Send payment to claim",
        
        # Suspicious but legitimate
        "What are the symptoms of COVID-19?",
        "How do I reset my forgotten password?"
    ]
    
    for i, text in enumerate(test_cases, 1):
        print(f"\n{i}. Testing: '{text[:50]}{'...' if len(text) > 50 else ''}")
        
        # Run comprehensive analysis
        result = infer_all(text)
        
        # Risk classification
        risk = result["risk"]
        print(f"   🚨 Risk: {risk['label']} ({risk['confidence']:.3f})")
        
        # Anomaly detection
        anomaly = result["anomaly"]
        anomaly_icon = "🔴" if anomaly["is_anomaly"] else "✅"
        print(f"   {anomaly_icon} Anomaly: {anomaly['anomaly_score']:.3f} (threshold: {anomaly['threshold']})")
        
        # Phishing detection
        phishing = result["phishing"]
        phishing_icon = "🎣" if phishing["is_phishing"] else "✅"
        print(f"   {phishing_icon} Phishing: {phishing['phishing_score']:.3f}")
        
        if phishing["matched_patterns"]:
            print(f"      Patterns: {', '.join(phishing['matched_patterns'][:3])}")
    
    print("\n" + "=" * 50)
    print("✅ Advanced ML models test complete!")
    
except Exception as e:
    print(f"❌ Error testing advanced models: {e}")
    import traceback
    traceback.print_exc()
