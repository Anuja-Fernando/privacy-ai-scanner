import requests
import json

# Test simple ML request to find exact error
try:
    # Get auth token
    auth_response = requests.post('http://localhost:8000/auth/token', json={})
    token = auth_response.json()['access_token']
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    # Test simple request
    data = {
        'text': 'test phone 123-456-7890',
        'operation': 'ml_inference',
        'protection_mode': 'auto'
    }
    
    print("Sending request...")
    response = requests.post('http://localhost:8000/ml/inference', 
                        json=data, headers=headers, timeout=30)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    
    if response.status_code != 200:
        print(f"Error Response: {response.text}")
    else:
        result = response.json()
        print("SUCCESS:")
        print(json.dumps(result, indent=2))
        
except Exception as e:
    print(f"Exception: {e}")
    import traceback
    traceback.print_exc()
