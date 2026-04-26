# Privacy AI Scanner - Secure Enclave

## Overview
This folder contains the secure enclave implementation for the Privacy AI Scanner. All sensitive processing operations happen here in the isolated enclave environment.

## Architecture
```
┌─────────────────┐    HTTPS POST    ┌──────────────────┐    Forward    ┌──────────────────┐
│ Chrome Extension │ ────────────────→ │  FastAPI Backend │ ─────────────→ │  Secure Enclave  │
│                 │    JWT Auth      │                  │  Packaged     │                  │
└─────────────────┘                   └──────────────────┘  Request      └─────────┬────────┘
                                                                                     │
                                                                                     │ Processing
                                                                                     ▼
                                                                             ┌──────────────────┐
                                                                             │ EnclaveController │
                                                                             │ - Model 2 Override│
                                                                             │ - Privacy Rules   │
                                                                             │ - Secure Processing│
                                                                             └──────────────────┘
```

## Security Features

### 🔒 **Secure Environment**
- **Isolated processing** - All sensitive operations in enclave
- **No external access** - Only backend can communicate
- **Memory protection** - Secure data handling
- **Audit logging** - All operations logged

### 🛡️ **Model 2 Override**
- **Data scope override** - Model 2 enforces strict privacy
- **Maximum privacy level** - Always uses strictest settings
- **Scope enforcement** - Cannot be bypassed by user claims

### 🔐 **Privacy Processing**
- **Additional anonymization** - Beyond client-side processing
- **Privacy watermarks** - Track enclave processing
- **Timestamp tracking** - Audit trail
- **Strict privacy rules** - Model 2 specific transformations

## Components

### EnclaveController
Main controller class that handles:
- **Request unpackaging** - Extract text, claims, metadata
- **Privacy processing** - Apply Model 2 rules
- **Response packaging** - Add processing metadata
- **Statistics tracking** - Monitor enclave usage

### Processing Flow
1. **Receive packaged request** from backend
2. **Validate request** - Check operation, claims, scope
3. **Apply Model 2 override** - Enforce strict privacy
4. **Process text** - Additional privacy transformations
5. **Package response** - Add metadata and results
6. **Return to backend** - Secure response transmission

## Model 2 Features

### Data Scope Override
```python
# User declares any scope, but Model 2 overrides
user_scope = "minimal"  # User requested
effective_scope = "strict_privacy"  # Model 2 enforces
```

### Strict Privacy Rules
- **Enhanced anonymization** - dummy_ → anon_
- **Organization masking** - TechCorp → ORG_X
- **Privacy watermarks** - [PROCESSED_IN_ENCLAVE]
- **Timestamp tracking** - [ENCLAVE_YYYYMMDD_HHMMSS]

### Security Logging
```python
logger.info("🔒 Enclave received request: ml_inference")
logger.info(f"👤 User: {user_claims.get('sub', 'unknown')}")
logger.info(f"🛡️ Model 2 override: Using scope 'strict_privacy'")
```

## Usage

### From Backend
```python
from enclave import enclave_controller

# Package request
packaged_request = {
    "text": "preprocessed text",
    "operation": "ml_inference",
    "user_claims": jwt_claims,
    "data_scope": "model_2_override"
}

# Process in enclave
result = enclave_controller.process_ml_inference(packaged_request)
```

### Response Format
```json
{
  "status": "success",
  "result": "[ENCLAVE_20260302_1124] my name is anon_mary i'm 25-34 years old i live in anon_salem and work at ORG_X [PROCESSED_IN_ENCLAVE]",
  "metadata": {
    "processed_by": "enclave",
    "effective_scope": "strict_privacy",
    "model_override": "model_2",
    "privacy_level": "maximum"
  }
}
```

## Security Guarantees

✅ **Isolated Processing** - All sensitive operations in enclave  
✅ **Model 2 Override** - Cannot be bypassed by user requests  
✅ **Enhanced Privacy** - Additional anonymization beyond client-side  
✅ **Audit Trail** - Complete logging of all operations  
✅ **Memory Protection** - Secure data handling in enclave  

This enclave ensures maximum privacy protection for your final year project! 🏆
