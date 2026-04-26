# Privacy AI Scanner Backend

## Overview
This backend implements the secure enclave integration for the Privacy AI Scanner Chrome extension.

## Architecture
```
┌─────────────────┐    HTTPS POST    ┌──────────────────┐
│ Chrome Extension │ ────────────────→ │  FastAPI Backend │
│                 │    JWT Auth      │                  │
└─────────────────┘                   └─────────┬────────┘
                                            │
                                            │ Request Packaging
                                            │ (text + claims + op)
                                            ▼
                                    ┌──────────────────┐
                                    │  Enclave        │
                                    │  Controller     │
                                    └──────────────────┘
```

## Setup

### Prerequisites
- Python 3.8+
- pip

### Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Start server (Linux/Mac)
./start.sh

# Start server (Windows)
start.bat

# Or manually
python main.py
```

## API Endpoints

### 1. Authentication
```http
POST /auth/token
Content-Type: application/json

# Returns JWT token for backend access
{
  "access_token": "eyJ0eXAiOiV...",
  "token_type": "bearer"
}
```

### 2. ML Inference (Secure)
```http
POST /ml/inference
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "text": "preprocessed privacy text",
  "operation": "ml_inference"
}

# Response
{
  "status": "success",
  "processed_by": "enclave",
  "result": "final processed text"
}
```

### 3. Health Check
```http
GET /health
```

## Security Features

### JWT Authentication
- **HS256** algorithm with secret key
- **30 minute** token expiration
- **Scope-based** access control (`ml_inference` scope)

### Request Packaging
The backend packages the request with:
- **Preprocessed text** from Chrome extension
- **JWT claims** (user identity, scopes)
- **Operation type** (`ml_inference`)
- **Data scope override** (`model_2_override`)

### Enclave Integration
- **Thin HTTP wrapper** - No security logic in endpoints
- **All logic in enclave** - Secure processing
- **Model 2 override** - Enforced data scope

## Environment Variables
```bash
SECRET_KEY=your-secret-key-here  # JWT signing key
```

## Development
```bash
# Install development dependencies
pip install -r requirements.txt

# Run with auto-reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
