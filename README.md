# 🔒 Privacy AI Scanner

A secure enclave-based privacy protection system for LLM prompts, built as a final year project for AIML and Cybersecurity.

The system intercepts user prompts before they reach an LLM, classifies their risk and data scope using fine-tuned DistilBERT models inside a simulated Trusted Execution Environment (TEE), applies Homomorphic Encryption and Differential Privacy, and returns a privacy-protected output.

---

## 🏗️ System Architecture

```
Chrome Extension (Frontend)
        │
        ▼
BERT NER Preprocessing
(Attribute Forgery + Generalization)
        │
        ▼
FastAPI Backend (JWT Authentication)
        │
        ▼
┌─────────────────────────────────────────┐
│         Enclave (TEE Simulation)        │
│                                         │
│  Phase 1 → Trust Scoring               │
│  Phase 2 → Risk Classification (ML)    │
│  Phase 3 → Policy Gate                 │
│  Phase 4 → Privacy Processing          │
│  Phase 5 → Scope Classification (ML)   │
│  Phase 6 → Response Filtering          │
│  Phase 7 → Audit Logging               │
└─────────────────────────────────────────┘
        │
        ▼
Homomorphic Encryption Layer
(TenSEAL CKKS / MockHE)
        │
        ▼
Differential Privacy + Budget Control
(Laplace / Gaussian Noise)
        │
        ▼
Chrome Extension Display
```

---

## 🤖 ML Models

| Model | Architecture | Labels | Accuracy | Training Time |
|---|---|---|---|---|
| Risk Classifier | DistilBERT-base-uncased | safe / sensitive / malicious | 98% | ~25 hours CPU |
| Scope Classifier | DistilBERT-base-uncased | user_pii / aggregate / public / unknown | 94% | ~42 mins CPU |

### Model Evaluation Results

**Risk Classifier — Final Test Set (747 rows):**

| Label | Precision | Recall | F1 |
|---|---|---|---|
| safe | 0.98 | 0.96 | 0.97 |
| sensitive | 0.98 | 1.00 | 0.99 |
| malicious | 0.98 | 0.97 | 0.97 |
| **Overall** | **0.98** | **0.98** | **0.98** |

**Scope Classifier — Final Test Set (571 rows):**

| Label | Precision | Recall | F1 |
|---|---|---|---|
| user_pii | 0.98 | 0.95 | 0.96 |
| aggregate | 0.92 | 0.90 | 0.91 |
| public | 0.89 | 0.92 | 0.90 |
| unknown | 0.96 | 0.99 | 0.97 |
| **Overall** | **0.94** | **0.94** | **0.94** |

---

## 📂 Project Structure

```
example/
├── backend/
│   ├── main.py                              ← FastAPI entry point
│   └── enclave/
│       ├── he_layer.py                      ← Homomorphic Encryption layer
│       ├── dp_layer.py                      ← Differential Privacy layer
│       └── enclave_ml/
│           ├── data/
│           │   └── raw/custom/              ← handcrafted training datasets
│           │       ├── clean_dataset.csv    ← risk classifier dataset (915 rows)
│           │       └── clean_scope_data.csv ← scope classifier dataset (2852 rows)
│           ├── models/                      ← ⚠️ Download from Google Drive
│           │   ├── risk_classifier/
│           │   └── scope_classifier/
│           ├── training/
│           │   ├── train_risk_classifier.py
│           │   ├── train_scope_classifier.py
│           │   ├── build_combined_risk.py
│           │   ├── build_combined_scope.py
│           │   ├── clean_and_test.py
│           │   └── test_scope_dataset.py
│           └── enclave/
│               ├── enclave_controller.py    ← 7-phase enclave pipeline
│               ├── inference.py             ← ML model loader
│               └── test_enclave.py          ← pipeline tests
├── popup.js                                 ← Chrome extension popup
├── popup.html
├── manifest.json
├── style.css
├── content-simple.js
├── preprocess-focused.js                    ← BERT NER preprocessing
└── ner-bert.js                              ← BERT NER model
```

---

## 📥 Download Trained Models (Google Drive)

The trained model files are too large for GitHub. Download them from Google Drive:

**🔗 [Download Models from Google Drive](https://drive.google.com/drive/folders/1-lYMMkcNC8oPB3TsKW9n2PRiAlFquSVU?usp=sharing)**

After downloading place the folders here:
```
backend/enclave/enclave_ml/models/risk_classifier/
backend/enclave/enclave_ml/models/scope_classifier/
```

Each folder should contain:
```
model.safetensors
config.json
tokenizer.json
tokenizer_config.json
vocab.txt
special_tokens_map.json
```

---

## ⚙️ Setup Instructions

### Prerequisites
- Python 3.12
- Node.js 18+
- Google Chrome

### 1. Clone the repository
```bash
git clone https://github.com/Anuja-Fernando/privacy-ai-scanner.git
cd privacy-ai-scanner
```

### 2. Download trained models
Download from Google Drive link above and place in `backend/enclave/enclave_ml/models/`

### 3. Create Python virtual environment
```bash
cd backend/enclave/enclave_ml
python -m venv enclave_env
```

**Windows:**
```bash
enclave_env\Scripts\activate
```

**Mac/Linux:**
```bash
source enclave_env/bin/activate
```

### 4. Install Python dependencies
```bash
pip install torch transformers datasets
pip install fastapi uvicorn python-jose[cryptography] python-dotenv
pip install scikit-learn pandas numpy phe
```

### 5. Install Node dependencies and build extension
```bash
cd ../../..
npm install
npm run build
```

### 6. Start the backend server
```bash
cd backend
enclave_ml\enclave_env\Scripts\python.exe -m uvicorn main:app --reload --port 8000
```

### 7. Load Chrome extension
- Go to `chrome://extensions/`
- Enable **Developer Mode** (top right toggle)
- Click **Load Unpacked**
- Select the `dist/` folder
- The Privacy AI Scanner extension will appear

---

## 🧪 Testing

### Test the enclave pipeline
```bash
cd backend/enclave/enclave_ml/enclave
python test_enclave.py
```

Expected output: 6 success, 4 blocked, 0 errors

### Test HE layer
```bash
python he_layer.py
```

### Test DP layer
```bash
python dp_layer.py
```

### Test via API (Swagger UI)
Go to: **http://localhost:8000/docs**

---

## 🔑 API Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/` | GET | No | Health check |
| `/health` | GET | No | Enclave status |
| `/auth/token` | POST | No | Get JWT token |
| `/ml/inference` | POST | JWT | Full 7-phase pipeline |
| `/scan` | POST | No | Quick risk + scope scan |
| `/enclave/status` | GET | No | Processing statistics |

### Quick Test with PowerShell
```powershell
# Get token
$token = (Invoke-RestMethod -Uri "http://localhost:8000/auth/token" -Method POST).access_token

# Run full pipeline
Invoke-RestMethod -Uri "http://localhost:8000/ml/inference" `
  -Method POST `
  -Headers @{"Authorization" = "Bearer $token"; "Content-Type" = "application/json"} `
  -Body '{"text": "Show me the patients medical records.", "operation": "ml_inference"}'
```

---

## 🗄️ Training Datasets

### Risk Classifier (3735 rows total)

| Dataset | Source | Label | Rows |
|---|---|---|---|
| Custom handcrafted | Manual | safe / sensitive / malicious | 915 |
| Civil Comments | `google/civil_comments` | safe (toxicity < 0.1) | 1000 |
| Tweet Eval | `tweet_eval` sentiment | safe (positive) | 1000 |
| Medical Questions | `medical_questions_pairs` | sensitive | 1000 |
| Tweet Eval | `tweet_eval` hate + offensive | malicious | 2000 |

### Scope Classifier (2852 rows total)

| Dataset | Source | Label | Rows |
|---|---|---|---|
| Custom handcrafted | Manual | all 4 labels | 1500 |
| Medical Questions | `medical_questions_pairs` | user_pii | 370 |
| Civil Comments | `google/civil_comments` | aggregate / public / unknown | 1110 |

### Retrain Models
```bash
cd backend/enclave/enclave_ml/training

# Build combined datasets
python build_combined_risk.py
python build_combined_scope.py

# Train models
python train_risk_classifier.py
python train_scope_classifier.py
```

---

## 🔒 Security Layers

| Layer | Technology | What it Protects |
|---|---|---|
| BERT NER Preprocessing | DistilBERT NER | Replaces PII entities before enclave |
| TEE Simulation | 7-phase Python enclave | Isolates ML inference |
| Homomorphic Encryption | TenSEAL CKKS / MockHE | Encrypts ML scores before transmission |
| Differential Privacy | Laplace / Gaussian mechanism | Adds noise to numbers in processed text |
| Privacy Budget | ε-budget tracker (ε=1.0, max=10.0) | Blocks queries when budget exhausted |

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| ML Models | DistilBERT-base-uncased (HuggingFace) |
| Backend | FastAPI + Python 3.12 |
| Authentication | JWT (python-jose) |
| Homomorphic Encryption | TenSEAL CKKS / MockHE fallback |
| Differential Privacy | Laplace / Gaussian (pure Python) |
| Frontend | Chrome Extension (JavaScript) |
| Preprocessing | BERT NER + Attribute Forgery |

---

## 👥 Team

Final year project — AIML / Cybersecurity
TEE Simulation with ML-based Privacy Classification