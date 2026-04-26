@echo off
echo 🚀 Starting Privacy AI Scanner Backend...
echo 📦 Installing dependencies...
pip install -r requirements.txt

echo 🔐 Starting FastAPI server on http://localhost:8000
echo 📋 Available endpoints:
echo   POST /auth/token - Get JWT token
echo   POST /ml/inference - ML inference (requires JWT)
echo   GET  /health - Health check
echo.

python main.py
pause
