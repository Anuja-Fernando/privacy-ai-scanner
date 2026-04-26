"""
Anomaly Detector - Autoencoder-based unusual pattern detection
Identifies anomalous user behavior and query patterns
"""

import torch
import torch.nn as nn
import numpy as np
import pickle
import os
from typing import Dict, List, Any
from transformers import AutoTokenizer, AutoModel

# Module-level model loading - runs ONCE when Python imports this file
print("Loading DistilBERT for anomaly detection...")
_tokenizer = AutoTokenizer.from_pretrained('distilbert-base-uncased')
_model = AutoModel.from_pretrained('distilbert-base-uncased')
_model.eval()
print("DistilBERT loaded for anomaly detection.")

class AnomalyDetector:
    def __init__(self, model_path: str = None):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        # Use module-level models to prevent reloading
        self.tokenizer = _tokenizer
        self.bert_model = _model
        self.model = None
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            self.init_autoencoder()
    
    def init_autoencoder(self):
        """Initialize autoencoder architecture"""
        class Autoencoder(nn.Module):
            def __init__(self, input_dim=768, hidden_dim=256):
                super().__init__()
                self.encoder = nn.Sequential(
                    nn.Linear(input_dim, hidden_dim),
                    nn.ReLU(),
                    nn.Linear(hidden_dim, 128),
                    nn.ReLU(),
                    nn.Linear(128, 64)
                )
                self.decoder = nn.Sequential(
                    nn.Linear(64, 128),
                    nn.ReLU(),
                    nn.Linear(128, hidden_dim),
                    nn.ReLU(),
                    nn.Linear(hidden_dim, input_dim)
                )
            
            def forward(self, x):
                encoded = self.encoder(x)
                decoded = self.decoder(encoded)
                return decoded
        
        self.model = Autoencoder().to(self.device)
        self.threshold = 0.5  # Anomaly threshold
    
    def load_model(self, model_path: str):
        """Load pre-trained anomaly detector"""
        try:
            self.model = torch.load(model_path, map_location=self.device)
            self.model.eval()
            print(f"✅ Anomaly detector loaded from {model_path}")
        except Exception as e:
            print(f"⚠️ Could not load anomaly model: {e}")
            self.init_autoencoder()
    
    def get_text_embedding(self, text: str) -> torch.Tensor:
        """Get BERT embedding for text"""
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=128)
        with torch.no_grad():
            outputs = self.bert_model(**inputs)
            # Use CLS token embedding
            embedding = outputs.last_hidden_state[:, 0, :]
        return embedding.to(self.device)
    
    def detect_anomaly(self, text: str) -> Dict[str, Any]:
        """
        Detect if text is anomalous
        
        Returns:
            dict: {
                "is_anomaly": bool,
                "anomaly_score": float (0-1),
                "reconstruction_error": float,
                "threshold": float
            }
        """
        if self.model is None:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "reconstruction_error": 0.0,
                "threshold": self.threshold
            }
        
        try:
            # Get text embedding
            embedding = self.get_text_embedding(text)
            
            # Pass through autoencoder
            with torch.no_grad():
                reconstructed = self.model(embedding)
                
                # Calculate reconstruction error
                mse_loss = nn.MSELoss()
                reconstruction_error = mse_loss(embedding, reconstructed).item()
                
                # Normalize to 0-1 range
                anomaly_score = min(1.0, reconstruction_error / 2.0)
                is_anomaly = anomaly_score > self.threshold
            
            return {
                "is_anomaly": is_anomaly,
                "anomaly_score": round(anomaly_score, 4),
                "reconstruction_error": round(reconstruction_error, 4),
                "threshold": self.threshold
            }
            
        except Exception as e:
            print(f"Anomaly detection error: {e}")
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "reconstruction_error": 0.0,
                "threshold": self.threshold
            }
    
    def detect_batch_anomaly(self, texts: List[str]) -> List[Dict[str, Any]]:
        """Detect anomalies for multiple texts"""
        return [self.detect_anomaly(text) for text in texts]
    
    def update_threshold(self, new_threshold: float):
        """Update anomaly detection threshold"""
        self.threshold = max(0.0, min(1.0, new_threshold))
        print(f"🔧 Anomaly threshold updated to {self.threshold}")

# Global instance
_anomaly_detector = AnomalyDetector()

def detect_anomaly(text: str) -> Dict[str, Any]:
    """Global function for anomaly detection"""
    return _anomaly_detector.detect_anomaly(text)

def detect_batch_anomaly(texts: List[str]) -> List[Dict[str, Any]]:
    """Global function for batch anomaly detection"""
    return _anomaly_detector.detect_batch_anomaly(texts)
