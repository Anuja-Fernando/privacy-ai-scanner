"""
Phishing Detector - BERT + Heuristic-based malicious intent detection
Identifies phishing, social engineering, and suspicious queries
"""

import re
import torch
from typing import Dict, List, Any, Tuple
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification

class PhishingDetector:
    def __init__(self, model_path: str = None):
        self.device = 0 if torch.cuda.is_available() else -1
        
        # Initialize BERT classifier
        if model_path:
            try:
                self.phishing_pipeline = pipeline(
                    "text-classification",
                    model=model_path,
                    tokenizer=model_path,
                    device=self.device
                )
                print(f"✅ Phishing detector loaded from {model_path}")
            except Exception as e:
                print(f"⚠️ Could not load phishing model: {e}")
                self.init_default_model()
        else:
            self.init_default_model()
    
    def init_default_model(self):
        """Initialize with default sentiment model as fallback"""
        self.phishing_pipeline = pipeline(
            "text-classification",
            model="distilbert-base-uncased-finetuned-sst-2-english",
            device=self.device
        )
        print("🔄 Using default model for phishing detection")
    
    def _get_heuristic_score(self, text: str) -> Tuple[float, List[str]]:
        """
        Heuristic-based phishing detection
        
        Returns:
            tuple: (score, matched_patterns)
        """
        text_lower = text.lower()
        matched_patterns = []
        score = 0.0
        
        # Urgency indicators
        urgency_patterns = [
            r'\burgent\b', r'\bimmediate\b', r'\bquickly\b', r'\basap\b',
            r'\bact now\b', r'\blimited time\b', r'\boffer expires\b'
        ]
        
        # Threat/Intimidation
        threat_patterns = [
            r'\bsuspended\b', r'\baccount will be\b', r'\bdeactivated\b',
            r'\bblocked\b', r'\bterminated\b', r'\blegal action\b'
        ]
        
        # Financial requests
        financial_patterns = [
            r'\bpayment\b', r'\bcredit card\b', r'\bbank account\b',
            r'\bwire transfer\b', r'\bsend money\b', r'\bverify account\b'
        ]
        
        # Authority impersonation
        authority_patterns = [
            r'\bbank of\b', r'\birs\b', r'\bgoogle\b', r'\bmicrosoft\b',
            r'\bamazon\b', r'\bfacebook\b', r'\bapple\b'
        ]
        
        # Suspicious links/requests
        suspicious_patterns = [
            r'click here', r'\bdownload\b', r'\binstall\b', r'\bupdate\b',
            r'\bverify\b', r'\bconfirm\b', r'\bsign in\b'
        ]
        
        # Check patterns
        all_patterns = [
            (urgency_patterns, 0.3, "urgency"),
            (threat_patterns, 0.4, "threat"),
            (financial_patterns, 0.3, "financial"),
            (authority_patterns, 0.2, "authority"),
            (suspicious_patterns, 0.2, "suspicious")
        ]
        
        for patterns, weight, category in all_patterns:
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    score += weight
                    matched_patterns.append(f"{category}:{pattern}")
        
        return min(1.0, score), matched_patterns
    
    def _get_bert_score(self, text: str) -> Tuple[float, str]:
        """
        BERT-based phishing detection
        
        Returns:
            tuple: (score, label)
        """
        try:
            result = self.phishing_pipeline(text, truncation=True, max_length=128)[0]
            
            # Map sentiment to phishing likelihood (inverse mapping)
            if result["label"] == "NEGATIVE":
                # Negative sentiment might indicate threats/urgency
                bert_score = result["score"] * 0.6
            else:
                # Positive/neutral sentiment
                bert_score = (1 - result["score"]) * 0.4
            
            return bert_score, result["label"]
            
        except Exception as e:
            print(f"BERT phishing detection error: {e}")
            return 0.0, "UNKNOWN"
    
    def detect_phishing(self, text: str) -> Dict[str, Any]:
        """
        Detect if text contains phishing/malicious intent
        
        Returns:
            dict: {
                "is_phishing": bool,
                "phishing_score": float (0-1),
                "heuristic_score": float,
                "bert_score": float,
                "matched_patterns": list,
                "bert_label": str,
                "confidence": float
            }
        """
        # Get heuristic score
        heuristic_score, matched_patterns = self._get_heuristic_score(text)
        
        # Get BERT score
        bert_score, bert_label = self._get_bert_score(text)
        
        # Combine scores (weighted average)
        combined_score = (heuristic_score * 0.6) + (bert_score * 0.4)
        
        # Determine if phishing
        is_phishing = combined_score > 0.5
        
        # Calculate confidence
        confidence = max(heuristic_score, bert_score)
        
        return {
            "is_phishing": is_phishing,
            "phishing_score": round(combined_score, 4),
            "heuristic_score": round(heuristic_score, 4),
            "bert_score": round(bert_score, 4),
            "matched_patterns": matched_patterns,
            "bert_label": bert_label,
            "confidence": round(confidence, 4)
        }
    
    def detect_batch_phishing(self, texts: List[str]) -> List[Dict[str, Any]]:
        """Detect phishing for multiple texts"""
        return [self.detect_phishing(text) for text in texts]
    
    def get_risk_factors(self, text: str) -> Dict[str, Any]:
        """Get detailed risk factor analysis"""
        result = self.detect_phishing(text)
        
        risk_factors = []
        
        if result["heuristic_score"] > 0.3:
            risk_factors.append("Suspicious language patterns detected")
        
        if any("urgency" in pattern for pattern in result["matched_patterns"]):
            risk_factors.append("Urgency indicators present")
        
        if any("threat" in pattern for pattern in result["matched_patterns"]):
            risk_factors.append("Threatening language detected")
        
        if any("financial" in pattern for pattern in result["matched_patterns"]):
            risk_factors.append("Financial request detected")
        
        if result["bert_score"] > 0.4:
            risk_factors.append("Negative sentiment detected")
        
        return {
            "risk_factors": risk_factors,
            "risk_count": len(risk_factors),
            "severity": "high" if len(risk_factors) >= 3 else "medium" if len(risk_factors) >= 1 else "low"
        }

# Global instance
_phishing_detector = PhishingDetector()

def detect_phishing(text: str) -> Dict[str, Any]:
    """Global function for phishing detection"""
    return _phishing_detector.detect_phishing(text)

def detect_batch_phishing(texts: List[str]) -> List[Dict[str, Any]]:
    """Global function for batch phishing detection"""
    return _phishing_detector.detect_batch_phishing(texts)

def get_phishing_risk_factors(text: str) -> Dict[str, Any]:
    """Global function for detailed risk factor analysis"""
    return _phishing_detector.get_risk_factors(text)
