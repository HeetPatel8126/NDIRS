"""
Hybrid DDoS/DoS Detector
Combines rule-based detection with ML anomaly detection for robust attack identification.
"""

from sklearn.ensemble import IsolationForest
import numpy as np
from collections import deque, defaultdict
from typing import Dict, Tuple, List, Optional
import time


class RuleBasedDetector:
    """Rule-based detection for known attack patterns"""
    
    def __init__(self):
        # Thresholds for different attack types
        self.thresholds = {
            "packets_per_sec": 100,      # High packet rate
            "bytes_per_sec": 1000000,    # 1 MB/s
            "unique_ports": 20,          # Port scan threshold
            "rate_spike_1s": 50,         # Sudden spike in 1s window
            "low_entropy": 1.5,          # Low entropy indicates attack
        }
        
        # Track per-IP violations
        self.violations = defaultdict(lambda: {
            "count": 0,
            "last_violation": 0,
            "violation_types": []
        })
    
    def detect(self, features: List[float], src_ip: str = None) -> Tuple[str, str, float]:
        """
        Detect attacks using rules.
        Returns: (result, attack_type, confidence)
        """
        # Feature indices (must match features.py)
        pkt_count = features[0]
        byte_count = features[1]
        pps = features[2]        # packets per second
        bps = features[3]        # bytes per second
        rate_1s = features[4]
        rate_5s = features[5]
        rate_30s = features[6]
        unique_ports = features[7]
        unique_ips = features[8]
        unique_protocols = features[9]
        pkt_size_mean = features[10]
        pkt_size_std = features[11]
        src_entropy = features[16]
        dst_entropy = features[17]
        
        violations = []
        
        # Rule 1: High packet rate (DoS/DDoS)
        if pps > self.thresholds["packets_per_sec"]:
            confidence = min((pps / self.thresholds["packets_per_sec"]) * 0.5, 0.95)
            violations.append(("HIGH_RATE", "dos", confidence))
        
        # Rule 2: High byte rate (volumetric attack)
        if bps > self.thresholds["bytes_per_sec"]:
            confidence = min((bps / self.thresholds["bytes_per_sec"]) * 0.5, 0.95)
            violations.append(("VOLUMETRIC", "ddos_volumetric", confidence))
        
        # Rule 3: Port scan detection
        if unique_ports > self.thresholds["unique_ports"]:
            confidence = min(0.6 + (unique_ports - 20) * 0.02, 0.9)
            violations.append(("PORT_SCAN", "port_scan", confidence))
        
        # Rule 4: Rate spike detection
        if rate_1s > self.thresholds["rate_spike_1s"] and rate_1s > rate_30s * 5:
            confidence = 0.75
            violations.append(("RATE_SPIKE", "dos", confidence))
        
        # Rule 5: Low source entropy (single source flood)
        if src_entropy < self.thresholds["low_entropy"] and pps > 50:
            confidence = 0.7
            violations.append(("SINGLE_SOURCE_FLOOD", "dos", confidence))
        
        # Rule 6: Small packet flood (common in SYN flood)
        if pkt_size_mean < 100 and pps > 100:
            confidence = 0.65
            violations.append(("SMALL_PKT_FLOOD", "syn_flood", confidence))
        
        # Rule 7: Consistent packet size (amplification attack indicator)
        if pkt_size_std < 10 and pps > 50 and pkt_size_mean > 500:
            confidence = 0.7
            violations.append(("AMPLIFICATION", "amplification_attack", confidence))
        
        if violations:
            # Track violations for this IP
            if src_ip:
                self.violations[src_ip]["count"] += len(violations)
                self.violations[src_ip]["last_violation"] = time.time()
                for v in violations:
                    self.violations[src_ip]["violation_types"].append(v[1])
            
            # Return highest confidence violation
            violations.sort(key=lambda x: x[2], reverse=True)
            return "ATTACK", violations[0][1], violations[0][2]
        
        return "NORMAL", None, 0.0
    
    def get_ip_risk_score(self, src_ip: str) -> float:
        """Get risk score for an IP based on past violations"""
        if src_ip not in self.violations:
            return 0.0
        
        v = self.violations[src_ip]
        # Decay factor based on time since last violation
        time_decay = max(0, 1 - (time.time() - v["last_violation"]) / 3600)
        return min(v["count"] * 0.1 * time_decay, 1.0)


class MLDetector:
    """ML-based anomaly detection using Isolation Forest"""
    
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            max_features=0.8
        )
        self.trained = False
        self.buffer = deque(maxlen=500)
        self.scaler_means = None
        self.scaler_stds = None
        self.min_training_samples = 100
    
    def _normalize(self, features: List[float]) -> np.ndarray:
        """Normalize features using running mean/std"""
        X = np.array(features).reshape(1, -1)
        if self.scaler_means is not None:
            X = (X - self.scaler_means) / (self.scaler_stds + 1e-10)
        return X
    
    def _update_scaler(self, X: np.ndarray):
        """Update running statistics for normalization"""
        self.scaler_means = np.mean(X, axis=0)
        self.scaler_stds = np.std(X, axis=0)
    
    def detect(self, features: List[float]) -> Tuple[str, float]:
        """
        Detect anomalies using ML.
        Returns: (result, anomaly_score)
        """
        self.buffer.append(features)
        
        if len(self.buffer) < self.min_training_samples:
            return "LEARNING", 0.0
        
        X = np.array(self.buffer)
        
        if not self.trained:
            self._update_scaler(X)
            X_normalized = (X - self.scaler_means) / (self.scaler_stds + 1e-10)
            self.model.fit(X_normalized)
            self.trained = True
            return "MODEL_TRAINED", 0.0
        
        # Normalize and predict
        X_normalized = self._normalize(features)
        prediction = self.model.predict(X_normalized)[0]
        anomaly_score = -self.model.score_samples(X_normalized)[0]
        
        # Retrain periodically
        if len(self.buffer) % 200 == 0:
            self._update_scaler(X)
            X_all_normalized = (X - self.scaler_means) / (self.scaler_stds + 1e-10)
            self.model.fit(X_all_normalized)
        
        if prediction == -1:
            return "ANOMALY", anomaly_score
        return "NORMAL", anomaly_score


class HybridDetector:
    """Combines rule-based and ML detection for robust attack identification"""
    
    def __init__(self):
        self.rule_detector = RuleBasedDetector()
        self.ml_detector = MLDetector()
        
        # Attack classification
        self.attack_types = {
            "dos": "Denial of Service",
            "ddos_volumetric": "Volumetric DDoS",
            "port_scan": "Port Scan",
            "syn_flood": "SYN Flood",
            "amplification_attack": "Amplification Attack",
            "ml_anomaly": "ML-Detected Anomaly"
        }
    
    def process(self, features: List[float], src_ip: str = None) -> Dict:
        """
        Process features through both detection methods.
        Returns detailed detection result.
        """
        # Rule-based detection
        rule_result, attack_type, rule_confidence = self.rule_detector.detect(features, src_ip)
        
        # ML detection
        ml_result, anomaly_score = self.ml_detector.detect(features)
        
        # Combine results
        result = {
            "status": "NORMAL",
            "attack_type": None,
            "confidence": 0.0,
            "rule_triggered": rule_result == "ATTACK",
            "ml_anomaly": ml_result == "ANOMALY",
            "anomaly_score": anomaly_score,
            "src_ip": src_ip,
            "risk_score": self.rule_detector.get_ip_risk_score(src_ip) if src_ip else 0.0
        }
        
        # Determine final verdict
        if rule_result == "ATTACK":
            result["status"] = "ATTACK"
            result["attack_type"] = attack_type
            result["confidence"] = rule_confidence
            
            # Boost confidence if ML also detects anomaly
            if ml_result == "ANOMALY":
                result["confidence"] = min(rule_confidence + 0.15, 0.98)
                result["detection_method"] = "hybrid"
            else:
                result["detection_method"] = "rule"
        
        elif ml_result == "ANOMALY" and ml_result not in ("LEARNING", "MODEL_TRAINED"):
            result["status"] = "ANOMALY"
            result["attack_type"] = "ml_anomaly"
            result["confidence"] = min(0.5 + anomaly_score * 0.1, 0.85)
            result["detection_method"] = "ml"
        
        elif ml_result in ("LEARNING", "MODEL_TRAINED"):
            result["status"] = ml_result
        
        return result


# Global instances
rule_detector = RuleBasedDetector()
ml_detector = MLDetector()
hybrid_detector = HybridDetector()

# Legacy globals for backward compatibility
model = ml_detector.model
trained = False
buffer = ml_detector.buffer


def process(features: List[float], src_ip: str = None) -> str:
    """
    Legacy process function with enhanced detection.
    Returns simple status string for backward compatibility.
    """
    global trained
    
    result = hybrid_detector.process(features, src_ip)
    trained = hybrid_detector.ml_detector.trained
    
    if result["status"] == "ATTACK":
        return "ANOMALY"  # Return ANOMALY for backward compatibility
    elif result["status"] == "ANOMALY":
        return "ANOMALY"
    elif result["status"] in ("LEARNING", "MODEL_TRAINED"):
        return result["status"]
    else:
        return "NORMAL"


def detect_detailed(features: List[float], src_ip: str = None) -> Dict:
    """
    New detailed detection function.
    Returns comprehensive detection result.
    """
    return hybrid_detector.process(features, src_ip)
