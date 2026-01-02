"""
Detection Accuracy Benchmark
Tests the detection system against labeled attack samples to measure real accuracy.
"""

import json
import time
from datetime import datetime
from typing import Dict, List, Tuple
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.detector import hybrid_detector, detect_detailed
from backend.features import feature_extractor


class AccuracyBenchmark:
    """Benchmark detection accuracy against known attack patterns"""
    
    def __init__(self):
        self.results = {
            "true_positives": 0,
            "false_positives": 0,
            "true_negatives": 0,
            "false_negatives": 0,
            "by_attack_type": {}
        }
    
    def generate_attack_samples(self) -> List[Tuple[Dict, str, bool]]:
        """
        Generate synthetic attack samples with known labels.
        Returns: List of (packet_data, attack_type, is_attack)
        """
        samples = []
        
        # ===== BENIGN TRAFFIC SAMPLES =====
        # Normal web browsing
        for i in range(50):
            samples.append((
                self._create_packet("192.168.1.100", "93.184.216.34", "TCP", 1200 + i*10, 443),
                "benign", False
            ))
        
        # Normal DNS queries
        for i in range(30):
            samples.append((
                self._create_packet("192.168.1.100", "8.8.8.8", "DNS", 70, 53),
                "benign", False
            ))
        
        # ===== DDOS ATTACK SAMPLES =====
        # High rate from single source (DoS)
        for i in range(100):
            samples.append((
                self._create_packet("10.0.0.1", "192.168.1.1", "TCP", 60, 80, pps=500),
                "dos", True
            ))
        
        # High rate from multiple sources (DDoS)
        for i in range(100):
            src = f"203.0.113.{i % 254 + 1}"
            samples.append((
                self._create_packet(src, "192.168.1.1", "TCP", 60, 80, pps=50),
                "ddos", True
            ))
        
        # ===== SYN FLOOD SAMPLES =====
        # Small packets, high rate (SYN flood pattern)
        for i in range(80):
            samples.append((
                self._create_packet("10.0.0.50", "192.168.1.1", "TCP", 40, 80, pps=200),
                "syn_flood", True
            ))
        
        # ===== PORT SCAN SAMPLES =====
        # Many unique ports from single source
        for port in range(1, 101):
            samples.append((
                self._create_packet("10.0.0.100", "192.168.1.1", "TCP", 60, port, unique_ports=port),
                "port_scan", True
            ))
        
        # ===== AMPLIFICATION ATTACK SAMPLES =====
        # Large packets, consistent size, high rate
        for i in range(50):
            samples.append((
                self._create_packet("203.0.113.1", "192.168.1.1", "UDP", 1400, 53, pps=100, consistent_size=True),
                "amplification", True
            ))
        
        # ===== MORE BENIGN SAMPLES =====
        # Normal HTTPS traffic
        for i in range(40):
            samples.append((
                self._create_packet("192.168.1.50", "172.217.14.110", "TCP", 800 + i*5, 443),
                "benign", False
            ))
        
        return samples
    
    def _create_packet(self, src_ip: str, dst_ip: str, protocol: str, 
                       length: int, dst_port: int, pps: float = 10,
                       unique_ports: int = 1, consistent_size: bool = False) -> Dict:
        """Create a packet with simulated features"""
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "length": length,
            "dst_port": dst_port,
            "_simulated_pps": pps,
            "_unique_ports": unique_ports,
            "_consistent_size": consistent_size
        }
    
    def _generate_features_for_sample(self, packet: Dict) -> List[float]:
        """Generate feature vector for a sample packet"""
        pps = packet.get("_simulated_pps", 10)
        unique_ports = packet.get("_unique_ports", 1)
        consistent_size = packet.get("_consistent_size", False)
        length = packet.get("length", 100)
        
        # Simulate the 21 features from features.py
        features = [
            pps * 10,           # packet_count
            pps * length * 10,  # byte_count
            pps,                # packets_per_sec
            pps * length,       # bytes_per_sec
            pps * 1.2,          # rate_1s
            pps * 1.0,          # rate_5s
            pps * 0.8,          # rate_30s
            unique_ports,       # unique_dst_ports
            1,                  # unique_dst_ips
            1,                  # unique_protocols
            length,             # pkt_size_mean
            0 if consistent_size else length * 0.2,  # pkt_size_std
            length - 20,        # pkt_size_min
            length + 20,        # pkt_size_max
            1.0 / max(pps, 1),  # iat_mean
            0.1 / max(pps, 1),  # iat_std
            2.0 if pps < 50 else 0.5,  # src_entropy (low for attacks)
            3.0,                # dst_entropy
            1.5,                # protocol_entropy
            10.0,               # flow_duration
            length              # avg_pkt_size
        ]
        return features
    
    def run_benchmark(self) -> Dict:
        """Run the accuracy benchmark"""
        print("="*60)
        print("DETECTION ACCURACY BENCHMARK")
        print("="*60)
        
        samples = self.generate_attack_samples()
        print(f"\nTotal samples: {len(samples)}")
        
        attack_samples = [s for s in samples if s[2]]
        benign_samples = [s for s in samples if not s[2]]
        print(f"Attack samples: {len(attack_samples)}")
        print(f"Benign samples: {len(benign_samples)}")
        
        print("\nRunning detection on all samples...")
        
        for i, (packet, attack_type, is_attack) in enumerate(samples):
            # Generate features
            features = self._generate_features_for_sample(packet)
            
            # Run detection
            result = detect_detailed(features, packet["src_ip"])
            detected_as_attack = result["status"] in ("ATTACK", "ANOMALY")
            
            # Track results
            if is_attack and detected_as_attack:
                self.results["true_positives"] += 1
            elif is_attack and not detected_as_attack:
                self.results["false_negatives"] += 1
            elif not is_attack and detected_as_attack:
                self.results["false_positives"] += 1
            else:
                self.results["true_negatives"] += 1
            
            # Track by attack type
            if attack_type not in self.results["by_attack_type"]:
                self.results["by_attack_type"][attack_type] = {
                    "total": 0, "detected": 0, "missed": 0
                }
            
            self.results["by_attack_type"][attack_type]["total"] += 1
            if is_attack:
                if detected_as_attack:
                    self.results["by_attack_type"][attack_type]["detected"] += 1
                else:
                    self.results["by_attack_type"][attack_type]["missed"] += 1
        
        # Calculate metrics
        tp = self.results["true_positives"]
        fp = self.results["false_positives"]
        tn = self.results["true_negatives"]
        fn = self.results["false_negatives"]
        
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0  # Detection Rate
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False Positive Rate
        
        metrics = {
            "accuracy": round(accuracy * 100, 2),
            "precision": round(precision * 100, 2),
            "recall_detection_rate": round(recall * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "false_positive_rate": round(fpr * 100, 2),
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn
            },
            "by_attack_type": {}
        }
        
        # Calculate per-attack-type detection rate
        for attack_type, data in self.results["by_attack_type"].items():
            if data["total"] > 0 and attack_type != "benign":
                detection_rate = data["detected"] / data["total"] * 100
                metrics["by_attack_type"][attack_type] = {
                    "detection_rate": round(detection_rate, 1),
                    "detected": data["detected"],
                    "missed": data["missed"],
                    "total": data["total"]
                }
        
        return metrics
    
    def print_results(self, metrics: Dict):
        """Print benchmark results"""
        print("\n" + "="*60)
        print("BENCHMARK RESULTS")
        print("="*60)
        
        print(f"\n📊 OVERALL METRICS:")
        print(f"   Accuracy:           {metrics['accuracy']}%")
        print(f"   Precision:          {metrics['precision']}%")
        print(f"   Recall (Detection): {metrics['recall_detection_rate']}%")
        print(f"   F1 Score:           {metrics['f1_score']}%")
        print(f"   False Positive Rate:{metrics['false_positive_rate']}%")
        
        print(f"\n📈 CONFUSION MATRIX:")
        cm = metrics["confusion_matrix"]
        print(f"   True Positives:  {cm['true_positives']} (attacks correctly detected)")
        print(f"   True Negatives:  {cm['true_negatives']} (benign correctly passed)")
        print(f"   False Positives: {cm['false_positives']} (benign flagged as attack)")
        print(f"   False Negatives: {cm['false_negatives']} (attacks missed)")
        
        print(f"\n🎯 DETECTION RATE BY ATTACK TYPE:")
        for attack_type, data in metrics["by_attack_type"].items():
            status = "✅" if data["detection_rate"] >= 80 else "⚠️" if data["detection_rate"] >= 50 else "❌"
            print(f"   {status} {attack_type}: {data['detection_rate']}% ({data['detected']}/{data['total']} detected)")
        
        print("\n" + "="*60)
        
        # Interpretation
        print("\n📋 INTERPRETATION:")
        if metrics['recall_detection_rate'] >= 90:
            print("   ✅ EXCELLENT: Very high attack detection rate")
        elif metrics['recall_detection_rate'] >= 75:
            print("   ✅ GOOD: Most attacks will be detected")
        elif metrics['recall_detection_rate'] >= 50:
            print("   ⚠️ MODERATE: Some attacks may be missed")
        else:
            print("   ❌ LOW: Many attacks may be missed - consider training with labeled data")
        
        if metrics['false_positive_rate'] <= 5:
            print("   ✅ Low false positive rate - minimal alert fatigue")
        elif metrics['false_positive_rate'] <= 15:
            print("   ⚠️ Moderate false positives - some noise expected")
        else:
            print("   ❌ High false positives - may cause alert fatigue")


if __name__ == "__main__":
    benchmark = AccuracyBenchmark()
    metrics = benchmark.run_benchmark()
    benchmark.print_results(metrics)
    
    # Save results to file
    with open("data/accuracy_benchmark.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print("\n📁 Results saved to data/accuracy_benchmark.json")
