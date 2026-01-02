"""
Enhanced Feature Extraction for DDoS/DoS Detection
Extracts rich features for ML-based anomaly detection and attack classification.
"""

from collections import defaultdict
import time
import math
from typing import Dict, List, Tuple


class FeatureExtractor:
    """Advanced feature extraction for network traffic analysis"""
    
    def __init__(self):
        # Per-IP statistics
        self.ip_stats = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "start_time": time.time(),
            "last_time": time.time(),
            "protocols": defaultdict(int),
            "dst_ports": set(),
            "dst_ips": set(),
            "packet_sizes": [],
            "inter_arrival_times": []
        })
        
        # Global statistics for entropy calculation
        self.global_stats = {
            "src_ip_counts": defaultdict(int),
            "dst_ip_counts": defaultdict(int),
            "protocol_counts": defaultdict(int),
            "total_packets": 0
        }
        
        # Time windows for rate calculation
        self.time_windows = {
            "1s": defaultdict(lambda: {"count": 0, "bytes": 0, "start": time.time()}),
            "5s": defaultdict(lambda: {"count": 0, "bytes": 0, "start": time.time()}),
            "30s": defaultdict(lambda: {"count": 0, "bytes": 0, "start": time.time()})
        }
    
    def extract(self, packet: Dict) -> List[float]:
        """Extract comprehensive features from a packet"""
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        protocol = packet.get("protocol", "")
        length = packet.get("length", 0)
        dst_port = packet.get("dst_port", 0)
        
        current_time = time.time()
        
        # Update IP statistics
        stats = self.ip_stats[src_ip]
        
        # Calculate inter-arrival time
        iat = current_time - stats["last_time"]
        stats["inter_arrival_times"].append(iat)
        if len(stats["inter_arrival_times"]) > 1000:
            stats["inter_arrival_times"] = stats["inter_arrival_times"][-500:]
        
        # Update stats
        stats["packet_count"] += 1
        stats["byte_count"] += length
        stats["last_time"] = current_time
        stats["protocols"][protocol] += 1
        if dst_port:
            stats["dst_ports"].add(dst_port)
        if dst_ip:
            stats["dst_ips"].add(dst_ip)
        stats["packet_sizes"].append(length)
        if len(stats["packet_sizes"]) > 1000:
            stats["packet_sizes"] = stats["packet_sizes"][-500:]
        
        # Update global stats
        self.global_stats["src_ip_counts"][src_ip] += 1
        self.global_stats["dst_ip_counts"][dst_ip] += 1
        self.global_stats["protocol_counts"][protocol] += 1
        self.global_stats["total_packets"] += 1
        
        # Update time window stats
        self._update_time_windows(src_ip, length, current_time)
        
        # Calculate features
        duration = max(current_time - stats["start_time"], 0.001)
        
        features = [
            # Basic counts
            stats["packet_count"],
            stats["byte_count"],
            
            # Rate features
            stats["packet_count"] / duration,  # packets per second
            stats["byte_count"] / duration,    # bytes per second
            
            # Time window rates
            self._get_window_rate(src_ip, "1s"),
            self._get_window_rate(src_ip, "5s"),
            self._get_window_rate(src_ip, "30s"),
            
            # Connection diversity
            len(stats["dst_ports"]),           # unique destination ports
            len(stats["dst_ips"]),             # unique destination IPs
            len(stats["protocols"]),           # unique protocols used
            
            # Packet size statistics
            self._mean(stats["packet_sizes"]),
            self._std(stats["packet_sizes"]),
            min(stats["packet_sizes"]) if stats["packet_sizes"] else 0,
            max(stats["packet_sizes"]) if stats["packet_sizes"] else 0,
            
            # Inter-arrival time statistics
            self._mean(stats["inter_arrival_times"]),
            self._std(stats["inter_arrival_times"]),
            
            # Entropy features (for DDoS detection)
            self._calculate_src_entropy(),
            self._calculate_dst_entropy(),
            self._calculate_protocol_entropy(),
            
            # Flow duration
            duration,
            
            # Ratio features
            stats["byte_count"] / max(stats["packet_count"], 1),  # avg packet size
        ]
        
        return features
    
    def _update_time_windows(self, src_ip: str, length: int, current_time: float):
        """Update time window statistics"""
        windows = {"1s": 1, "5s": 5, "30s": 30}
        
        for window_name, window_duration in windows.items():
            window = self.time_windows[window_name][src_ip]
            
            # Reset window if expired
            if current_time - window["start"] > window_duration:
                window["count"] = 0
                window["bytes"] = 0
                window["start"] = current_time
            
            window["count"] += 1
            window["bytes"] += length
    
    def _get_window_rate(self, src_ip: str, window_name: str) -> float:
        """Get packets per second for a specific time window"""
        window = self.time_windows[window_name][src_ip]
        duration = max(time.time() - window["start"], 0.001)
        return window["count"] / duration
    
    def _calculate_src_entropy(self) -> float:
        """Calculate source IP entropy (low entropy = possible DDoS)"""
        return self._calculate_entropy(self.global_stats["src_ip_counts"])
    
    def _calculate_dst_entropy(self) -> float:
        """Calculate destination IP entropy"""
        return self._calculate_entropy(self.global_stats["dst_ip_counts"])
    
    def _calculate_protocol_entropy(self) -> float:
        """Calculate protocol entropy"""
        return self._calculate_entropy(self.global_stats["protocol_counts"])
    
    def _calculate_entropy(self, counts: Dict) -> float:
        """Calculate Shannon entropy"""
        total = sum(counts.values())
        if total == 0:
            return 0.0
        
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _mean(self, values: List[float]) -> float:
        """Calculate mean of a list"""
        if not values:
            return 0.0
        return sum(values) / len(values)
    
    def _std(self, values: List[float]) -> float:
        """Calculate standard deviation of a list"""
        if len(values) < 2:
            return 0.0
        mean = self._mean(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)
    
    def get_feature_names(self) -> List[str]:
        """Get names of all features"""
        return [
            "packet_count",
            "byte_count",
            "packets_per_sec",
            "bytes_per_sec",
            "rate_1s",
            "rate_5s",
            "rate_30s",
            "unique_dst_ports",
            "unique_dst_ips",
            "unique_protocols",
            "pkt_size_mean",
            "pkt_size_std",
            "pkt_size_min",
            "pkt_size_max",
            "iat_mean",
            "iat_std",
            "src_entropy",
            "dst_entropy",
            "protocol_entropy",
            "flow_duration",
            "avg_pkt_size"
        ]


# Global feature extractor instance
feature_extractor = FeatureExtractor()


# Legacy function for backward compatibility
traffic = defaultdict(lambda: {"count": 0, "bytes": 0, "start": time.time()})

def extract_features(packet):
    """Legacy feature extraction (enhanced)"""
    # Use the new feature extractor
    return feature_extractor.extract(packet)
