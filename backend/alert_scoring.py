"""
Alert Scoring & Prioritization System
Uses ML and heuristics to score alerts and reduce alert fatigue.
Prioritizes true positives while suppressing false positives and noise.
"""

import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass
import threading
import json
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass
class ScoredAlert:
    """Alert with priority score and context"""
    id: str
    original_alert: Dict
    priority_score: float  # 0-100, higher = more critical
    confidence: float  # 0-1, model confidence
    factors: Dict  # Contributing factors to the score
    suppressed: bool = False
    suppression_reason: str = ""
    related_alerts: List[str] = None
    actionable: bool = True
    recommended_action: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "priority_score": round(self.priority_score, 1),
            "confidence": round(self.confidence, 2),
            "severity": self._score_to_severity(),
            "factors": self.factors,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "related_alerts": self.related_alerts or [],
            "actionable": self.actionable,
            "recommended_action": self.recommended_action,
            **self.original_alert
        }
    
    def _score_to_severity(self) -> str:
        if self.priority_score >= 80:
            return "critical"
        elif self.priority_score >= 60:
            return "high"
        elif self.priority_score >= 40:
            return "medium"
        else:
            return "low"


class AlertScorer:
    """Scores individual alerts based on multiple factors"""
    
    # Base severity scores
    SEVERITY_SCORES = {
        "critical": 40,
        "high": 30,
        "medium": 20,
        "low": 10,
        "info": 5
    }
    
    # Attack type criticality multipliers
    ATTACK_CRITICALITY = {
        "data_exfiltration": 1.5,
        "ransomware": 1.5,
        "privilege_escalation": 1.3,
        "lateral_movement": 1.3,
        "credential_theft": 1.3,
        "ddos": 1.2,
        "dos": 1.1,
        "brute_force": 1.2,
        "port_scan": 0.8,
        "reconnaissance": 0.7,
    }
    
    # High-value targets that increase alert priority
    HIGH_VALUE_TARGETS = {
        "domain controller", "dc", "ad", "active directory",
        "database", "db", "sql", "oracle",
        "backup", "vault",
        "mail", "exchange",
        "admin", "root", "administrator"
    }
    
    def __init__(self):
        self.historical_scores = []
        self.known_good_ips = set()
        self.known_bad_ips = set()
        self.alert_history = defaultdict(list)
    
    def score(self, alert: Dict) -> ScoredAlert:
        """Calculate priority score for an alert"""
        factors = {}
        base_score = 0
        
        # Factor 1: Base severity
        severity = alert.get("severity", "medium").lower()
        base_score = self.SEVERITY_SCORES.get(severity, 20)
        factors["base_severity"] = base_score
        
        # Factor 2: Attack type criticality
        attack_type = alert.get("attack_type", alert.get("type", "")).lower()
        multiplier = self.ATTACK_CRITICALITY.get(attack_type, 1.0)
        factors["attack_criticality"] = multiplier
        
        # Factor 3: Target value
        target_score = self._score_target_value(alert)
        factors["target_value"] = target_score
        
        # Factor 4: Source reputation
        src_score = self._score_source_reputation(alert.get("src_ip"))
        factors["source_reputation"] = src_score
        
        # Factor 5: Attack chain participation
        chain_score = self._score_chain_participation(alert)
        factors["chain_participation"] = chain_score
        
        # Factor 6: Time-based (recent attacks on same target)
        time_score = self._score_temporal_correlation(alert)
        factors["temporal_correlation"] = time_score
        
        # Factor 7: Confidence from ML model
        confidence = alert.get("confidence", 0.5)
        ml_score = confidence * 20
        factors["ml_confidence"] = ml_score
        
        # Calculate final score
        final_score = (base_score * multiplier) + target_score + src_score + chain_score + time_score + ml_score
        final_score = min(max(final_score, 0), 100)  # Clamp to 0-100
        
        # Generate recommended action
        action = self._recommend_action(alert, final_score)
        
        return ScoredAlert(
            id=f"scored_{alert.get('id', hash(str(alert)))}",
            original_alert=alert,
            priority_score=final_score,
            confidence=confidence,
            factors=factors,
            actionable=final_score >= 30,
            recommended_action=action
        )
    
    def _score_target_value(self, alert: Dict) -> float:
        """Score based on target value"""
        target = alert.get("dst_ip", "") or alert.get("hostname", "") or alert.get("user", "")
        target = target.lower()
        
        for high_value in self.HIGH_VALUE_TARGETS:
            if high_value in target:
                return 15
        
        return 0
    
    def _score_source_reputation(self, src_ip: str) -> float:
        """Score based on source IP reputation"""
        if not src_ip:
            return 0
        
        if src_ip in self.known_bad_ips:
            return 20
        if src_ip in self.known_good_ips:
            return -10
        
        # Check if IP is internal
        if self._is_internal_ip(src_ip):
            return 5  # Internal IPs acting maliciously is more concerning
        
        return 0
    
    def _is_internal_ip(self, ip: str) -> bool:
        if not ip:
            return False
        return (ip.startswith("10.") or 
                ip.startswith("192.168.") or 
                ip.startswith("172.16.") or
                ip.startswith("172.17."))
    
    def _score_chain_participation(self, alert: Dict) -> float:
        """Score based on whether alert is part of an attack chain"""
        stage = alert.get("stage")
        if stage:
            # Later stages are more concerning
            stage_scores = {
                "reconnaissance": 2,
                "initial_access": 5,
                "execution": 8,
                "persistence": 10,
                "privilege_escalation": 12,
                "lateral_movement": 15,
                "exfiltration": 20,
                "impact": 20
            }
            return stage_scores.get(stage, 5)
        return 0
    
    def _score_temporal_correlation(self, alert: Dict) -> float:
        """Score based on recent related activity"""
        src_ip = alert.get("src_ip")
        dst_ip = alert.get("dst_ip")
        
        score = 0
        recent_cutoff = datetime.now() - timedelta(hours=1)
        
        # Check recent alerts from same source
        if src_ip and src_ip in self.alert_history:
            recent = [a for a in self.alert_history[src_ip] 
                     if a.get("timestamp", datetime.min) > recent_cutoff]
            if len(recent) >= 3:
                score += 10  # Multiple alerts = more concerning
        
        # Track this alert
        if src_ip:
            self.alert_history[src_ip].append({
                "timestamp": datetime.now(),
                "alert": alert
            })
        
        return score
    
    def _recommend_action(self, alert: Dict, score: float) -> str:
        """Generate recommended action based on alert"""
        attack_type = alert.get("attack_type", "").lower()
        src_ip = alert.get("src_ip")
        
        if score >= 80:
            if attack_type in ("ddos", "dos"):
                return f"IMMEDIATE: Block source IP {src_ip} and enable rate limiting"
            elif attack_type == "data_exfiltration":
                return f"IMMEDIATE: Isolate affected system and block outbound traffic"
            elif attack_type == "brute_force":
                return f"IMMEDIATE: Block IP {src_ip} and enforce account lockout"
            else:
                return f"IMMEDIATE: Investigate and consider blocking {src_ip}"
        elif score >= 60:
            return f"HIGH PRIORITY: Investigate source {src_ip} within 1 hour"
        elif score >= 40:
            return f"MEDIUM PRIORITY: Review activity from {src_ip} during next shift"
        else:
            return "LOW PRIORITY: Monitor for escalation"
    
    def add_known_bad_ip(self, ip: str):
        """Add an IP to known bad list"""
        self.known_bad_ips.add(ip)
    
    def add_known_good_ip(self, ip: str):
        """Add an IP to known good list"""
        self.known_good_ips.add(ip)


class AlertDeduplicator:
    """Deduplicates and groups similar alerts"""
    
    def __init__(self):
        self.seen_alerts = {}  # signature -> first occurrence
        self.dedup_window = timedelta(minutes=5)
    
    def _generate_signature(self, alert: Dict) -> str:
        """Generate a signature for deduplication"""
        components = [
            alert.get("attack_type", alert.get("type", "")),
            alert.get("src_ip", ""),
            alert.get("dst_ip", ""),
            alert.get("event_type", "")
        ]
        return "_".join(str(c) for c in components)
    
    def is_duplicate(self, alert: Dict) -> Tuple[bool, Optional[str]]:
        """Check if alert is a duplicate"""
        signature = self._generate_signature(alert)
        now = datetime.now()
        
        # Clean old entries
        self.seen_alerts = {
            sig: ts for sig, ts in self.seen_alerts.items()
            if now - ts < self.dedup_window
        }
        
        if signature in self.seen_alerts:
            return True, signature
        
        self.seen_alerts[signature] = now
        return False, signature


class AlertSuppressor:
    """Suppresses low-value and noisy alerts"""
    
    def __init__(self):
        self.suppression_rules = []
        self._init_default_rules()
        self.suppression_counts = defaultdict(int)
    
    def _init_default_rules(self):
        """Initialize default suppression rules"""
        # Suppress scanner traffic from known scanners
        self.suppression_rules.append({
            "name": "known_scanners",
            "condition": lambda a: a.get("src_ip") in self._get_known_scanners(),
            "reason": "Traffic from known security scanner"
        })
        
        # Suppress low confidence ML alerts
        self.suppression_rules.append({
            "name": "low_confidence",
            "condition": lambda a: a.get("confidence", 1.0) < 0.3,
            "reason": "Low ML confidence score"
        })
        
        # Suppress internal port scans during business hours (could be IT)
        self.suppression_rules.append({
            "name": "internal_scan_business_hours",
            "condition": lambda a: (
                a.get("attack_type") == "port_scan" and
                self._is_internal(a.get("src_ip")) and
                self._is_business_hours()
            ),
            "reason": "Internal port scan during business hours (potential IT activity)"
        })
    
    def _get_known_scanners(self) -> set:
        """Return known scanner IPs (e.g., Nessus, Qualys)"""
        return set()  # Configure with your scanner IPs
    
    def _is_internal(self, ip: str) -> bool:
        if not ip:
            return False
        return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")
    
    def _is_business_hours(self) -> bool:
        hour = datetime.now().hour
        weekday = datetime.now().weekday()
        return weekday < 5 and 8 <= hour <= 18
    
    def should_suppress(self, alert: Dict) -> Tuple[bool, str]:
        """Check if alert should be suppressed"""
        for rule in self.suppression_rules:
            try:
                if rule["condition"](alert):
                    self.suppression_counts[rule["name"]] += 1
                    return True, rule["reason"]
            except Exception:
                continue
        return False, ""
    
    def add_suppression_rule(self, name: str, condition, reason: str):
        """Add a custom suppression rule"""
        self.suppression_rules.append({
            "name": name,
            "condition": condition,
            "reason": reason
        })


class AlertAggregator:
    """Aggregates related alerts into single actionable items"""
    
    def __init__(self):
        self.aggregation_window = timedelta(minutes=15)
    
    def aggregate(self, alerts: List[ScoredAlert]) -> List[Dict]:
        """Aggregate similar alerts"""
        groups = defaultdict(list)
        
        for alert in alerts:
            # Group by source IP and attack type
            key = (
                alert.original_alert.get("src_ip", "unknown"),
                alert.original_alert.get("attack_type", "unknown")
            )
            groups[key].append(alert)
        
        aggregated = []
        for (src_ip, attack_type), group in groups.items():
            if len(group) == 1:
                aggregated.append(group[0].to_dict())
            else:
                # Create aggregated alert
                agg = self._create_aggregated_alert(group, src_ip, attack_type)
                aggregated.append(agg)
        
        return aggregated
    
    def _create_aggregated_alert(
        self, 
        alerts: List[ScoredAlert], 
        src_ip: str, 
        attack_type: str
    ) -> Dict:
        """Create a single aggregated alert from multiple"""
        max_score = max(a.priority_score for a in alerts)
        
        return {
            "id": f"agg_{src_ip}_{attack_type}_{int(datetime.now().timestamp())}",
            "type": "aggregated",
            "attack_type": attack_type,
            "src_ip": src_ip,
            "alert_count": len(alerts),
            "priority_score": max_score,
            "severity": "critical" if max_score >= 80 else "high" if max_score >= 60 else "medium",
            "first_seen": min(a.original_alert.get("timestamp", "") for a in alerts),
            "last_seen": max(a.original_alert.get("timestamp", "") for a in alerts),
            "target_ips": list(set(a.original_alert.get("dst_ip") for a in alerts if a.original_alert.get("dst_ip"))),
            "summary": f"{len(alerts)} {attack_type} events from {src_ip}",
            "component_alerts": [a.id for a in alerts]
        }


class AlertPrioritizationEngine:
    """Main engine for alert scoring, deduplication, and prioritization"""
    
    def __init__(self):
        self.scorer = AlertScorer()
        self.deduplicator = AlertDeduplicator()
        self.suppressor = AlertSuppressor()
        self.aggregator = AlertAggregator()
        self.processed_alerts: List[ScoredAlert] = []
        self.suppressed_count = 0
        self.deduplicated_count = 0
        self.lock = threading.Lock()
    
    def process_alert(self, alert: Dict) -> Optional[ScoredAlert]:
        """Process a single alert through the prioritization pipeline"""
        with self.lock:
            # Step 1: Check for duplicates
            is_dup, signature = self.deduplicator.is_duplicate(alert)
            if is_dup:
                self.deduplicated_count += 1
                return None
            
            # Step 2: Score the alert
            scored = self.scorer.score(alert)
            
            # Step 3: Check suppression rules
            suppress, reason = self.suppressor.should_suppress(alert)
            if suppress:
                scored.suppressed = True
                scored.suppression_reason = reason
                self.suppressed_count += 1
            
            # Step 4: Store processed alert
            self.processed_alerts.append(scored)
            
            # Keep only recent alerts
            cutoff = datetime.now() - timedelta(hours=24)
            self.processed_alerts = [
                a for a in self.processed_alerts
                if not a.suppressed  # Keep unsuppressed
            ][-1000:]  # Keep max 1000
            
            return scored
    
    def process_alerts(self, alerts: List[Dict]) -> List[ScoredAlert]:
        """Process multiple alerts"""
        results = []
        for alert in alerts:
            result = self.process_alert(alert)
            if result and not result.suppressed:
                results.append(result)
        return results
    
    def get_prioritized_alerts(self, limit: int = 50) -> List[Dict]:
        """Get alerts sorted by priority"""
        with self.lock:
            active = [a for a in self.processed_alerts if not a.suppressed]
            sorted_alerts = sorted(active, key=lambda x: x.priority_score, reverse=True)
            return [a.to_dict() for a in sorted_alerts[:limit]]
    
    def get_aggregated_alerts(self, limit: int = 50) -> List[Dict]:
        """Get aggregated and prioritized alerts"""
        with self.lock:
            active = [a for a in self.processed_alerts if not a.suppressed]
            aggregated = self.aggregator.aggregate(active)
            return sorted(aggregated, key=lambda x: x.get("priority_score", 0), reverse=True)[:limit]
    
    def get_statistics(self) -> Dict:
        """Get alert processing statistics"""
        with self.lock:
            active = [a for a in self.processed_alerts if not a.suppressed]
            
            severity_dist = defaultdict(int)
            for alert in active:
                severity_dist[alert._score_to_severity()] += 1
            
            return {
                "total_processed": len(self.processed_alerts) + self.suppressed_count + self.deduplicated_count,
                "active_alerts": len(active),
                "suppressed": self.suppressed_count,
                "deduplicated": self.deduplicated_count,
                "by_severity": dict(severity_dist),
                "avg_priority_score": sum(a.priority_score for a in active) / max(len(active), 1),
                "reduction_rate": (self.suppressed_count + self.deduplicated_count) / max(len(self.processed_alerts) + self.suppressed_count + self.deduplicated_count, 1) * 100
            }


# Global alert prioritization engine instance
alert_engine = AlertPrioritizationEngine()
