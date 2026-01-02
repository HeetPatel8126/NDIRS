"""
Event Correlation Engine
Correlates disparate log events into meaningful attack narratives.
Uses temporal, spatial, and behavioral analysis to group related events.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
import threading
import math
import json


@dataclass
class CorrelatedEvent:
    """A group of correlated events forming a potential attack narrative"""
    id: str
    events: List[Dict] = field(default_factory=list)
    attack_type: str = "unknown"
    confidence: float = 0.0
    severity: str = "low"
    first_seen: datetime = None
    last_seen: datetime = None
    source_ips: Set[str] = field(default_factory=set)
    target_ips: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    narrative: str = ""
    stage: str = "unknown"  # reconnaissance, initial_access, execution, persistence, etc.
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "attack_type": self.attack_type,
            "confidence": round(self.confidence, 2),
            "severity": self.severity,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "duration_seconds": (self.last_seen - self.first_seen).total_seconds() if self.first_seen and self.last_seen else 0,
            "source_ips": list(self.source_ips),
            "target_ips": list(self.target_ips),
            "users": list(self.users),
            "event_count": len(self.events),
            "narrative": self.narrative,
            "stage": self.stage,
            "events": self.events[:50]  # Limit events in response
        }


class AttackPattern:
    """Defines patterns for detecting specific attack types"""
    
    def __init__(self, name: str, stages: List[Dict], time_window: int = 300):
        self.name = name
        self.stages = stages  # List of stage definitions
        self.time_window = time_window  # seconds
    
    def match(self, events: List[Dict]) -> Tuple[bool, float, str]:
        """Check if events match this attack pattern"""
        raise NotImplementedError


class CorrelationRule:
    """Base class for correlation rules"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    def evaluate(self, events: List[Dict]) -> Optional[CorrelatedEvent]:
        raise NotImplementedError


class BruteForceRule(CorrelationRule):
    """Detect brute force attacks: multiple failed logins followed by success"""
    
    def __init__(self):
        super().__init__(
            "brute_force",
            "Detects multiple failed login attempts potentially followed by success"
        )
        self.threshold_failures = 5
        self.time_window = 300  # 5 minutes
    
    def evaluate(self, events: List[Dict]) -> Optional[CorrelatedEvent]:
        # Group by source IP and target user
        login_attempts = defaultdict(list)
        
        for event in events:
            if event.get("event_type") == "login":
                key = (event.get("src_ip"), event.get("user"))
                login_attempts[key].append(event)
        
        for (src_ip, user), attempts in login_attempts.items():
            if not src_ip or not user:
                continue
            
            failures = [e for e in attempts if e.get("action") == "failure"]
            successes = [e for e in attempts if e.get("action") == "success"]
            
            if len(failures) >= self.threshold_failures:
                correlated = CorrelatedEvent(
                    id=f"brute_force_{src_ip}_{int(time.time())}",
                    events=attempts,
                    attack_type="brute_force",
                    confidence=min(0.5 + (len(failures) * 0.1), 0.95),
                    severity="critical" if successes else "high",
                    first_seen=datetime.fromisoformat(attempts[0]["timestamp"]) if attempts else datetime.now(),
                    last_seen=datetime.fromisoformat(attempts[-1]["timestamp"]) if attempts else datetime.now(),
                    source_ips={src_ip} if src_ip else set(),
                    users={user} if user else set(),
                    stage="initial_access",
                    narrative=self._generate_narrative(src_ip, user, failures, successes)
                )
                return correlated
        
        return None
    
    def _generate_narrative(self, src_ip: str, user: str, failures: List, successes: List) -> str:
        narrative = f"Potential brute force attack detected. "
        narrative += f"Source IP {src_ip} attempted {len(failures)} failed login(s) "
        narrative += f"against user '{user}'. "
        if successes:
            narrative += f"ALERT: {len(successes)} successful login(s) detected after failures - possible compromise!"
        return narrative


class PortScanRule(CorrelationRule):
    """Detect port scanning activity"""
    
    def __init__(self):
        super().__init__(
            "port_scan",
            "Detects port scanning reconnaissance activity"
        )
        self.threshold_ports = 15
        self.time_window = 60  # 1 minute
    
    def evaluate(self, events: List[Dict]) -> Optional[CorrelatedEvent]:
        # Group connections by source IP
        connections = defaultdict(lambda: {"ports": set(), "events": []})
        
        for event in events:
            if event.get("source_type") in ("network", "firewall"):
                src_ip = event.get("src_ip")
                dst_port = event.get("dst_port")
                if src_ip and dst_port:
                    connections[src_ip]["ports"].add(dst_port)
                    connections[src_ip]["events"].append(event)
        
        for src_ip, data in connections.items():
            if len(data["ports"]) >= self.threshold_ports:
                events_list = data["events"]
                return CorrelatedEvent(
                    id=f"port_scan_{src_ip}_{int(time.time())}",
                    events=events_list,
                    attack_type="port_scan",
                    confidence=min(0.6 + (len(data["ports"]) * 0.02), 0.95),
                    severity="medium",
                    first_seen=datetime.fromisoformat(events_list[0]["timestamp"]) if events_list else datetime.now(),
                    last_seen=datetime.fromisoformat(events_list[-1]["timestamp"]) if events_list else datetime.now(),
                    source_ips={src_ip},
                    stage="reconnaissance",
                    narrative=f"Port scan detected from {src_ip}. {len(data['ports'])} unique ports probed in short timeframe."
                )
        
        return None


class DDoSRule(CorrelationRule):
    """Detect DDoS/DoS attacks"""
    
    def __init__(self):
        super().__init__(
            "ddos",
            "Detects distributed denial of service attacks"
        )
        self.threshold_pps = 1000  # packets per second
        self.threshold_sources = 5  # for DDoS vs DoS
    
    def evaluate(self, events: List[Dict]) -> Optional[CorrelatedEvent]:
        # Group by target IP
        targets = defaultdict(lambda: {"sources": set(), "events": [], "bytes": 0})
        
        for event in events:
            if event.get("source_type") == "network":
                dst_ip = event.get("dst_ip")
                src_ip = event.get("src_ip")
                if dst_ip:
                    targets[dst_ip]["sources"].add(src_ip)
                    targets[dst_ip]["events"].append(event)
                    targets[dst_ip]["bytes"] += event.get("metadata", {}).get("length", 0)
        
        for dst_ip, data in targets.items():
            events_list = data["events"]
            if len(events_list) < 100:
                continue
            
            # Calculate rate
            if len(events_list) >= 2:
                first_ts = datetime.fromisoformat(events_list[0]["timestamp"])
                last_ts = datetime.fromisoformat(events_list[-1]["timestamp"])
                duration = max((last_ts - first_ts).total_seconds(), 1)
                pps = len(events_list) / duration
                
                if pps >= self.threshold_pps:
                    is_distributed = len(data["sources"]) >= self.threshold_sources
                    attack_type = "ddos" if is_distributed else "dos"
                    
                    return CorrelatedEvent(
                        id=f"{attack_type}_{dst_ip}_{int(time.time())}",
                        events=events_list,
                        attack_type=attack_type,
                        confidence=min(0.7 + (pps / 10000), 0.98),
                        severity="critical",
                        first_seen=first_ts,
                        last_seen=last_ts,
                        source_ips=data["sources"],
                        target_ips={dst_ip},
                        stage="impact",
                        narrative=self._generate_narrative(dst_ip, data["sources"], pps, is_distributed)
                    )
        
        return None
    
    def _generate_narrative(self, target: str, sources: Set[str], pps: float, is_distributed: bool) -> str:
        attack_name = "DDoS" if is_distributed else "DoS"
        narrative = f"{attack_name} attack detected targeting {target}. "
        narrative += f"Rate: {pps:.0f} packets/sec from {len(sources)} source(s). "
        if is_distributed:
            narrative += f"Attack is distributed across multiple sources indicating botnet or coordinated attack."
        return narrative


class LateralMovementRule(CorrelationRule):
    """Detect lateral movement patterns"""
    
    def __init__(self):
        super().__init__(
            "lateral_movement",
            "Detects lateral movement within the network"
        )
    
    def evaluate(self, events: List[Dict]) -> Optional[CorrelatedEvent]:
        # Track authentication events between internal hosts
        auth_graph = defaultdict(set)  # src -> set of destinations
        auth_events = []
        
        for event in events:
            if event.get("event_type") in ("login", "authentication"):
                src = event.get("src_ip")
                dst = event.get("dst_ip") or event.get("hostname")
                if src and dst and self._is_internal(src):
                    auth_graph[src].add(dst)
                    auth_events.append(event)
        
        # Check for fan-out pattern (one source → many destinations)
        for src, destinations in auth_graph.items():
            if len(destinations) >= 3:  # Accessing 3+ internal systems
                return CorrelatedEvent(
                    id=f"lateral_movement_{src}_{int(time.time())}",
                    events=auth_events,
                    attack_type="lateral_movement",
                    confidence=0.7,
                    severity="high",
                    source_ips={src},
                    target_ips=destinations,
                    stage="lateral_movement",
                    narrative=f"Potential lateral movement from {src}. Host accessed {len(destinations)} internal systems: {', '.join(list(destinations)[:5])}"
                )
        
        return None
    
    def _is_internal(self, ip: str) -> bool:
        """Check if IP is internal/private"""
        if not ip:
            return False
        return (ip.startswith("10.") or 
                ip.startswith("192.168.") or 
                ip.startswith("172.16.") or
                ip.startswith("172.17.") or
                ip.startswith("172.18."))


class DataExfiltrationRule(CorrelationRule):
    """Detect potential data exfiltration"""
    
    def __init__(self):
        super().__init__(
            "data_exfiltration",
            "Detects potential data exfiltration based on unusual outbound traffic"
        )
        self.threshold_bytes = 100 * 1024 * 1024  # 100 MB
    
    def evaluate(self, events: List[Dict]) -> Optional[CorrelatedEvent]:
        # Track outbound data volume by source
        outbound = defaultdict(lambda: {"bytes": 0, "events": [], "destinations": set()})
        
        for event in events:
            if event.get("source_type") == "network":
                src = event.get("src_ip")
                dst = event.get("dst_ip")
                if src and dst and self._is_internal(src) and not self._is_internal(dst):
                    length = event.get("metadata", {}).get("length", 0)
                    outbound[src]["bytes"] += length
                    outbound[src]["events"].append(event)
                    outbound[src]["destinations"].add(dst)
        
        for src, data in outbound.items():
            if data["bytes"] >= self.threshold_bytes:
                return CorrelatedEvent(
                    id=f"exfiltration_{src}_{int(time.time())}",
                    events=data["events"],
                    attack_type="data_exfiltration",
                    confidence=0.6,
                    severity="critical",
                    source_ips={src},
                    target_ips=data["destinations"],
                    stage="exfiltration",
                    narrative=f"Potential data exfiltration from {src}. {data['bytes'] / (1024*1024):.1f} MB sent to {len(data['destinations'])} external destination(s)."
                )
        
        return None
    
    def _is_internal(self, ip: str) -> bool:
        if not ip:
            return False
        return (ip.startswith("10.") or 
                ip.startswith("192.168.") or 
                ip.startswith("172.16."))


class PrivilegeEscalationRule(CorrelationRule):
    """Detect privilege escalation attempts"""
    
    def __init__(self):
        super().__init__(
            "privilege_escalation",
            "Detects privilege escalation attempts"
        )
    
    def evaluate(self, events: List[Dict]) -> Optional[CorrelatedEvent]:
        priv_events = []
        
        for event in events:
            event_type = event.get("event_type")
            metadata = event.get("metadata", {})
            
            # Check for privilege-related Windows events
            if metadata.get("event_id") in (4672, 4673, 4674):
                priv_events.append(event)
            
            # Check for sudo/su in syslog
            if event.get("source_type") == "syslog":
                msg = event.get("message", "").lower()
                if "sudo" in msg or "su:" in msg or "privilege" in msg:
                    priv_events.append(event)
        
        if len(priv_events) >= 3:
            users = {e.get("user") for e in priv_events if e.get("user")}
            sources = {e.get("src_ip") for e in priv_events if e.get("src_ip")}
            
            return CorrelatedEvent(
                id=f"priv_escalation_{int(time.time())}",
                events=priv_events,
                attack_type="privilege_escalation",
                confidence=0.65,
                severity="high",
                source_ips=sources,
                users=users,
                stage="privilege_escalation",
                narrative=f"Potential privilege escalation detected. {len(priv_events)} privilege-related events from user(s): {', '.join(users)}"
            )
        
        return None


class CorrelationEngine:
    """Main correlation engine that processes logs and generates attack narratives"""
    
    def __init__(self):
        self.rules = [
            BruteForceRule(),
            PortScanRule(),
            DDoSRule(),
            LateralMovementRule(),
            DataExfiltrationRule(),
            PrivilegeEscalationRule(),
        ]
        self.correlated_events: List[CorrelatedEvent] = []
        self.event_window = []  # Rolling window of recent events
        self.window_duration = 300  # 5 minutes
        self.lock = threading.Lock()
        self.processed_event_ids = set()
    
    def add_event(self, event: Dict):
        """Add a new event to the correlation window"""
        with self.lock:
            self.event_window.append(event)
            self._cleanup_old_events()
    
    def add_events(self, events: List[Dict]):
        """Add multiple events"""
        with self.lock:
            self.event_window.extend(events)
            self._cleanup_old_events()
    
    def _cleanup_old_events(self):
        """Remove events outside the time window"""
        cutoff = datetime.now() - timedelta(seconds=self.window_duration)
        self.event_window = [
            e for e in self.event_window
            if datetime.fromisoformat(e.get("timestamp", datetime.now().isoformat())) > cutoff
        ]
    
    def correlate(self) -> List[CorrelatedEvent]:
        """Run all correlation rules and return new correlated events"""
        new_correlations = []
        
        with self.lock:
            events_snapshot = list(self.event_window)
        
        for rule in self.rules:
            try:
                result = rule.evaluate(events_snapshot)
                if result and result.id not in self.processed_event_ids:
                    new_correlations.append(result)
                    self.correlated_events.append(result)
                    self.processed_event_ids.add(result.id)
            except Exception as e:
                print(f"[CORRELATION] Rule {rule.name} error: {e}")
        
        # Keep only recent correlations
        cutoff = datetime.now() - timedelta(hours=24)
        self.correlated_events = [
            ce for ce in self.correlated_events
            if ce.last_seen and ce.last_seen > cutoff
        ]
        
        return new_correlations
    
    def get_active_threats(self) -> List[Dict]:
        """Get currently active threat correlations"""
        return [ce.to_dict() for ce in self.correlated_events]
    
    def get_threat_summary(self) -> Dict:
        """Get summary of current threats"""
        summary = {
            "total_correlations": len(self.correlated_events),
            "by_severity": defaultdict(int),
            "by_type": defaultdict(int),
            "by_stage": defaultdict(int)
        }
        
        for ce in self.correlated_events:
            summary["by_severity"][ce.severity] += 1
            summary["by_type"][ce.attack_type] += 1
            summary["by_stage"][ce.stage] += 1
        
        return {
            "total_correlations": summary["total_correlations"],
            "by_severity": dict(summary["by_severity"]),
            "by_type": dict(summary["by_type"]),
            "by_stage": dict(summary["by_stage"])
        }
    
    def get_attack_timeline(self) -> List[Dict]:
        """Get timeline of attacks sorted by time"""
        timeline = []
        for ce in sorted(self.correlated_events, key=lambda x: x.first_seen or datetime.min):
            timeline.append({
                "id": ce.id,
                "time": ce.first_seen.isoformat() if ce.first_seen else None,
                "type": ce.attack_type,
                "severity": ce.severity,
                "stage": ce.stage,
                "summary": ce.narrative[:100] + "..." if len(ce.narrative) > 100 else ce.narrative
            })
        return timeline


# Global correlation engine instance
correlation_engine = CorrelationEngine()
