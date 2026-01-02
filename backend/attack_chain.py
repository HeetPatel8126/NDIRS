"""
Attack Chain Detector
Detects multi-stage attacks using MITRE ATT&CK framework mapping.
Identifies low-and-slow attacks by tracking attack progression over extended periods.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
import threading
import json


# MITRE ATT&CK Tactics (Kill Chain Stages)
ATTACK_STAGES = {
    "reconnaissance": {
        "order": 1,
        "description": "Gathering information about the target",
        "indicators": ["port_scan", "dns_enumeration", "service_discovery"]
    },
    "resource_development": {
        "order": 2,
        "description": "Establishing resources for the attack",
        "indicators": ["infrastructure_setup"]
    },
    "initial_access": {
        "order": 3,
        "description": "Gaining initial foothold",
        "indicators": ["brute_force", "phishing", "exploit_public_app", "valid_accounts"]
    },
    "execution": {
        "order": 4,
        "description": "Running malicious code",
        "indicators": ["powershell_execution", "script_execution", "scheduled_task"]
    },
    "persistence": {
        "order": 5,
        "description": "Maintaining access",
        "indicators": ["registry_modification", "scheduled_task", "account_creation"]
    },
    "privilege_escalation": {
        "order": 6,
        "description": "Gaining higher-level permissions",
        "indicators": ["privilege_escalation", "token_manipulation", "sudo_abuse"]
    },
    "defense_evasion": {
        "order": 7,
        "description": "Avoiding detection",
        "indicators": ["log_deletion", "disable_security_tools", "timestomping"]
    },
    "credential_access": {
        "order": 8,
        "description": "Stealing credentials",
        "indicators": ["credential_dumping", "keylogging", "brute_force"]
    },
    "discovery": {
        "order": 9,
        "description": "Exploring the environment",
        "indicators": ["network_discovery", "system_discovery", "account_discovery"]
    },
    "lateral_movement": {
        "order": 10,
        "description": "Moving through the network",
        "indicators": ["lateral_movement", "remote_services", "pass_the_hash"]
    },
    "collection": {
        "order": 11,
        "description": "Gathering data of interest",
        "indicators": ["data_collection", "email_collection", "screen_capture"]
    },
    "command_and_control": {
        "order": 12,
        "description": "Communicating with compromised systems",
        "indicators": ["c2_communication", "dns_tunneling", "encrypted_channel"]
    },
    "exfiltration": {
        "order": 13,
        "description": "Stealing data",
        "indicators": ["data_exfiltration", "exfil_over_c2", "exfil_over_web"]
    },
    "impact": {
        "order": 14,
        "description": "Disrupting availability or integrity",
        "indicators": ["ddos", "dos", "ransomware", "data_destruction"]
    }
}


@dataclass
class AttackChain:
    """Represents a multi-stage attack campaign"""
    id: str
    name: str = ""
    stages_detected: Dict[str, List[Dict]] = field(default_factory=dict)
    source_ips: Set[str] = field(default_factory=set)
    target_ips: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    first_seen: datetime = None
    last_seen: datetime = None
    total_events: int = 0
    confidence: float = 0.0
    severity: str = "low"
    is_active: bool = True
    
    def add_stage(self, stage: str, events: List[Dict]):
        """Add events to a stage"""
        if stage not in self.stages_detected:
            self.stages_detected[stage] = []
        self.stages_detected[stage].extend(events)
        self.total_events += len(events)
        self._update_metadata(events)
        self._calculate_severity()
    
    def _update_metadata(self, events: List[Dict]):
        """Update chain metadata from events"""
        for event in events:
            if event.get("src_ip"):
                self.source_ips.add(event["src_ip"])
            if event.get("dst_ip"):
                self.target_ips.add(event["dst_ip"])
            if event.get("user"):
                self.users.add(event["user"])
            
            ts = event.get("timestamp")
            if ts:
                event_time = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
                if not self.first_seen or event_time < self.first_seen:
                    self.first_seen = event_time
                if not self.last_seen or event_time > self.last_seen:
                    self.last_seen = event_time
    
    def _calculate_severity(self):
        """Calculate severity based on stages and progression"""
        num_stages = len(self.stages_detected)
        max_stage_order = max(
            ATTACK_STAGES.get(s, {}).get("order", 0) 
            for s in self.stages_detected.keys()
        ) if self.stages_detected else 0
        
        # More stages = higher confidence this is a real attack
        self.confidence = min(0.3 + (num_stages * 0.15), 0.95)
        
        # Severity based on how far the attack has progressed
        if max_stage_order >= 13:  # exfiltration or impact
            self.severity = "critical"
        elif max_stage_order >= 10:  # lateral movement onwards
            self.severity = "high"
        elif max_stage_order >= 6:  # privilege escalation onwards
            self.severity = "medium"
        else:
            self.severity = "low"
    
    def get_progression(self) -> List[Dict]:
        """Get attack progression in order"""
        progression = []
        for stage in sorted(
            self.stages_detected.keys(),
            key=lambda s: ATTACK_STAGES.get(s, {}).get("order", 99)
        ):
            progression.append({
                "stage": stage,
                "order": ATTACK_STAGES.get(stage, {}).get("order", 99),
                "description": ATTACK_STAGES.get(stage, {}).get("description", ""),
                "event_count": len(self.stages_detected[stage]),
                "first_event": self.stages_detected[stage][0] if self.stages_detected[stage] else None
            })
        return progression
    
    def generate_narrative(self) -> str:
        """Generate human-readable attack narrative"""
        if not self.stages_detected:
            return "No attack activity detected."
        
        progression = self.get_progression()
        narrative = f"**Attack Campaign: {self.name or self.id}**\n\n"
        narrative += f"**Duration**: {self._format_duration()}\n"
        narrative += f"**Source IPs**: {', '.join(list(self.source_ips)[:5])}\n"
        narrative += f"**Target IPs**: {', '.join(list(self.target_ips)[:5])}\n"
        narrative += f"**Users Involved**: {', '.join(list(self.users)[:5]) or 'N/A'}\n\n"
        narrative += "**Attack Timeline**:\n\n"
        
        for stage_info in progression:
            narrative += f"→ **{stage_info['stage'].replace('_', ' ').title()}** "
            narrative += f"({stage_info['event_count']} events)\n"
            narrative += f"   {stage_info['description']}\n\n"
        
        return narrative
    
    def _format_duration(self) -> str:
        if not self.first_seen or not self.last_seen:
            return "Unknown"
        duration = self.last_seen - self.first_seen
        if duration.days > 0:
            return f"{duration.days} days, {duration.seconds // 3600} hours"
        elif duration.seconds > 3600:
            return f"{duration.seconds // 3600} hours, {(duration.seconds % 3600) // 60} minutes"
        else:
            return f"{duration.seconds // 60} minutes"
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "stages": list(self.stages_detected.keys()),
            "stage_count": len(self.stages_detected),
            "progression": self.get_progression(),
            "source_ips": list(self.source_ips),
            "target_ips": list(self.target_ips),
            "users": list(self.users),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "duration": self._format_duration(),
            "total_events": self.total_events,
            "confidence": round(self.confidence, 2),
            "severity": self.severity,
            "is_active": self.is_active,
            "narrative": self.generate_narrative()
        }


class AttackChainDetector:
    """Detects and tracks multi-stage attack chains"""
    
    def __init__(self):
        self.chains: Dict[str, AttackChain] = {}
        self.lock = threading.Lock()
        # Map attack types to MITRE stages
        self.attack_type_to_stage = {
            "port_scan": "reconnaissance",
            "service_scan": "reconnaissance",
            "dns_enum": "reconnaissance",
            "brute_force": "initial_access",
            "password_spray": "initial_access",
            "exploit": "initial_access",
            "phishing": "initial_access",
            "malware": "execution",
            "powershell": "execution",
            "script": "execution",
            "scheduled_task": "persistence",
            "registry": "persistence",
            "account_created": "persistence",
            "privilege_escalation": "privilege_escalation",
            "token_abuse": "privilege_escalation",
            "log_clear": "defense_evasion",
            "credential_dump": "credential_access",
            "mimikatz": "credential_access",
            "lateral_movement": "lateral_movement",
            "psexec": "lateral_movement",
            "wmi_remote": "lateral_movement",
            "rdp_access": "lateral_movement",
            "data_staging": "collection",
            "c2_beacon": "command_and_control",
            "dns_tunnel": "command_and_control",
            "data_exfiltration": "exfiltration",
            "large_upload": "exfiltration",
            "ddos": "impact",
            "dos": "impact",
            "ransomware": "impact",
        }
        self.inactive_threshold = timedelta(hours=4)
    
    def _get_chain_key(self, event: Dict) -> Optional[str]:
        """Generate a key to group related events into chains"""
        # Group by source IP, target IP, or user
        src_ip = event.get("src_ip")
        user = event.get("user")
        
        if src_ip:
            return f"chain_{src_ip}"
        elif user:
            return f"chain_user_{user}"
        return None
    
    def _determine_stage(self, event: Dict) -> Optional[str]:
        """Determine which attack stage an event belongs to"""
        attack_type = event.get("attack_type", event.get("event_type", "")).lower()
        
        # Direct mapping
        if attack_type in self.attack_type_to_stage:
            return self.attack_type_to_stage[attack_type]
        
        # Check event metadata
        metadata = event.get("metadata", {})
        event_id = metadata.get("event_id")
        
        # Windows Event ID mappings
        windows_stage_map = {
            4624: "initial_access",  # Successful login
            4625: "initial_access",  # Failed login
            4672: "privilege_escalation",  # Special privileges
            4720: "persistence",  # Account created
            4732: "persistence",  # Group membership changed
            7045: "persistence",  # Service installed
            4688: "execution",  # Process created
            4697: "persistence",  # Service installed
            1102: "defense_evasion",  # Log cleared
        }
        
        if event_id in windows_stage_map:
            return windows_stage_map[event_id]
        
        # Keyword-based detection
        message = event.get("message", "").lower()
        keywords_to_stage = {
            "reconnaissance": ["scan", "probe", "enumerate", "discovery"],
            "initial_access": ["login", "authentication", "access denied", "password"],
            "execution": ["execute", "powershell", "cmd", "script", "process"],
            "persistence": ["service", "scheduled", "registry", "startup"],
            "privilege_escalation": ["privilege", "admin", "root", "sudo", "elevation"],
            "lateral_movement": ["remote", "psexec", "wmi", "rdp", "ssh"],
            "exfiltration": ["upload", "transfer", "exfil", "send"],
        }
        
        for stage, keywords in keywords_to_stage.items():
            if any(kw in message for kw in keywords):
                return stage
        
        return None
    
    def process_event(self, event: Dict) -> Optional[AttackChain]:
        """Process an event and update attack chains"""
        stage = self._determine_stage(event)
        if not stage:
            return None
        
        chain_key = self._get_chain_key(event)
        if not chain_key:
            return None
        
        with self.lock:
            if chain_key not in self.chains:
                self.chains[chain_key] = AttackChain(
                    id=chain_key,
                    name=f"Campaign {len(self.chains) + 1}"
                )
            
            chain = self.chains[chain_key]
            chain.add_stage(stage, [event])
            chain.is_active = True
            
            return chain
    
    def process_correlated_event(self, correlated_event: Dict) -> Optional[AttackChain]:
        """Process a correlated event from the correlation engine"""
        attack_type = correlated_event.get("attack_type", "")
        stage = self.attack_type_to_stage.get(attack_type)
        
        if not stage:
            stage = correlated_event.get("stage")
        
        if not stage:
            return None
        
        # Use source IP as chain key
        source_ips = correlated_event.get("source_ips", [])
        if not source_ips:
            return None
        
        chain_key = f"chain_{source_ips[0]}"
        
        with self.lock:
            if chain_key not in self.chains:
                self.chains[chain_key] = AttackChain(
                    id=chain_key,
                    name=f"Campaign {len(self.chains) + 1}"
                )
            
            chain = self.chains[chain_key]
            # Convert correlated event to event format
            event_data = {
                "src_ip": source_ips[0] if source_ips else None,
                "dst_ip": correlated_event.get("target_ips", [None])[0],
                "user": correlated_event.get("users", [None])[0] if correlated_event.get("users") else None,
                "timestamp": correlated_event.get("first_seen", datetime.now().isoformat()),
                "attack_type": attack_type,
                "message": correlated_event.get("narrative", "")
            }
            chain.add_stage(stage, [event_data])
            chain.is_active = True
            
            return chain
    
    def get_active_chains(self) -> List[Dict]:
        """Get all active attack chains"""
        with self.lock:
            self._mark_inactive_chains()
            return [chain.to_dict() for chain in self.chains.values() if chain.is_active]
    
    def get_all_chains(self) -> List[Dict]:
        """Get all attack chains"""
        with self.lock:
            return [chain.to_dict() for chain in self.chains.values()]
    
    def _mark_inactive_chains(self):
        """Mark chains as inactive if no recent activity"""
        now = datetime.now()
        for chain in self.chains.values():
            if chain.last_seen and (now - chain.last_seen) > self.inactive_threshold:
                chain.is_active = False
    
    def get_chain_by_ip(self, ip: str) -> Optional[Dict]:
        """Get attack chain associated with an IP"""
        chain_key = f"chain_{ip}"
        with self.lock:
            if chain_key in self.chains:
                return self.chains[chain_key].to_dict()
        return None
    
    def get_critical_chains(self) -> List[Dict]:
        """Get chains with critical severity"""
        with self.lock:
            return [
                chain.to_dict() for chain in self.chains.values()
                if chain.severity == "critical" and chain.is_active
            ]
    
    def get_chain_statistics(self) -> Dict:
        """Get statistics about attack chains"""
        with self.lock:
            active_chains = [c for c in self.chains.values() if c.is_active]
            all_chains = list(self.chains.values())
            
            stage_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            
            for chain in all_chains:
                for stage in chain.stages_detected:
                    stage_counts[stage] += 1
                severity_counts[chain.severity] += 1
            
            return {
                "total_chains": len(all_chains),
                "active_chains": len(active_chains),
                "by_severity": dict(severity_counts),
                "by_stage": dict(stage_counts),
                "avg_stages_per_chain": sum(len(c.stages_detected) for c in all_chains) / max(len(all_chains), 1),
                "chains_with_exfiltration": sum(1 for c in all_chains if "exfiltration" in c.stages_detected),
                "chains_with_lateral_movement": sum(1 for c in all_chains if "lateral_movement" in c.stages_detected)
            }


# Global attack chain detector instance
attack_chain_detector = AttackChainDetector()
