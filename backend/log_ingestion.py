"""
Log Ingestion Module
Handles ingesting logs from multiple heterogeneous sources:
- Network packets (existing)
- Windows Event Logs
- Syslog (Linux/Unix)
- Firewall logs
- Application logs (JSON, CSV)
- Custom log formats
"""

import json
import re
import os
from datetime import datetime
from typing import Dict, List, Optional, Generator
from pathlib import Path
from collections import deque
import threading
import time

# Unified log schema
class NormalizedLog:
    """Standard schema for all log types"""
    def __init__(
        self,
        timestamp: datetime,
        source_type: str,  # network, windows, syslog, firewall, application
        source_name: str,  # specific source identifier
        event_type: str,   # login, connection, access, error, etc.
        severity: str,     # info, low, medium, high, critical
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        user: Optional[str] = None,
        hostname: Optional[str] = None,
        process: Optional[str] = None,
        action: Optional[str] = None,  # allow, deny, success, failure
        protocol: Optional[str] = None,
        message: str = "",
        raw_log: str = "",
        metadata: Optional[Dict] = None
    ):
        self.timestamp = timestamp
        self.source_type = source_type
        self.source_name = source_name
        self.event_type = event_type
        self.severity = severity
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.user = user
        self.hostname = hostname
        self.process = process
        self.action = action
        self.protocol = protocol
        self.message = message
        self.raw_log = raw_log
        self.metadata = metadata or {}
        self.id = f"{timestamp.timestamp()}_{hash(raw_log) % 100000}"
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source_type": self.source_type,
            "source_name": self.source_name,
            "event_type": self.event_type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "user": self.user,
            "hostname": self.hostname,
            "process": self.process,
            "action": self.action,
            "protocol": self.protocol,
            "message": self.message,
            "metadata": self.metadata
        }


class LogBuffer:
    """Thread-safe buffer for incoming logs"""
    def __init__(self, maxlen: int = 10000):
        self.buffer = deque(maxlen=maxlen)
        self.lock = threading.Lock()
    
    def add(self, log: NormalizedLog):
        with self.lock:
            self.buffer.append(log)
    
    def get_all(self) -> List[NormalizedLog]:
        with self.lock:
            return list(self.buffer)
    
    def get_recent(self, count: int) -> List[NormalizedLog]:
        with self.lock:
            return list(self.buffer)[-count:]
    
    def get_by_timerange(self, start: datetime, end: datetime) -> List[NormalizedLog]:
        with self.lock:
            return [log for log in self.buffer 
                    if start <= log.timestamp <= end]


# Global log buffer
log_buffer = LogBuffer(maxlen=50000)


class WindowsEventParser:
    """Parse Windows Event Log entries"""
    
    # Important Windows Event IDs
    EVENT_MAPPING = {
        # Security Events
        4624: ("login", "success", "info"),      # Successful login
        4625: ("login", "failure", "high"),      # Failed login
        4634: ("logout", "success", "info"),     # Logoff
        4648: ("login", "explicit", "medium"),   # Login with explicit credentials
        4672: ("privilege", "assigned", "medium"), # Special privileges assigned
        4720: ("account", "created", "medium"),  # User account created
        4722: ("account", "enabled", "low"),     # User account enabled
        4725: ("account", "disabled", "medium"), # User account disabled
        4726: ("account", "deleted", "high"),    # User account deleted
        4732: ("group", "member_added", "medium"), # Member added to security group
        4740: ("account", "locked", "high"),     # Account locked out
        4768: ("kerberos", "tgt_request", "info"), # Kerberos TGT request
        4769: ("kerberos", "service_ticket", "info"), # Kerberos service ticket
        4771: ("kerberos", "preauth_failure", "high"), # Kerberos pre-auth failed
        4776: ("ntlm", "validation", "info"),    # NTLM credential validation
        
        # System Events
        7045: ("service", "installed", "medium"), # New service installed
        7036: ("service", "state_change", "info"), # Service state changed
        
        # PowerShell Events
        4103: ("powershell", "module_logged", "medium"),
        4104: ("powershell", "script_block", "medium"),
    }
    
    @classmethod
    def parse(cls, event_data: Dict) -> Optional[NormalizedLog]:
        """Parse Windows Event to normalized format"""
        try:
            event_id = event_data.get("EventID", 0)
            mapping = cls.EVENT_MAPPING.get(event_id, ("unknown", "unknown", "info"))
            
            return NormalizedLog(
                timestamp=datetime.fromisoformat(event_data.get("TimeCreated", datetime.now().isoformat())),
                source_type="windows",
                source_name=event_data.get("Channel", "Security"),
                event_type=mapping[0],
                severity=mapping[2],
                src_ip=event_data.get("IpAddress"),
                user=event_data.get("TargetUserName") or event_data.get("SubjectUserName"),
                hostname=event_data.get("WorkstationName") or event_data.get("Computer"),
                process=event_data.get("ProcessName"),
                action=mapping[1],
                message=event_data.get("Message", ""),
                raw_log=json.dumps(event_data),
                metadata={
                    "event_id": event_id,
                    "logon_type": event_data.get("LogonType"),
                    "status": event_data.get("Status"),
                    "failure_reason": event_data.get("FailureReason")
                }
            )
        except Exception as e:
            print(f"[LOG_INGESTION] Windows event parse error: {e}")
            return None


class SyslogParser:
    """Parse Syslog entries (RFC 3164 and RFC 5424)"""
    
    # Syslog severity levels
    SEVERITY_MAP = {
        0: "critical",  # Emergency
        1: "critical",  # Alert
        2: "critical",  # Critical
        3: "high",      # Error
        4: "medium",    # Warning
        5: "low",       # Notice
        6: "info",      # Informational
        7: "info"       # Debug
    }
    
    # Common syslog patterns
    RFC3164_PATTERN = re.compile(
        r'^<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
    )
    
    RFC5424_PATTERN = re.compile(
        r'^<(\d+)>\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[.*?\])?\s*(.*)$'
    )
    
    @classmethod
    def parse(cls, line: str) -> Optional[NormalizedLog]:
        """Parse syslog line to normalized format"""
        try:
            # Try RFC 5424 first
            match = cls.RFC5424_PATTERN.match(line)
            if match:
                priority = int(match.group(1))
                facility = priority >> 3
                severity = priority & 0x7
                
                return NormalizedLog(
                    timestamp=datetime.fromisoformat(match.group(2).replace('Z', '+00:00')),
                    source_type="syslog",
                    source_name=match.group(3),  # hostname
                    event_type=match.group(4),   # app-name
                    severity=cls.SEVERITY_MAP.get(severity, "info"),
                    hostname=match.group(3),
                    process=match.group(4),
                    message=match.group(7),
                    raw_log=line,
                    metadata={
                        "facility": facility,
                        "severity_num": severity,
                        "proc_id": match.group(5),
                        "msg_id": match.group(6)
                    }
                )
            
            # Try RFC 3164
            match = cls.RFC3164_PATTERN.match(line)
            if match:
                priority = int(match.group(1))
                severity = priority & 0x7
                
                # Parse timestamp (assumes current year)
                ts_str = match.group(2)
                ts = datetime.strptime(f"{datetime.now().year} {ts_str}", "%Y %b %d %H:%M:%S")
                
                return NormalizedLog(
                    timestamp=ts,
                    source_type="syslog",
                    source_name=match.group(3),
                    event_type=match.group(4),
                    severity=cls.SEVERITY_MAP.get(severity, "info"),
                    hostname=match.group(3),
                    process=match.group(4),
                    message=match.group(6),
                    raw_log=line,
                    metadata={
                        "pid": match.group(5),
                        "severity_num": severity
                    }
                )
            
            return None
        except Exception as e:
            print(f"[LOG_INGESTION] Syslog parse error: {e}")
            return None


class FirewallLogParser:
    """Parse common firewall log formats"""
    
    @classmethod
    def parse_pfsense(cls, line: str) -> Optional[NormalizedLog]:
        """Parse pfSense/OPNsense filterlog format"""
        try:
            parts = line.split(',')
            if len(parts) < 20:
                return None
            
            action = "allow" if parts[6] == "pass" else "deny"
            protocol = parts[8].lower()
            
            return NormalizedLog(
                timestamp=datetime.now(),  # pfSense logs often lack timestamp
                source_type="firewall",
                source_name="pfsense",
                event_type="connection",
                severity="info" if action == "allow" else "medium",
                src_ip=parts[18] if len(parts) > 18 else None,
                dst_ip=parts[19] if len(parts) > 19 else None,
                src_port=int(parts[20]) if len(parts) > 20 and parts[20].isdigit() else None,
                dst_port=int(parts[21]) if len(parts) > 21 and parts[21].isdigit() else None,
                protocol=protocol,
                action=action,
                message=f"Firewall {action} {protocol}",
                raw_log=line,
                metadata={
                    "interface": parts[4] if len(parts) > 4 else None,
                    "direction": parts[7] if len(parts) > 7 else None
                }
            )
        except Exception as e:
            return None
    
    @classmethod
    def parse_iptables(cls, line: str) -> Optional[NormalizedLog]:
        """Parse iptables/netfilter log format"""
        try:
            # Extract key-value pairs from iptables log
            kv_pattern = re.compile(r'(\w+)=(\S+)')
            matches = dict(kv_pattern.findall(line))
            
            action = "deny" if "DPT=" in line or "DROP" in line else "allow"
            
            return NormalizedLog(
                timestamp=datetime.now(),
                source_type="firewall",
                source_name="iptables",
                event_type="connection",
                severity="info" if action == "allow" else "medium",
                src_ip=matches.get("SRC"),
                dst_ip=matches.get("DST"),
                src_port=int(matches.get("SPT", 0)) or None,
                dst_port=int(matches.get("DPT", 0)) or None,
                protocol=matches.get("PROTO", "").lower(),
                action=action,
                message=f"iptables {action}",
                raw_log=line,
                metadata={
                    "in_interface": matches.get("IN"),
                    "out_interface": matches.get("OUT"),
                    "mac": matches.get("MAC")
                }
            )
        except Exception as e:
            return None


class NetworkPacketNormalizer:
    """Convert network packets to normalized log format"""
    
    @classmethod
    def normalize(cls, packet: Dict) -> NormalizedLog:
        """Convert packet dict to NormalizedLog"""
        return NormalizedLog(
            timestamp=datetime.now(),
            source_type="network",
            source_name="capture",
            event_type="packet",
            severity="info",
            src_ip=packet.get("src_ip"),
            dst_ip=packet.get("dst_ip"),
            src_port=packet.get("src_port"),
            dst_port=packet.get("dst_port"),
            protocol=packet.get("protocol"),
            action="captured",
            message=f"Network packet: {packet.get('protocol')}",
            raw_log=json.dumps(packet),
            metadata={
                "length": packet.get("length"),
                "flags": packet.get("flags")
            }
        )


class JSONLogParser:
    """Parse generic JSON formatted logs"""
    
    # Common field mappings for different JSON log formats
    FIELD_MAPPINGS = {
        "timestamp": ["timestamp", "@timestamp", "time", "datetime", "created_at", "date"],
        "src_ip": ["src_ip", "source_ip", "client_ip", "remote_addr", "src", "clientIP"],
        "dst_ip": ["dst_ip", "dest_ip", "destination_ip", "server_ip", "dst"],
        "user": ["user", "username", "user_name", "userid", "user_id", "account"],
        "action": ["action", "event_action", "operation", "method"],
        "message": ["message", "msg", "description", "text", "event_message"]
    }
    
    @classmethod
    def parse(cls, data: Dict, source_name: str = "json") -> Optional[NormalizedLog]:
        """Parse JSON log entry"""
        try:
            # Find timestamp
            timestamp = datetime.now()
            for field in cls.FIELD_MAPPINGS["timestamp"]:
                if field in data:
                    ts_val = data[field]
                    if isinstance(ts_val, str):
                        timestamp = datetime.fromisoformat(ts_val.replace('Z', '+00:00'))
                    break
            
            # Find other fields
            src_ip = None
            for field in cls.FIELD_MAPPINGS["src_ip"]:
                if field in data:
                    src_ip = data[field]
                    break
            
            dst_ip = None
            for field in cls.FIELD_MAPPINGS["dst_ip"]:
                if field in data:
                    dst_ip = data[field]
                    break
            
            user = None
            for field in cls.FIELD_MAPPINGS["user"]:
                if field in data:
                    user = data[field]
                    break
            
            message = ""
            for field in cls.FIELD_MAPPINGS["message"]:
                if field in data:
                    message = str(data[field])
                    break
            
            return NormalizedLog(
                timestamp=timestamp,
                source_type="application",
                source_name=source_name,
                event_type=data.get("event_type", data.get("type", "log")),
                severity=data.get("severity", data.get("level", "info")).lower(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                user=user,
                message=message,
                raw_log=json.dumps(data),
                metadata=data
            )
        except Exception as e:
            print(f"[LOG_INGESTION] JSON parse error: {e}")
            return None


class LogIngestionEngine:
    """Main engine for ingesting logs from multiple sources"""
    
    def __init__(self):
        self.running = False
        self.sources = {}  # source_id -> config
        self.threads = []
    
    def add_file_source(self, source_id: str, file_path: str, parser_type: str = "auto"):
        """Add a file-based log source"""
        self.sources[source_id] = {
            "type": "file",
            "path": file_path,
            "parser": parser_type
        }
    
    def add_network_source(self, source_id: str, host: str, port: int, protocol: str = "tcp"):
        """Add a network-based log source (syslog receiver)"""
        self.sources[source_id] = {
            "type": "network",
            "host": host,
            "port": port,
            "protocol": protocol
        }
    
    def ingest_log_line(self, line: str, source_type: str = "auto") -> Optional[NormalizedLog]:
        """Ingest a single log line and return normalized log"""
        line = line.strip()
        if not line:
            return None
        
        normalized = None
        
        # Try JSON first
        if line.startswith('{'):
            try:
                data = json.loads(line)
                normalized = JSONLogParser.parse(data)
            except:
                pass
        
        # Try syslog
        if not normalized and source_type in ("auto", "syslog"):
            normalized = SyslogParser.parse(line)
        
        # Try firewall formats
        if not normalized and source_type in ("auto", "firewall"):
            normalized = FirewallLogParser.parse_iptables(line)
            if not normalized:
                normalized = FirewallLogParser.parse_pfsense(line)
        
        if normalized:
            log_buffer.add(normalized)
        
        return normalized
    
    def ingest_packet(self, packet: Dict) -> NormalizedLog:
        """Ingest a network packet"""
        normalized = NetworkPacketNormalizer.normalize(packet)
        log_buffer.add(normalized)
        return normalized
    
    def ingest_windows_event(self, event_data: Dict) -> Optional[NormalizedLog]:
        """Ingest a Windows Event"""
        normalized = WindowsEventParser.parse(event_data)
        if normalized:
            log_buffer.add(normalized)
        return normalized
    
    def ingest_json(self, data: Dict, source_name: str = "api") -> Optional[NormalizedLog]:
        """Ingest a JSON log entry"""
        normalized = JSONLogParser.parse(data, source_name)
        if normalized:
            log_buffer.add(normalized)
        return normalized
    
    def get_recent_logs(self, count: int = 100) -> List[Dict]:
        """Get recent normalized logs"""
        logs = log_buffer.get_recent(count)
        return [log.to_dict() for log in logs]
    
    def get_logs_by_timerange(self, start: datetime, end: datetime) -> List[Dict]:
        """Get logs within a time range"""
        logs = log_buffer.get_by_timerange(start, end)
        return [log.to_dict() for log in logs]
    
    def get_logs_by_source(self, source_type: str, count: int = 100) -> List[Dict]:
        """Get logs from a specific source type"""
        all_logs = log_buffer.get_recent(count * 5)  # Get more to filter
        filtered = [log for log in all_logs if log.source_type == source_type]
        return [log.to_dict() for log in filtered[:count]]


# Global ingestion engine instance
ingestion_engine = LogIngestionEngine()
