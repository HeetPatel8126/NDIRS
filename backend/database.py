from sqlalchemy import create_engine, Column, Integer, Float, String, DateTime, Boolean, Text, Index, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
import json

# Ensure data directory exists
os.makedirs("data", exist_ok=True)

engine = create_engine("sqlite:///data/traffic.db", echo=False)
Base = declarative_base()


class Traffic(Base):
    """Stores individual packet/traffic records"""
    __tablename__ = "traffic"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String(45), index=True)  # IPv6 max length
    dst_ip = Column(String(45))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(20), index=True)
    packet_size = Column(Integer)
    packet_count = Column(Integer, default=1)
    avg_size = Column(Float)
    
    __table_args__ = (
        Index('idx_traffic_src_dst', 'src_ip', 'dst_ip'),
    )


class NormalizedLog(Base):
    """Stores normalized logs from all sources"""
    __tablename__ = "normalized_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    log_id = Column(String(100), unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_type = Column(String(50), index=True)  # network, windows, syslog, firewall
    source_name = Column(String(100))
    event_type = Column(String(50), index=True)
    severity = Column(String(20), index=True)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    user = Column(String(100), index=True)
    hostname = Column(String(255))
    process = Column(String(255))
    action = Column(String(50))
    protocol = Column(String(20))
    message = Column(Text)
    raw_log = Column(Text)
    metadata_json = Column(Text)  # JSON string for flexible metadata
    
    __table_args__ = (
        Index('idx_logs_source_time', 'source_type', 'timestamp'),
        Index('idx_logs_event_time', 'event_type', 'timestamp'),
    )


class CorrelatedEvent(Base):
    """Stores correlated events / attack detections"""
    __tablename__ = "correlated_events"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    correlation_id = Column(String(100), unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    attack_type = Column(String(50), index=True)
    severity = Column(String(20), index=True)
    confidence = Column(Float)
    source_ips = Column(Text)  # JSON array
    target_ips = Column(Text)  # JSON array
    users = Column(Text)  # JSON array
    event_count = Column(Integer)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    stage = Column(String(50))  # MITRE ATT&CK stage
    narrative = Column(Text)
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime)
    
    __table_args__ = (
        Index('idx_corr_type_time', 'attack_type', 'timestamp'),
    )


class AttackChain(Base):
    """Stores multi-stage attack chains"""
    __tablename__ = "attack_chains"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    chain_id = Column(String(100), unique=True, index=True)
    name = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    stages_json = Column(Text)  # JSON object of stages
    source_ips = Column(Text)  # JSON array
    target_ips = Column(Text)  # JSON array
    users = Column(Text)  # JSON array
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    total_events = Column(Integer)
    confidence = Column(Float)
    severity = Column(String(20), index=True)
    is_active = Column(Boolean, default=True, index=True)
    narrative = Column(Text)
    
    __table_args__ = (
        Index('idx_chain_active_severity', 'is_active', 'severity'),
    )


class ScoredAlert(Base):
    """Stores scored and prioritized alerts"""
    __tablename__ = "scored_alerts"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(100), unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    priority_score = Column(Float, index=True)
    confidence = Column(Float)
    severity = Column(String(20), index=True)
    attack_type = Column(String(50))
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45))
    factors_json = Column(Text)  # JSON object
    suppressed = Column(Boolean, default=False)
    suppression_reason = Column(String(255))
    actionable = Column(Boolean, default=True)
    recommended_action = Column(Text)
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(100))
    acknowledged_at = Column(DateTime)
    
    __table_args__ = (
        Index('idx_scored_priority', 'suppressed', 'priority_score'),
    )


class Alert(Base):
    """Stores security alerts and anomalies detected"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    alert_type = Column(String(50), index=True)  # ML_ANOMALY, RATE_LIMIT, PORT_SCAN, etc.
    severity = Column(String(20), default="medium")  # low, medium, high, critical
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45))
    protocol = Column(String(20))
    description = Column(Text)
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime)
    
    __table_args__ = (
        Index('idx_alerts_unresolved', 'is_resolved', 'timestamp'),
    )


class SystemStats(Base):
    """Stores periodic system statistics snapshots"""
    __tablename__ = "system_stats"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    total_packets = Column(Integer, default=0)
    packets_per_second = Column(Float, default=0.0)
    anomaly_count = Column(Integer, default=0)
    protocol_breakdown = Column(Text)  # JSON string of protocol counts


class BlockedIP(Base):
    """Stores IPs that have been blocked due to suspicious activity"""
    __tablename__ = "blocked_ips"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), unique=True, index=True)
    blocked_at = Column(DateTime, default=datetime.utcnow)
    reason = Column(Text)
    alert_count = Column(Integer, default=1)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime)  # Optional auto-unblock time


# Create all tables
Base.metadata.create_all(engine)

# Session factory
Session = sessionmaker(bind=engine)


# Helper functions for database operations
def get_session():
    """Get a new database session"""
    return Session()


def save_traffic(session, packet_data):
    """Save a traffic record to the database"""
    traffic = Traffic(
        src_ip=packet_data.get("src_ip"),
        dst_ip=packet_data.get("dst_ip"),
        src_port=packet_data.get("src_port"),
        dst_port=packet_data.get("dst_port"),
        protocol=packet_data.get("protocol"),
        packet_size=packet_data.get("size", 0)
    )
    session.add(traffic)
    return traffic


def save_alert(session, alert_data):
    """Save an alert to the database"""
    alert = Alert(
        alert_type=alert_data.get("type"),
        severity=alert_data.get("severity", "medium"),
        src_ip=alert_data.get("src_ip"),
        dst_ip=alert_data.get("dst_ip"),
        protocol=alert_data.get("protocol"),
        description=alert_data.get("description", "")
    )
    session.add(alert)
    return alert


def save_normalized_log(session, log_data):
    """Save a normalized log to the database"""
    log = NormalizedLog(
        log_id=log_data.get("id"),
        timestamp=datetime.fromisoformat(log_data["timestamp"]) if isinstance(log_data.get("timestamp"), str) else log_data.get("timestamp"),
        source_type=log_data.get("source_type"),
        source_name=log_data.get("source_name"),
        event_type=log_data.get("event_type"),
        severity=log_data.get("severity"),
        src_ip=log_data.get("src_ip"),
        dst_ip=log_data.get("dst_ip"),
        src_port=log_data.get("src_port"),
        dst_port=log_data.get("dst_port"),
        user=log_data.get("user"),
        hostname=log_data.get("hostname"),
        process=log_data.get("process"),
        action=log_data.get("action"),
        protocol=log_data.get("protocol"),
        message=log_data.get("message"),
        raw_log=log_data.get("raw_log"),
        metadata_json=json.dumps(log_data.get("metadata", {}))
    )
    session.add(log)
    return log


def save_correlated_event(session, event_data):
    """Save a correlated event to the database"""
    event = CorrelatedEvent(
        correlation_id=event_data.get("id"),
        attack_type=event_data.get("attack_type"),
        severity=event_data.get("severity"),
        confidence=event_data.get("confidence"),
        source_ips=json.dumps(event_data.get("source_ips", [])),
        target_ips=json.dumps(event_data.get("target_ips", [])),
        users=json.dumps(event_data.get("users", [])),
        event_count=event_data.get("event_count", 0),
        first_seen=datetime.fromisoformat(event_data["first_seen"]) if isinstance(event_data.get("first_seen"), str) else event_data.get("first_seen"),
        last_seen=datetime.fromisoformat(event_data["last_seen"]) if isinstance(event_data.get("last_seen"), str) else event_data.get("last_seen"),
        stage=event_data.get("stage"),
        narrative=event_data.get("narrative")
    )
    session.add(event)
    return event


def save_attack_chain(session, chain_data):
    """Save an attack chain to the database"""
    chain = AttackChain(
        chain_id=chain_data.get("id"),
        name=chain_data.get("name"),
        stages_json=json.dumps(chain_data.get("stages", [])),
        source_ips=json.dumps(chain_data.get("source_ips", [])),
        target_ips=json.dumps(chain_data.get("target_ips", [])),
        users=json.dumps(chain_data.get("users", [])),
        first_seen=datetime.fromisoformat(chain_data["first_seen"]) if isinstance(chain_data.get("first_seen"), str) else chain_data.get("first_seen"),
        last_seen=datetime.fromisoformat(chain_data["last_seen"]) if isinstance(chain_data.get("last_seen"), str) else chain_data.get("last_seen"),
        total_events=chain_data.get("total_events", 0),
        confidence=chain_data.get("confidence"),
        severity=chain_data.get("severity"),
        is_active=chain_data.get("is_active", True),
        narrative=chain_data.get("narrative")
    )
    session.add(chain)
    return chain


def save_scored_alert(session, alert_data):
    """Save a scored alert to the database"""
    alert = ScoredAlert(
        alert_id=alert_data.get("id"),
        priority_score=alert_data.get("priority_score"),
        confidence=alert_data.get("confidence"),
        severity=alert_data.get("severity"),
        attack_type=alert_data.get("attack_type"),
        src_ip=alert_data.get("src_ip"),
        dst_ip=alert_data.get("dst_ip"),
        factors_json=json.dumps(alert_data.get("factors", {})),
        suppressed=alert_data.get("suppressed", False),
        suppression_reason=alert_data.get("suppression_reason"),
        actionable=alert_data.get("actionable", True),
        recommended_action=alert_data.get("recommended_action")
    )
    session.add(alert)
    return alert


def get_recent_alerts(session, limit=50):
    """Get recent unresolved alerts"""
    return session.query(Alert).filter(
        Alert.is_resolved == False
    ).order_by(Alert.timestamp.desc()).limit(limit).all()


def get_blocked_ips(session):
    """Get currently blocked IPs"""
    return session.query(BlockedIP).filter(
        BlockedIP.is_active == True
    ).all()


def block_ip(session, ip_address, reason):
    """Block an IP address"""
    existing = session.query(BlockedIP).filter(
        BlockedIP.ip_address == ip_address
    ).first()
    
    if existing:
        existing.alert_count += 1
        existing.is_active = True
        return existing
    
    blocked = BlockedIP(ip_address=ip_address, reason=reason)
    session.add(blocked)
    return blocked

