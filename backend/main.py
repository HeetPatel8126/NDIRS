from fastapi import FastAPI, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import threading
import os
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from backend.state import stats
from backend.engine import start_engine
from backend.database import (
    get_session, Traffic, Alert, BlockedIP, SystemStats,
    NormalizedLog as NormalizedLogDB, CorrelatedEvent as CorrelatedEventDB,
    AttackChain as AttackChainDB, ScoredAlert as ScoredAlertDB,
    get_recent_alerts, get_blocked_ips, block_ip,
    save_normalized_log, save_correlated_event, save_attack_chain, save_scored_alert
)
from backend.log_ingestion import ingestion_engine, log_buffer
from backend.correlation import correlation_engine
from backend.attack_chain import attack_chain_detector
from backend.alert_scoring import alert_engine


app = FastAPI(title="NIDRS API")

# Enable CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Get the base directory (project root)
BASE_DIR = Path(__file__).resolve().parent.parent
REACT_BUILD_DIR = BASE_DIR / "dashboard-react" / "build"

# Mount React static files
app.mount("/static", StaticFiles(directory=str(REACT_BUILD_DIR / "static")), name="static")

@app.on_event("startup")
def startup():
    thread = threading.Thread(target=start_engine, daemon=True)
    thread.start()

@app.get("/")
def root():
    """Serve the React dashboard"""
    return FileResponse(str(REACT_BUILD_DIR / "index.html"))

@app.get("/api/status")
def api_status():
    return {"status": "NIDRS Running"}

@app.get("/stats")
def get_stats():
    return {
        "total_packets": stats["total_packets"],
        "protocols": dict(stats["protocols"])
    }

@app.get("/alerts")
def get_alerts():
    return stats["alerts"]


# ============ NEW DATABASE ENDPOINTS ============

@app.get("/api/alerts/history")
def get_alerts_history(
    limit: int = Query(50, ge=1, le=500),
    resolved: bool = Query(None)
):
    """Get alerts from database with optional filtering"""
    session = get_session()
    try:
        query = session.query(Alert).order_by(Alert.timestamp.desc())
        if resolved is not None:
            query = query.filter(Alert.is_resolved == resolved)
        alerts = query.limit(limit).all()
        return [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "type": a.alert_type,
                "severity": a.severity,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "protocol": a.protocol,
                "description": a.description,
                "is_resolved": a.is_resolved
            }
            for a in alerts
        ]
    finally:
        session.close()


@app.get("/api/traffic/recent")
def get_recent_traffic(limit: int = Query(100, ge=1, le=1000)):
    """Get recent traffic records from database"""
    session = get_session()
    try:
        traffic = session.query(Traffic).order_by(
            Traffic.timestamp.desc()
        ).limit(limit).all()
        return [
            {
                "id": t.id,
                "timestamp": t.timestamp.isoformat() if t.timestamp else None,
                "src_ip": t.src_ip,
                "dst_ip": t.dst_ip,
                "protocol": t.protocol,
                "packet_size": t.packet_size
            }
            for t in traffic
        ]
    finally:
        session.close()


@app.get("/api/traffic/by-ip/{ip}")
def get_traffic_by_ip(ip: str, limit: int = Query(100, ge=1, le=1000)):
    """Get traffic records for a specific IP"""
    session = get_session()
    try:
        traffic = session.query(Traffic).filter(
            (Traffic.src_ip == ip) | (Traffic.dst_ip == ip)
        ).order_by(Traffic.timestamp.desc()).limit(limit).all()
        return [
            {
                "id": t.id,
                "timestamp": t.timestamp.isoformat() if t.timestamp else None,
                "src_ip": t.src_ip,
                "dst_ip": t.dst_ip,
                "protocol": t.protocol,
                "packet_size": t.packet_size
            }
            for t in traffic
        ]
    finally:
        session.close()


@app.get("/api/blocked-ips")
def get_blocked_ips_list():
    """Get list of currently blocked IPs"""
    session = get_session()
    try:
        blocked = get_blocked_ips(session)
        return [
            {
                "id": b.id,
                "ip_address": b.ip_address,
                "blocked_at": b.blocked_at.isoformat() if b.blocked_at else None,
                "reason": b.reason,
                "alert_count": b.alert_count
            }
            for b in blocked
        ]
    finally:
        session.close()


@app.post("/api/block-ip/{ip}")
def block_ip_address(ip: str, reason: str = "Manual block"):
    """Manually block an IP address"""
    session = get_session()
    try:
        blocked = block_ip(session, ip, reason)
        session.commit()
        return {"status": "blocked", "ip": ip}
    finally:
        session.close()


@app.post("/api/unblock-ip/{ip}")
def unblock_ip_address(ip: str):
    """Unblock an IP address"""
    session = get_session()
    try:
        blocked = session.query(BlockedIP).filter(
            BlockedIP.ip_address == ip
        ).first()
        if blocked:
            blocked.is_active = False
            session.commit()
            return {"status": "unblocked", "ip": ip}
        return {"status": "not_found", "ip": ip}
    finally:
        session.close()


@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int):
    """Mark an alert as resolved"""
    session = get_session()
    try:
        alert = session.query(Alert).filter(Alert.id == alert_id).first()
        if alert:
            alert.is_resolved = True
            alert.resolved_at = datetime.utcnow()
            session.commit()
            return {"status": "resolved", "alert_id": alert_id}
        return {"status": "not_found", "alert_id": alert_id}
    finally:
        session.close()


@app.get("/api/stats/summary")
def get_stats_summary():
    """Get summary statistics from database"""
    session = get_session()
    try:
        total_traffic = session.query(Traffic).count()
        total_alerts = session.query(Alert).count()
        unresolved_alerts = session.query(Alert).filter(
            Alert.is_resolved == False
        ).count()
        blocked_count = session.query(BlockedIP).filter(
            BlockedIP.is_active == True
        ).count()
        
        # Get alerts in last 24 hours
        day_ago = datetime.utcnow() - timedelta(hours=24)
        recent_alerts = session.query(Alert).filter(
            Alert.timestamp >= day_ago
        ).count()
        
        return {
            "total_traffic_records": total_traffic,
            "total_alerts": total_alerts,
            "unresolved_alerts": unresolved_alerts,
            "blocked_ips": blocked_count,
            "alerts_last_24h": recent_alerts,
            "live_packets": stats["total_packets"],
            "live_protocols": dict(stats["protocols"])
        }
    finally:
        session.close()


# ============ LOG CORRELATION ENGINE ENDPOINTS ============

@app.post("/api/logs/ingest")
def ingest_log(log_data: Dict = Body(...)):
    """Ingest a single log entry (JSON format)"""
    normalized = ingestion_engine.ingest_json(log_data, source_name="api")
    if normalized:
        # Also feed to correlation engine
        correlation_engine.add_event(normalized.to_dict())
        return {"status": "ingested", "log_id": normalized.id}
    return {"status": "failed", "error": "Could not parse log"}


@app.post("/api/logs/ingest/batch")
def ingest_logs_batch(logs: List[Dict] = Body(...)):
    """Ingest multiple log entries"""
    ingested = 0
    for log_data in logs:
        normalized = ingestion_engine.ingest_json(log_data, source_name="api")
        if normalized:
            correlation_engine.add_event(normalized.to_dict())
            ingested += 1
    return {"status": "completed", "ingested": ingested, "total": len(logs)}


@app.post("/api/logs/ingest/syslog")
def ingest_syslog(line: str = Body(..., embed=True)):
    """Ingest a syslog line"""
    normalized = ingestion_engine.ingest_log_line(line, source_type="syslog")
    if normalized:
        correlation_engine.add_event(normalized.to_dict())
        return {"status": "ingested", "log_id": normalized.id}
    return {"status": "failed", "error": "Could not parse syslog"}


@app.get("/api/logs/recent")
def get_recent_logs(limit: int = Query(100, ge=1, le=1000)):
    """Get recent normalized logs"""
    return ingestion_engine.get_recent_logs(limit)


@app.get("/api/logs/by-source/{source_type}")
def get_logs_by_source(source_type: str, limit: int = Query(100, ge=1, le=500)):
    """Get logs filtered by source type"""
    return ingestion_engine.get_logs_by_source(source_type, limit)


# ============ CORRELATION ENGINE ENDPOINTS ============

@app.get("/api/correlation/threats")
def get_active_threats():
    """Get currently active correlated threats"""
    return correlation_engine.get_active_threats()


@app.get("/api/correlation/summary")
def get_threat_summary():
    """Get summary of current threats"""
    return correlation_engine.get_threat_summary()


@app.get("/api/correlation/timeline")
def get_attack_timeline():
    """Get timeline of attacks"""
    return correlation_engine.get_attack_timeline()


@app.post("/api/correlation/run")
def run_correlation():
    """Manually trigger correlation analysis"""
    new_correlations = correlation_engine.correlate()
    
    # Feed to attack chain detector
    for corr in new_correlations:
        attack_chain_detector.process_correlated_event(corr.to_dict())
    
    return {
        "status": "completed",
        "new_correlations": len(new_correlations),
        "total_active": len(correlation_engine.correlated_events)
    }


# ============ ATTACK CHAIN ENDPOINTS ============

@app.get("/api/chains/active")
def get_active_attack_chains():
    """Get active multi-stage attack chains"""
    return attack_chain_detector.get_active_chains()


@app.get("/api/chains/all")
def get_all_attack_chains():
    """Get all attack chains (active and inactive)"""
    return attack_chain_detector.get_all_chains()


@app.get("/api/chains/critical")
def get_critical_chains():
    """Get critical severity attack chains"""
    return attack_chain_detector.get_critical_chains()


@app.get("/api/chains/by-ip/{ip}")
def get_chain_by_ip(ip: str):
    """Get attack chain associated with an IP"""
    chain = attack_chain_detector.get_chain_by_ip(ip)
    if chain:
        return chain
    return {"status": "not_found", "ip": ip}


@app.get("/api/chains/statistics")
def get_chain_statistics():
    """Get attack chain statistics"""
    return attack_chain_detector.get_chain_statistics()


# ============ ALERT SCORING ENDPOINTS ============

@app.get("/api/alerts/prioritized")
def get_prioritized_alerts(limit: int = Query(50, ge=1, le=200)):
    """Get alerts sorted by priority score"""
    return alert_engine.get_prioritized_alerts(limit)


@app.get("/api/alerts/aggregated")
def get_aggregated_alerts(limit: int = Query(50, ge=1, le=200)):
    """Get aggregated and prioritized alerts"""
    return alert_engine.get_aggregated_alerts(limit)


@app.get("/api/alerts/statistics")
def get_alert_statistics():
    """Get alert processing statistics (suppression rate, etc.)"""
    return alert_engine.get_statistics()


@app.post("/api/alerts/score")
def score_alert(alert_data: Dict = Body(...)):
    """Score a single alert and get prioritization"""
    scored = alert_engine.process_alert(alert_data)
    if scored:
        return scored.to_dict()
    return {"status": "suppressed_or_duplicate"}


# ============ SOC DASHBOARD ENDPOINTS ============

@app.get("/api/soc/overview")
def get_soc_overview():
    """Get comprehensive SOC overview for dashboard"""
    session = get_session()
    try:
        return {
            "threat_summary": correlation_engine.get_threat_summary(),
            "alert_stats": alert_engine.get_statistics(),
            "chain_stats": attack_chain_detector.get_chain_statistics(),
            "active_threats": len(correlation_engine.correlated_events),
            "critical_chains": len(attack_chain_detector.get_critical_chains()),
            "top_source_ips": _get_top_source_ips(session),
            "recent_high_priority": alert_engine.get_prioritized_alerts(10)
        }
    finally:
        session.close()


def _get_top_source_ips(session, limit=10):
    """Get top source IPs from alerts"""
    from sqlalchemy import func
    results = session.query(
        Alert.src_ip,
        func.count(Alert.id).label('count')
    ).filter(
        Alert.src_ip != None
    ).group_by(Alert.src_ip).order_by(
        func.count(Alert.id).desc()
    ).limit(limit).all()
    
    return [{"ip": r[0], "count": r[1]} for r in results]


@app.get("/api/soc/attack-narratives")
def get_attack_narratives(limit: int = Query(10, ge=1, le=50)):
    """Get human-readable attack narratives"""
    chains = attack_chain_detector.get_active_chains()
    narratives = []
    for chain in chains[:limit]:
        narratives.append({
            "id": chain["id"],
            "name": chain["name"],
            "severity": chain["severity"],
            "narrative": chain["narrative"],
            "stages": chain["stages"],
            "confidence": chain["confidence"]
        })
    return narratives
