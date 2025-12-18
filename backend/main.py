from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import threading
import os
from pathlib import Path
from datetime import datetime, timedelta
from backend.state import stats
from backend.engine import start_engine
from backend.database import (
    get_session, Traffic, Alert, BlockedIP, SystemStats,
    get_recent_alerts, get_blocked_ips, block_ip
)


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
