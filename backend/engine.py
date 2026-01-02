from backend.capture import packet_stream
from backend.state import stats
from backend.detector import process
from backend.features import extract_features
from backend.database import get_session, save_traffic, save_alert, save_correlated_event, save_scored_alert
from backend.log_ingestion import ingestion_engine
from backend.correlation import correlation_engine
from backend.attack_chain import attack_chain_detector
from backend.alert_scoring import alert_engine
import json
import time
import threading


def correlation_worker():
    """Background worker to run correlation periodically"""
    print("[CORRELATION] Worker started")
    while True:
        try:
            # Run correlation every 5 seconds
            time.sleep(5)
            
            new_correlations = correlation_engine.correlate()
            
            if new_correlations:
                print(f"[CORRELATION] Found {len(new_correlations)} new correlations")
                
                session = get_session()
                try:
                    for corr in new_correlations:
                        # Feed to attack chain detector
                        attack_chain_detector.process_correlated_event(corr.to_dict())
                        
                        # Save to database
                        save_correlated_event(session, corr.to_dict())
                        
                        # Score the correlation as an alert
                        scored = alert_engine.process_alert(corr.to_dict())
                        if scored and not scored.suppressed:
                            save_scored_alert(session, scored.to_dict())
                    
                    session.commit()
                finally:
                    session.close()
                    
        except Exception as e:
            print(f"[CORRELATION] Worker error: {e}")


def start_engine():
    print("[ENGINE] Started")
    
    # Start correlation worker in background
    corr_thread = threading.Thread(target=correlation_worker, daemon=True)
    corr_thread.start()
    
    session = get_session()
    batch_count = 0
    BATCH_SIZE = 100  # Commit every 100 packets for efficiency
    correlation_batch = []

    try:
        for packet in packet_stream():
            stats["total_packets"] += 1
            stats["protocols"][packet["protocol"]] += 1

            # Save traffic to database
            save_traffic(session, packet)
            batch_count += 1

            # Normalize packet and add to log buffer
            normalized_log = ingestion_engine.ingest_packet(packet)
            
            # Add to correlation engine
            log_dict = normalized_log.to_dict()
            correlation_engine.add_event(log_dict)

            features = extract_features(packet)
            result = process(features)

            if result == "ANOMALY":
                alert_data = {
                    "type": "ML_ANOMALY",
                    "attack_type": "anomaly",
                    "severity": "high",
                    "src_ip": packet["src_ip"],
                    "dst_ip": packet.get("dst_ip"),
                    "protocol": packet["protocol"],
                    "description": f"Anomalous traffic detected from {packet['src_ip']}",
                    "confidence": 0.7
                }
                
                # Save alert to database
                save_alert(session, alert_data)
                
                # Process through alert scoring engine
                scored_alert = alert_engine.process_alert(alert_data)
                if scored_alert and not scored_alert.suppressed:
                    save_scored_alert(session, scored_alert.to_dict())
                    
                    # Add to state for real-time dashboard
                    stats["alerts"].append(scored_alert.to_dict())
                else:
                    # Still track original alert for dashboard
                    stats["alerts"].append(alert_data)

            # Batch commit for performance
            if batch_count >= BATCH_SIZE:
                session.commit()
                batch_count = 0

    except KeyboardInterrupt:
        print("[ENGINE] Stopping...")
        session.commit()  # Final commit
        session.close()
        print("[ENGINE] Stopped")
