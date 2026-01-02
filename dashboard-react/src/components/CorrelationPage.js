import React, { useState, useEffect, useCallback } from 'react';
import './CorrelationPage.css';

const API_BASE = process.env.NODE_ENV === 'production' ? '' : 'http://127.0.0.1:8000';

function CorrelationPage() {
  const [threats, setThreats] = useState([]);
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [threatsRes, summaryRes, timelineRes] = await Promise.all([
        fetch(`${API_BASE}/api/correlation/threats`),
        fetch(`${API_BASE}/api/correlation/summary`),
        fetch(`${API_BASE}/api/correlation/timeline`)
      ]);
      
      const threatsData = await threatsRes.json();
      const summaryData = await summaryRes.json();
      const timelineData = await timelineRes.json();
      
      setThreats(Array.isArray(threatsData) ? threatsData : []);
      setSummary(summaryData);
      setTimeline(Array.isArray(timelineData) ? timelineData : []);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch correlation data:', error);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const runCorrelation = async () => {
    try {
      await fetch(`${API_BASE}/api/correlation/run`, { method: 'POST' });
      fetchData();
    } catch (error) {
      console.error('Failed to run correlation:', error);
    }
  };

  const getSeverityClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'severity-critical';
      case 'high': return 'severity-high';
      case 'medium': return 'severity-medium';
      default: return 'severity-low';
    }
  };

  if (loading) {
    return (
      <div className="correlation-page">
        <div className="loading">Loading correlation data...</div>
      </div>
    );
  }

  return (
    <div className="correlation-page">
      <div className="page-header">
        <div className="header-content">
          <h2>Event Correlation</h2>
          <p>Correlated threats and attack narratives from multiple data sources</p>
        </div>
        <button className="run-btn" onClick={runCorrelation}>
          Run Correlation
        </button>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="summary-grid">
          <div className="summary-card">
            <div className="summary-content">
              <div className="summary-value">{summary.total_threats || 0}</div>
              <div className="summary-label">Active Threats</div>
            </div>
          </div>
          <div className="summary-card critical">
            <div className="summary-content">
              <div className="summary-value">{summary.critical_count || 0}</div>
              <div className="summary-label">Critical</div>
            </div>
          </div>
          <div className="summary-card high">
            <div className="summary-content">
              <div className="summary-value">{summary.high_count || 0}</div>
              <div className="summary-label">High</div>
            </div>
          </div>
          <div className="summary-card">
            <div className="summary-content">
              <div className="summary-value">{summary.total_events || 0}</div>
              <div className="summary-label">Correlated Events</div>
            </div>
          </div>
        </div>
      )}

      <div className="correlation-content">
        {/* Threats List */}
        <div className="threats-panel panel">
          <div className="panel-header">
            <h3 className="panel-title">Active Threats</h3>
            <span className="panel-subtitle">{threats.length} detected</span>
          </div>
          
          {threats.length === 0 ? (
            <div className="no-data">
              <p>No active correlated threats</p>
            </div>
          ) : (
            <div className="threats-list">
              {threats.map((threat, index) => (
                <div 
                  key={threat.id || index}
                  className={`threat-item ${selectedThreat?.id === threat.id ? 'selected' : ''}`}
                  onClick={() => setSelectedThreat(threat)}
                >
                  <div className="threat-header">
                    <span className={`severity-badge ${getSeverityClass(threat.severity)}`}>
                      {threat.severity?.toUpperCase()}
                    </span>
                    <span className="threat-type">{threat.attack_type}</span>
                    <span className="confidence">
                      {Math.round((threat.confidence || 0) * 100)}%
                    </span>
                  </div>
                  <div className="threat-meta">
                    <span className="stage">{threat.stage}</span>
                    <span className="event-count">{threat.event_count || 0} events</span>
                  </div>
                  {threat.source_ips?.length > 0 && (
                    <div className="threat-ips">
                      <span>Sources: {threat.source_ips.slice(0, 3).join(', ')}</span>
                      {threat.source_ips.length > 3 && <span> +{threat.source_ips.length - 3} more</span>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Threat Details */}
        <div className="details-panel panel">
          <div className="panel-header">
            <h3 className="panel-title">Threat Details</h3>
          </div>
          
          {selectedThreat ? (
            <div className="threat-details">
              <div className="detail-section">
                <h4>Attack Narrative</h4>
                <p className="narrative">{selectedThreat.narrative || 'No narrative available'}</p>
              </div>
              
              <div className="detail-grid">
                <div className="detail-item">
                  <label>Attack Type</label>
                  <span>{selectedThreat.attack_type}</span>
                </div>
                <div className="detail-item">
                  <label>Stage</label>
                  <span>{selectedThreat.stage}</span>
                </div>
                <div className="detail-item">
                  <label>First Seen</label>
                  <span>{selectedThreat.first_seen ? new Date(selectedThreat.first_seen).toLocaleString() : 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Last Seen</label>
                  <span>{selectedThreat.last_seen ? new Date(selectedThreat.last_seen).toLocaleString() : 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Duration</label>
                  <span>{selectedThreat.duration_seconds ? `${Math.round(selectedThreat.duration_seconds)}s` : 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Confidence</label>
                  <span>{Math.round((selectedThreat.confidence || 0) * 100)}%</span>
                </div>
              </div>

              {selectedThreat.source_ips?.length > 0 && (
                <div className="detail-section">
                  <h4>Source IPs</h4>
                  <div className="ip-tags">
                    {selectedThreat.source_ips.map((ip, i) => (
                      <span key={i} className="ip-tag source">{ip}</span>
                    ))}
                  </div>
                </div>
              )}

              {selectedThreat.target_ips?.length > 0 && (
                <div className="detail-section">
                  <h4>Target IPs</h4>
                  <div className="ip-tags">
                    {selectedThreat.target_ips.map((ip, i) => (
                      <span key={i} className="ip-tag target">{ip}</span>
                    ))}
                  </div>
                </div>
              )}

              {selectedThreat.events?.length > 0 && (
                <div className="detail-section">
                  <h4>Related Events ({selectedThreat.event_count})</h4>
                  <div className="events-list">
                    {selectedThreat.events.slice(0, 10).map((event, i) => (
                      <div key={i} className="event-item">
                        <span className="event-time">
                          {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : ''}
                        </span>
                        <span className="event-type">{event.event_type || event.type}</span>
                        <span className="event-src">{event.src_ip}</span>
                      </div>
                    ))}
                    {selectedThreat.events.length > 10 && (
                      <div className="more-events">
                        +{selectedThreat.events.length - 10} more events
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="no-selection">
              <p>Select a threat to view details</p>
            </div>
          )}
        </div>
      </div>

      {/* Timeline */}
      {timeline.length > 0 && (
        <div className="timeline-panel panel">
          <div className="panel-header">
            <h3 className="panel-title">Attack Timeline</h3>
          </div>
          <div className="timeline">
            {timeline.slice(0, 20).map((item, index) => (
              <div key={index} className={`timeline-item ${getSeverityClass(item.severity)}`}>
                <div className="timeline-dot"></div>
                <div className="timeline-content">
                  <div className="timeline-time">
                    {item.timestamp ? new Date(item.timestamp).toLocaleString() : ''}
                  </div>
                  <div className="timeline-title">{item.attack_type || item.type}</div>
                  <div className="timeline-desc">{item.narrative || item.description}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default CorrelationPage;
