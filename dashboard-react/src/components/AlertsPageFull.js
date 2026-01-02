import React, { useState, useEffect, useCallback } from 'react';
import './AlertsPageFull.css';

const API_BASE = process.env.NODE_ENV === 'production' ? '' : 'http://127.0.0.1:8000';

function AlertsPage() {
  const [prioritizedAlerts, setPrioritizedAlerts] = useState([]);
  const [aggregatedAlerts, setAggregatedAlerts] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [viewMode, setViewMode] = useState('prioritized');
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [prioritizedRes, aggregatedRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/api/alerts/prioritized?limit=100`),
        fetch(`${API_BASE}/api/alerts/aggregated?limit=100`),
        fetch(`${API_BASE}/api/alerts/statistics`)
      ]);
      
      const prioritizedData = await prioritizedRes.json();
      const aggregatedData = await aggregatedRes.json();
      const statsData = await statsRes.json();
      
      setPrioritizedAlerts(Array.isArray(prioritizedData) ? prioritizedData : []);
      setAggregatedAlerts(Array.isArray(aggregatedData) ? aggregatedData : []);
      setStatistics(statsData);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch alerts data:', error);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const getSeverityClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'severity-critical';
      case 'high': return 'severity-high';
      case 'medium': return 'severity-medium';
      default: return 'severity-low';
    }
  };

  const getPriorityColor = (score) => {
    if (score >= 80) return '#ff4d4d';
    if (score >= 60) return '#ffaa4d';
    if (score >= 40) return '#ffe64d';
    return '#4dff4d';
  };

  const displayAlerts = viewMode === 'prioritized' ? prioritizedAlerts : aggregatedAlerts;

  if (loading) {
    return (
      <div className="alerts-page">
        <div className="loading">Loading alerts data...</div>
      </div>
    );
  }

  return (
    <div className="alerts-page">
      <div className="page-header">
        <div className="header-content">
          <h2>Alerts</h2>
          <p>Prioritized and aggregated security alerts with intelligent scoring</p>
        </div>
        <div className="view-toggle">
          <button 
            className={viewMode === 'prioritized' ? 'active' : ''} 
            onClick={() => setViewMode('prioritized')}
          >
            Prioritized
          </button>
          <button 
            className={viewMode === 'aggregated' ? 'active' : ''} 
            onClick={() => setViewMode('aggregated')}
          >
            Aggregated
          </button>
        </div>
      </div>

      {/* Statistics */}
      {statistics && (
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-content">
              <div className="stat-value">{statistics.total_processed || 0}</div>
              <div className="stat-label">Total Processed</div>
            </div>
          </div>
          <div className="stat-card suppressed">
            <div className="stat-content">
              <div className="stat-value">{statistics.suppressed || 0}</div>
              <div className="stat-label">Suppressed</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-content">
              <div className="stat-value">
                {statistics.suppression_rate ? `${(statistics.suppression_rate * 100).toFixed(1)}%` : '0%'}
              </div>
              <div className="stat-label">Suppression Rate</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-content">
              <div className="stat-value">{statistics.aggregated_groups || 0}</div>
              <div className="stat-label">Aggregated Groups</div>
            </div>
          </div>
        </div>
      )}

      <div className="alerts-content">
        {/* Alerts List */}
        <div className="alerts-list-panel panel">
          <div className="panel-header">
            <h3 className="panel-title">
              {viewMode === 'prioritized' ? 'Prioritized Alerts' : 'Aggregated Alerts'}
            </h3>
            <span className="panel-subtitle">{displayAlerts.length} alerts</span>
          </div>
          
          {displayAlerts.length === 0 ? (
            <div className="no-data">
              <p>No alerts</p>
            </div>
          ) : (
            <div className="alerts-list">
              {displayAlerts.map((alert, index) => (
                <div 
                  key={alert.id || index}
                  className={`alert-item ${selectedAlert?.id === alert.id ? 'selected' : ''}`}
                  onClick={() => setSelectedAlert(alert)}
                >
                  <div className="alert-header">
                    <div className="priority-score" style={{ background: getPriorityColor(alert.priority_score || 0) }}>
                      {Math.round(alert.priority_score || 0)}
                    </div>
                    <span className={`severity-badge ${getSeverityClass(alert.severity)}`}>
                      {alert.severity?.toUpperCase()}
                    </span>
                    <span className="alert-type">{alert.alert_type || alert.type}</span>
                  </div>
                  
                  <div className="alert-source">
                    <span className="label">Source:</span>
                    <span className="ip">{alert.src_ip || 'Unknown'}</span>
                    {alert.count > 1 && (
                      <span className="count-badge">×{alert.count}</span>
                    )}
                  </div>

                  <div className="alert-meta">
                    <span className="timestamp">
                      {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : ''}
                    </span>
                    {alert.factors && (
                      <div className="factor-tags">
                        {alert.factors.slice(0, 2).map((factor, i) => (
                          <span key={i} className="factor-tag">{factor}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Alert Details */}
        <div className="details-panel panel">
          <div className="panel-header">
            <h3 className="panel-title">Alert Details</h3>
          </div>
          
          {selectedAlert ? (
            <div className="alert-details">
              <div className="priority-header">
                <div 
                  className="priority-badge" 
                  style={{ background: getPriorityColor(selectedAlert.priority_score || 0) }}
                >
                  <span className="priority-value">{Math.round(selectedAlert.priority_score || 0)}</span>
                  <span className="priority-label">Priority Score</span>
                </div>
                <div className="severity-info">
                  <span className={`severity-badge large ${getSeverityClass(selectedAlert.severity)}`}>
                    {selectedAlert.severity?.toUpperCase()}
                  </span>
                  <span className="alert-type-large">{selectedAlert.alert_type || selectedAlert.type}</span>
                </div>
              </div>

              <div className="detail-grid">
                <div className="detail-item">
                  <label>Source IP</label>
                  <span className="ip-value">{selectedAlert.src_ip || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Destination IP</label>
                  <span className="ip-value">{selectedAlert.dst_ip || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Timestamp</label>
                  <span>{selectedAlert.timestamp ? new Date(selectedAlert.timestamp).toLocaleString() : 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Protocol</label>
                  <span>{selectedAlert.protocol || 'N/A'}</span>
                </div>
                {selectedAlert.count > 1 && (
                  <div className="detail-item">
                    <label>Occurrences</label>
                    <span className="count-value">{selectedAlert.count}</span>
                  </div>
                )}
                <div className="detail-item">
                  <label>Base Score</label>
                  <span>{selectedAlert.base_score?.toFixed(1) || 'N/A'}</span>
                </div>
              </div>

              {selectedAlert.description && (
                <div className="detail-section">
                  <h4>Description</h4>
                  <div className="description-box">{selectedAlert.description}</div>
                </div>
              )}

              {selectedAlert.factors && selectedAlert.factors.length > 0 && (
                <div className="detail-section">
                  <h4>Scoring Factors</h4>
                  <div className="factors-list">
                    {selectedAlert.factors.map((factor, i) => (
                      <div key={i} className="factor-item">
                        <span className="factor-text">{factor}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedAlert.score_breakdown && (
                <div className="detail-section">
                  <h4>Score Breakdown</h4>
                  <div className="score-breakdown">
                    {Object.entries(selectedAlert.score_breakdown).map(([key, value]) => (
                      <div key={key} className="breakdown-item">
                        <span className="breakdown-label">{key.replace('_', ' ')}</span>
                        <div className="breakdown-bar-container">
                          <div 
                            className="breakdown-bar" 
                            style={{ width: `${Math.min(value * 5, 100)}%` }}
                          ></div>
                        </div>
                        <span className="breakdown-value">{typeof value === 'number' ? value.toFixed(1) : value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedAlert.related_alerts && selectedAlert.related_alerts.length > 0 && (
                <div className="detail-section">
                  <h4>Related Alerts ({selectedAlert.related_alerts.length})</h4>
                  <div className="related-list">
                    {selectedAlert.related_alerts.slice(0, 5).map((related, i) => (
                      <div key={i} className="related-item">
                        <span className="related-type">{related.type || related.alert_type}</span>
                        <span className="related-time">
                          {related.timestamp ? new Date(related.timestamp).toLocaleTimeString() : ''}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="no-selection">
              <p>Select an alert to view details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default AlertsPage;
