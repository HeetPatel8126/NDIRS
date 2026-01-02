import React, { useState, useEffect, useCallback } from 'react';
import './LogsPage.css';

const API_BASE = process.env.NODE_ENV === 'production' ? '' : 'http://127.0.0.1:8000';

function LogsPage() {
  const [logs, setLogs] = useState([]);
  const [selectedLog, setSelectedLog] = useState(null);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchLogs = useCallback(async () => {
    try {
      let url = `${API_BASE}/api/logs/recent?limit=200`;
      if (filter !== 'all') {
        url = `${API_BASE}/api/logs/by-source/${filter}?limit=200`;
      }
      
      const response = await fetch(url);
      const data = await response.json();
      setLogs(Array.isArray(data) ? data : []);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch logs:', error);
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [fetchLogs]);

  const getSeverityClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'severity-critical';
      case 'high': case 'error': return 'severity-high';
      case 'medium': case 'warning': return 'severity-medium';
      default: return 'severity-low';
    }
  };

  const filteredLogs = logs.filter(log => {
    if (!searchTerm) return true;
    const searchLower = searchTerm.toLowerCase();
    return (
      log.src_ip?.toLowerCase().includes(searchLower) ||
      log.dst_ip?.toLowerCase().includes(searchLower) ||
      log.event_type?.toLowerCase().includes(searchLower) ||
      log.user?.toLowerCase().includes(searchLower) ||
      log.message?.toLowerCase().includes(searchLower)
    );
  });

  const sourceTypes = ['all', 'syslog', 'windows', 'firewall', 'network', 'api'];

  if (loading) {
    return (
      <div className="logs-page">
        <div className="loading">Loading logs...</div>
      </div>
    );
  }

  return (
    <div className="logs-page">
      <div className="page-header">
        <div className="header-content">
          <h2>Logs</h2>
          <p>Normalized and ingested log entries from all sources</p>
        </div>
        <div className="header-actions">
          <div className="search-box">
            <input
              type="text"
              placeholder="Search logs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="filter-tabs">
        {sourceTypes.map(source => (
          <button
            key={source}
            className={filter === source ? 'active' : ''}
            onClick={() => setFilter(source)}
          >
            {source.charAt(0).toUpperCase() + source.slice(1)}
          </button>
        ))}
      </div>

      {/* Stats Bar */}
      <div className="stats-bar">
        <div className="stat-item">
          <span className="stat-value">{filteredLogs.length}</span>
          <span className="stat-label">Total Logs</span>
        </div>
        <div className="stat-item">
          <span className="stat-value">
            {filteredLogs.filter(l => l.severity === 'high' || l.severity === 'critical').length}
          </span>
          <span className="stat-label">High Severity</span>
        </div>
        <div className="stat-item">
          <span className="stat-value">
            {[...new Set(filteredLogs.map(l => l.src_ip).filter(Boolean))].length}
          </span>
          <span className="stat-label">Unique Sources</span>
        </div>
      </div>

      <div className="logs-content">
        {/* Logs Table */}
        <div className="logs-panel panel">
          <div className="panel-header">
            <h3 className="panel-title">Log Entries</h3>
            <span className="panel-subtitle">{filteredLogs.length} entries</span>
          </div>
          
          {filteredLogs.length === 0 ? (
            <div className="no-data">
              <p>No logs found</p>
            </div>
          ) : (
            <div className="logs-table-container">
              <table className="logs-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Source IP</th>
                    <th>User</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.map((log, index) => (
                    <tr 
                      key={log.id || index}
                      className={selectedLog?.id === log.id ? 'selected' : ''}
                      onClick={() => setSelectedLog(log)}
                    >
                      <td className="col-time">
                        {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '-'}
                      </td>
                      <td className="col-type">
                        <span className="event-type">
                          {log.event_type || '-'}
                        </span>
                      </td>
                      <td className="col-severity">
                        <span className={`severity-badge ${getSeverityClass(log.severity)}`}>
                          {log.severity || 'info'}
                        </span>
                      </td>
                      <td className="col-ip">
                        <span className="ip-address">{log.src_ip || '-'}</span>
                      </td>
                      <td className="col-user">{log.user || '-'}</td>
                      <td className="col-message">
                        <span className="message-text">{log.message?.substring(0, 60) || '-'}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Log Details */}
        <div className="details-panel panel">
          <div className="panel-header">
            <h3 className="panel-title">Log Details</h3>
          </div>
          
          {selectedLog ? (
            <div className="log-details">
              <div className="detail-header">
                <span className={`severity-badge large ${getSeverityClass(selectedLog.severity)}`}>
                  {selectedLog.severity?.toUpperCase() || 'INFO'}
                </span>
                <span className="event-type-large">
                  {selectedLog.event_type}
                </span>
              </div>

              <div className="detail-grid">
                <div className="detail-item">
                  <label>Timestamp</label>
                  <span>{selectedLog.timestamp ? new Date(selectedLog.timestamp).toLocaleString() : 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Source Type</label>
                  <span>{selectedLog.source_type || 'unknown'}</span>
                </div>
                <div className="detail-item">
                  <label>Source IP</label>
                  <span className="ip-value">{selectedLog.src_ip || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Destination IP</label>
                  <span className="ip-value">{selectedLog.dst_ip || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>User</label>
                  <span>{selectedLog.user || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Action</label>
                  <span>{selectedLog.action || 'N/A'}</span>
                </div>
                {selectedLog.port && (
                  <div className="detail-item">
                    <label>Port</label>
                    <span>{selectedLog.port}</span>
                  </div>
                )}
                {selectedLog.protocol && (
                  <div className="detail-item">
                    <label>Protocol</label>
                    <span>{selectedLog.protocol}</span>
                  </div>
                )}
              </div>

              {selectedLog.message && (
                <div className="detail-section">
                  <h4>Message</h4>
                  <div className="message-box">{selectedLog.message}</div>
                </div>
              )}

              {selectedLog.raw_log && (
                <div className="detail-section">
                  <h4>Raw Log</h4>
                  <div className="raw-log-box">
                    <pre>{selectedLog.raw_log}</pre>
                  </div>
                </div>
              )}

              {selectedLog.extra_fields && Object.keys(selectedLog.extra_fields).length > 0 && (
                <div className="detail-section">
                  <h4>Additional Fields</h4>
                  <div className="extra-fields">
                    {Object.entries(selectedLog.extra_fields).map(([key, value]) => (
                      <div key={key} className="extra-field">
                        <span className="field-key">{key}:</span>
                        <span className="field-value">{String(value)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="no-selection">
              <div className="no-selection-icon">👆</div>
              <p>Select a log entry to view details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default LogsPage;
