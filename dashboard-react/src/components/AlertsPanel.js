import React, { useMemo } from 'react';
import './AlertsPanel.css';

function AlertItem({ alert, index }) {
  const severityClass = alert.type?.toLowerCase().includes('critical') 
    ? 'critical' 
    : alert.type?.toLowerCase().includes('high')
    ? 'high'
    : 'medium';

  return (
    <div className={`alert-item ${severityClass}`} style={{ animationDelay: `${index * 0.05}s` }}>
      <div className="alert-header">
        <span className="alert-type">
          <span className="alert-icon">⚠️</span>
          {alert.type}
        </span>
        <span className="alert-time">
          {new Date(alert.timestamp || Date.now()).toLocaleTimeString()}
        </span>
      </div>
      <div className="alert-details">
        <div className="alert-detail">
          <span className="detail-icon">🌐</span>
          <span className="detail-label">Source:</span>
          <span className="detail-value">{alert.src_ip}</span>
        </div>
        <div className="alert-detail">
          <span className="detail-icon">📡</span>
          <span className="detail-label">Protocol:</span>
          <span className="detail-value">{alert.protocol}</span>
        </div>
        {alert.dst_ip && (
          <div className="alert-detail">
            <span className="detail-icon">🎯</span>
            <span className="detail-label">Target:</span>
            <span className="detail-value">{alert.dst_ip}</span>
          </div>
        )}
      </div>
    </div>
  );
}

function AlertsPanel({ alerts }) {
  const recentAlerts = useMemo(() => {
    return [...alerts].reverse().slice(0, 20);
  }, [alerts]);

  const alertsByType = useMemo(() => {
    return alerts.reduce((acc, alert) => {
      acc[alert.type] = (acc[alert.type] || 0) + 1;
      return acc;
    }, {});
  }, [alerts]);

  return (
    <div className="panel alerts-panel">
      <div className="panel-header">
        <h2 className="panel-title">
          <span className="panel-icon">🚨</span>
          Security Alerts
        </h2>
        <span className="alert-count">{alerts.length} total</span>
      </div>

      {Object.keys(alertsByType).length > 0 && (
        <div className="alert-summary">
          {Object.entries(alertsByType).map(([type, count]) => (
            <span key={type} className="alert-tag">
              {type}: {count}
            </span>
          ))}
        </div>
      )}

      <div className="alerts-list">
        {recentAlerts.length > 0 ? (
          recentAlerts.map((alert, index) => (
            <AlertItem key={`${alert.src_ip}-${alert.timestamp}-${index}`} alert={alert} index={index} />
          ))
        ) : (
          <div className="no-alerts">
            <span className="no-alerts-icon">✅</span>
            <p>No alerts detected</p>
            <span className="no-alerts-subtitle">System is secure</span>
          </div>
        )}
      </div>
    </div>
  );
}

export default AlertsPanel;
