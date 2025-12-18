import React from 'react';
import './StatsGrid.css';

function StatCard({ icon, label, value, colorClass, trend }) {
  return (
    <div className={`stat-card ${colorClass}`}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-content">
        <span className="stat-label">{label}</span>
        <span className="stat-value">{value.toLocaleString()}</span>
        {trend && (
          <span className={`stat-trend ${trend > 0 ? 'up' : 'down'}`}>
            {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
          </span>
        )}
      </div>
    </div>
  );
}

function StatsGrid({ totalPackets, protocolCount, alertCount }) {
  return (
    <div className="stats-grid">
      <StatCard
        icon="📦"
        label="Total Packets Captured"
        value={totalPackets}
        colorClass="packets"
      />
      <StatCard
        icon="🔌"
        label="Unique Protocols"
        value={protocolCount}
        colorClass="protocols"
      />
      <StatCard
        icon="🚨"
        label="Security Alerts"
        value={alertCount}
        colorClass="alerts"
      />
      <StatCard
        icon="⚡"
        label="Packets/Second"
        value={Math.round(totalPackets / 60)}
        colorClass="rate"
      />
    </div>
  );
}

export default StatsGrid;
