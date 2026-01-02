import React from 'react';
import './StatsGrid.css';

function StatCard({ label, value, colorClass, trend }) {
  return (
    <div className={`stat-card ${colorClass}`}>
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
        label="Total Packets"
        value={totalPackets}
        colorClass="packets"
      />
      <StatCard
        label="Protocols"
        value={protocolCount}
        colorClass="protocols"
      />
      <StatCard
        label="Alerts"
        value={alertCount}
        colorClass="alerts"
      />
      <StatCard
        label="Packets/Sec"
        value={Math.round(totalPackets / 60)}
        colorClass="rate"
      />
    </div>
  );
}

export default StatsGrid;
