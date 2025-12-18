import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import StatsGrid from './components/StatsGrid';
import ProtocolChart from './components/ProtocolChart';
import TrafficChart from './components/TrafficChart';
import AlertsPanel from './components/AlertsPanel';
import TopSourcesChart from './components/TopSourcesChart';
import './App.css';

// Use relative URLs when served from FastAPI, or full URL for development
const API_BASE = process.env.NODE_ENV === 'production' ? '' : 'http://127.0.0.1:8000';

function App() {
  const [isConnected, setIsConnected] = useState(false);
  const [stats, setStats] = useState({
    total_packets: 0,
    protocols: {},
  });
  const [alerts, setAlerts] = useState([]);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [lastUpdate, setLastUpdate] = useState(null);

  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/stats`);
      const data = await response.json();
      setStats(data);
      setIsConnected(true);
      
      // Update traffic history for time-series chart
      setTrafficHistory(prev => {
        const now = new Date();
        const newEntry = {
          time: now.toLocaleTimeString(),
          packets: data.total_packets,
        };
        const updated = [...prev, newEntry].slice(-20); // Keep last 20 entries
        return updated;
      });
      
      setLastUpdate(new Date());
    } catch (error) {
      setIsConnected(false);
      console.error('Failed to fetch stats:', error);
    }
  }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/alerts`);
      const data = await response.json();
      setAlerts(data);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    }
  }, []);

  useEffect(() => {
    // Initial fetch
    fetchStats();
    fetchAlerts();

    // Set up polling interval
    const interval = setInterval(() => {
      fetchStats();
      fetchAlerts();
    }, 2000);

    return () => clearInterval(interval);
  }, [fetchStats, fetchAlerts]);

  const protocolCount = Object.keys(stats.protocols).length;

  return (
    <div className="app">
      <Header isConnected={isConnected} />
      
      <main className="container">
        <StatsGrid 
          totalPackets={stats.total_packets}
          protocolCount={protocolCount}
          alertCount={alerts.length}
        />

        <div className="charts-grid">
          <ProtocolChart protocols={stats.protocols} />
          <TrafficChart trafficHistory={trafficHistory} />
        </div>

        <div className="main-grid">
          <TopSourcesChart alerts={alerts} />
          <AlertsPanel alerts={alerts} />
        </div>

        <div className="refresh-info">
          Auto-refreshing every 2 seconds | Last update: {lastUpdate ? lastUpdate.toLocaleTimeString() : '-'}
        </div>
      </main>
    </div>
  );
}

export default App;
