import React, { useState, useEffect, useCallback } from 'react';
import './AttackChainsPage.css';

const API_BASE = process.env.NODE_ENV === 'production' ? '' : 'http://127.0.0.1:8000';

function AttackChainsPage() {
  const [activeChains, setActiveChains] = useState([]);
  const [allChains, setAllChains] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [selectedChain, setSelectedChain] = useState(null);
  const [viewMode, setViewMode] = useState('active'); // 'active', 'all', 'critical'
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [activeRes, allRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/api/chains/active`),
        fetch(`${API_BASE}/api/chains/all`),
        fetch(`${API_BASE}/api/chains/statistics`)
      ]);
      
      const activeData = await activeRes.json();
      const allData = await allRes.json();
      const statsData = await statsRes.json();
      
      setActiveChains(Array.isArray(activeData) ? activeData : []);
      setAllChains(Array.isArray(allData) ? allData : []);
      setStatistics(statsData);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch attack chain data:', error);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const getDisplayChains = () => {
    switch (viewMode) {
      case 'active':
        return activeChains;
      case 'critical':
        return allChains.filter(c => c.severity === 'critical');
      default:
        return allChains;
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

  const getStageProgress = (stages) => {
    if (!stages || stages.length === 0) return [];
    const allStages = [
      'reconnaissance', 'initial_access', 'execution', 'persistence',
      'privilege_escalation', 'defense_evasion', 'credential_access',
      'discovery', 'lateral_movement', 'collection', 'exfiltration', 'impact'
    ];
    return allStages.map(stage => ({
      name: stage,
      completed: stages.includes(stage)
    }));
  };

  const displayChains = getDisplayChains();

  if (loading) {
    return (
      <div className="attack-chains-page">
        <div className="loading">Loading attack chain data...</div>
      </div>
    );
  }

  return (
    <div className="attack-chains-page">
      <div className="page-header">
        <div className="header-content">
          <h2>Attack Chains</h2>
          <p>Multi-stage attack detection and kill chain analysis</p>
        </div>
        <div className="view-toggle">
          <button 
            className={viewMode === 'active' ? 'active' : ''} 
            onClick={() => setViewMode('active')}
          >
            Active
          </button>
          <button 
            className={viewMode === 'critical' ? 'active' : ''} 
            onClick={() => setViewMode('critical')}
          >
            Critical
          </button>
          <button 
            className={viewMode === 'all' ? 'active' : ''} 
            onClick={() => setViewMode('all')}
          >
            All
          </button>
        </div>
      </div>

      {/* Statistics */}
      {statistics && (
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-content">
              <div className="stat-value">{statistics.total_chains || 0}</div>
              <div className="stat-label">Total Chains</div>
            </div>
          </div>
          <div className="stat-card active">
            <div className="stat-content">
              <div className="stat-value">{statistics.active_chains || 0}</div>
              <div className="stat-label">Active Chains</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-content">
              <div className="stat-value">{statistics.avg_stages?.toFixed(1) || 0}</div>
              <div className="stat-label">Avg Stages</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-content">
              <div className="stat-value">{statistics.unique_attackers || 0}</div>
              <div className="stat-label">Unique Attackers</div>
            </div>
          </div>
        </div>
      )}

      <div className="chains-content">
        {/* Chains List */}
        <div className="chains-panel panel">
          <div className="panel-header">
            <h3 className="panel-title">Attack Chains</h3>
            <span className="panel-subtitle">{displayChains.length} chains</span>
          </div>
          
          {displayChains.length === 0 ? (
            <div className="no-data">
              <p>No attack chains detected</p>
            </div>
          ) : (
            <div className="chains-list">
              {displayChains.map((chain, index) => (
                <div 
                  key={chain.id || index}
                  className={`chain-item ${selectedChain?.id === chain.id ? 'selected' : ''}`}
                  onClick={() => setSelectedChain(chain)}
                >
                  <div className="chain-header">
                    <span className={`severity-badge ${getSeverityClass(chain.severity)}`}>
                      {chain.severity?.toUpperCase()}
                    </span>
                    <span className="chain-id">Chain #{chain.id?.slice(-6) || index}</span>
                    <span className={`chain-status ${chain.is_active ? 'active' : 'inactive'}`}>
                      {chain.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                  
                  <div className="chain-attacker">
                    <span className="label">Attacker:</span>
                    <span className="value">{chain.attacker_ip || 'Unknown'}</span>
                  </div>

                  <div className="chain-stages">
                    {chain.stages?.slice(0, 5).map((stage, i) => (
                      <span key={i} className="stage-tag">
                        {stage.replace('_', ' ')}
                      </span>
                    ))}
                    {chain.stages?.length > 5 && (
                      <span className="stage-more">+{chain.stages.length - 5}</span>
                    )}
                  </div>

                  <div className="chain-meta">
                    <span>{chain.event_count || 0} events</span>
                    <span>{Math.round((chain.confidence || 0) * 100)}%</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Chain Details */}
        <div className="details-panel panel">
          <div className="panel-header">
            <h3 className="panel-title">Chain Details</h3>
          </div>
          
          {selectedChain ? (
            <div className="chain-details">
              {/* Kill Chain Progress */}
              <div className="detail-section">
                <h4>Kill Chain Progress</h4>
                <div className="kill-chain-progress">
                  {getStageProgress(selectedChain.stages).map((stage, i) => (
                    <div key={i} className={`stage-step ${stage.completed ? 'completed' : ''}`}>
                      <div className="stage-name">{stage.name.replace('_', ' ')}</div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="detail-grid">
                <div className="detail-item">
                  <label>Attacker IP</label>
                  <span className="ip-value">{selectedChain.attacker_ip || 'Unknown'}</span>
                </div>
                <div className="detail-item">
                  <label>Status</label>
                  <span className={selectedChain.is_active ? 'status-active' : 'status-inactive'}>
                    {selectedChain.is_active ? 'Active' : 'Inactive'}
                  </span>
                </div>
                <div className="detail-item">
                  <label>First Seen</label>
                  <span>{selectedChain.first_seen ? new Date(selectedChain.first_seen).toLocaleString() : 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Last Activity</label>
                  <span>{selectedChain.last_activity ? new Date(selectedChain.last_activity).toLocaleString() : 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Duration</label>
                  <span>{selectedChain.duration_seconds ? `${Math.round(selectedChain.duration_seconds / 60)} min` : 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Confidence</label>
                  <span>{Math.round((selectedChain.confidence || 0) * 100)}%</span>
                </div>
              </div>

              {selectedChain.target_ips?.length > 0 && (
                <div className="detail-section">
                  <h4>Target IPs</h4>
                  <div className="ip-tags">
                    {selectedChain.target_ips.map((ip, i) => (
                      <span key={i} className="ip-tag">{ip}</span>
                    ))}
                  </div>
                </div>
              )}

              {selectedChain.narrative && (
                <div className="detail-section">
                  <h4>Attack Narrative</h4>
                  <p className="narrative">{selectedChain.narrative}</p>
                </div>
              )}

              {selectedChain.events?.length > 0 && (
                <div className="detail-section">
                  <h4>Events Timeline</h4>
                  <div className="events-timeline">
                    {selectedChain.events.slice(0, 15).map((event, i) => (
                      <div key={i} className="timeline-event">
                        <div className="event-stage">
                          {event.stage}
                        </div>
                        <div className="event-detail">
                          <span className="event-type">{event.event_type || event.type}</span>
                          <span className="event-time">
                            {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : ''}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="no-selection">
              <p>Select an attack chain to view details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default AttackChainsPage;
