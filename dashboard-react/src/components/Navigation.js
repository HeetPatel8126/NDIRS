import React from 'react';
import './Navigation.css';

function Navigation({ currentPage, setCurrentPage }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'correlation', label: 'Correlation' },
    { id: 'attack-chains', label: 'Attack Chains' },
    { id: 'logs', label: 'Logs' },
    { id: 'alerts', label: 'Alerts' },
  ];

  return (
    <nav className="navigation">
      <div className="nav-container">
        {navItems.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${currentPage === item.id ? 'active' : ''}`}
            onClick={() => setCurrentPage(item.id)}
          >
            <span className="nav-label">{item.label}</span>
          </button>
        ))}
      </div>
    </nav>
  );
}

export default Navigation;
