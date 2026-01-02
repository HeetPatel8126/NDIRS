import React from 'react';
import './Header.css';

function Header({ isConnected }) {
  return (
    <header className="header">
      <div className="header-left">
        <span className="logo">NIDRS</span>
        <span className="subtitle">Network Intrusion Detection & Response System</span>
      </div>
      <div className={`status-badge ${isConnected ? 'online' : 'offline'}`}>
        <span className="status-dot"></span>
        <span className="status-text">
          {isConnected ? 'System Active' : 'Connection Lost'}
        </span>
      </div>
    </header>
  );
}

export default Header;
