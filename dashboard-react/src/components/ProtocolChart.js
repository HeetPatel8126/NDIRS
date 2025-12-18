import React from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import './ProtocolChart.css';

ChartJS.register(ArcElement, Tooltip, Legend);

const COLORS = [
  '#74b9ff', '#a29bfe', '#fd79a8', '#ffeaa7', '#55efc4',
  '#81ecec', '#fab1a0', '#ff7675', '#dfe6e9', '#b2bec3'
];

function ProtocolChart({ protocols }) {
  const protocolNames = Object.keys(protocols);
  const protocolValues = Object.values(protocols);
  const total = protocolValues.reduce((a, b) => a + b, 0);

  const chartData = {
    labels: protocolNames,
    datasets: [
      {
        data: protocolValues,
        backgroundColor: COLORS,
        borderWidth: 0,
        hoverOffset: 15,
        borderRadius: 5,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#fff',
          padding: 15,
          font: { size: 12, weight: '500' },
          usePointStyle: true,
          pointStyle: 'circle',
        },
      },
      tooltip: {
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleFont: { size: 14, weight: '600' },
        bodyFont: { size: 13 },
        padding: 12,
        cornerRadius: 8,
        callbacks: {
          label: (context) => {
            const value = context.raw;
            const percentage = ((value / total) * 100).toFixed(1);
            return ` ${value.toLocaleString()} packets (${percentage}%)`;
          },
        },
      },
    },
    cutout: '65%',
    animation: {
      animateRotate: true,
      animateScale: true,
    },
  };

  const sortedProtocols = Object.entries(protocols)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return (
    <div className="panel protocol-panel">
      <div className="panel-header">
        <h2 className="panel-title">
          <span className="panel-icon">📊</span>
          Protocol Distribution
        </h2>
        <span className="panel-subtitle">{protocolNames.length} protocols detected</span>
      </div>
      
      <div className="chart-container">
        {total > 0 ? (
          <Doughnut data={chartData} options={options} />
        ) : (
          <div className="no-data">
            <span className="no-data-icon">📭</span>
            <p>Waiting for data...</p>
          </div>
        )}
      </div>

      <div className="protocol-bars">
        {sortedProtocols.map(([name, count], index) => {
          const percent = total > 0 ? ((count / total) * 100).toFixed(1) : 0;
          return (
            <div key={name} className="protocol-bar-item">
              <div className="protocol-bar-header">
                <span className="protocol-name">{name}</span>
                <span className="protocol-count">{count.toLocaleString()}</span>
              </div>
              <div className="protocol-bar-bg">
                <div
                  className="protocol-bar-fill"
                  style={{
                    width: `${percent}%`,
                    backgroundColor: COLORS[index % COLORS.length],
                  }}
                >
                  <span className="protocol-percent">{percent}%</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default ProtocolChart;
