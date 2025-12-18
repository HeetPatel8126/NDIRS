import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Line } from 'react-chartjs-2';
import './TrafficChart.css';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

function TrafficChart({ trafficHistory }) {
  // Calculate packet deltas for rate
  const packetRates = trafficHistory.map((entry, index) => {
    if (index === 0) return 0;
    const delta = entry.packets - trafficHistory[index - 1].packets;
    return Math.max(0, delta);
  });

  const chartData = {
    labels: trafficHistory.map((entry) => entry.time),
    datasets: [
      {
        label: 'Packets/Update',
        data: packetRates,
        borderColor: '#74b9ff',
        backgroundColor: 'rgba(116, 185, 255, 0.1)',
        borderWidth: 3,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointHoverRadius: 6,
        pointBackgroundColor: '#74b9ff',
        pointBorderColor: '#fff',
        pointBorderWidth: 2,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      intersect: false,
      mode: 'index',
    },
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleFont: { size: 14, weight: '600' },
        bodyFont: { size: 13 },
        padding: 12,
        cornerRadius: 8,
        callbacks: {
          label: (context) => ` ${context.raw.toLocaleString()} packets`,
        },
      },
    },
    scales: {
      x: {
        grid: {
          color: 'rgba(255, 255, 255, 0.05)',
          drawBorder: false,
        },
        ticks: {
          color: 'rgba(255, 255, 255, 0.5)',
          font: { size: 10 },
          maxRotation: 0,
          maxTicksLimit: 8,
        },
      },
      y: {
        beginAtZero: true,
        grid: {
          color: 'rgba(255, 255, 255, 0.05)',
          drawBorder: false,
        },
        ticks: {
          color: 'rgba(255, 255, 255, 0.5)',
          font: { size: 11 },
          callback: (value) => value.toLocaleString(),
        },
      },
    },
    animation: {
      duration: 300,
    },
  };

  const currentRate = packetRates.length > 0 ? packetRates[packetRates.length - 1] : 0;
  const avgRate = packetRates.length > 0 
    ? Math.round(packetRates.reduce((a, b) => a + b, 0) / packetRates.length)
    : 0;
  const maxRate = Math.max(...packetRates, 0);

  return (
    <div className="panel traffic-panel">
      <div className="panel-header">
        <h2 className="panel-title">
          <span className="panel-icon">📈</span>
          Real-Time Traffic
        </h2>
        <div className="traffic-stats">
          <span className="traffic-stat current">
            <span className="stat-label">Current</span>
            <span className="stat-value">{currentRate}</span>
          </span>
          <span className="traffic-stat avg">
            <span className="stat-label">Avg</span>
            <span className="stat-value">{avgRate}</span>
          </span>
          <span className="traffic-stat max">
            <span className="stat-label">Max</span>
            <span className="stat-value">{maxRate}</span>
          </span>
        </div>
      </div>

      <div className="chart-container">
        {trafficHistory.length > 1 ? (
          <Line data={chartData} options={options} />
        ) : (
          <div className="no-data">
            <span className="no-data-icon">⏳</span>
            <p>Collecting traffic data...</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default TrafficChart;
