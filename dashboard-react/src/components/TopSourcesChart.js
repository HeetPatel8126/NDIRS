import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';
import './TopSourcesChart.css';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

function TopSourcesChart({ alerts }) {
  // Count alerts by source IP
  const sourceCounts = alerts.reduce((acc, alert) => {
    acc[alert.src_ip] = (acc[alert.src_ip] || 0) + 1;
    return acc;
  }, {});

  // Sort and take top 10
  const topSources = Object.entries(sourceCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  const chartData = {
    labels: topSources.map(([ip]) => ip),
    datasets: [
      {
        label: 'Alert Count',
        data: topSources.map(([, count]) => count),
        backgroundColor: [
          'rgba(255, 71, 87, 0.8)',
          'rgba(255, 107, 107, 0.8)',
          'rgba(255, 143, 143, 0.8)',
          'rgba(255, 168, 168, 0.8)',
          'rgba(255, 193, 193, 0.8)',
          'rgba(255, 107, 129, 0.8)',
          'rgba(255, 132, 150, 0.8)',
          'rgba(255, 157, 171, 0.8)',
          'rgba(255, 182, 192, 0.8)',
          'rgba(255, 207, 213, 0.8)',
        ],
        borderRadius: 8,
        borderSkipped: false,
      },
    ],
  };

  const options = {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
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
          label: (context) => ` ${context.raw} alerts`,
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
          font: { size: 11 },
        },
      },
      y: {
        grid: {
          display: false,
        },
        ticks: {
          color: 'rgba(255, 255, 255, 0.8)',
          font: { size: 11, family: 'monospace' },
        },
      },
    },
    animation: {
      duration: 500,
    },
  };

  return (
    <div className="panel sources-panel">
      <div className="panel-header">
        <h2 className="panel-title">
          <span className="panel-icon">🎯</span>
          Top Alert Sources
        </h2>
        <span className="panel-subtitle">{topSources.length} unique sources</span>
      </div>

      <div className="chart-container">
        {topSources.length > 0 ? (
          <Bar data={chartData} options={options} />
        ) : (
          <div className="no-data">
            <span className="no-data-icon">✅</span>
            <p>No suspicious sources detected</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default TopSourcesChart;
