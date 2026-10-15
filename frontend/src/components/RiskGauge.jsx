import React from 'react';

export default function RiskGauge({ score = 0, level = 'low' }) {
  // Semi-circle gauge (180 degrees)
  // Score 0 -> -90 deg, Score 100 -> +90 deg
  const clampedScore = Math.max(0, Math.min(100, score));
  const angle = -90 + (clampedScore / 100) * 180;

  const getColor = (lvl) => {
    switch (lvl?.toLowerCase()) {
      case 'critical':
        return '#ef4444';
      case 'high':
        return '#f97316';
      case 'medium':
        return '#f59e0b';
      case 'low':
      default:
        return '#10b981';
    }
  };

  const color = getColor(level);

  return (
    <div className="gauge-container" id="risk-gauge-component">
      <svg className="gauge-svg" viewBox="0 0 200 120">
        <defs>
          <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#10b981" />
            <stop offset="35%" stopColor="#f59e0b" />
            <stop offset="70%" stopColor="#f97316" />
            <stop offset="100%" stopColor="#ef4444" />
          </linearGradient>
          <filter id="needleGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="0" stdDeviation="3" floodColor={color} />
          </filter>
        </defs>

        {/* Background Track */}
        <path
          d="M 20 100 A 80 80 0 0 1 180 100"
          fill="none"
          stroke="rgba(255, 255, 255, 0.08)"
          strokeWidth="16"
          strokeLinecap="round"
        />

        {/* Gradient Arc */}
        <path
          d="M 20 100 A 80 80 0 0 1 180 100"
          fill="none"
          stroke="url(#gaugeGradient)"
          strokeWidth="16"
          strokeLinecap="round"
          strokeDasharray="251.2"
          strokeDashoffset={251.2 - (251.2 * clampedScore) / 100}
          style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1)' }}
        />

        {/* Center Pivot */}
        <circle cx="100" cy="100" r="7" fill="#0d1424" stroke={color} strokeWidth="3" />

        {/* Needle */}
        <g
          transform={`rotate(${angle} 100 100)`}
          style={{ transition: 'transform 0.8s cubic-bezier(0.4, 0, 0.2, 1)' }}
          filter="url(#needleGlow)"
        >
          <line
            x1="100"
            y1="100"
            x2="100"
            y2="34"
            stroke={color}
            strokeWidth="3.5"
            strokeLinecap="round"
          />
        </g>
      </svg>

      <div className="gauge-center">
        <div className="gauge-score mono" style={{ color }}>
          {clampedScore.toFixed(1)}
        </div>
        <div className={`badge badge-${level.toLowerCase()} gauge-level-tag`}>
          {level.toUpperCase()} RISK
        </div>
      </div>
    </div>
  );
}
