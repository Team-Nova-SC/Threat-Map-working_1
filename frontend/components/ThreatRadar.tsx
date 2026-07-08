"use client";

import React, { useEffect, useRef } from "react";

interface ThreatRadarProps {
  distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  totalScans: number;
}

const AXES = [
  { label: "Critical",  key: "critical", color: "#f87171", angle: -90 },
  { label: "High",      key: "high",     color: "#fb923c", angle: -18 },
  { label: "Medium",    key: "medium",   color: "#facc15", angle:  54 },
  { label: "Low",       key: "low",      color: "#4ade80", angle: 126 },
  { label: "Secure",    key: "secure",   color: "#adc6ff", angle: 198 },
];

function polarToXY(angle: number, radius: number, cx: number, cy: number) {
  const rad = (angle * Math.PI) / 180;
  return {
    x: cx + radius * Math.cos(rad),
    y: cy + radius * Math.sin(rad),
  };
}

export default function ThreatRadar({ distribution, totalScans }: ThreatRadarProps) {
  const secureVal = Math.max(0, 100 - distribution.critical - distribution.high - distribution.medium - distribution.low);
  const values: Record<string, number> = {
    critical: distribution.critical,
    high: distribution.high,
    medium: distribution.medium,
    low: distribution.low,
    secure: secureVal,
  };

  const cx = 120, cy = 120, R = 90;

  // Build radar polygon points
  const levels = [0.25, 0.5, 0.75, 1.0];

  function buildPolygon(scale: number) {
    return AXES.map(ax => {
      const val = (values[ax.key] / 100) * scale;
      const p = polarToXY(ax.angle, val * R, cx, cy);
      return `${p.x},${p.y}`;
    }).join(" ");
  }

  const dataPolygon = AXES.map(ax => {
    const val = Math.max(0.05, (values[ax.key] || 0) / 100);
    const p = polarToXY(ax.angle, val * R, cx, cy);
    return `${p.x},${p.y}`;
  }).join(" ");

  return (
    <div className="flex flex-col items-center">
      <svg width="240" height="240" viewBox="0 0 240 240">
        <defs>
          <radialGradient id="radarGrad" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#adc6ff" stopOpacity="0.15" />
            <stop offset="100%" stopColor="#020617" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Grid rings */}
        {levels.map((lv, i) => (
          <polygon
            key={i}
            points={AXES.map(ax => {
              const p = polarToXY(ax.angle, lv * R, cx, cy);
              return `${p.x},${p.y}`;
            }).join(" ")}
            fill="none"
            stroke="rgba(255,255,255,0.07)"
            strokeWidth="1"
          />
        ))}

        {/* Axis lines */}
        {AXES.map(ax => {
          const outer = polarToXY(ax.angle, R, cx, cy);
          return (
            <line
              key={ax.key}
              x1={cx} y1={cy}
              x2={outer.x} y2={outer.y}
              stroke="rgba(255,255,255,0.08)"
              strokeWidth="1"
            />
          );
        })}

        {/* Data fill */}
        <polygon
          points={dataPolygon}
          fill="url(#radarGrad)"
          stroke="rgba(173, 198, 255, 0.5)"
          strokeWidth="1.5"
          style={{ filter: "drop-shadow(0 0 6px rgba(173,198,255,0.3))" }}
        />

        {/* Axis dots + labels */}
        {AXES.map(ax => {
          const val = Math.max(0.05, (values[ax.key] || 0) / 100);
          const dot = polarToXY(ax.angle, val * R, cx, cy);
          const labelPos = polarToXY(ax.angle, R + 18, cx, cy);
          return (
            <g key={ax.key}>
              <circle cx={dot.x} cy={dot.y} r={3.5} fill={ax.color} style={{ filter: `drop-shadow(0 0 4px ${ax.color})` }} />
              <text
                x={labelPos.x} y={labelPos.y}
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize="8"
                fill={ax.color}
                fontFamily="JetBrains Mono, monospace"
                fontWeight="bold"
              >
                {ax.label.toUpperCase()}
              </text>
            </g>
          );
        })}

        {/* Center label */}
        <circle cx={cx} cy={cy} r={24} fill="rgba(2,6,23,0.8)" stroke="rgba(255,255,255,0.05)" strokeWidth="1" />
        <text x={cx} y={cy - 6} textAnchor="middle" fill="white" fontSize="13" fontWeight="bold" fontFamily="JetBrains Mono, monospace">
          {totalScans}
        </text>
        <text x={cx} y={cy + 8} textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="6" fontFamily="JetBrains Mono, monospace">
          SCANS
        </text>
      </svg>

      {/* Legend */}
      <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 w-full mt-1">
        {AXES.map(ax => (
          <div key={ax.key} className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full shrink-0" style={{ background: ax.color, boxShadow: `0 0 4px ${ax.color}` }} />
            <span className="text-[9px] font-mono text-on-surface-variant">{ax.label}</span>
            <span className="text-[9px] font-mono text-white ml-auto">{values[ax.key] ?? 0}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}
