import React from "react";

interface RiskGaugeProps {
  score: number;
  size?: number;
  strokeWidth?: number;
  feedCount?: number;
}

import { motion } from "framer-motion";
import { useEffect, useState } from "react";

const ZONES = [
  { max: 29,  label: "SAFE",       color: "#22c55e", textColor: "text-emerald-400" },
  { max: 59,  label: "SUSPICIOUS", color: "#eab308", textColor: "text-yellow-400"  },
  { max: 79,  label: "DANGEROUS",  color: "#f97316", textColor: "text-orange-400"  },
  { max: 100, label: "CRITICAL",   color: "#ef4444", textColor: "text-red-400"     },
];

function getZone(score: number) {
  return ZONES.find((z) => score <= z.max) ?? ZONES[ZONES.length - 1];
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  size = 192,
  strokeWidth = 8,
  feedCount = 5,
}) => {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let start = 0;
    const end = score;
    if (start === end) {
      setAnimatedScore(end);
      return;
    }
    const duration = 1000;
    const incrementTime = Math.max(duration / end, 10);
    
    const timer = setInterval(() => {
      start += 1;
      setAnimatedScore(start);
      if (start === end) clearInterval(timer);
    }, incrementTime);
    
    return () => clearInterval(timer);
  }, [score]);

  const radius       = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset       = circumference - (score / 100) * circumference;
  const zone         = getZone(score);

  return (
    <div className="flex flex-col items-center gap-4">
      {/* Gauge ring */}
      <div className="relative flex flex-col items-center justify-center" style={{ width: size, height: size }}>
        <svg className="w-full h-full transform -rotate-90" viewBox={`0 0 ${size} ${size}`}>
          {/* Background track */}
          <circle
            className="text-white/5"
            cx={size / 2} cy={size / 2}
            fill="transparent" r={radius}
            stroke="currentColor" strokeWidth={strokeWidth}
          />
          {/* Animated arc */}
          <motion.circle
            cx={size / 2} cy={size / 2}
            fill="transparent" r={radius}
            stroke={zone.color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1.5, ease: [0.16, 1, 0.3, 1] }}
            strokeLinecap="round"
          />
        </svg>

        {/* Center content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center select-none">
          <span className="text-5xl font-black text-white leading-none">{animatedScore}</span>
          <span className={`text-xs font-bold mt-1 tracking-wider font-mono-sm ${zone.textColor}`}>
            {zone.label}
          </span>
        </div>
      </div>

      {/* Zone legend */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 w-full max-w-[180px]">
        {ZONES.map((z) => (
          <div key={z.label} className={`flex items-center gap-1.5 text-[10px] font-mono-sm ${score <= z.max && score > (ZONES[ZONES.indexOf(z) - 1]?.max ?? -1) ? "opacity-100" : "opacity-30"}`}>
            <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: z.color }} />
            <span className="text-on-surface-variant">
              {z.label}
            </span>
          </div>
        ))}
      </div>

      {/* Feed count */}
      <p className="text-[10px] text-on-surface-variant/60 font-mono-sm text-center">
        Aggregated from {feedCount} security feeds
      </p>
    </div>
  );
};

export default RiskGauge;
