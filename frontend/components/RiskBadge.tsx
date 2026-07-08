import React, { useState } from "react";

interface RiskBadgeProps {
  level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  score?: number;
}

import { motion } from "framer-motion";

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, score }) => {
  const [showTooltip, setShowTooltip] = useState(false);

  const getBadgeStyle = () => {
    switch (level.toUpperCase()) {
      case "CRITICAL":
        return {
          bg: "bg-[#93000a]/30 text-[#ffb4ab] border-[#ffb4ab]/25",
          icon: "brightness_high",
          text: "Critical",
        };
      case "HIGH":
        return {
          bg: "bg-[#df7412]/20 text-[#ffb786] border-[#ffb786]/20",
          icon: "warning",
          text: "High Risk",
        };
      case "MEDIUM":
        return {
          bg: "bg-secondary-container/30 text-on-secondary-container border-on-secondary-container/20",
          icon: "report",
          text: "Medium",
        };
      default:
        return {
          bg: "bg-surface-container-low text-primary border-primary/20",
          icon: "check_circle",
          text: "Low Risk",
        };
    }
  };

  const style = getBadgeStyle();
  const isCritical = level.toUpperCase() === "CRITICAL";

  return (
    <div 
      className="relative inline-flex items-center"
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <motion.span
        initial={{ scale: 0, opacity: 0 }}
        animate={{ scale: [1.1, 1], opacity: 1 }}
        transition={{ duration: 0.4, type: "spring" as const, stiffness: 300, damping: 15 }}
        className={`inline-flex items-center gap-1.5 px-3 py-1 text-[11px] font-bold font-mono-sm border rounded-full ${style.bg} ${isCritical ? "animate-pulse" : ""}`}
      >
        <span className="material-symbols-outlined text-[14px]">{style.icon}</span>
        {style.text} {score !== undefined && `(${score})`}
      </motion.span>

      {/* Tooltip Legend */}
      {showTooltip && (
        <div className="absolute top-full left-1/2 -translate-x-1/2 mt-2 w-48 bg-surface-container-highest border border-white/10 rounded-lg p-3 text-[10px] text-on-surface-variant z-50 shadow-2xl pointer-events-none">
          <p className="font-bold text-white mb-2 uppercase tracking-wider font-mono-sm">Risk Score Legend</p>
          <div className="space-y-1.5">
            <div className="flex justify-between items-center"><span className="text-primary font-bold">0 - 15</span><span className="bg-primary/10 px-1 rounded">LOW</span></div>
            <div className="flex justify-between items-center"><span className="text-on-secondary-container font-bold">16 - 50</span><span className="bg-secondary-container/30 px-1 rounded">MEDIUM</span></div>
            <div className="flex justify-between items-center"><span className="text-[#ffb786] font-bold">51 - 89</span><span className="bg-[#df7412]/20 px-1 rounded">HIGH</span></div>
            <div className="flex justify-between items-center"><span className="text-[#ffb4ab] font-bold">90 - 100</span><span className="bg-[#93000a]/30 px-1 rounded">CRITICAL</span></div>
          </div>
        </div>
      )}
    </div>
  );
};
export default RiskBadge;
