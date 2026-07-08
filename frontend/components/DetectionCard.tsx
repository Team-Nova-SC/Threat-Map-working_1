import React from "react";

interface DetectionCardProps {
  title: string;
  subtitle?: string;   // plain-English vendor description
  status: string;
  isMalicious: boolean;
  iconName: string;
  children?: React.ReactNode;
}

import { motion } from "framer-motion";

export const DetectionCard: React.FC<DetectionCardProps> = ({
  title,
  subtitle,
  status,
  isMalicious,
  iconName,
  children,
}) => {
  return (
    <motion.div 
      initial={{ y: 20, opacity: 0, scale: 0.98 }}
      animate={{ y: 0, opacity: 1, scale: 1 }}
      transition={{ type: "spring" as const, stiffness: 300, damping: 20 }}
      className="glass-panel p-md rounded-xl flex flex-col justify-between hover:border-white/20 transition-all duration-300"
    >
      <div>
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-surface-container-low border border-white/5 flex items-center justify-center">
              <span className="material-symbols-outlined text-primary text-[20px]">{iconName}</span>
            </div>
            <div>
              <h4 className="font-bold text-white text-sm tracking-wide font-headline-sm">{title}</h4>
              <p className="text-[10px] text-on-surface-variant/70 font-mono-sm leading-tight">
                {subtitle ?? "Threat intelligence feed"}
              </p>
            </div>
          </div>
          <span
            className={`px-2.5 py-0.5 rounded text-[10px] font-mono-sm font-bold border ${
              isMalicious
                ? "bg-[#93000a]/20 text-[#ffb4ab] border-[#ffb4ab]/25"
                : "bg-surface-container-low text-primary border-primary/20"
            }`}
          >
            {status}
          </span>
        </div>
        {children && <div className="space-y-2 mt-2">{children}</div>}
      </div>
    </motion.div>
  );
};
export default DetectionCard;
