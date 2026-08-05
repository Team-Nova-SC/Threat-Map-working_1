import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

interface DetectionCardProps {
  title: string;
  subtitle?: string;   // plain-English vendor description
  status: string;
  isMalicious: boolean;
  iconName: string;
  children?: React.ReactNode;
  vendorLink?: string;
  timestamp?: string;
  rawJson?: any;
}

export const DetectionCard: React.FC<DetectionCardProps> = ({
  title,
  subtitle,
  status,
  isMalicious,
  iconName,
  children,
  vendorLink,
  timestamp,
  rawJson,
}) => {
  const [showRaw, setShowRaw] = useState(false);

  return (
    <motion.div 
      initial={{ y: 20, opacity: 0, scale: 0.98 }}
      animate={{ y: 0, opacity: 1, scale: 1 }}
      transition={{ type: "spring" as const, stiffness: 300, damping: 20 }}
      className="glass-panel p-md rounded-xl flex flex-col hover:border-white/20 transition-all duration-300"
    >
      <div className="flex-1">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-surface-container-low border border-white/5 flex items-center justify-center">
              <span className="material-symbols-outlined text-primary text-[20px]">{iconName}</span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="font-bold text-white text-sm tracking-wide font-headline-sm">{title}</h4>
                {vendorLink && (
                  <a href={vendorLink} target="_blank" rel="noopener noreferrer" className="text-primary hover:text-white transition-colors flex items-center group" title={`View on ${title}`}>
                    <span className="material-symbols-outlined text-[14px]">open_in_new</span>
                  </a>
                )}
              </div>
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
        <div className="mb-4">
          {children}
        </div>
      </div>
      
      {(timestamp || rawJson) && (
        <div className="mt-auto border-t border-white/5 pt-2 flex items-center justify-between">
          {timestamp ? (
            <span className="text-[9px] font-mono-sm text-on-surface-variant/50">Checked at: {new Date(timestamp).toLocaleTimeString()}</span>
          ) : <span />}
          {rawJson && (
            <button 
              onClick={() => setShowRaw(!showRaw)}
              className="text-[9px] font-mono-sm text-primary hover:text-white transition-colors flex items-center gap-1"
            >
              <span className="material-symbols-outlined text-[12px]">{showRaw ? 'expand_less' : 'expand_more'}</span>
              RAW JSON
            </button>
          )}
        </div>
      )}

      <AnimatePresence>
        {showRaw && rawJson && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden mt-2"
          >
            <div className="bg-black/40 p-2 rounded-lg border border-white/5 max-h-[150px] overflow-y-auto">
              <pre className="text-[8px] font-mono-sm text-on-surface-variant whitespace-pre-wrap">
                {JSON.stringify(rawJson, null, 2)}
              </pre>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};
export default DetectionCard;
