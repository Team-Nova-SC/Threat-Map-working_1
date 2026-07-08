"use client";

import React, { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AlertTriangle, RefreshCw } from "lucide-react";

export const ConnectionBanner: React.FC = () => {
  const [isOffline, setIsOffline] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const countdownRef = useRef(countdown);
  countdownRef.current = countdown;

  useEffect(() => {
    let BASE = process.env.NEXT_PUBLIC_API_URL || "https://threatmap-production.up.railway.app/api/v1";
    if (BASE && !BASE.endsWith('/api/v1')) {
      BASE = BASE.replace(/\/$/, '') + '/api/v1';
    }

    const pingHealth = async (): Promise<boolean> => {
      try {
        const res = await fetch(`${BASE}/health`, {
          signal: AbortSignal.timeout(4000),
          cache: "no-store",
        });
        return res.ok;
      } catch {
        return false;
      }
    };

    let polling: NodeJS.Timeout;

    const runCheck = async () => {
      const alive = await pingHealth();
      if (alive) {
        setIsOffline(false);
        setCountdown(0);
      } else {
        setIsOffline(true);
        setCountdown(10);
      }
    };

    // Initial check on mount
    runCheck();

    // Poll every 15 seconds regardless of state
    polling = setInterval(runCheck, 15000);

    return () => clearInterval(polling);
  }, []);

  // Countdown ticker — runs only while offline
  useEffect(() => {
    if (!isOffline) return;
    const tick = setInterval(() => {
      setCountdown((c) => (c > 0 ? c - 1 : 0));
    }, 1000);
    return () => clearInterval(tick);
  }, [isOffline]);

  return (
    <AnimatePresence>
      {isOffline && (
        <motion.div
          initial={{ y: -50, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -50, opacity: 0 }}
          className="fixed top-0 left-0 right-0 z-50 bg-[#93000a] text-[#ffb4ab] border-b border-[#ffb4ab]/25 px-4 py-2 flex items-center justify-center gap-3 font-mono-sm text-xs font-bold shadow-lg"
        >
          <AlertTriangle className="w-4 h-4" />
          <span>Telemetry Offline: Backend unreachable.</span>
          <div className="flex items-center gap-1.5 opacity-80">
            <RefreshCw className="w-3 h-3 animate-spin" />
            <span>Reconnecting in {countdown}s...</span>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default ConnectionBanner;
