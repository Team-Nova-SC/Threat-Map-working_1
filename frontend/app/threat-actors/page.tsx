"use client";

import React, { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { motion } from "framer-motion";
import { ShieldAlert, RefreshCw, Flag, Network } from "lucide-react";

export default function ThreatActorsPage() {
  const [actors, setActors] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [message, setMessage] = useState("");

  const fetchActors = async () => {
    try {
      setIsLoading(true);
      const data = await api.getThreatActors();
      setActors(data);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchActors();
  }, []);

  const handleSync = async () => {
    try {
      setIsSyncing(true);
      await api.syncThreatActors();
      setMessage("MITRE ATT&CK sync started. This may take a minute.");
      setTimeout(() => setMessage(""), 5000);
      // Re-fetch after 10s assuming sync finishes
      setTimeout(fetchActors, 10000);
    } catch (err) {
      console.error(err);
    } finally {
      setIsSyncing(false);
    }
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    show: { y: 0, opacity: 1 }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-12 px-4 md:px-8 mt-6">
      {/* Header Banner */}
      <div className="glass-panel p-md rounded-xl flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <ShieldAlert className="text-error w-6 h-6" />
            <h2 className="text-xl font-black text-white tracking-tight font-headline-lg">
              Threat Actor Intelligence
            </h2>
          </div>
          <p className="text-xs text-on-surface-variant/80 font-body-sm">
            Known Advanced Persistent Threat (APT) groups mapped via MITRE ATT&CK.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {message && <span className="text-xs text-emerald-400 font-mono-sm">{message}</span>}
          <button
            onClick={handleSync}
            disabled={isSyncing}
            className="py-2.5 px-4 bg-surface-container-high text-white font-bold text-xs font-label-caps rounded-lg hover:opacity-90 active:scale-[0.98] transition-all flex items-center gap-2"
          >
            <RefreshCw size={14} className={isSyncing ? "animate-spin" : ""} />
            {isSyncing ? "SYNCING..." : "SYNC MITRE DB"}
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <RefreshCw className="w-8 h-8 text-primary animate-spin" />
        </div>
      ) : (
        <motion.div 
          variants={containerVariants}
          initial="hidden"
          animate="show"
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
        >
          {actors.map((actor) => (
            <motion.div 
              key={actor.id} 
              variants={itemVariants} 
              whileHover={{ y: -8, scale: 1.02, boxShadow: "0 20px 40px -10px rgba(0,0,0,0.5)" }}
              transition={{ type: "spring" as const, stiffness: 300, damping: 20 }}
              className="glass-panel p-md rounded-xl hover:border-white/20 transition-colors duration-300 relative overflow-hidden group"
            >
              {/* Premium Glow effect on hover */}
              <div className="absolute inset-0 bg-gradient-to-br from-primary/0 via-primary/0 to-primary/10 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none" />
              
              <div className="flex items-start justify-between mb-4 relative z-10">
                <div>
                  <h3 className="font-bold text-white text-lg tracking-wide">{actor.name}</h3>
                  <div className="flex items-center gap-1 text-xs text-on-surface-variant/70 mt-1">
                    <Flag className="w-3 h-3" />
                    <span>{actor.country || "Unknown Origin"}</span>
                  </div>
                </div>
                <motion.span 
                  animate={actor.threat_level === "CRITICAL" ? { boxShadow: ["0 0 0px rgba(255,180,171,0)", "0 0 15px rgba(255,180,171,0.5)", "0 0 0px rgba(255,180,171,0)"] } : {}}
                  transition={{ duration: 2, repeat: Infinity }}
                  className={`px-2 py-0.5 rounded text-[10px] font-mono-sm font-bold border ${
                    actor.threat_level === "CRITICAL" 
                      ? "bg-[#93000a]/20 text-[#ffb4ab] border-[#ffb4ab]/25" 
                      : "bg-[#df7412]/20 text-[#ffb786] border-[#ffb786]/20"
                  }`}
                >
                  {actor.threat_level}
                </motion.span>
              </div>
              
              <div className="space-y-4">
                <p className="text-xs text-on-surface-variant font-body-sm line-clamp-3">
                  {actor.description || "No description available."}
                </p>
                
                {actor.aliases && (
                  <div>
                    <span className="text-[10px] font-mono-sm text-on-surface-variant uppercase">Known Aliases</span>
                    <p className="text-xs text-white truncate">{actor.aliases}</p>
                  </div>
                )}
              </div>
              
              <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-1 text-[10px] text-primary">
                  <Network className="w-3 h-3" />
                  <span>Tracking IOCs</span>
                </div>
                <span className="text-[10px] text-on-surface-variant/50">ID: {actor.id.split("--")[1]?.substring(0, 8)}</span>
              </div>
            </motion.div>
          ))}
        </motion.div>
      )}
    </div>
  );
}
