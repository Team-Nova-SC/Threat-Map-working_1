"use client";

import React, { useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import RiskBadge from "@/components/RiskBadge";
import { Eye, RefreshCw, Trash2, ArrowRight, Notebook, Download, Rss, Settings, X, Save, Bell } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

// 14-day Heatmap generator
const generateHeatmap = (items: any[]) => {
  const days = Array.from({length: 14}).map((_, i) => {
    const d = new Date();
    d.setDate(d.getDate() - (13 - i));
    return d.toISOString().split('T')[0];
  });
  
  return days.map(date => {
    const activeScans = items.filter(item => item.last_scanned_at && item.last_scanned_at.startsWith(date));
    const maxRisk = activeScans.reduce((max, item) => Math.max(max, item.last_risk_score || 0), 0);
    return { date, risk: maxRisk, count: activeScans.length };
  });
};

export default function WatchlistPage() {
  const [message, setMessage] = useState("");
  const [editingItem, setEditingItem] = useState<any>(null);
  const [editForm, setEditForm] = useState({ tags: "", notes: "", webhook_url: "", custom_threshold: 70, schedule_frequency: "daily" });
  
  const queryClient = useQueryClient();

  const { data: watchlist = [], isLoading, error: queryError } = useQuery({
    queryKey: ['watchlist'],
    queryFn: () => api.getWatchlist(),
    staleTime: 10000,
  });

  const removeMutation = useMutation({
    mutationFn: (indicator: string) => api.removeFromWatchlist(indicator),
    onSuccess: (_, variables) => {
      setMessage(`Removed ${variables} from watchlist.`);
      setTimeout(() => setMessage(""), 3000);
      queryClient.invalidateQueries({ queryKey: ['watchlist'] });
    }
  });

  const scanMutation = useMutation({
    mutationFn: () => api.scanWatchlistAll(),
    onMutate: () => setMessage("Triggering parallel OSINT scanner updates..."),
    onSuccess: () => {
      setMessage("Scanner job completed. Watchlist threat scores updated.");
      setTimeout(() => setMessage(""), 4000);
      queryClient.invalidateQueries({ queryKey: ['watchlist'] });
    }
  });

  const updateMutation = useMutation({
    mutationFn: ({indicator, data}: {indicator: string, data: any}) => api.updateWatchlistItem(indicator, data),
    onSuccess: () => {
      setMessage("Watchlist settings saved.");
      setEditingItem(null);
      setTimeout(() => setMessage(""), 3000);
      queryClient.invalidateQueries({ queryKey: ['watchlist'] });
    }
  });

  const openSettings = (item: any) => {
    setEditingItem(item);
    setEditForm({
      tags: item.tags || "",
      notes: item.notes || "",
      webhook_url: item.webhook_url || "",
      custom_threshold: item.custom_threshold || 70,
      schedule_frequency: item.schedule_frequency || "daily"
    });
  };

  const handleSaveSettings = () => {
    if (!editingItem) return;
    updateMutation.mutate({ indicator: editingItem.indicator, data: editForm });
  };

  const isScanning = scanMutation.isPending;
  const error = queryError ? "Failed to fetch watchlist registry." : scanMutation.isError ? "Scanner job failed." : "";
  const heatmapData = generateHeatmap(watchlist);

  if (isLoading) {
    return (
      <div className="max-w-6xl mx-auto space-y-6 py-8 animate-pulse px-4 md:px-8">
        <div className="h-14 bg-white/5 rounded-xl border border-white/5" />
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-44 bg-white/5 rounded-xl border border-white/5" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-12 px-4 md:px-8 mt-6">
      {/* Header Banner */}
      <div className="glass-panel p-md rounded-xl flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-[24px]">visibility</span>
            <h2 className="text-xl font-black text-white tracking-tight font-headline-lg">
              Monitored Watchlist Hub
            </h2>
          </div>
          <p className="text-xs text-on-surface-variant/80 font-body-sm">
            Continuous threat auditing on target indicators. Shifts in reputation trigger incident alerts.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <a
            href={api.getRssFeedUrl()}
            target="_blank"
            className="p-2.5 bg-[#f26522]/10 text-[#f26522] rounded-lg hover:bg-[#f26522]/20 border border-[#f26522]/30 transition-all flex items-center justify-center"
            title="RSS Threat Feed"
          >
            <Rss size={16} />
          </a>
          <a
            href={api.getBulkExportUrl("csv")}
            className="py-2 px-4 bg-surface-container border border-white/10 text-on-surface-variant text-xs font-bold rounded-lg hover:bg-white/5 hover:text-white transition-all flex items-center gap-2"
          >
            <Download size={14} />
            BULK EXPORT
          </a>
          <button
            onClick={() => scanMutation.mutate()}
            disabled={isScanning || watchlist.length === 0}
            className="py-2 px-4 bg-primary text-on-primary font-bold text-xs font-label-caps rounded-lg hover:opacity-90 active:scale-[0.98] transition-all flex items-center gap-2 disabled:opacity-50 disabled:scale-100"
          >
            <RefreshCw size={14} className={isScanning ? "animate-spin" : ""} />
            {isScanning ? "SCANNING IOCS..." : "AUDIT WATCHLIST"}
          </button>
        </div>
      </div>

      {/* Heatmap Section */}
      {watchlist.length > 0 && (
        <div className="glass-panel p-4 rounded-xl flex items-center gap-6 overflow-x-auto">
            <div className="text-xs font-bold text-on-surface-variant shrink-0">14-Day Threat Severity Map:</div>
            <div className="flex gap-1">
                {heatmapData.map((d, i) => {
                    let color = "bg-surface-container border border-white/5";
                    if (d.risk >= 90) color = "bg-error/80 border border-error";
                    else if (d.risk >= 70) color = "bg-[#f97316]/80 border border-[#f97316]";
                    else if (d.risk >= 35) color = "bg-yellow-500/80 border border-yellow-500";
                    else if (d.risk > 0) color = "bg-primary/50 border border-primary";

                    return (
                        <div key={i} className={`w-6 h-6 rounded ${color} flex items-center justify-center group relative`}>
                            <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-black text-white text-[10px] px-2 py-1 rounded opacity-0 group-hover:opacity-100 whitespace-nowrap pointer-events-none transition-opacity">
                                {d.date}: {d.count} scans (Max Risk: {d.risk})
                            </div>
                        </div>
                    )
                })}
            </div>
        </div>
      )}

      {/* Action Messages */}
      {message && (
        <div className="bg-primary/10 border border-primary/20 text-primary px-4 py-3 rounded-lg text-xs font-mono-sm transition-all">
          {message}
        </div>
      )}
      {error && (
        <div className="bg-error-container/20 border border-error-container/30 text-error px-4 py-3 rounded-lg text-xs font-mono-sm transition-all">
          {error}
        </div>
      )}

      {/* Watchlist Cards Bento Grid */}
      {watchlist.length === 0 ? (
        <div className="glass-panel p-3xl rounded-xl flex flex-col items-center justify-center text-center space-y-4">
          <div className="p-4 rounded-full bg-white/5 border border-white/10 text-on-surface-variant/40 flex items-center justify-center">
            <Eye size={48} className="animate-pulse" />
          </div>
          <div className="space-y-1">
            <h3 className="font-bold text-white text-md font-headline-sm">Watchlist is Empty</h3>
            <p className="text-xs text-on-surface-variant/80 max-w-sm leading-relaxed">
              No IOC targets are currently being monitored. Add assets from dynamic threat scan pages to track reputation deviations.
            </p>
          </div>
          <Link href="/" className="bg-primary/20 text-primary border border-primary/25 py-2 px-6 rounded-lg text-xs font-bold font-label-caps hover:bg-primary/30 transition-all">
            SCAN NEW IOC
          </Link>
        </div>
      ) : (
        <motion.div layout className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <AnimatePresence mode="popLayout">
            {watchlist.map((item: any) => {
              let level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "LOW";
              if (item.last_risk_score >= 90) level = "CRITICAL";
              else if (item.last_risk_score >= 70) level = "HIGH";
              else if (item.last_risk_score >= 35) level = "MEDIUM";

              return (
                <motion.div
                  layout
                  key={item.id}
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.8, transition: { duration: 0.2 } }}
                  className="glass-panel p-4 rounded-xl flex flex-col justify-between hover:border-white/20 transition-colors duration-300 min-h-[190px] relative"
                >
                  <button 
                    onClick={() => openSettings(item)}
                    className="absolute top-4 right-4 text-on-surface-variant hover:text-white transition-colors"
                  >
                    <Settings size={16} />
                  </button>

                  <div className="space-y-3 pr-8">
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1 min-w-0">
                        <span className="inline-block text-[9px] font-mono-sm uppercase bg-white/5 border border-white/10 px-1.5 py-0.5 rounded text-on-surface-variant">
                          {item.type}
                        </span>
                        <h4 className="font-bold text-white text-sm tracking-wide break-all font-mono-md select-all truncate">
                          {item.indicator}
                        </h4>
                      </div>
                    </div>
                    <RiskBadge level={level} score={item.last_risk_score} />
                    
                    {item.tags && (
                        <div className="flex flex-wrap gap-1">
                            {item.tags.split(',').map((t: string) => (
                                <span key={t} className="text-[9px] bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 rounded uppercase">{t.trim()}</span>
                            ))}
                        </div>
                    )}

                    {item.notes && (
                      <div className="flex items-start gap-2 bg-surface-container-low p-2 rounded border border-white/5 mt-2">
                        <Notebook size={12} className="text-primary shrink-0 mt-0.5" />
                        <p className="text-[11px] text-on-surface-variant leading-relaxed line-clamp-2">
                          {item.notes}
                        </p>
                      </div>
                    )}
                  </div>

                  <div className="border-t border-white/5 pt-3 mt-4 flex items-center justify-between text-[10px] font-mono-sm text-on-surface-variant">
                    <div className="space-y-0.5 flex flex-col items-start">
                      <span className="flex items-center gap-1">
                         <RefreshCw size={10} /> {item.last_scanned_at ? new Date(item.last_scanned_at).toLocaleDateString() : "Never"}
                      </span>
                      {item.webhook_url && (
                          <span className="flex items-center gap-1 text-primary">
                              <Bell size={10} /> Webhook Active ({item.custom_threshold}+)
                          </span>
                      )}
                    </div>
                    
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => removeMutation.mutate(item.indicator)}
                        className="p-1.5 hover:bg-error-container/20 border border-transparent hover:border-error-container/30 rounded text-on-surface-variant hover:text-error transition-all"
                      >
                        <Trash2 size={14} />
                      </button>
                      <button
                        onClick={async () => {
                          try {
                            const scanResult = await api.analyzeIndicator(item.indicator, item.type as "ip" | "url" | "domain" | "hash");
                            window.location.href = `/results/${scanResult.id}`;
                          } catch (err) {
                            console.error("Redirect failed:", err);
                          }
                        }}
                        className="p-1.5 hover:bg-white/5 border border-transparent hover:border-white/10 rounded text-primary hover:text-white transition-all flex items-center gap-0.5"
                      >
                        REPORT <ArrowRight size={12} />
                      </button>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </AnimatePresence>
        </motion.div>
      )}

      {/* Settings Modal */}
      <AnimatePresence>
        {editingItem && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-surface glass-panel w-full max-w-lg rounded-2xl border border-white/10 shadow-2xl overflow-hidden flex flex-col"
            >
              <div className="p-4 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
                <h3 className="text-white font-bold text-lg flex items-center gap-2">
                  <Settings size={18} className="text-primary"/> 
                  Edit Watchlist Item
                </h3>
                <button onClick={() => setEditingItem(null)} className="text-on-surface-variant hover:text-white transition-colors">
                  <X size={20} />
                </button>
              </div>
              
              <div className="p-6 space-y-4 overflow-y-auto max-h-[60vh] custom-scrollbar">
                <div className="mb-4">
                  <span className="text-xs text-on-surface-variant uppercase tracking-wider block mb-1">Target Indicator</span>
                  <span className="text-white font-mono bg-black/50 px-3 py-1.5 rounded-lg border border-white/10 block">{editingItem.indicator}</span>
                </div>

                <div className="space-y-1">
                  <label className="text-xs text-on-surface-variant uppercase tracking-wider">Tags (comma separated)</label>
                  <input 
                    type="text" 
                    value={editForm.tags} 
                    onChange={e => setEditForm({...editForm, tags: e.target.value})}
                    className="w-full bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-primary focus:ring-1 focus:ring-primary outline-none"
                    placeholder="e.g. ransomware, apt29, critical-infra"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs text-on-surface-variant uppercase tracking-wider">Custom Alert Threshold</label>
                  <input 
                    type="number" 
                    value={editForm.custom_threshold} 
                    onChange={e => setEditForm({...editForm, custom_threshold: parseInt(e.target.value) || 0})}
                    className="w-full bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-primary focus:ring-1 focus:ring-primary outline-none"
                  />
                  <p className="text-[10px] text-on-surface-variant">Alerts when risk score reaches or exceeds this value.</p>
                </div>

                <div className="space-y-1">
                  <label className="text-xs text-on-surface-variant uppercase tracking-wider">Webhook URL (Optional)</label>
                  <input 
                    type="url" 
                    value={editForm.webhook_url} 
                    onChange={e => setEditForm({...editForm, webhook_url: e.target.value})}
                    className="w-full bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-primary focus:ring-1 focus:ring-primary outline-none"
                    placeholder="https://your-server.com/webhook"
                  />
                  <p className="text-[10px] text-on-surface-variant">Sends POST payload if threshold is exceeded during scan.</p>
                </div>

                <div className="space-y-1">
                  <label className="text-xs text-on-surface-variant uppercase tracking-wider">Automated Scan Schedule</label>
                  <select 
                    value={editForm.schedule_frequency} 
                    onChange={e => setEditForm({...editForm, schedule_frequency: e.target.value})}
                    className="w-full bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-primary focus:ring-1 focus:ring-primary outline-none appearance-none"
                  >
                    <option value="none">Manual Only</option>
                    <option value="daily">Daily Check</option>
                    <option value="weekly">Weekly Check</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs text-on-surface-variant uppercase tracking-wider">Notes</label>
                  <textarea 
                    value={editForm.notes} 
                    onChange={e => setEditForm({...editForm, notes: e.target.value})}
                    className="w-full bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-primary focus:ring-1 focus:ring-primary outline-none min-h-[80px]"
                    placeholder="Investigative notes or context..."
                  />
                </div>
              </div>

              <div className="p-4 border-t border-white/5 bg-white/[0.02] flex justify-end gap-3">
                <button 
                  onClick={() => setEditingItem(null)}
                  className="px-4 py-2 text-sm font-bold text-on-surface-variant hover:text-white transition-colors"
                >
                  CANCEL
                </button>
                <button 
                  onClick={handleSaveSettings}
                  disabled={updateMutation.isPending}
                  className="px-4 py-2 bg-primary text-black font-bold text-sm rounded-lg hover:bg-primary/90 flex items-center gap-2 transition-all disabled:opacity-50"
                >
                  <Save size={16} />
                  {updateMutation.isPending ? "SAVING..." : "SAVE CHANGES"}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
