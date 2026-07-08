"use client";

import React, { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { motion, AnimatePresence } from "framer-motion";
import { Plus, Trash2, Target, ChevronRight, X, Shield, RefreshCw } from "lucide-react";
import Link from "next/link";

interface Campaign {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
  ioc_count: number;
}

interface CampaignDetail extends Campaign {
  iocs: {
    id: number;
    scan_id: string;
    indicator: string;
    type: string;
    risk_score: number;
    risk_level: string;
    added_at: string;
  }[];
}

const RISK_COLORS: Record<string, string> = {
  CRITICAL: "text-[#ffb4ab] bg-[#93000a]/20 border-[#ffb4ab]/25",
  HIGH: "text-[#ffb786] bg-[#df7412]/20 border-[#ffb786]/20",
  MEDIUM: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  LOW: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
};

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [selected, setSelected] = useState<CampaignDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [creating, setCreating] = useState(false);

  const fetchCampaigns = async () => {
    setLoading(true);
    try {
      const data = await api.getCampaigns();
      setCampaigns(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchCampaigns(); }, []);

  const handleSelectCampaign = async (id: string) => {
    setDetailLoading(true);
    try {
      const data = await api.getCampaign(id);
      setSelected(data);
    } catch (e) {
      console.error(e);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleCreate = async () => {
    if (!newName.trim()) return;
    setCreating(true);
    try {
      await api.createCampaign(newName.trim(), newDesc.trim() || undefined);
      setNewName("");
      setNewDesc("");
      setShowCreate(false);
      fetchCampaigns();
    } catch (e) {
      console.error(e);
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteCampaign = async (id: string) => {
    if (!confirm("Delete this campaign and all its IOC links?")) return;
    try {
      await api.deleteCampaign(id);
      if (selected?.id === id) setSelected(null);
      fetchCampaigns();
    } catch (e) {
      console.error(e);
    }
  };

  const handleRemoveIOC = async (scanId: string) => {
    if (!selected) return;
    try {
      await api.removeIOCFromCampaign(selected.id, scanId);
      handleSelectCampaign(selected.id);
    } catch (e) {
      console.error(e);
    }
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    show: { opacity: 1, transition: { staggerChildren: 0.07 } }
  };
  const itemVariants = { hidden: { y: 16, opacity: 0 }, show: { y: 0, opacity: 1 } };

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-12 px-4 md:px-8 mt-6">
      {/* Header */}
      <div className="glass-panel p-md rounded-xl flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Target className="text-primary w-6 h-6" />
            <h2 className="text-xl font-black text-white tracking-tight">Campaign Tracker</h2>
          </div>
          <p className="text-xs text-on-surface-variant/80">
            Group related IOCs into threat campaigns for coordinated investigation.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="py-2.5 px-4 bg-primary text-on-primary font-bold text-xs rounded-lg hover:opacity-90 active:scale-[0.98] transition-all flex items-center gap-2"
        >
          <Plus size={14} /> NEW CAMPAIGN
        </button>
      </div>

      {/* Create Modal */}
      <AnimatePresence>
        {showCreate && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-md px-4"
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
              className="bg-surface-container border border-white/10 rounded-2xl p-6 w-full max-w-md shadow-2xl"
            >
              <div className="flex items-center justify-between mb-5">
                <h3 className="text-lg font-bold text-white">Create Campaign</h3>
                <button onClick={() => setShowCreate(false)} className="text-on-surface-variant hover:text-white transition-colors">
                  <X size={20} />
                </button>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="text-[10px] font-mono-sm uppercase text-on-surface-variant mb-1.5 block">Campaign Name *</label>
                  <input
                    value={newName} onChange={e => setNewName(e.target.value)}
                    placeholder="e.g. APT28 Infrastructure Q4 2024"
                    className="w-full bg-surface-container-low border border-white/10 rounded-lg px-3 py-2.5 text-sm text-white placeholder-on-surface-variant/50 focus:outline-none focus:border-primary/50"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-mono-sm uppercase text-on-surface-variant mb-1.5 block">Description</label>
                  <textarea
                    value={newDesc} onChange={e => setNewDesc(e.target.value)}
                    placeholder="Optional: what is this campaign tracking?"
                    rows={3}
                    className="w-full bg-surface-container-low border border-white/10 rounded-lg px-3 py-2.5 text-sm text-white placeholder-on-surface-variant/50 focus:outline-none focus:border-primary/50 resize-none"
                  />
                </div>
                <button
                  onClick={handleCreate} disabled={creating || !newName.trim()}
                  className="w-full py-2.5 bg-primary text-on-primary font-bold text-sm rounded-lg hover:opacity-90 disabled:opacity-50 transition-all flex items-center justify-center gap-2"
                >
                  {creating ? <RefreshCw size={14} className="animate-spin" /> : <Plus size={14} />}
                  {creating ? "Creating..." : "Create Campaign"}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Campaign List */}
        <div className="lg:col-span-1 space-y-3">
          <p className="text-[10px] font-mono-sm uppercase text-on-surface-variant tracking-wider">
            {campaigns.length} Campaign{campaigns.length !== 1 ? "s" : ""}
          </p>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <RefreshCw className="w-6 h-6 text-primary animate-spin" />
            </div>
          ) : campaigns.length === 0 ? (
            <div className="glass-panel p-8 rounded-xl text-center">
              <Target className="w-10 h-10 text-on-surface-variant/30 mx-auto mb-3" />
              <p className="text-sm text-on-surface-variant">No campaigns yet.</p>
              <p className="text-xs text-on-surface-variant/50 mt-1">Create one to group related IOCs.</p>
            </div>
          ) : (
            <motion.div variants={containerVariants} initial="hidden" animate="show" className="space-y-2">
              {campaigns.map(c => (
                <motion.button
                  key={c.id} variants={itemVariants}
                  onClick={() => handleSelectCampaign(c.id)}
                  className={`w-full text-left glass-panel p-4 rounded-xl hover:border-primary/30 transition-all group ${selected?.id === c.id ? "border-primary/40 bg-primary/5" : ""}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <p className="font-bold text-white text-sm truncate">{c.name}</p>
                      <p className="text-[10px] text-on-surface-variant mt-0.5">
                        {c.ioc_count} IOC{c.ioc_count !== 1 ? "s" : ""} · Updated {new Date(c.updated_at).toLocaleDateString()}
                      </p>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        onClick={e => { e.stopPropagation(); handleDeleteCampaign(c.id); }}
                        className="opacity-0 group-hover:opacity-100 text-on-surface-variant hover:text-error transition-all p-1"
                      >
                        <Trash2 size={13} />
                      </button>
                      <ChevronRight size={14} className={`text-on-surface-variant transition-transform ${selected?.id === c.id ? "rotate-90 text-primary" : ""}`} />
                    </div>
                  </div>
                </motion.button>
              ))}
            </motion.div>
          )}
        </div>

        {/* Campaign Detail */}
        <div className="lg:col-span-2">
          {detailLoading ? (
            <div className="glass-panel rounded-xl p-12 flex items-center justify-center">
              <RefreshCw className="w-6 h-6 text-primary animate-spin" />
            </div>
          ) : selected ? (
            <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="glass-panel rounded-xl overflow-hidden">
              <div className="p-5 border-b border-white/5">
                <h3 className="font-bold text-white text-lg">{selected.name}</h3>
                {selected.description && (
                  <p className="text-xs text-on-surface-variant mt-1">{selected.description}</p>
                )}
                <p className="text-[10px] text-on-surface-variant/50 mt-2">
                  Created {new Date(selected.created_at).toLocaleString()} · {selected.iocs?.length || 0} IOCs
                </p>
              </div>
              {!selected.iocs || selected.iocs.length === 0 ? (
                <div className="p-12 text-center">
                  <Shield className="w-10 h-10 text-on-surface-variant/30 mx-auto mb-3" />
                  <p className="text-sm text-on-surface-variant">No IOCs in this campaign yet.</p>
                  <p className="text-xs text-on-surface-variant/50 mt-1">
                    Add IOCs from a scan result page using the &quot;Add to Campaign&quot; button.
                  </p>
                </div>
              ) : (
                <div className="divide-y divide-white/5">
                  {selected.iocs.map(ioc => (
                    <div key={ioc.id} className="flex items-center gap-3 px-5 py-3.5 hover:bg-white/[0.02] transition-all group">
                      <div className="p-1.5 rounded-md bg-surface-container-low border border-white/5">
                        <span className="material-symbols-outlined text-primary text-[14px]">
                          {ioc.type === "ip" ? "sensors" : ioc.type === "url" ? "link" : ioc.type === "domain" ? "language" : "tag"}
                        </span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-white font-mono-sm truncate">{ioc.indicator}</p>
                        <p className="text-[10px] text-on-surface-variant">{ioc.type.toUpperCase()} · Added {new Date(ioc.added_at).toLocaleDateString()}</p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${RISK_COLORS[ioc.risk_level] || RISK_COLORS.LOW}`}>
                          {ioc.risk_level}
                        </span>
                        <span className="text-xs font-bold text-white">{ioc.risk_score}</span>
                        <Link
                          href={`/results/${ioc.scan_id}`}
                          className="opacity-0 group-hover:opacity-100 text-[10px] text-primary hover:text-white border border-primary/20 px-2 py-1 rounded transition-all"
                        >
                          VIEW
                        </Link>
                        <button
                          onClick={() => handleRemoveIOC(ioc.scan_id)}
                          className="opacity-0 group-hover:opacity-100 text-on-surface-variant hover:text-error p-1 transition-all"
                        >
                          <X size={12} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>
          ) : (
            <div className="glass-panel rounded-xl p-12 flex flex-col items-center justify-center text-center h-full min-h-[300px]">
              <Target className="w-12 h-12 text-on-surface-variant/20 mb-4" />
              <p className="text-on-surface-variant">Select a campaign to view its IOCs</p>
              <p className="text-xs text-on-surface-variant/50 mt-1">or create a new one to get started</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
